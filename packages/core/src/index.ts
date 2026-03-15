import { spawnSync } from "node:child_process";
import { createHmac, randomBytes } from "node:crypto";
import {
  existsSync,
  readFileSync,
} from "node:fs";
import { basename } from "node:path";

import {
  createVaultConfig,
  decryptWithKey,
  encryptWithKey,
  randomId,
  unlockRootKey,
  type EncryptedBlob,
} from "../../crypto/src/index.ts";
import {
  assertPathIsDirectory,
  assertPathIsFile,
  decryptFileArtifact,
  decryptFolderArtifact,
  defaultDecryptedFilePath,
  defaultDecryptedFolderPath,
  defaultEncryptedFilePath,
  defaultEncryptedFolderPath,
  encryptFileArtifact,
  encryptFolderArtifact,
} from "./artifacts.ts";
import { AuthoDatabase, type AuditRow, type LeaseRow, type SecretRow } from "../../storage/src/index.ts";
import {
  defaultProjectFilePath,
  defaultVaultPath,
  writeTextFileSecure,
} from "./paths.ts";

export type SecretType = "note" | "otp" | "password";

export type SecretRecord = {
  createdAt: string;
  id: string;
  metadata: Record<string, unknown>;
  name: string;
  type: SecretType;
  updatedAt: string;
  username: string | null;
  value: string;
};

export type SecretSummary = Omit<SecretRecord, "metadata" | "username" | "value">;

export type AuditEvent = {
  createdAt: string;
  eventType: string;
  id: string;
  message: string;
  metadata: Record<string, unknown>;
  subjectRef: string | null;
  subjectType: string;
};

export type EnvMapping = {
  envName: string;
  secretRef: string;
};

export type VaultStatus = {
  activeLeaseCount: number;
  auditEventCount: number;
  initialized: boolean;
  projectFile: string | null;
  projectMappings: string[];
  secretCount: number;
  unlocked: boolean;
  vaultPath: string;
};

type StoredSecretPayload = {
  metadata: Record<string, unknown>;
  username: string | null;
  value: string;
};

type LeaseState = {
  createdAt: string;
  expiresAt: string;
  id: string;
  name: string;
  revokedAt: string | null;
  secretRefs: string[];
};

type LegacySecret = {
  algorithm?: string;
  description?: string;
  digits?: number;
  name?: string;
  secret?: string;
  type?: string;
  url?: string;
  username?: string;
  value?: string;
};

function requireValue(value: string | undefined, label: string): string {
  if (!value) {
    throw new Error(`Missing required option: ${label}`);
  }

  return value;
}

function decodeBase32(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("OTP secret must be valid base32");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Uint8Array.from(output);
}

function generateTotp(
  secret: string,
  options?: { algorithm?: string; digits?: number },
  now = Date.now(),
): { code: string; expiresAt: string } {
  const algorithm = (options?.algorithm ?? "sha1").toLowerCase();
  const digits = options?.digits ?? 6;
  const key = decodeBase32(secret);
  const counter = Math.floor(now / 30_000);
  const message = Buffer.alloc(8);
  let cursor = counter;

  for (let index = 7; index >= 0; index -= 1) {
    message[index] = cursor & 0xff;
    cursor >>= 8;
  }

  const hash = createHmac(algorithm, Buffer.from(key)).update(message).digest();
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  const mod = 10 ** digits;
  const code = String(binary % mod).padStart(digits, "0");
  const expiresAt = new Date((counter + 1) * 30_000).toISOString();

  return { code, expiresAt };
}

function normalizeSecretType(type: string): SecretType {
  if (type === "password" || type === "note" || type === "otp") {
    return type;
  }

  throw new Error(`Unsupported secret type: ${type}`);
}

function parseProjectMappings(projectFile: string): EnvMapping[] {
  const raw = JSON.parse(readFileSync(projectFile, "utf8")) as {
    env?: Record<string, string>;
  };

  return Object.entries(raw.env ?? {}).map(([envName, secretRef]) => ({
    envName,
    secretRef,
  }));
}

function parseLease(row: LeaseRow): LeaseState {
  return {
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    id: row.id,
    name: row.name,
    revokedAt: row.revokedAt,
    secretRefs: JSON.parse(row.secretRefs) as string[],
  };
}

function toAuditEvent(row: AuditRow): AuditEvent {
  return {
    createdAt: row.createdAt,
    eventType: row.eventType,
    id: row.id,
    message: row.message,
    metadata: JSON.parse(row.metadata) as Record<string, unknown>,
    subjectRef: row.subjectRef,
    subjectType: row.subjectType,
  };
}

function normalizeMetadata(input: Record<string, unknown> | undefined): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(input ?? {}).filter(([, value]) => value !== undefined && value !== null && value !== ""),
  );
}

function parseLegacySecret(secret: LegacySecret): {
  metadata: Record<string, unknown>;
  name: string;
  type: SecretType;
  username?: string;
  value: string;
} {
  const type = normalizeSecretType(requireValue(secret.type, "legacy.type"));
  const name = requireValue(secret.name, "legacy.name");
  const value = requireValue(secret.secret ?? secret.value, "legacy.secret");

  if (type === "password") {
    return {
      metadata: normalizeMetadata({
        description: secret.description,
        url: secret.url,
      }),
      name,
      type,
      username: secret.username,
      value,
    };
  }

  if (type === "otp") {
    return {
      metadata: normalizeMetadata({
        algorithm: secret.algorithm ?? "SHA1",
        description: secret.description,
        digits: secret.digits ?? 6,
      }),
      name,
      type,
      username: secret.username,
      value,
    };
  }

  return {
    metadata: normalizeMetadata({
      description: secret.description,
    }),
    name,
    type,
    value,
  };
}

function quoteEnvValue(value: string): string {
  return JSON.stringify(value);
}

function summarizeCommand(cmd: string[]): { argCount: number; executable: string } {
  return {
    argCount: Math.max(0, cmd.length - 1),
    executable: basename(cmd[0] ?? "unknown"),
  };
}

function projectMappingsForStatus(projectFile?: string): { path: string | null; mappings: string[] } {
  if (!projectFile || !existsSync(projectFile)) {
    return {
      mappings: [],
      path: projectFile ?? null,
    };
  }

  return {
    mappings: parseProjectMappings(projectFile).map((mapping) => mapping.envName),
    path: projectFile,
  };
}

export { defaultProjectFilePath, defaultVaultPath } from "./paths.ts";

export function resolveMappings(options: {
  maps?: string[];
  projectFile?: string;
}): EnvMapping[] {
  const fromMaps = (options.maps ?? []).map((mapping) => {
    const splitIndex = mapping.indexOf("=");
    if (splitIndex === -1) {
      throw new Error(`Invalid env mapping: ${mapping}`);
    }

    return {
      envName: mapping.slice(0, splitIndex),
      secretRef: mapping.slice(splitIndex + 1),
    };
  });

  if (options.projectFile) {
    if (!existsSync(options.projectFile)) {
      throw new Error(`Project mapping file not found: ${options.projectFile}`);
    }

    return [...parseProjectMappings(options.projectFile), ...fromMaps];
  }

  return fromMaps;
}

export function writeProjectConfig(input: {
  force?: boolean;
  mappings: EnvMapping[];
  outputPath: string;
}): { mappingCount: number; outputPath: string } {
  if (input.mappings.length === 0) {
    throw new Error("Provide at least one env mapping");
  }
  if (!input.force && existsSync(input.outputPath)) {
    throw new Error(`Project config already exists: ${input.outputPath}`);
  }

  const env = Object.fromEntries(input.mappings.map((mapping) => [mapping.envName, mapping.secretRef]));
  writeTextFileSecure(
    input.outputPath,
    JSON.stringify(
      {
        env,
        generatedAt: new Date().toISOString(),
        version: 1,
      },
      null,
      2,
    ) + "\n",
  );

  return {
    mappingCount: input.mappings.length,
    outputPath: input.outputPath,
  };
}

export class VaultService {
  static initialize(vaultPath: string, password: string): { vaultPath: string } {
    const db = new AuthoDatabase(vaultPath);

    try {
      if (db.getVaultConfig()) {
        throw new Error(`Vault already initialized at ${vaultPath}`);
      }

      const { config } = createVaultConfig(password);
      db.setVaultConfig(config);
      db.insertAudit({
        createdAt: new Date().toISOString(),
        eventType: "vault.initialized",
        id: randomId(),
        message: "Vault initialized",
        metadata: JSON.stringify({ version: config.version }),
        subjectRef: null,
        subjectType: "vault",
      });

      return { vaultPath };
    } finally {
      db.close();
    }
  }

  static status(vaultPath: string, options?: { password?: string; projectFile?: string }): VaultStatus {
    const db = new AuthoDatabase(vaultPath);

    try {
      const config = db.getVaultConfig();
      const project = projectMappingsForStatus(options?.projectFile);
      if (!config) {
        return {
          activeLeaseCount: 0,
          auditEventCount: 0,
          initialized: false,
          projectFile: project.path,
          projectMappings: project.mappings,
          secretCount: 0,
          unlocked: false,
          vaultPath,
        };
      }

      if (!options?.password) {
        return {
          activeLeaseCount: 0,
          auditEventCount: 0,
          initialized: true,
          projectFile: project.path,
          projectMappings: project.mappings,
          secretCount: 0,
          unlocked: false,
          vaultPath,
        };
      }

      const rootKey = unlockRootKey(options.password, config);
      const session = new VaultSession(db, rootKey);
      return session.status(vaultPath, project.path, project.mappings);
    } finally {
      db.close();
    }
  }

  static unlock(vaultPath: string, password: string): VaultSession {
    const db = new AuthoDatabase(vaultPath);
    const config = db.getVaultConfig();
    if (!config) {
      db.close();
      throw new Error(`Vault is not initialized at ${vaultPath}`);
    }

    try {
      const rootKey = unlockRootKey(password, config);
      return new VaultSession(db, rootKey);
    } catch (error) {
      db.close();
      throw new Error("Invalid vault password", { cause: error });
    }
  }
}

export class VaultSession {
  constructor(
    private readonly db: AuthoDatabase,
    private readonly rootKey: Buffer,
  ) {}

  close(): void {
    this.db.close();
  }

  status(vaultPath: string, projectFile?: string | null, projectMappings: string[] = []): VaultStatus {
    return {
      activeLeaseCount: this.db.countActiveLeases(new Date().toISOString()),
      auditEventCount: this.db.countAuditEvents(),
      initialized: true,
      projectFile: projectFile ?? null,
      projectMappings,
      secretCount: this.db.countSecrets(),
      unlocked: true,
      vaultPath,
    };
  }

  private audit(
    eventType: string,
    subjectType: string,
    subjectRef: string | null,
    message: string,
    metadata: Record<string, unknown>,
  ): void {
    this.db.insertAudit({
      createdAt: new Date().toISOString(),
      eventType,
      id: randomId(),
      message,
      metadata: JSON.stringify(metadata),
      subjectRef,
      subjectType,
    });
  }

  private unwrapSecret(row: SecretRow): SecretRecord {
    const wrappedKey = JSON.parse(row.wrappedKey) as EncryptedBlob;
    const payload = JSON.parse(row.payload) as EncryptedBlob;
    const dek = decryptWithKey(wrappedKey, this.rootKey, `autho:secret:${row.id}:dek`);
    const secret = JSON.parse(
      decryptWithKey(payload, dek, `autho:secret:${row.id}:payload`).toString("utf8"),
    ) as StoredSecretPayload;

    return {
      createdAt: row.createdAt,
      id: row.id,
      metadata: normalizeMetadata(secret.metadata),
      name: row.name,
      type: normalizeSecretType(row.type),
      updatedAt: row.updatedAt,
      username: secret.username,
      value: secret.value,
    };
  }

  private getSecretOrThrow(ref: string): SecretRecord {
    const row = this.db.findSecret(ref);
    if (!row) {
      throw new Error(`Secret not found: ${ref}`);
    }

    return this.unwrapSecret(row);
  }

  private getLeaseOrThrow(id: string): LeaseState {
    const row = this.db.findLease(id);
    if (!row) {
      throw new Error(`Lease not found: ${id}`);
    }

    return parseLease(row);
  }

  private assertLeaseAllows(leaseId: string | undefined, secretRef: string): void {
    if (!leaseId) {
      return;
    }

    const lease = this.getLeaseOrThrow(leaseId);
    if (lease.revokedAt) {
      throw new Error(`Lease revoked: ${lease.id}`);
    }
    if (Date.parse(lease.expiresAt) <= Date.now()) {
      throw new Error(`Lease expired: ${lease.id}`);
    }

    const secret = this.getSecretOrThrow(secretRef);
    if (!lease.secretRefs.includes(secret.id) && !lease.secretRefs.includes(secret.name)) {
      throw new Error(`Lease ${lease.id} does not allow secret ${secretRef}`);
    }
  }

  addSecret(input: {
    metadata?: Record<string, unknown>;
    name: string;
    type: string;
    username?: string;
    value: string;
  }): SecretSummary {
    requireValue(input.name, "--name");
    requireValue(input.value, "--value");

    const type = normalizeSecretType(input.type);
    if (this.db.findSecret(input.name)) {
      throw new Error(`Secret already exists: ${input.name}`);
    }

    const now = new Date().toISOString();
    const id = randomId();
    const dek = randomBytes(32);
    const payload = encryptWithKey(
      JSON.stringify({
        metadata: normalizeMetadata(input.metadata),
        username: input.username ?? null,
        value: input.value,
      } satisfies StoredSecretPayload),
      dek,
      `autho:secret:${id}:payload`,
    );
    const wrappedKey = encryptWithKey(dek, this.rootKey, `autho:secret:${id}:dek`);

    this.db.insertSecret({
      createdAt: now,
      id,
      name: input.name,
      payload: JSON.stringify(payload),
      type,
      updatedAt: now,
      wrappedKey: JSON.stringify(wrappedKey),
    });
    this.audit("secret.created", "secret", id, "Secret created", {
      metadataKeyCount: Object.keys(normalizeMetadata(input.metadata)).length,
      type,
    });

    return {
      createdAt: now,
      id,
      name: input.name,
      type,
      updatedAt: now,
    };
  }

  importLegacyFile(filePath: string, options?: { skipExisting?: boolean }): {
    imported: number;
    skipped: number;
  } {
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as LegacySecret[];
    let imported = 0;
    let skipped = 0;

    for (const entry of raw) {
      if (!entry) {
        continue;
      }

      const parsed = parseLegacySecret(entry);
      if (this.db.findSecret(parsed.name)) {
        if (options?.skipExisting ?? true) {
          skipped += 1;
          continue;
        }
        throw new Error(`Secret already exists: ${parsed.name}`);
      }

      this.addSecret(parsed);
      imported += 1;
    }

    this.audit("import.legacy", "vault", null, "Legacy backup imported", {
      imported,
      skipped,
    });

    return { imported, skipped };
  }

  listSecrets(): SecretSummary[] {
    return this.db.listSecrets().map((row) => ({
      createdAt: row.createdAt,
      id: row.id,
      name: row.name,
      type: normalizeSecretType(row.type),
      updatedAt: row.updatedAt,
    }));
  }

  getSecret(ref: string): SecretRecord {
    const secret = this.getSecretOrThrow(ref);
    this.audit("secret.read", "secret", secret.id, "Secret read", {
      metadataKeyCount: Object.keys(secret.metadata).length,
      type: secret.type,
    });

    return secret;
  }

  removeSecret(ref: string): { id: string; name: string } {
    const secret = this.getSecretOrThrow(ref);
    this.db.deleteSecret(secret.id);
    this.audit("secret.deleted", "secret", secret.id, "Secret deleted", {
      type: secret.type,
    });

    return { id: secret.id, name: secret.name };
  }

  generateOtp(ref: string): { code: string; expiresAt: string; secret: string } {
    const secret = this.getSecretOrThrow(ref);
    if (secret.type !== "otp") {
      throw new Error(`Secret is not an OTP secret: ${ref}`);
    }

    const result = generateTotp(secret.value, {
      algorithm: secret.metadata.algorithm as string | undefined,
      digits: secret.metadata.digits as number | undefined,
    });
    this.audit("otp.generated", "secret", secret.id, "OTP code generated", {
      expiresAt: result.expiresAt,
    });

    return {
      code: result.code,
      expiresAt: result.expiresAt,
      secret: secret.name,
    };
  }

  createLease(input: {
    name: string;
    secretRefs: string[];
    ttlSeconds: number;
  }): LeaseState {
    if (input.secretRefs.length === 0) {
      throw new Error("Lease requires at least one --secret");
    }
    if (input.ttlSeconds <= 0) {
      throw new Error("Lease ttl must be greater than zero");
    }

    const resolved = input.secretRefs.map((ref) => this.getSecretOrThrow(ref));
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + input.ttlSeconds * 1000).toISOString();
    const lease: LeaseState = {
      createdAt: now,
      expiresAt,
      id: randomId(),
      name: input.name || "session",
      revokedAt: null,
      secretRefs: resolved.map((secret) => secret.id),
    };

    this.db.insertLease({
      createdAt: lease.createdAt,
      expiresAt: lease.expiresAt,
      id: lease.id,
      name: lease.name,
      revokedAt: lease.revokedAt,
      secretRefs: JSON.stringify(lease.secretRefs),
    });
    this.audit("lease.created", "lease", lease.id, "Lease created", {
      expiresAt,
      secretCount: lease.secretRefs.length,
    });

    return lease;
  }

  revokeLease(id: string): LeaseState {
    const lease = this.getLeaseOrThrow(id);
    const revokedAt = new Date().toISOString();
    this.db.revokeLease(id, revokedAt);
    this.audit("lease.revoked", "lease", id, "Lease revoked", {
      id,
    });

    return {
      ...lease,
      revokedAt,
    };
  }

  private buildEnv(
    mappings: EnvMapping[],
    leaseId?: string,
  ): Record<string, string> {
    if (mappings.length === 0) {
      throw new Error("Provide at least one env mapping");
    }

    const output: Record<string, string> = {};
    for (const mapping of mappings) {
      this.assertLeaseAllows(leaseId, mapping.secretRef);
      const secret = this.getSecretOrThrow(mapping.secretRef);
      output[mapping.envName] = secret.value;
    }

    return output;
  }

  renderEnv(mappings: EnvMapping[], leaseId?: string): Record<string, string> {
    const env = this.buildEnv(mappings, leaseId);
    this.audit("env.rendered", "lease", leaseId ?? null, "Environment rendered", {
      leaseId: leaseId ?? null,
      varCount: Object.keys(env).length,
    });

    return env;
  }

  syncEnvFile(input: {
    force?: boolean;
    leaseId?: string;
    mappings: EnvMapping[];
    outputPath: string;
    ttlSeconds?: number;
  }): { expiresAt: string | null; outputPath: string; varCount: number } {
    const env = this.buildEnv(input.mappings, input.leaseId);
    if (!input.force && existsSync(input.outputPath)) {
      throw new Error(`Env file already exists: ${input.outputPath}`);
    }

    const createdAt = new Date().toISOString();
    const expiresAt = input.ttlSeconds
      ? new Date(Date.now() + input.ttlSeconds * 1000).toISOString()
      : null;
    const lines = [
      "# autho-generated=true",
      `# autho-created-at=${createdAt}`,
      `# autho-expires-at=${expiresAt ?? ""}`,
      ...Object.entries(env).map(([key, value]) => `${key}=${quoteEnvValue(value)}`),
      "",
    ];

    writeTextFileSecure(input.outputPath, lines.join("\n"));
    this.audit("env.synced", "lease", input.leaseId ?? null, "Environment file written", {
      expiresAt,
      leaseId: input.leaseId ?? null,
      varCount: Object.keys(env).length,
    });

    return {
      expiresAt,
      outputPath: input.outputPath,
      varCount: Object.keys(env).length,
    };
  }

  runExec(input: {
    cmd: string[];
    leaseId?: string;
    mappings: EnvMapping[];
  }): {
    exitCode: number;
    stderr: string;
    stdout: string;
  } {
    if (input.cmd.length === 0) {
      throw new Error("Missing command after --");
    }

    const injectedEnv = this.buildEnv(input.mappings, input.leaseId);
    const result = spawnSync(input.cmd[0], input.cmd.slice(1), {
      env: {
        ...process.env,
        ...injectedEnv,
      },
      stdio: "pipe",
    });

    this.audit("exec.run", "lease", input.leaseId ?? null, "Injected command executed", {
      ...summarizeCommand(input.cmd),
      envCount: Object.keys(injectedEnv).length,
      exitCode: result.status ?? 1,
      leaseId: input.leaseId ?? null,
    });

    return {
      exitCode: result.status ?? 1,
      stderr: (result.stderr ?? Buffer.from("")).toString("utf8"),
      stdout: (result.stdout ?? Buffer.from("")).toString("utf8"),
    };
  }

  encryptFile(inputPath: string, outputPath?: string): { outputPath: string } {
    assertPathIsFile(inputPath);
    const result = encryptFileArtifact(
      inputPath,
      outputPath ?? defaultEncryptedFilePath(inputPath),
      this.rootKey,
    );
    this.audit("file.encrypted", "artifact", null, "File encrypted", {
      kind: "file",
    });

    return result;
  }

  decryptFile(inputPath: string, outputPath?: string): { outputPath: string } {
    assertPathIsFile(inputPath);
    const result = decryptFileArtifact(
      inputPath,
      outputPath ?? defaultDecryptedFilePath(inputPath),
      this.rootKey,
    );
    this.audit("file.decrypted", "artifact", null, "File decrypted", {
      kind: "file",
    });

    return result;
  }

  encryptFolder(inputPath: string, outputPath?: string): { fileCount: number; outputPath: string } {
    assertPathIsDirectory(inputPath);
    const result = encryptFolderArtifact(
      inputPath,
      outputPath ?? defaultEncryptedFolderPath(inputPath),
      this.rootKey,
    );
    this.audit("folder.encrypted", "artifact", null, "Folder encrypted", {
      fileCount: result.fileCount,
      kind: "folder",
    });

    return result;
  }

  decryptFolder(inputPath: string, outputPath?: string): { fileCount: number; outputPath: string } {
    assertPathIsFile(inputPath);
    const result = decryptFolderArtifact(
      inputPath,
      outputPath ?? defaultDecryptedFolderPath(inputPath),
      this.rootKey,
    );
    this.audit("folder.decrypted", "artifact", null, "Folder decrypted", {
      fileCount: result.fileCount,
      kind: "folder",
    });

    return result;
  }

  listAudit(limit = 50): AuditEvent[] {
    return this.db.listAudit(limit).map(toAuditEvent);
  }
}







