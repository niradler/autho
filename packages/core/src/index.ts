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
  deriveKeyFromPassword,
  deriveKeyFromSecret,
  encryptWithKey,
  generateTotpSecret,
  randomId,
  totpUri,
  unlockRootKey,
  unwrapRootKey,
  verifyTotpCode,
  wrapRootKey,
  type EncryptedBlob,
  type VaultKdfConfig,
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
import { AuthoDatabase, type AuditRow, type LeaseRow, type SecretRow, type VaultAuth, type VaultPasskey } from "../../storage/src/index.ts";
import {
  currentSealRecord,
  sealedSnapshot,
  sealKey,
  unlockWithPassword,
  verifySeal,
  VaultTamperedError,
  writeSeal,
  type SealChange,
  type SealRecord,
  type SealState,
} from "./seal.ts";
import {
  defaultProjectFilePath,
  defaultVaultPath,
  writeTextFileSecure,
} from "./paths.ts";

export type SecretType = "note" | "otp" | "password";

export type UnlockCredentials = {
  password: string;
  totp?: string;
  recovery?: string;
  /** WebAuthn PRF result from a registered passkey or security key (both base64url). */
  passkey?: { credentialId: string; prfOutput: string };
  /**
   * Newest seal seen for this vault (kept in the OS keychain). Not a
   * credential: it lets the seal check catch an older copy of the vault file
   * or a removed seal, whichever way the vault was unlocked.
   */
  sealRecord?: SealRecord | null;
};

/** Public passkey details: safe to show before unlocking. */
export type PasskeyInfo = Omit<VaultPasskey, "wrappedRootKey">;

const PASSKEY_INFO = "autho:vault-passkey";

function passkeyAad(id: string): string {
  return `${PASSKEY_INFO}:${id}`;
}

function passkeyKek(id: string, prfOutput: Buffer): Buffer {
  // The salt binds the KEK to this registration; the PRF output is the real key material.
  return deriveKeyFromSecret(prfOutput, Buffer.from(passkeyAad(id), "utf8"), PASSKEY_INFO);
}

function decodePrfOutput(value: string): Buffer {
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== 32) {
    throw new Error("Passkey PRF output must be 32 bytes");
  }
  return bytes;
}

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

/** Searchable, non-secret fields for list views. Never carries the secret value. */
export type SecretIndexEntry = SecretSummary & {
  description: string | null;
  /** How many secrets this one links to. */
  linkCount: number;
  url: string | null;
  username: string | null;
};

/** A secret on the other end of a link: identifying fields only, never the value. */
export type LinkedSecret = { id: string; name: string; type: SecretType };

export type SecretLinks = {
  /** Secrets this one links to (it is their primary). */
  links: LinkedSecret[];
  /** Primaries that link to this secret. */
  linkedFrom: LinkedSecret[];
};

/** A secret a lease can read, and the primary it is reached through when it's a linked secret. */
export type LeaseCoverage = LinkedSecret & { via: LinkedSecret | null };

export type ResealResult = {
  changes: SealChange[];
  diffTrusted: boolean;
  /** Changes quarantine couldn't undo: they are still in the vault. */
  kept: SealChange[];
  mode: "accept" | "quarantine";
  reason: string | null;
  /** True when the root key wrap was re-marked as sealed (needs the master password). */
  rebound: boolean;
  revokedLeases: number;
  /** The new seal, for the caller to save as the record. */
  sealRecord: SealRecord | null;
  /** Changes quarantine undid: added rows deleted, edited or deleted rows put back. */
  undone: SealChange[];
  wasIntact: boolean;
};

export { VaultTamperedError, type SealChange, type SealRecord, type SealState } from "./seal.ts";

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

export type LeaseState = {
  createdAt: string;
  expiresAt: string;
  id: string;
  /** The lease also covers secrets linked from its secrets, resolved at read time. */
  includeLinks: boolean;
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
    includeLinks: row.includeLinks !== 0,
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

export { defaultProjectFilePath, defaultVaultPath, defaultDaemonStatePath, authoConfigDir, authoHomeDir, configFilePath, loadConfig, saveConfig, resetConfigCache } from "./paths.ts";
export * from "./settings.ts";
export type { AuthoConfig } from "./paths.ts";

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

      const { config, rootKey } = createVaultConfig(password, undefined, { sealed: true });
      db.immediateTransaction(() => {
        db.setVaultConfig(config);
        writeSeal(db, sealKey(rootKey));
        db.insertAudit({
          createdAt: new Date().toISOString(),
          eventType: "vault.initialized",
          id: randomId(),
          message: "Vault initialized",
          metadata: JSON.stringify({ version: config.version }),
          subjectRef: null,
          subjectType: "vault",
        });
      });
      rootKey.fill(0);

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

  static unlock(vaultPath: string, credentials: UnlockCredentials | string): VaultSession {
    const creds: UnlockCredentials = typeof credentials === "string"
      ? { password: credentials }
      : credentials;

    const db = new AuthoDatabase(vaultPath);
    const config = db.getVaultConfig();
    if (!config) {
      db.close();
      throw new Error(`Vault is not initialized at ${vaultPath}`);
    }

    const vaultAuth = db.getVaultAuth();

    // Recovery path
    if (creds.recovery) {
      if (!vaultAuth?.recovery) {
        db.close();
        throw new Error("No recovery token configured for this vault");
      }
      try {
        const recoveryKEK = deriveKeyFromPassword(creds.recovery, vaultAuth.recovery.kdf);
        const rootKey = decryptWithKey(vaultAuth.recovery.wrappedRootKey, recoveryKEK, "autho:vault-recovery");
        db.insertAudit({
          createdAt: new Date().toISOString(),
          eventType: "auth.unlock.recovery",
          id: randomId(),
          message: "Vault unlocked via recovery file",
          metadata: JSON.stringify({}),
          subjectRef: null,
          subjectType: "vault",
        });
        return new VaultSession(db, rootKey, { sealRecord: creds.sealRecord });
      } catch (error) {
        db.close();
        throw new Error("Invalid recovery token", { cause: error });
      }
    }

    // Passkey path: the authenticator's PRF output is the key material, and
    // WebAuthn already required user verification (PIN or biometric) on it.
    if (creds.passkey) {
      const passkey = vaultAuth?.passkeys?.find((p) => p.credentialId === creds.passkey!.credentialId);
      if (!passkey) {
        db.close();
        throw new Error("This passkey is not registered for this vault");
      }
      try {
        const kek = passkeyKek(passkey.id, decodePrfOutput(creds.passkey.prfOutput));
        const rootKey = decryptWithKey(passkey.wrappedRootKey, kek, passkeyAad(passkey.id));
        db.insertAudit({
          createdAt: new Date().toISOString(),
          eventType: "auth.unlock.passkey",
          id: randomId(),
          message: "Vault unlocked with a passkey",
          metadata: JSON.stringify({ label: passkey.label, passkeyId: passkey.id }),
          subjectRef: passkey.id,
          subjectType: "vault",
        });
        return new VaultSession(db, rootKey, { sealRecord: creds.sealRecord });
      } catch (error) {
        db.close();
        throw new Error("Passkey did not unlock the vault", { cause: error });
      }
    }

    // Password path
    try {
      // The password KEK is derived once and reused for the TOTP check and the root key.
      const { rootKey, sealBound } = unlockWithPassword(
        db,
        creds.password,
        (passwordKEK) => checkVaultTotp(vaultAuth, passwordKEK, creds.totp),
        creds.sealRecord,
      );
      return new VaultSession(db, rootKey, { sealBound, sealRecord: creds.sealRecord });
    } catch (error) {
      db.close();
      if (error instanceof Error && error.message === "Invalid or missing TOTP code") {
        throw error;
      }
      throw new Error("Invalid vault password", { cause: error });
    }
  }

  static getAuthConfig(vaultPath: string): VaultAuth | null {
    const db = new AuthoDatabase(vaultPath);
    try {
      return db.getVaultAuth();
    } finally {
      db.close();
    }
  }

  static setupTotp(vaultPath: string): { secret: string; uri: string } {
    const secret = generateTotpSecret();
    const uri = totpUri(secret, "autho", vaultPath);
    return { secret, uri };
  }

  /**
   * Checks the unlock credentials once (password and TOTP, or a passkey or
   * recovery token) and returns a handle for changing how the vault unlocks.
   * Callers must close() it; it holds the root key until then.
   */
  static authorize(vaultPath: string, credentials: UnlockCredentials): VaultAdmin {
    const session = VaultService.unlock(vaultPath, credentials);
    const rootKey = session.getRootKey();
    const sealBound = session.sealBound;
    session.close();
    const viaPassword = !credentials.passkey && !credentials.recovery;
    return new VaultAdmin(vaultPath, rootKey, viaPassword ? credentials.password : null, sealBound, credentials.sealRecord);
  }

  /**
   * Unwraps the root key with the master password (and the TOTP code when the
   * vault has one), sealing a vault from before sealing on the way. For the
   * daemon and the web UI, which keep the key and open a session per request.
   */
  static unlockRootKey(
    vaultPath: string,
    credentials: Pick<UnlockCredentials, "password" | "sealRecord" | "totp">,
  ): { rootKey: Buffer; sealBound: boolean } {
    const db = new AuthoDatabase(vaultPath);
    try {
      if (!db.getVaultConfig()) {
        throw new Error(`Vault is not initialized at ${vaultPath}`);
      }
      const vaultAuth = db.getVaultAuth();
      return unlockWithPassword(
        db,
        credentials.password,
        (passwordKEK) => checkVaultTotp(vaultAuth, passwordKEK, credentials.totp),
        credentials.sealRecord,
      );
    } finally {
      db.close();
    }
  }

  /** Re-signs the vault after a change made outside autho. See VaultAdmin.reseal. */
  static reseal(vaultPath: string, credentials: UnlockCredentials, mode: "accept" | "quarantine"): ResealResult {
    return VaultService.withAdmin(vaultPath, credentials, (admin) => admin.reseal(mode));
  }

  private static withAdmin<T>(vaultPath: string, credentials: UnlockCredentials, fn: (admin: VaultAdmin) => T): T {
    const admin = VaultService.authorize(vaultPath, credentials);
    try {
      return fn(admin);
    } finally {
      admin.close();
    }
  }

  static enableTotp(vaultPath: string, credentials: UnlockCredentials, secret: string, code: string): void {
    assertTotpCode(secret, code);
    VaultService.withAdmin(vaultPath, credentials, (admin) => admin.enableTotp(secret, code));
  }

  static removeTotp(vaultPath: string, credentials: UnlockCredentials): void {
    VaultService.withAdmin(vaultPath, credentials, (admin) => admin.removeTotp());
  }

  static generateRecovery(vaultPath: string, credentials: UnlockCredentials): { fileContent: string } {
    return VaultService.withAdmin(vaultPath, credentials, (admin) => admin.generateRecovery());
  }

  static revokeRecovery(vaultPath: string, credentials: UnlockCredentials): void {
    VaultService.withAdmin(vaultPath, credentials, (admin) => admin.revokeRecovery());
  }

  static changePassword(vaultPath: string, credentials: UnlockCredentials, newPassword: string): void {
    VaultService.withAdmin(vaultPath, credentials, (admin) => admin.changePassword(newPassword));
  }

  static listPasskeys(vaultPath: string): PasskeyInfo[] {
    return (VaultService.getAuthConfig(vaultPath)?.passkeys ?? []).map(({ wrappedRootKey: _key, ...info }) => info);
  }

  /**
   * Registers a passkey: the root key is wrapped with a key derived from the
   * authenticator's PRF output. Requires normal unlock credentials first.
   */
  static addPasskey(vaultPath: string, credentials: UnlockCredentials, input: PasskeyInput): PasskeyInfo {
    return VaultService.withAdmin(vaultPath, credentials, (admin) => admin.addPasskey(input));
  }

  /** Removes a passkey by id or label. Requires unlock credentials. */
  static removePasskey(vaultPath: string, credentials: UnlockCredentials, ref: string): PasskeyInfo {
    return VaultService.withAdmin(vaultPath, credentials, (admin) => admin.removePasskey(ref));
  }
}

export type PasskeyInput = { credentialId: string; label: string; prfSalt: string; prfOutput: string; transports?: string[] };

/** Minimum length for a changed master password. */
export const MIN_PASSWORD_LENGTH = 8;

/** Throws unless `totp` is a current code for the vault's authenticator, when one is set. */
function checkVaultTotp(vaultAuth: VaultAuth | null, passwordKEK: Buffer, totp: string | undefined): void {
  if (!vaultAuth?.totp) return;
  const totpSecret = decryptWithKey(vaultAuth.totp.encryptedSecret, passwordKEK, "autho:vault-totp").toString("utf8");
  if (!totp || !verifyTotpCode(totpSecret, totp)) {
    throw new Error("Invalid or missing TOTP code");
  }
}

function assertTotpCode(secret: string, code: string): void {
  if (!verifyTotpCode(secret, code)) {
    throw new Error("Invalid TOTP code — make sure your authenticator app is showing the right code");
  }
}

/**
 * Changes how a vault unlocks: password, TOTP, passkeys and the recovery
 * token. Made by VaultService.authorize after a full credential check, so a
 * settings screen can make several changes without re-entering a TOTP code
 * that has since expired. Every change is audited.
 */
export class VaultAdmin {
  private closed = false;

  constructor(
    readonly vaultPath: string,
    private rootKey: Buffer,
    /** Null when authorized with a passkey or recovery token. */
    private password: string | null,
    /** The root key's wrap says this vault is sealed, so a missing seal means tampering. */
    private readonly sealBound = false,
    /** Newest seal seen for this vault; updated as this handle re-signs it. */
    private record: SealRecord | null = null,
  ) {}

  /** The seal as of this handle's last change, for the caller to save as the record. */
  sealRecord(): SealRecord | null {
    return this.record;
  }

  /** True when authorized with the master password (needed for TOTP and keychain changes). */
  get hasPassword(): boolean {
    return this.password !== null;
  }

  /** The master password this handle was authorized with, e.g. to save it to the OS keychain. */
  masterPassword(): string {
    return this.requirePassword("This needs the master password");
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.rootKey.fill(0);
    this.password = null;
  }

  enableTotp(secret: string, code: string): void {
    assertTotpCode(secret, code);
    const password = this.requirePassword("Two-factor codes need the master password — authorize with it, not a passkey or recovery file");
    this.write((db) => {
      const passwordKEK = deriveKeyFromPassword(password, db.getVaultConfig()!.kdf);
      const encryptedSecret = encryptWithKey(Buffer.from(secret, "utf8"), passwordKEK, "autho:vault-totp");
      db.setVaultAuth({
        version: 1,
        ...db.getVaultAuth(),
        totp: { algorithm: "SHA1", digits: 6, encryptedSecret, period: 30 },
      });
      audit(db, "auth.totp.enabled", "TOTP vault unlock enabled");
    });
  }

  removeTotp(): void {
    this.write((db) => {
      const existing = db.getVaultAuth();
      if (existing) {
        const { totp: _removed, ...rest } = existing;
        db.setVaultAuth({ ...rest, version: 1 });
      }
      audit(db, "auth.totp.removed", "TOTP vault unlock removed");
    });
  }

  /**
   * Re-wraps the root key under a new password; secrets are untouched.
   * The TOTP secret is re-encrypted too, which needs the old password.
   */
  changePassword(newPassword: string): void {
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      throw new Error(`The new password must be at least ${MIN_PASSWORD_LENGTH} characters`);
    }
    this.write((db, sealed) => {
      const auth = db.getVaultAuth();
      const { config } = createVaultConfig(newPassword, this.liveRootKey(), { sealed });
      if (auth?.totp) {
        const oldPassword = this.requirePassword("Two-factor codes are on: authorize with the current master password to change it");
        const oldKEK = deriveKeyFromPassword(oldPassword, db.getVaultConfig()!.kdf);
        const secret = decryptWithKey(auth.totp.encryptedSecret, oldKEK, "autho:vault-totp");
        const newKEK = deriveKeyFromPassword(newPassword, config.kdf);
        db.setVaultAuth({ ...auth, version: 1, totp: { ...auth.totp, encryptedSecret: encryptWithKey(secret, newKEK, "autho:vault-totp") } });
      }
      db.setVaultConfig(config);
      audit(db, "auth.password.changed", "Master password changed");
    });
    this.password = newPassword;
  }

  generateRecovery(): { fileContent: string } {
    return this.write((db) => {
      const token = randomBytes(32).toString("hex");
      const recoveryKdf: VaultKdfConfig = {
        keyLength: 32,
        name: "scrypt",
        salt: randomBytes(16).toString("base64"),
        N: 1 << 17,
        p: 1,
        r: 8,
      };
      const wrappedRootKey = encryptWithKey(this.liveRootKey(), deriveKeyFromPassword(token, recoveryKdf), "autho:vault-recovery");
      db.setVaultAuth({
        version: 1,
        ...db.getVaultAuth(),
        recovery: { createdAt: new Date().toISOString(), kdf: recoveryKdf, wrappedRootKey },
      });
      audit(db, "auth.recovery.generated", "Recovery file generated");
      return { fileContent: recoveryFileContent(this.vaultPath, token) };
    });
  }

  revokeRecovery(): void {
    this.write((db) => {
      const existing = db.getVaultAuth();
      if (existing) {
        const { recovery: _removed, ...rest } = existing;
        db.setVaultAuth({ ...rest, version: 1 });
      }
      audit(db, "auth.recovery.revoked", "Recovery file revoked");
    });
  }

  addPasskey(input: PasskeyInput): PasskeyInfo {
    const prfOutput = decodePrfOutput(input.prfOutput);
    if (Buffer.from(input.prfSalt, "base64url").length < 16) {
      throw new Error("Passkey PRF salt must be at least 16 bytes");
    }
    return this.write((db) => {
      const existing = db.getVaultAuth();
      const passkeys = existing?.passkeys ?? [];
      if (passkeys.some((p) => p.credentialId === input.credentialId)) {
        throw new Error("This passkey is already registered");
      }
      const id = randomId(8);
      const label = input.label.trim() || `Passkey ${passkeys.length + 1}`;
      const draft: VaultPasskey = {
        createdAt: new Date().toISOString(),
        credentialId: input.credentialId,
        id,
        label,
        prfSalt: input.prfSalt,
        transports: input.transports?.length ? input.transports : undefined,
        wrappedRootKey: encryptWithKey(this.liveRootKey(), passkeyKek(id, prfOutput), passkeyAad(id)),
      };
      db.setVaultAuth({ version: 1, ...existing, passkeys: [...passkeys, draft] });
      audit(db, "auth.passkey.added", "Passkey added", { label, passkeyId: id }, id);
      const { wrappedRootKey: _key, ...info } = draft;
      return info;
    });
  }

  removePasskey(ref: string): PasskeyInfo {
    return this.write((db) => {
      const existing = db.getVaultAuth();
      const passkeys = existing?.passkeys ?? [];
      const matches = passkeys.filter((p) => p.id === ref || p.label === ref);
      if (matches.length === 0) {
        throw new Error(`No passkey matches "${ref}"`);
      }
      if (matches.length > 1) {
        throw new Error(`"${ref}" matches several passkeys — use the id from \`autho passkey list\``);
      }
      const removed = matches[0]!;
      db.setVaultAuth({ ...existing!, version: 1, passkeys: passkeys.filter((p) => p !== removed) });
      audit(db, "auth.passkey.removed", "Passkey removed", { label: removed.label, passkeyId: removed.id }, removed.id);
      const { wrappedRootKey: _key, ...info } = removed;
      return info;
    });
  }

  private liveRootKey(): Buffer {
    if (this.closed) {
      throw new Error("Authorization expired — confirm your password again");
    }
    return this.rootKey;
  }

  private requirePassword(message: string): string {
    this.liveRootKey();
    if (this.password === null) {
      throw new Error(message);
    }
    return this.password;
  }

  /**
   * Re-signs the vault after it was changed outside autho. Needs a full
   * credential check (password, passkey or recovery file), never a daemon
   * session, so an agent can't bless its own edit.
   *
   * - quarantine: puts the vault back the way autho last sealed it, as far
   *   as it can: deletes added rows and restores edited or deleted rows from
   *   their sealed copies, then revokes every active lease. When the stored
   *   signatures were edited too (or a row has no sealed copy), it only
   *   deletes links and leases that grant access, and reports the rest.
   * - accept: re-signs the vault as it is now (your own SQLite edit, or a
   *   change made by an older autho).
   *
   * Either way the new seal's counter lands above the one on record, so a
   * reseal after a rollback also clears the rollback warning.
   */
  reseal(mode: "accept" | "quarantine"): ResealResult {
    const rootKey = this.liveRootKey();
    const key = sealKey(rootKey);
    const db = new AuthoDatabase(this.vaultPath);
    try {
      return db.immediateTransaction(() => {
        const seal = verifySeal(db, key, true, this.record);
        const result: ResealResult = {
          changes: seal.state === "tampered" ? seal.changes : [],
          diffTrusted: seal.state === "tampered" ? seal.diffTrusted : true,
          kept: [],
          mode,
          reason: seal.state === "tampered" ? seal.reason : seal.state === "unsealed" ? "unsealed" : null,
          rebound: false,
          revokedLeases: 0,
          sealRecord: null,
          undone: [],
          wasIntact: seal.state === "intact",
        };
        if (seal.state === "intact") return result;

        if (mode === "quarantine") {
          Object.assign(result, quarantineChanges(db, key, result.changes, result.diffTrusted));
          result.revokedLeases = db.revokeActiveLeases(new Date().toISOString());
        } else {
          result.kept = result.changes;
        }

        if (this.password !== null) {
          const config = db.getVaultConfig()!;
          const passwordKey = deriveKeyFromPassword(this.password, config.kdf);
          if (!unwrapRootKey(config, passwordKey).sealed) {
            db.setVaultConfig({ ...config, wrappedRootKey: wrapRootKey(rootKey, passwordKey, true) });
            result.rebound = true;
          }
        }

        result.sealRecord = writeSeal(db, key, { minCounter: this.record ? this.record.counter + 1 : 0 });
        this.record = result.sealRecord;
        audit(db, `vault.reseal.${mode}`, mode === "accept" ? "Vault re-sealed as is" : "Vault re-sealed after quarantine", {
          changes: result.changes.slice(0, 200),
          diffTrusted: result.diffTrusted,
          kept: result.kept.length,
          reason: result.reason,
          revokedLeases: result.revokedLeases,
          undone: result.undone.length,
        });
        return result;
      });
    } finally {
      key.fill(0);
      db.close();
    }
  }

  /**
   * Runs `fn` in one write-locked transaction that checks the vault seal
   * first and re-signs it after. `sealed` tells `fn` whether the vault
   * carries a seal (false for a vault from before sealing).
   */
  private write<T>(fn: (db: AuthoDatabase, sealed: boolean) => T): T {
    const key = sealKey(this.liveRootKey());
    const db = new AuthoDatabase(this.vaultPath);
    try {
      return db.immediateTransaction(() => {
        const seal = verifySeal(db, key, this.sealBound, this.record);
        if (seal.state === "tampered") throw new VaultTamperedError(seal);
        const result = fn(db, seal.state === "intact");
        if (seal.state === "intact") this.record = writeSeal(db, key);
        return result;
      });
    } finally {
      key.fill(0);
      db.close();
    }
  }
}

/** Tables whose rows grant access: quarantine drops their changed rows even without a sealed copy. */
const ACCESS_TABLES = new Set(["leases", "secret_links"]);

/**
 * Undoes the changes reverse-diffed by verifySeal. Rows are put back only
 * from copies whose signature still checks out, and only when the list of
 * sealed rows itself is trusted; otherwise an attacker who edited seal_rows
 * could make a real secret look "added" and get it deleted.
 */
function quarantineChanges(
  db: AuthoDatabase,
  key: Buffer,
  changes: SealChange[],
  diffTrusted: boolean,
): Pick<ResealResult, "kept" | "undone"> {
  const sealed = new Map(db.listSealRows().map((row) => [`${row.tableName}\0${row.rowId}`, row]));
  // Current copies of modified rows, to put back if their restore fails.
  const current = new Map(db.listProtectedRows().map((row) => [`${row.tableName}\0${row.rowId}`, row.row]));
  const undone: SealChange[] = [];
  const kept: SealChange[] = [];
  const restores: { change: SealChange; row: Record<string, unknown> }[] = [];
  const deletes: SealChange[] = [];

  for (const change of changes) {
    const sealedRow = sealed.get(`${change.table}\0${change.rowId}`);
    const snapshot = diffTrusted && change.change !== "added" && sealedRow ? sealedSnapshot(key, sealedRow) : null;
    if (snapshot) {
      if (change.change === "modified") deletes.push(change);
      restores.push({ change, row: snapshot });
    } else if (change.change === "added" && diffTrusted) {
      deletes.push(change);
      undone.push(change);
    } else if (change.change !== "removed" && ACCESS_TABLES.has(change.table)) {
      deletes.push(change);
      undone.push(change);
    } else {
      kept.push(change);
    }
  }

  // Delete first, so a restored row never collides with the row that replaced it.
  for (const change of deletes) db.deleteProtectedRow(change.table, change.rowId);
  for (const { change, row } of restores) {
    try {
      db.insertProtectedRow(change.table, row);
      undone.push(change);
    } catch {
      // e.g. a kept row now holds the restored secret's name; leave it to the user.
      const modified = change.change === "modified" ? current.get(`${change.table}\0${change.rowId}`) : undefined;
      if (modified) db.insertProtectedRow(change.table, modified);
      kept.push(change);
    }
  }
  return { kept, undone };
}

function audit(db: AuthoDatabase, eventType: string, message: string, metadata: Record<string, unknown> = {}, subjectRef: string | null = null): void {
  db.insertAudit({
    createdAt: new Date().toISOString(),
    eventType,
    id: randomId(),
    message,
    metadata: JSON.stringify(metadata),
    subjectRef,
    subjectType: "vault",
  });
}

function recoveryFileContent(vaultPath: string, token: string): string {
  const formattedToken = token.toUpperCase().match(/.{1,8}/g)!.join("-");
  return [
    "================================================================================",
    "AUTHO VAULT RECOVERY FILE",
    "================================================================================",
    `Generated : ${new Date().toISOString()}`,
    `Vault     : ${vaultPath}`,
    "",
    "WARNING: Anyone with this file can open your vault regardless of password,",
    "PIN, or authenticator app. Store it offline (printed paper, encrypted USB,",
    "safety deposit box). Revoke with: autho recovery revoke",
    "",
    "RECOVERY TOKEN:",
    formattedToken,
    "",
    "To use: autho unlock --recovery-file <path-to-this-file>",
    "================================================================================",
  ].join("\n");
}

export class VaultSession {
  private readonly sealKey: Buffer;
  /** The root key's wrap says this vault is sealed, so a missing seal means tampering. */
  readonly sealBound: boolean;
  /** Newest seal seen for this vault (from the OS keychain), to catch an older copy of the file. */
  private readonly sealRecord: SealRecord | null;

  constructor(
    private readonly db: AuthoDatabase,
    private readonly rootKey: Buffer,
    options: { sealBound?: boolean; sealRecord?: SealRecord | null } = {},
  ) {
    this.sealKey = sealKey(rootKey);
    this.sealBound = options.sealBound ?? false;
    this.sealRecord = options.sealRecord ?? null;
  }

  /**
   * The current seal when it checks out, for the caller to save as the
   * record. Null when the vault is tampered or unsealed, so a bad state is
   * never written over a good record.
   */
  sealCheckpoint(): SealRecord | null {
    return this.verifySeal().state === "intact" ? currentSealRecord(this.db) : null;
  }

  getRootKey(): Buffer {
    return Buffer.from(this.rootKey);
  }

  close(): void {
    this.sealKey.fill(0);
    this.db.close();
  }

  /** Checks the vault seal: intact, unsealed (vault from before sealing), or tampered with a row-level diff. */
  verifySeal(): SealState {
    return verifySeal(this.db, this.sealKey, this.sealBound, this.sealRecord);
  }

  /**
   * Runs a change to sealed rows: takes the write lock, refuses if the vault
   * was edited outside autho, applies `fn`, and re-signs. Nested calls join
   * the outer transaction. `allowTampered` is only for revoking a lease,
   * which must keep working while the vault is in a bad state; it doesn't
   * re-sign, so the tampering stays visible.
   */
  private sealedWrite<T>(fn: () => T, options?: { allowTampered?: boolean }): T {
    if (this.db.inTransaction) {
      return fn();
    }
    return this.db.immediateTransaction(() => {
      const seal = this.verifySeal();
      if (seal.state === "tampered" && !options?.allowTampered) {
        throw new VaultTamperedError(seal);
      }
      const result = fn();
      if (seal.state === "intact") {
        writeSeal(this.db, this.sealKey);
      }
      return result;
    });
  }

  /** Agent access (env, exec, leases) fails closed unless the seal is intact. */
  private requireIntactSeal(): void {
    const seal = this.verifySeal();
    if (seal.state === "tampered") {
      throw new VaultTamperedError(seal);
    }
    if (seal.state === "unsealed") {
      throw new Error("This vault isn't sealed yet: unlock it once with the master password, then retry");
    }
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

  private getActiveLeaseOrThrow(id: string): LeaseState {
    const lease = this.getLeaseOrThrow(id);
    if (lease.revokedAt) {
      throw new Error(`Lease revoked: ${lease.id}`);
    }
    if (Date.parse(lease.expiresAt) <= Date.now()) {
      throw new Error(`Lease expired: ${lease.id}`);
    }
    return lease;
  }

  private linkedSecret(id: string): LinkedSecret | null {
    const row = this.db.findSecret(id);
    return row ? { id: row.id, name: row.name, type: normalizeSecretType(row.type) } : null;
  }

  /**
   * Whether a lease can read `secret`: directly, or through a primary it
   * covers that links to it. Links are read live, so linking a new secret
   * extends the lease and unlinking takes access away immediately.
   * Returns the primary for linked access, null for direct access.
   */
  private leaseAccess(lease: LeaseState, secret: { id: string; name: string }): { via: LinkedSecret | null } {
    if (lease.secretRefs.includes(secret.id) || lease.secretRefs.includes(secret.name)) {
      return { via: null };
    }
    if (lease.includeLinks) {
      for (const link of this.db.listLinksTo(secret.id)) {
        if (lease.secretRefs.includes(link.primaryId)) {
          return { via: this.linkedSecret(link.primaryId) };
        }
      }
    }
    throw new Error(`Lease ${lease.id} does not allow secret ${secret.name}`);
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
    return this.sealedWrite(() => this.insertNewSecret(input, type));
  }

  private insertNewSecret(
    input: { metadata?: Record<string, unknown>; name: string; username?: string; value: string },
    type: SecretType,
  ): SecretSummary {
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

  updateSecret(
    ref: string,
    updates: {
      metadata?: Record<string, unknown>;
      name?: string;
      type?: string;
      username?: string;
      value?: string;
    },
  ): SecretSummary {
    return this.sealedWrite(() => this.applySecretUpdate(ref, updates));
  }

  private applySecretUpdate(
    ref: string,
    updates: { metadata?: Record<string, unknown>; name?: string; type?: string; username?: string; value?: string },
  ): SecretSummary {
    const existing = this.getSecretOrThrow(ref);

    // Check name uniqueness if renaming
    if (updates.name && updates.name !== existing.name) {
      const conflict = this.db.findSecret(updates.name);
      if (conflict && conflict.id !== existing.id) {
        throw new Error(`Secret already exists: ${updates.name}`);
      }
    }

    const newName = updates.name ?? existing.name;
    const newType = updates.type ? normalizeSecretType(updates.type) : existing.type;
    const newValue = updates.value ?? existing.value;
    const newUsername = updates.username !== undefined ? (updates.username || null) : existing.username;
    const newMetadata = updates.metadata
      ? normalizeMetadata({ ...existing.metadata, ...updates.metadata })
      : existing.metadata;

    const now = new Date().toISOString();

    // Re-encrypt payload with existing DEK
    const wrappedKeyBlob = JSON.parse(this.db.findSecret(existing.id)!.wrappedKey) as EncryptedBlob;
    const dek = decryptWithKey(wrappedKeyBlob, this.rootKey, `autho:secret:${existing.id}:dek`);
    const payload = encryptWithKey(
      JSON.stringify({
        metadata: newMetadata,
        username: newUsername,
        value: newValue,
      } satisfies StoredSecretPayload),
      dek,
      `autho:secret:${existing.id}:payload`,
    );

    this.db.updateSecret(existing.id, {
      name: newName,
      payload: JSON.stringify(payload),
      type: newType,
      updatedAt: now,
    });

    this.audit("secret.updated", "secret", existing.id, "Secret updated", {
      fields: Object.keys(updates).filter((k) => (updates as Record<string, unknown>)[k] !== undefined),
    });

    return {
      createdAt: existing.createdAt,
      id: existing.id,
      name: newName,
      type: newType,
      updatedAt: now,
    };
  }

  importLegacyFile(filePath: string, options?: { skipExisting?: boolean }): {
    imported: number;
    skipped: number;
  } {
    const raw = JSON.parse(readFileSync(filePath, "utf8")) as LegacySecret[];
    return this.sealedWrite(() => this.importLegacyEntries(raw, options));
  }

  private importLegacyEntries(raw: LegacySecret[], options?: { skipExisting?: boolean }): {
    imported: number;
    skipped: number;
  } {
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

  /**
   * Decrypts every secret but returns only display fields (username, url,
   * description), so list UIs can search without holding values in memory.
   * Audited once per call instead of once per secret.
   */
  listSecretIndex(): SecretIndexEntry[] {
    const linkCounts = new Map<string, number>();
    for (const link of this.db.listLinks()) {
      linkCounts.set(link.primaryId, (linkCounts.get(link.primaryId) ?? 0) + 1);
    }
    const entries = this.db.listSecrets().map((row) => {
      const secret = this.unwrapSecret(row);
      const { url, description } = secret.metadata;
      return {
        createdAt: secret.createdAt,
        description: typeof description === "string" && description ? description : null,
        id: secret.id,
        linkCount: linkCounts.get(secret.id) ?? 0,
        name: secret.name,
        type: secret.type,
        updatedAt: secret.updatedAt,
        url: typeof url === "string" && url ? url : null,
        username: secret.username,
      };
    });
    this.audit("secret.index", "vault", null, "Secret index listed", { count: entries.length });
    return entries;
  }

  getSecret(ref: string): SecretRecord {
    const secret = this.getSecretOrThrow(ref);
    this.audit("secret.read", "secret", secret.id, "Secret read", {
      metadataKeyCount: Object.keys(secret.metadata).length,
      type: secret.type,
    });

    return secret;
  }

  /**
   * Deletes a secret and its links. With `withLinked`, also deletes the
   * secrets it links to, except ones another primary still links to: those
   * are kept and listed in `keptLinked`.
   */
  removeSecret(
    ref: string,
    options?: { withLinked?: boolean },
  ): { id: string; keptLinked: LinkedSecret[]; name: string; removedLinked: LinkedSecret[] } {
    return this.sealedWrite(() => {
      const secret = this.getSecretOrThrow(ref);
      const removedLinked: LinkedSecret[] = [];
      const keptLinked: LinkedSecret[] = [];
      if (options?.withLinked) {
        for (const link of this.db.listLinksFrom(secret.id)) {
          const linked = this.linkedSecret(link.linkedId);
          if (!linked) continue;
          const otherPrimaries = this.db.listLinksTo(linked.id).filter((l) => l.primaryId !== secret.id);
          (otherPrimaries.length > 0 ? keptLinked : removedLinked).push(linked);
        }
      }

      for (const target of [{ id: secret.id, type: secret.type }, ...removedLinked]) {
        this.db.deleteSecret(target.id);
        this.audit("secret.deleted", "secret", target.id, "Secret deleted", {
          type: target.type,
          ...(target.id === secret.id ? {} : { withPrimary: secret.id }),
        });
      }

      return { id: secret.id, keptLinked, name: secret.name, removedLinked };
    });
  }

  /** Links `linkedRef` under `primaryRef`. Linking twice is a no-op (`created: false`). */
  linkSecrets(primaryRef: string, linkedRef: string): { created: boolean; linked: LinkedSecret; primary: LinkedSecret } {
    return this.sealedWrite(() => {
      const primary = this.requireLinkedSecret(primaryRef);
      const linked = this.requireLinkedSecret(linkedRef);
      if (primary.id === linked.id) {
        throw new Error("A secret can't be linked to itself");
      }
      if (this.db.hasLink(primary.id, linked.id)) {
        return { created: false, linked, primary };
      }
      this.db.insertLink({ createdAt: new Date().toISOString(), linkedId: linked.id, primaryId: primary.id });
      this.audit("secret.linked", "secret", primary.id, `Linked ${linked.name} under ${primary.name}`, {
        linkedId: linked.id,
        primaryId: primary.id,
      });
      return { created: true, linked, primary };
    });
  }

  unlinkSecrets(primaryRef: string, linkedRef: string): { linked: LinkedSecret; primary: LinkedSecret } {
    return this.sealedWrite(() => {
      const primary = this.requireLinkedSecret(primaryRef);
      const linked = this.requireLinkedSecret(linkedRef);
      if (!this.db.deleteLink(primary.id, linked.id)) {
        throw new Error(`${linked.name} is not linked under ${primary.name}`);
      }
      this.audit("secret.unlinked", "secret", primary.id, `Unlinked ${linked.name} from ${primary.name}`, {
        linkedId: linked.id,
        primaryId: primary.id,
      });
      return { linked, primary };
    });
  }

  /** The secrets `ref` links to, and the primaries linking to it. Names and types only. */
  getLinks(ref: string): SecretLinks {
    const secret = this.requireLinkedSecret(ref);
    const resolve = (ids: string[]): LinkedSecret[] =>
      ids.map((id) => this.linkedSecret(id)).filter((entry): entry is LinkedSecret => entry !== null);
    return {
      linkedFrom: resolve(this.db.listLinksTo(secret.id).map((link) => link.primaryId)),
      links: resolve(this.db.listLinksFrom(secret.id).map((link) => link.linkedId)),
    };
  }

  private requireLinkedSecret(ref: string): LinkedSecret {
    const row = this.db.findSecret(ref);
    if (!row) {
      throw new Error(`Secret not found: ${ref}`);
    }
    return { id: row.id, name: row.name, type: normalizeSecretType(row.type) };
  }

  /**
   * Current code for an OTP secret. `audit: false` is for display-only views
   * that refresh the code on a timer; copying or printing a code is audited.
   */
  generateOtp(ref: string, options?: { audit?: boolean }): { code: string; expiresAt: string; secret: string } {
    const secret = this.getSecretOrThrow(ref);
    if (secret.type !== "otp") {
      throw new Error(`Secret is not an OTP secret: ${ref}`);
    }

    const result = this.otpCode(secret);
    if (options?.audit ?? true) {
      this.audit("otp.generated", "secret", secret.id, "OTP code generated", {
        expiresAt: result.expiresAt,
      });
    }

    return {
      code: result.code,
      expiresAt: result.expiresAt,
      secret: secret.name,
    };
  }

  private otpCode(secret: SecretRecord): { code: string; expiresAt: string } {
    return generateTotp(secret.value, {
      algorithm: secret.metadata.algorithm as string | undefined,
      digits: secret.metadata.digits as number | undefined,
    });
  }

  /** A lease and every secret it can read right now, linked secrets included. */
  showLease(id: string): { coverage: LeaseCoverage[]; lease: LeaseState } {
    const lease = this.getLeaseOrThrow(id);
    const coverage: LeaseCoverage[] = [];
    const seen = new Set<string>();
    for (const ref of lease.secretRefs) {
      const direct = this.linkedSecret(ref);
      if (!direct || seen.has(direct.id)) continue;
      seen.add(direct.id);
      coverage.push({ ...direct, via: null });
    }
    if (lease.includeLinks) {
      for (const primary of [...coverage]) {
        for (const link of this.db.listLinksFrom(primary.id)) {
          const linked = this.linkedSecret(link.linkedId);
          if (!linked || seen.has(linked.id)) continue;
          seen.add(linked.id);
          coverage.push({ ...linked, via: { id: primary.id, name: primary.name, type: primary.type } });
        }
      }
    }
    return { coverage, lease };
  }

  createLease(input: {
    name: string;
    /** Lease only the named secrets, not the secrets linked from them. */
    noLinks?: boolean;
    secretRefs: string[];
    ttlSeconds: number;
  }): LeaseState {
    return this.sealedWrite(() => this.insertLease(input));
  }

  private insertLease(input: { name: string; noLinks?: boolean; secretRefs: string[]; ttlSeconds: number }): LeaseState {
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
      includeLinks: !input.noLinks,
      name: input.name || "session",
      revokedAt: null,
      secretRefs: resolved.map((secret) => secret.id),
    };

    this.db.insertLease({
      createdAt: lease.createdAt,
      expiresAt: lease.expiresAt,
      id: lease.id,
      includeLinks: lease.includeLinks ? 1 : 0,
      name: lease.name,
      revokedAt: lease.revokedAt,
      secretRefs: JSON.stringify(lease.secretRefs),
    });
    this.audit("lease.created", "lease", lease.id, "Lease created", {
      expiresAt,
      includeLinks: lease.includeLinks,
      secretCount: lease.secretRefs.length,
    });

    return lease;
  }

  /** Works even when the vault seal is broken: taking access away must never be blocked. */
  revokeLease(id: string): LeaseState {
    return this.sealedWrite(
      () => {
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
      },
      { allowTampered: true },
    );
  }

  /**
   * Resolves env mappings to values. Holds the write lock while it checks
   * the seal and reads, so nothing can change in between. An OTP secret
   * injects its current code, never its seed.
   */
  private buildEnv(
    mappings: EnvMapping[],
    leaseId?: string,
  ): Record<string, string> {
    if (mappings.length === 0) {
      throw new Error("Provide at least one env mapping");
    }

    return this.db.immediateTransaction(() => {
      this.requireIntactSeal();
      const lease = leaseId ? this.getActiveLeaseOrThrow(leaseId) : null;
      const output: Record<string, string> = {};
      for (const mapping of mappings) {
        const secret = this.getSecretOrThrow(mapping.secretRef);
        if (lease) {
          const { via } = this.leaseAccess(lease, secret);
          if (via) {
            this.audit("lease.link_access", "secret", secret.id, `Secret read via link from ${via.name}`, {
              leaseId: lease.id,
              primaryId: via.id,
            });
          }
        }
        output[mapping.envName] = secret.type === "otp" ? this.otpCode(secret).code : secret.value;
      }
      return output;
    });
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

  encryptFile(inputPath: string, outputPath?: string, options?: { force?: boolean }): { outputPath: string } {
    assertPathIsFile(inputPath);
    const resolvedOutput = outputPath ?? defaultEncryptedFilePath(inputPath);
    if (!options?.force && existsSync(resolvedOutput)) {
      throw new Error(`Output file already exists: ${resolvedOutput}`);
    }
    const result = encryptFileArtifact(
      inputPath,
      resolvedOutput,
      this.rootKey,
    );
    this.audit("file.encrypted", "artifact", null, "File encrypted", {
      kind: "file",
    });

    return result;
  }

  decryptFile(inputPath: string, outputPath?: string, options?: { force?: boolean }): { outputPath: string } {
    assertPathIsFile(inputPath);
    const resolvedOutput = outputPath ?? defaultDecryptedFilePath(inputPath);
    if (!options?.force && existsSync(resolvedOutput)) {
      throw new Error(`Output file already exists: ${resolvedOutput}`);
    }
    const result = decryptFileArtifact(
      inputPath,
      resolvedOutput,
      this.rootKey,
    );
    this.audit("file.decrypted", "artifact", null, "File decrypted", {
      kind: "file",
    });

    return result;
  }

  encryptFolder(inputPath: string, outputPath?: string, options?: { force?: boolean }): { fileCount: number; outputPath: string } {
    assertPathIsDirectory(inputPath);
    const resolvedOutput = outputPath ?? defaultEncryptedFolderPath(inputPath);
    if (!options?.force && existsSync(resolvedOutput)) {
      throw new Error(`Output file already exists: ${resolvedOutput}`);
    }
    const result = encryptFolderArtifact(
      inputPath,
      resolvedOutput,
      this.rootKey,
    );
    this.audit("folder.encrypted", "artifact", null, "Folder encrypted", {
      fileCount: result.fileCount,
      kind: "folder",
    });

    return result;
  }

  decryptFolder(inputPath: string, outputPath?: string, options?: { force?: boolean }): { fileCount: number; outputPath: string } {
    assertPathIsFile(inputPath);
    const resolvedOutput = outputPath ?? defaultDecryptedFolderPath(inputPath);
    if (!options?.force && existsSync(resolvedOutput)) {
      throw new Error(`Output path already exists: ${resolvedOutput}`);
    }
    const result = decryptFolderArtifact(
      inputPath,
      resolvedOutput,
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







