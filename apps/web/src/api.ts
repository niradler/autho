import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import { AuthoDatabase } from "../../../packages/storage/src/index.ts";
import {
  AUDIT_SOURCES,
  MIN_PASSWORD_LENGTH,
  PREFERENCES,
  UNGROUPED_LABEL,
  VaultService,
  VaultSession,
  authoHomeDir,
  configFilePath,
  defaultDaemonStatePath,
  defaultProjectFilePath,
  formatPreference,
  loadConfig,
  parsePreference,
  parseRecoveryFile,
  resolvePreference,
  saveConfig,
  setPreference,
  type AuditSource,
  type PreferenceKey,
  type SecretIndexEntry,
  type UnlockCredentials,
  type VaultAdmin,
} from "../../../packages/core/src/index.ts";
import {
  closeSessionAndRecordSeal,
  deletePin,
  deleteVaultPassword,
  hasPinSet,
  loadSealRecord,
  loadVaultPassword,
  osSecretsDisabled,
  saveSealRecord,
  storePinHash,
  storeVaultPassword,
} from "../../../packages/core/src/os-secrets.ts";
import pkg from "../../cli/package.json";
import type { SessionStore, WebSession } from "./sessions.ts";
import type { UnlockThrottle } from "./security.ts";

export class HttpError extends Error {
  constructor(readonly status: number, message: string, readonly headers: Record<string, string> = {}) {
    super(message);
  }
}

export type ApiContext = {
  vaultPath: string;
  sessions: SessionStore;
  throttle: UnlockThrottle;
};

type Params = Record<string, string>;
type Body = Record<string, unknown>;
type Reply = { data: unknown; status?: number; session?: WebSession | "ended" };

// ── Input validation ──────────────────────────────────────────────

const LIMITS = { name: 200, value: 65_536, short: 512, notes: 8192, password: 1024 };
const B64URL = /^[A-Za-z0-9_-]+$/;
const SECRET_TYPES = new Set(["password", "note", "otp"]);

function str(body: Body, key: string, max: number): string {
  const value = body[key];
  if (typeof value !== "string") throw new HttpError(400, `${key} is required`);
  if (value.length > max) throw new HttpError(400, `${key} is too long`);
  return value;
}

function optStr(body: Body, key: string, max: number): string | undefined {
  return body[key] === undefined || body[key] === null ? undefined : str(body, key, max);
}

/** A secret's group: missing keeps it, null or "" ungroups, a string names an existing group (id or name). */
function groupField(body: Body): string | null | undefined {
  const value = body.group;
  if (value === undefined) return undefined;
  if (value === null || value === "") return null;
  if (typeof value !== "string") throw new HttpError(400, "group must be a string or null");
  if (value.length > LIMITS.name) throw new HttpError(400, "group is too long");
  return value;
}

function secretType(body: Body): string {
  const type = str(body, "type", 16);
  if (!SECRET_TYPES.has(type)) throw new HttpError(400, "type must be password, note or otp");
  return type;
}

function b64url(body: Body, key: string, max: number): string {
  const value = str(body, key, max);
  if (!B64URL.test(value)) throw new HttpError(400, `${key} is malformed`);
  return value;
}

function totpCode(body: Body): string | undefined {
  const code = optStr(body, "totp", 16)?.replace(/\s/g, "");
  if (code !== undefined && code !== "" && !/^\d{6,8}$/.test(code)) throw new HttpError(400, "The authenticator code is 6 digits");
  return code || undefined;
}

/** Password, passkey or recovery credentials from an unlock or authorize body. */
function credentials(body: Body, allowRecovery: boolean): UnlockCredentials {
  switch (body.method) {
    case "password":
      return { password: str(body, "password", LIMITS.password), totp: totpCode(body) };
    case "passkey":
      return { password: "", passkey: { credentialId: b64url(body, "credentialId", 1400), prfOutput: b64url(body, "prfOutput", 64) } };
    case "recovery":
      if (!allowRecovery) break;
      try {
        return { password: "", recovery: parseRecoveryFile(str(body, "recoveryFile", 4096)) };
      } catch {
        throw new HttpError(400, "That is not an autho recovery file");
      }
  }
  throw new HttpError(400, "Unknown unlock method");
}

/** Runs one credential check under the unlock throttle; a failure counts toward the backoff. */
async function throttled<T>(ctx: ApiContext, body: Body, allowRecovery: boolean, check: (creds: UnlockCredentials) => T | Promise<T>): Promise<T> {
  const creds = credentials(body, allowRecovery);
  if (!ctx.throttle.begin()) {
    const wait = Math.max(1, Math.ceil(ctx.throttle.retryAfterMs() / 1000));
    throw new HttpError(429, `Too many attempts — try again in ${wait}s`, { "retry-after": String(wait) });
  }
  let result: T;
  try {
    result = await check(creds);
  } catch (error) {
    ctx.throttle.fail();
    const message = error instanceof Error ? error.message : String(error);
    throw new HttpError(401, /TOTP/.test(message) ? "Invalid or missing authenticator code" : message);
  }
  ctx.throttle.succeed();
  return result;
}

// ── Shapes sent to the page ──────────────────────────────────────

const PREF_KEYS = PREFERENCES.map((spec) => spec.key);
/** Settings that outlive this session and loosen how secrets are protected everywhere: they need a fresh identity check. */
const GUARDED_PREFS = new Set<PreferenceKey>(["idleLockSeconds", "clipboardClearSeconds"]);

function uiPrefs(): Record<string, number | boolean> {
  return Object.fromEntries(
    (["revealSeconds", "clipboardClearSeconds", "idleLockSeconds", "passwordLength", "passwordSymbols"] as PreferenceKey[])
      .map((key) => [key, resolvePreference(key).value]),
  );
}

function sessionInfo(ctx: ApiContext, session: WebSession): Body {
  const { idleAt, hardAt } = ctx.sessions.expiresAt(session);
  return {
    csrf: session.csrf,
    idleAt,
    hardAt,
    prefs: uiPrefs(),
    vault: { name: basename(ctx.vaultPath), path: ctx.vaultPath },
    version: pkg.version,
  };
}

/** A secret's detail without its value: the value only leaves through /reveal. */
function secretDetail(session: VaultSession, entry: SecretIndexEntry): Body {
  return { ...entry, ...session.getLinks(entry.id) };
}

function findEntry(session: VaultSession, ref: string): SecretIndexEntry {
  const entry = session.listSecretIndex().find((e) => e.id === ref || e.name === ref);
  if (!entry) throw new HttpError(404, `Secret not found: ${ref}`);
  return entry;
}

function metadataFrom(body: Body, type: string): Record<string, unknown> {
  const metadata: Record<string, unknown> = {};
  const url = optStr(body, "url", LIMITS.short)?.trim();
  const description = optStr(body, "description", LIMITS.notes)?.trim();
  if (type === "password" && url) {
    if (!/^https?:\/\//i.test(url)) throw new HttpError(400, "URL must start with http:// or https://");
    metadata.url = url;
  }
  if (description) metadata.description = description;
  return metadata;
}

// ── Vault access ─────────────────────────────────────────────────

async function withVault<T>(ctx: ApiContext, session: WebSession, fn: (vault: VaultSession) => T): Promise<T> {
  const vault = new VaultSession(new AuthoDatabase(ctx.vaultPath), session.rootKey, {
    sealBound: session.sealBound,
    sealRecord: await loadSealRecord(ctx.vaultPath),
    source: "web",
  });
  try {
    return fn(vault);
  } finally {
    await closeSessionAndRecordSeal(ctx.vaultPath, vault);
  }
}

function requireAdmin(ctx: ApiContext, session: WebSession): VaultAdmin {
  const admin = ctx.sessions.admin(session);
  if (!admin) throw new HttpError(403, "Confirm your identity to change security settings");
  return admin;
}

/** Runs an admin change and records the seal it leaves behind. */
async function adminChange<T>(ctx: ApiContext, admin: VaultAdmin, fn: () => T | Promise<T>): Promise<T> {
  const result = await fn();
  await saveSealRecord(ctx.vaultPath, admin.sealRecord());
  return result;
}

async function securityStatus(ctx: ApiContext, session: WebSession): Promise<Body> {
  const auth = VaultService.getAuthConfig(ctx.vaultPath);
  const osStore = !osSecretsDisabled();
  const admin = ctx.sessions.admin(session);
  return {
    adminUntil: admin ? session.admin?.expiresAt ?? null : null,
    adminHasPassword: admin?.hasPassword ?? false,
    keychain: osStore ? (await loadVaultPassword(ctx.vaultPath)) !== null : false,
    osStore,
    passkeys: VaultService.listPasskeys(ctx.vaultPath).map(({ id, label, createdAt, credentialId }) => ({ id, label, createdAt, credentialId })),
    pin: osStore ? await hasPinSet(ctx.vaultPath) : false,
    recoveryAt: auth?.recovery?.createdAt ?? null,
    totp: auth?.totp !== undefined,
  };
}

// ── Routes ───────────────────────────────────────────────────────

type Handler = (ctx: ApiContext, input: { body: Body; params: Params; query: URLSearchParams; session: WebSession | null }) => Promise<Reply> | Reply;
type Route = { method: string; pattern: RegExp; keys: string[]; auth: boolean; handler: Handler };

const routes: Route[] = [];

function route(method: string, path: string, auth: boolean, handler: Handler): void {
  const keys: string[] = [];
  const pattern = new RegExp(`^${path.replace(/:(\w+)/g, (_, key: string) => { keys.push(key); return "([^/]+)"; })}$`);
  routes.push({ method, pattern, keys, auth, handler });
}

export function matchRoute(method: string, pathname: string): { route: Route; params: Params } | "method" | null {
  let pathMatched = false;
  for (const candidate of routes) {
    const match = candidate.pattern.exec(pathname);
    if (!match) continue;
    pathMatched = true;
    if (candidate.method !== method) continue;
    const params: Params = {};
    try {
      candidate.keys.forEach((key, index) => {
        params[key] = decodeURIComponent(match[index + 1]!);
      });
    } catch {
      return null; // A malformed %-escape names nothing.
    }
    return { route: candidate, params };
  }
  return pathMatched ? "method" : null;
}

// Unlock

route("GET", "/api/auth", false, (ctx) => {
  const auth = VaultService.getAuthConfig(ctx.vaultPath);
  const initialized = new AuthoDatabase(ctx.vaultPath);
  let ready: boolean;
  try {
    ready = initialized.getVaultConfig() !== null;
  } finally {
    initialized.close();
  }
  return {
    data: {
      initialized: ready,
      passkeys: VaultService.listPasskeys(ctx.vaultPath).map(({ credentialId, prfSalt, transports, label }) => ({ credentialId, prfSalt, transports, label })),
      recovery: auth?.recovery !== undefined,
      rpId: "localhost",
      totp: auth?.totp !== undefined,
      vault: basename(ctx.vaultPath),
    },
  };
});

route("POST", "/api/session/unlock", false, async (ctx, { body }) => {
  const { rootKey, sealBound } = await throttled(ctx, body, true, async (creds) => {
    const vault = VaultService.unlock(ctx.vaultPath, { ...creds, sealRecord: await loadSealRecord(ctx.vaultPath), source: "web" });
    const unlocked = { rootKey: vault.getRootKey(), sealBound: vault.sealBound };
    await closeSessionAndRecordSeal(ctx.vaultPath, vault);
    return unlocked;
  });
  const session = ctx.sessions.create(rootKey, sealBound);
  return { data: sessionInfo(ctx, session), session };
});

route("POST", "/api/session/lock", false, () => ({ data: { locked: true }, session: "ended" }));

route("GET", "/api/session", true, (ctx, { session }) => ({ data: sessionInfo(ctx, session!) }));

// Secrets

route("GET", "/api/secrets", true, (ctx, { query, session }) =>
  withVault(ctx, session!, (vault) => {
    const entries = vault.listSecretIndex();
    const group = query.get("group");
    if (group === null) return { data: entries };
    // "(ungrouped)" or an empty value lists the secrets in no group.
    const groupId = group === "" || group === UNGROUPED_LABEL ? null : vault.getGroup(group).id;
    return { data: entries.filter((entry) => entry.groupId === groupId) };
  }));

route("POST", "/api/secrets", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => {
    const type = secretType(body);
    const username = type === "note" ? undefined : optStr(body, "username", LIMITS.short)?.trim() || undefined;
    const created = vault.addSecret({
      group: groupField(body) ?? undefined,
      metadata: metadataFrom(body, type),
      name: str(body, "name", LIMITS.name).trim(),
      type,
      username,
      value: str(body, "value", LIMITS.value),
    });
    return { data: created, status: 201 };
  }));

route("GET", "/api/secrets/:ref", true, (ctx, { params, session }) =>
  withVault(ctx, session!, (vault) => ({ data: secretDetail(vault, findEntry(vault, params.ref!)) })));

route("PATCH", "/api/secrets/:ref", true, (ctx, { body, params, session }) =>
  withVault(ctx, session!, (vault) => {
    const existing = findEntry(vault, params.ref!);
    const type = body.type === undefined ? existing.type : secretType(body);
    const parsed = metadataFrom(body, type);
    // Metadata merges: a sent field replaces (or, when "", clears) it; a missing one is kept. Only logins keep a URL.
    const metadata: Record<string, unknown> = {};
    if ("url" in body || type !== "password") metadata.url = parsed.url;
    if ("description" in body) metadata.description = parsed.description;
    const updated = vault.updateSecret(existing.id, {
      group: groupField(body),
      metadata,
      name: optStr(body, "name", LIMITS.name)?.trim() || undefined,
      type,
      username: type === "note" ? "" : optStr(body, "username", LIMITS.short)?.trim(),
      value: optStr(body, "value", LIMITS.value) || undefined,
    });
    return { data: updated };
  }));

route("DELETE", "/api/secrets/:ref", true, (ctx, { params, query, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.removeSecret(params.ref!, { withLinked: query.get("withLinked") === "1" }) })));

route("POST", "/api/secrets/:ref/reveal", true, (ctx, { params, session }) =>
  withVault(ctx, session!, (vault) => {
    const secret = vault.getSecret(params.ref!);
    return { data: { value: secret.value } };
  }));

route("GET", "/api/secrets/:ref/otp", true, (ctx, { params, query, session }) =>
  // Showing the live code isn't audited (it refreshes every few seconds); copying it is.
  withVault(ctx, session!, (vault) => ({ data: vault.generateOtp(params.ref!, { audit: query.get("copy") === "1" }) })));

// Links

route("POST", "/api/links", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.linkSecrets(str(body, "primary", LIMITS.name), str(body, "secret", LIMITS.name)) })));

route("DELETE", "/api/links", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.unlinkSecrets(str(body, "primary", LIMITS.name), str(body, "secret", LIMITS.name)) })));

// Groups

route("GET", "/api/groups", true, (ctx, { session }) => withVault(ctx, session!, (vault) => ({ data: vault.listGroups() })));

route("POST", "/api/groups", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.createGroup(str(body, "name", LIMITS.name)), status: 201 })));

route("PATCH", "/api/groups/:id", true, (ctx, { body, params, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.renameGroup(params.id!, str(body, "name", LIMITS.name)) })));

route("DELETE", "/api/groups/:id", true, (ctx, { params, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.removeGroup(params.id!) })));

// Leases

route("GET", "/api/leases", true, (ctx, { session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.listLeases(200).map((lease) => ({ ...lease, coverage: vault.showLease(lease.id).coverage })) })));

route("POST", "/api/leases", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => {
    const refs = body.secrets;
    if (!Array.isArray(refs) || refs.length === 0 || refs.length > 500 || !refs.every((r) => typeof r === "string" && r.length <= LIMITS.name)) {
      throw new HttpError(400, "Pick at least one secret");
    }
    const ttl = body.ttlSeconds;
    if (typeof ttl !== "number" || !Number.isInteger(ttl) || ttl <= 0 || ttl > 2_592_000) {
      throw new HttpError(400, "TTL must be between 1 second and 30 days");
    }
    const lease = vault.createLease({
      name: optStr(body, "name", LIMITS.name)?.trim() || "web",
      noLinks: body.includeLinks === false,
      secretRefs: refs as string[],
      ttlSeconds: ttl,
    });
    return { data: lease, status: 201 };
  }));

route("POST", "/api/leases/:id/revoke", true, (ctx, { params, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.revokeLease(params.id!) })));

// Vault

route("GET", "/api/audit", true, (ctx, { query, session }) => {
  const limit = Math.min(500, Math.max(1, Number(query.get("limit") ?? 100) || 100));
  const filter = (key: string) => query.get(key)?.trim() || undefined;
  const source = filter("source");
  if (source && !AUDIT_SOURCES.includes(source as AuditSource)) throw new HttpError(400, `Unknown source: ${source}`);
  return withVault(ctx, session!, (vault) => ({
    data: vault.listAudit({
      eventType: filter("type"),
      leaseRef: filter("lease"),
      limit,
      secretRef: filter("secret"),
      source: source as AuditSource | undefined,
    }),
  }));
});

route("GET", "/api/vault/verify", true, (ctx, { session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.verifySeal() })));

route("POST", "/api/import", true, (ctx, { body, session }) =>
  withVault(ctx, session!, (vault) => ({ data: vault.importLegacy(body.entries, { skipExisting: body.skipExisting !== false }) })));

// Settings

route("GET", "/api/settings", true, async (ctx, { session }) => ({
  data: {
    about: { bun: Bun.version, platform: `${process.platform}-${process.arch}`, version: pkg.version },
    paths: {
      config: configFilePath(),
      envHome: process.env.AUTHO_HOME !== undefined,
      vaultDir: loadConfig().vaultDir ?? null,
      daemon: defaultDaemonStatePath(),
      home: authoHomeDir(),
      project: defaultProjectFilePath(),
      vault: ctx.vaultPath,
    },
    preferences: PREFERENCES.map((spec) => {
      const { value, source } = resolvePreference(spec.key);
      return { ...spec, display: formatPreference(spec.key, value), guarded: GUARDED_PREFS.has(spec.key), source, value };
    }),
    security: await securityStatus(ctx, session!),
  },
}));

route("PUT", "/api/settings/preferences/:key", true, (ctx, { body, params, session }) => {
  const key = params.key as PreferenceKey;
  if (!PREF_KEYS.includes(key)) throw new HttpError(404, `Unknown setting: ${params.key}`);
  if (GUARDED_PREFS.has(key)) requireAdmin(ctx, session!);
  if (body.value === null) {
    setPreference(key, null);
  } else if (typeof body.value === "number" || typeof body.value === "boolean" || typeof body.value === "string") {
    try {
      setPreference(key, parsePreference(key, String(body.value)));
    } catch (error) {
      throw new HttpError(400, error instanceof Error ? error.message : String(error));
    }
  } else {
    throw new HttpError(400, "value is required");
  }
  const { value, source } = resolvePreference(key);
  return { data: { display: formatPreference(key, value), key, source, value, prefs: uiPrefs() } };
});

// Repointing the vault folder changes where every later CLI, TUI and daemon run reads and writes secrets.
route("PUT", "/api/settings/vault-dir", true, (ctx, { body, session }) => {
  requireAdmin(ctx, session!);
  if (process.env.AUTHO_HOME) throw new HttpError(400, "AUTHO_HOME is set, so it decides the folder");
  const raw = optStr(body, "path", 1024)?.trim();
  const config = { ...loadConfig() };
  const target = raw ? resolve(raw).replace(/\\/g, "/") : null;
  if (target) config.vaultDir = target;
  else delete config.vaultDir;
  saveConfig(config);
  return { data: { home: authoHomeDir(), missingVault: target !== null && !existsSync(join(target, "vault.db")), vaultDir: target } };
});

// Security (admin)

route("POST", "/api/admin/authorize", true, async (ctx, { body, session }) => {
  const handle = await throttled(ctx, body, false, async (creds) =>
    VaultService.authorize(ctx.vaultPath, { ...creds, sealRecord: await loadSealRecord(ctx.vaultPath), source: "web" }));
  ctx.sessions.grantAdmin(session!, handle);
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/release", true, async (ctx, { session }) => {
  ctx.sessions.dropAdmin(session!);
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/password", true, async (ctx, { body, session }) => {
  const admin = requireAdmin(ctx, session!);
  const next = str(body, "newPassword", LIMITS.password);
  if (next.length < MIN_PASSWORD_LENGTH) throw new HttpError(400, `Use at least ${MIN_PASSWORD_LENGTH} characters`);
  await adminChange(ctx, admin, async () => {
    admin.changePassword(next);
    if (await loadVaultPassword(ctx.vaultPath)) await storeVaultPassword(ctx.vaultPath, next);
  });
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/totp/setup", true, (ctx, { session }) => {
  requireAdmin(ctx, session!);
  session!.pendingTotp = VaultService.setupTotp(ctx.vaultPath);
  return { data: session!.pendingTotp };
});

route("POST", "/api/admin/totp", true, async (ctx, { body, session }) => {
  const admin = requireAdmin(ctx, session!);
  const pending = session!.pendingTotp;
  if (!pending) throw new HttpError(400, "Start two-factor setup first");
  const code = totpCode({ totp: body.code });
  if (!code) throw new HttpError(400, "Enter the code from your authenticator app");
  try {
    await adminChange(ctx, admin, () => admin.enableTotp(pending.secret, code));
  } catch (error) {
    throw new HttpError(400, error instanceof Error ? error.message : String(error));
  }
  session!.pendingTotp = null;
  return { data: await securityStatus(ctx, session!) };
});

route("DELETE", "/api/admin/totp", true, async (ctx, { session }) => {
  const admin = requireAdmin(ctx, session!);
  await adminChange(ctx, admin, () => admin.removeTotp());
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/passkeys/options", true, (ctx, { session }) => {
  requireAdmin(ctx, session!);
  const prfSalt = randomBytes(32).toString("base64url");
  session!.pendingPasskey = { prfSalt };
  return {
    data: {
      exclude: VaultService.listPasskeys(ctx.vaultPath).map((p) => p.credentialId),
      prfSalt,
      rpId: "localhost",
      userId: randomBytes(16).toString("base64url"),
      userName: `autho (${basename(ctx.vaultPath)})`,
    },
  };
});

route("POST", "/api/admin/passkeys", true, async (ctx, { body, session }) => {
  const admin = requireAdmin(ctx, session!);
  const pending = session!.pendingPasskey;
  if (!pending) throw new HttpError(400, "Start adding a passkey first");
  const transports = Array.isArray(body.transports)
    ? body.transports.filter((t): t is string => typeof t === "string" && /^[a-z-]{1,20}$/.test(t)).slice(0, 8)
    : undefined;
  const info = await adminChange(ctx, admin, () => admin.addPasskey({
    credentialId: b64url(body, "credentialId", 1400),
    label: str(body, "label", 64).trim() || "passkey",
    prfOutput: b64url(body, "prfOutput", 64),
    prfSalt: pending.prfSalt,
    transports,
  }));
  session!.pendingPasskey = null;
  return { data: { added: info.label, security: await securityStatus(ctx, session!) } };
});

route("DELETE", "/api/admin/passkeys/:id", true, async (ctx, { params, session }) => {
  const admin = requireAdmin(ctx, session!);
  await adminChange(ctx, admin, () => admin.removePasskey(params.id!));
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/recovery", true, async (ctx, { session }) => {
  const admin = requireAdmin(ctx, session!);
  const { fileContent } = await adminChange(ctx, admin, () => admin.generateRecovery());
  return { data: { fileContent, security: await securityStatus(ctx, session!) } };
});

route("DELETE", "/api/admin/recovery", true, async (ctx, { session }) => {
  const admin = requireAdmin(ctx, session!);
  await adminChange(ctx, admin, () => admin.revokeRecovery());
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/keychain", true, async (ctx, { session }) => {
  const admin = requireAdmin(ctx, session!);
  if (osSecretsDisabled()) throw new HttpError(400, "The OS keychain is not available");
  if (!admin.hasPassword) throw new HttpError(400, "Confirm with your master password to save it in the keychain");
  if (!(await storeVaultPassword(ctx.vaultPath, admin.masterPassword()))) throw new HttpError(400, "The OS keychain refused the password");
  return { data: await securityStatus(ctx, session!) };
});

// Forgetting the saved password only removes a convenience, so it needs no re-authorization (as in the TUI).
route("DELETE", "/api/admin/keychain", true, async (ctx, { session }) => {
  await deleteVaultPassword(ctx.vaultPath);
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/pin", true, async (ctx, { body, session }) => {
  requireAdmin(ctx, session!);
  if (osSecretsDisabled()) throw new HttpError(400, "The OS keychain is not available");
  const pin = str(body, "pin", 12);
  if (!/^\d{4,12}$/.test(pin)) throw new HttpError(400, "Use 4 to 12 digits");
  if (!(await storePinHash(ctx.vaultPath, pin))) throw new HttpError(400, "The OS keychain refused the PIN");
  return { data: await securityStatus(ctx, session!) };
});

route("DELETE", "/api/admin/pin", true, async (ctx, { session }) => {
  requireAdmin(ctx, session!);
  await deletePin(ctx.vaultPath);
  return { data: await securityStatus(ctx, session!) };
});

route("POST", "/api/admin/reseal", true, async (ctx, { body, session }) => {
  const admin = requireAdmin(ctx, session!);
  if (body.mode !== "accept" && body.mode !== "quarantine") throw new HttpError(400, "mode must be accept or quarantine");
  const { sealRecord, ...result } = admin.reseal(body.mode);
  await saveSealRecord(ctx.vaultPath, sealRecord);
  return { data: result };
});
