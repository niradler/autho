/**
 * Thin client for the local web server. Every call carries the request
 * header; once unlocked it also carries the session's CSRF token, which lives
 * in sessionStorage (per tab) because the cookie alone is shared by every
 * localhost port and must never be enough.
 */

export type SecretType = "password" | "note" | "otp";

export type SecretEntry = {
  id: string;
  name: string;
  type: SecretType;
  createdAt: string;
  updatedAt: string;
  username: string | null;
  url: string | null;
  description: string | null;
  linkCount: number;
  /** The group it belongs to, if any (one group per secret). */
  group: string | null;
  groupId: string | null;
};

export type Group = { id: string; name: string; createdAt: string; updatedAt: string; secretCount: number };

/** Names the list's "no group" row; it isn't a real group. */
export const UNGROUPED_LABEL = "(ungrouped)";

export type LinkedSecret = { id: string; name: string; type: SecretType };
export type SecretDetail = SecretEntry & { links: LinkedSecret[]; linkedFrom: LinkedSecret[] };

export type Prefs = {
  revealSeconds: number;
  clipboardClearSeconds: number;
  idleLockSeconds: number;
  passwordLength: number;
  passwordSymbols: boolean;
};

export type SessionInfo = {
  csrf: string;
  idleAt: number | null;
  hardAt: number;
  prefs: Prefs;
  vault: { name: string; path: string };
  version: string;
};

export type AuthInfo = {
  initialized: boolean;
  passkeys: { credentialId: string; prfSalt: string; transports?: string[]; label: string }[];
  recovery: boolean;
  rpId: string;
  totp: boolean;
  vault: string;
};

export type Lease = {
  id: string;
  name: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  includeLinks: boolean;
  secretRefs: string[];
  coverage: (LinkedSecret & { via: LinkedSecret | null })[];
};

export type AuditEvent = {
  id: string;
  createdAt: string;
  eventType: string;
  /** Set when the event happened through a lease (env, exec, lease use). */
  leaseId: string | null;
  message: string;
  metadata: Record<string, unknown>;
  /** Where it happened: cli, tui, web or daemon; null for events from before sources were recorded. */
  source: string | null;
  subjectRef: string | null;
  subjectType: string;
};

export const AUDIT_SOURCES = ["cli", "tui", "web", "daemon"] as const;

export type SealChange = { change: "added" | "modified" | "removed"; rowId: string; table: string };
export type SealState = {
  state: "intact" | "unsealed" | "tampered";
  changes?: SealChange[];
  diffTrusted?: boolean;
  reason?: string | null;
};
export type ResealResult = {
  changes: SealChange[];
  diffTrusted: boolean;
  /** Changes quarantine couldn't undo; they are still in the vault. */
  kept: SealChange[];
  mode: "accept" | "quarantine";
  rebound: boolean;
  revokedLeases: number;
  reason: string | null;
  undone: SealChange[];
  wasIntact: boolean;
};

export type PreferenceRow = {
  key: string;
  label: string;
  help: string;
  env?: string;
  kind: "number" | "boolean";
  default: number | boolean;
  zero?: string;
  value: number | boolean;
  display: string;
  source: "env" | "config" | "default";
  /** Changing it needs a fresh identity check. */
  guarded: boolean;
  min?: number;
  max?: number;
  unit?: string;
};

export type SecurityStatus = {
  adminUntil: number | null;
  adminHasPassword: boolean;
  keychain: boolean;
  osStore: boolean;
  passkeys: { id: string; label: string; createdAt: string; credentialId: string }[];
  pin: boolean;
  recoveryAt: string | null;
  totp: boolean;
};

export type Settings = {
  about: { bun: string; platform: string; version: string };
  paths: { config: string; daemon: string; home: string; project: string; vault: string; envHome: boolean; vaultDir: string | null };
  preferences: PreferenceRow[];
  security: SecurityStatus;
};

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

const CSRF_KEY = "autho.csrf";

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

export function setCsrf(token: string | null): void {
  const store = storage();
  if (!store) return;
  if (token) store.setItem(CSRF_KEY, token);
  else store.removeItem(CSRF_KEY);
}

export function hasCsrf(): boolean {
  return Boolean(storage()?.getItem(CSRF_KEY));
}

let onLocked: () => void = () => {};
/** Called whenever the server says the session is gone (idle lock, restart, another tab locked). */
export function setLockedHandler(handler: () => void): void {
  onLocked = handler;
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "x-autho-request": "1" };
  const csrf = storage()?.getItem(CSRF_KEY);
  if (csrf) headers["x-autho-csrf"] = csrf;
  if (body !== undefined) headers["content-type"] = "application/json";
  let response: Response;
  try {
    response = await fetch(path, {
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: "no-store",
      credentials: "same-origin",
      headers,
      method,
    });
  } catch {
    throw new ApiError(0, "Can't reach autho — is `autho web serve` still running?");
  }
  const payload = (await response.json().catch(() => ({}))) as { data?: T; error?: string };
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/session/unlock" && path !== "/api/admin/authorize") {
      setCsrf(null);
      onLocked();
    }
    throw new ApiError(response.status, payload.error ?? `Request failed (${response.status})`);
  }
  return payload.data as T;
}

export const api = {
  auth: () => request<AuthInfo>("GET", "/api/auth"),
  unlock: (body: Record<string, unknown>) => request<SessionInfo>("POST", "/api/session/unlock", body),
  lock: () => request<{ locked: true }>("POST", "/api/session/lock"),
  session: () => request<SessionInfo>("GET", "/api/session"),

  secrets: () => request<SecretEntry[]>("GET", "/api/secrets"),
  secret: (id: string) => request<SecretDetail>("GET", `/api/secrets/${encodeURIComponent(id)}`),
  createSecret: (body: Record<string, unknown>) => request<SecretEntry>("POST", "/api/secrets", body),
  updateSecret: (id: string, body: Record<string, unknown>) => request<SecretEntry>("PATCH", `/api/secrets/${encodeURIComponent(id)}`, body),
  deleteSecret: (id: string, withLinked: boolean) =>
    request<{ id: string; name: string; removedLinked: LinkedSecret[]; keptLinked: LinkedSecret[] }>(
      "DELETE",
      `/api/secrets/${encodeURIComponent(id)}${withLinked ? "?withLinked=1" : ""}`,
    ),
  reveal: (id: string) => request<{ value: string }>("POST", `/api/secrets/${encodeURIComponent(id)}/reveal`),
  otp: (id: string, copy = false) => request<{ code: string; expiresAt: string }>("GET", `/api/secrets/${encodeURIComponent(id)}/otp${copy ? "?copy=1" : ""}`),
  groups: () => request<Group[]>("GET", "/api/groups"),
  createGroup: (name: string) => request<Group>("POST", "/api/groups", { name }),
  renameGroup: (id: string, name: string) => request<Group>("PATCH", `/api/groups/${encodeURIComponent(id)}`, { name }),
  deleteGroup: (id: string) => request<{ id: string; name: string; ungrouped: number }>("DELETE", `/api/groups/${encodeURIComponent(id)}`),

  link: (primary: string, secret: string) => request<{ created: boolean }>("POST", "/api/links", { primary, secret }),
  unlink: (primary: string, secret: string) => request<unknown>("DELETE", "/api/links", { primary, secret }),

  leases: () => request<Lease[]>("GET", "/api/leases"),
  createLease: (body: { name: string; secrets: string[]; ttlSeconds: number; includeLinks: boolean }) => request<Lease>("POST", "/api/leases", body),
  revokeLease: (id: string) => request<Lease>("POST", `/api/leases/${encodeURIComponent(id)}/revoke`),

  audit: (limit = 200, source?: string) =>
    request<AuditEvent[]>("GET", `/api/audit?limit=${limit}${source ? `&source=${encodeURIComponent(source)}` : ""}`),
  verify: () => request<SealState>("GET", "/api/vault/verify"),
  importLegacy: (entries: unknown, skipExisting: boolean) => request<{ imported: number; skipped: number }>("POST", "/api/import", { entries, skipExisting }),

  settings: () => request<Settings>("GET", "/api/settings"),
  setPreference: (key: string, value: number | boolean | null) =>
    request<{ display: string; source: string; prefs: Prefs }>("PUT", `/api/settings/preferences/${encodeURIComponent(key)}`, { value }),
  setVaultDir: (path: string | null) => request<{ home: string; missingVault: boolean; vaultDir: string | null }>("PUT", "/api/settings/vault-dir", { path }),

  authorize: (body: Record<string, unknown>) => request<SecurityStatus>("POST", "/api/admin/authorize", body),
  release: () => request<SecurityStatus>("POST", "/api/admin/release"),
  changePassword: (newPassword: string) => request<SecurityStatus>("POST", "/api/admin/password", { newPassword }),
  totpSetup: () => request<{ secret: string; uri: string }>("POST", "/api/admin/totp/setup"),
  totpEnable: (code: string) => request<SecurityStatus>("POST", "/api/admin/totp", { code }),
  totpDisable: () => request<SecurityStatus>("DELETE", "/api/admin/totp"),
  passkeyOptions: () =>
    request<{ exclude: string[]; prfSalt: string; rpId: string; userId: string; userName: string }>("POST", "/api/admin/passkeys/options"),
  addPasskey: (body: { credentialId: string; prfOutput: string; transports?: string[]; label: string }) =>
    request<{ added: string; security: SecurityStatus }>("POST", "/api/admin/passkeys", body),
  removePasskey: (id: string) => request<SecurityStatus>("DELETE", `/api/admin/passkeys/${encodeURIComponent(id)}`),
  createRecovery: () => request<{ fileContent: string; security: SecurityStatus }>("POST", "/api/admin/recovery"),
  revokeRecovery: () => request<SecurityStatus>("DELETE", "/api/admin/recovery"),
  saveKeychain: () => request<SecurityStatus>("POST", "/api/admin/keychain"),
  forgetKeychain: () => request<SecurityStatus>("DELETE", "/api/admin/keychain"),
  setPin: (pin: string) => request<SecurityStatus>("POST", "/api/admin/pin", { pin }),
  removePin: () => request<SecurityStatus>("DELETE", "/api/admin/pin"),
  reseal: (mode: "accept" | "quarantine") => request<ResealResult>("POST", "/api/admin/reseal", { mode }),
};

export const errorMessage = (error: unknown): string => (error instanceof Error ? error.message : String(error));
