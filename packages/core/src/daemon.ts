import { createHash, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";

import { AuthoDatabase } from "../../storage/src/index.ts";
import { randomId } from "../../crypto/src/index.ts";
import { VaultService, VaultSession, type EnvMapping, type LeaseState, type VaultStatus } from "./index.ts";
import { LeaseKeyring } from "./lease-keyring.ts";
import { LeaseKeyRegistry } from "./lease-keys.ts";
import { LeaseInputError, leaseObject, parseLeaseIssue, parseLeaseMappings, type LeaseIssueInput } from "./lease-validation.ts";
import { closeSessionAndRecordSeal, loadSealRecord } from "./os-secrets.ts";
import { defaultDaemonStatePath, writeTextFileSecure } from "./paths.ts";

const DAEMON_TOKEN_SERVICE = "autho.daemon";

type StoredDaemonState = {
  pid: number;
  port: number;
  startedAt: string;
  token?: string;
  tokenName?: string;
  tokenStorage?: "file" | "os";
  vaultPath: string;
  version: 1;
};

export type DaemonState = {
  pid: number;
  port: number;
  startedAt: string;
  token: string | null;
  tokenName: string | null;
  tokenStorage: "file" | "os";
  vaultPath: string;
  version: 1;
};

export type DaemonSession = {
  expiresAt: string;
  id: string;
  rootKey: Buffer;
  /** The root key's wrap says the vault is sealed. */
  sealBound: boolean;
  vaultPath: string;
};

export { defaultDaemonStatePath } from "./paths.ts";

function daemonTokenName(statePath: string): string {
  return createHash("sha256").update(statePath).digest("hex");
}

async function storeDaemonToken(statePath: string, token: string): Promise<{
  token: string | null;
  tokenName: string | null;
  tokenStorage: "file" | "os";
}> {
  const tokenName = daemonTokenName(statePath);

  if (process.env.AUTHO_DISABLE_OS_SECRETS !== "1") {
    try {
      await Bun.secrets.set({
        name: tokenName,
        service: DAEMON_TOKEN_SERVICE,
        value: token,
      });
      return {
        token: null,
        tokenName,
        tokenStorage: "os",
      };
    } catch {
      // fall back to file state when no OS secret backend is available
    }
  }

  return {
    token,
    tokenName: null,
    tokenStorage: "file",
  };
}

async function resolveDaemonToken(state: DaemonState): Promise<string> {
  if (state.tokenStorage === "os") {
    if (!state.tokenName) {
      throw new Error("Daemon state is missing tokenName for OS secret storage");
    }

    const token = await Bun.secrets.get({
      name: state.tokenName,
      service: DAEMON_TOKEN_SERVICE,
    });

    if (!token) {
      throw new Error("Daemon token not found in OS secret storage");
    }

    return token;
  }

  if (!state.token) {
    throw new Error("Daemon state is missing token");
  }

  return state.token;
}

async function deleteStoredDaemonToken(state: DaemonState | null): Promise<void> {
  if (!state || state.tokenStorage !== "os" || !state.tokenName) {
    return;
  }

  try {
    await Bun.secrets.delete({
      name: state.tokenName,
      service: DAEMON_TOKEN_SERVICE,
    });
  } catch {
    // best effort cleanup only
  }
}

export function readDaemonState(statePath: string): DaemonState | null {
  if (!existsSync(statePath)) {
    return null;
  }

  const stored = JSON.parse(readFileSync(statePath, "utf8")) as StoredDaemonState;
  return {
    pid: stored.pid,
    port: stored.port,
    startedAt: stored.startedAt,
    token: stored.token ?? null,
    tokenName: stored.tokenName ?? null,
    tokenStorage: stored.tokenStorage ?? (stored.token ? "file" : "os"),
    vaultPath: stored.vaultPath,
    version: stored.version,
  };
}

export async function writeDaemonState(
  statePath: string,
  state: Omit<DaemonState, "token" | "tokenName" | "tokenStorage"> & { token: string },
): Promise<void> {
  const tokenState = await storeDaemonToken(statePath, state.token);
  writeTextFileSecure(
    statePath,
    JSON.stringify(
      {
        pid: state.pid,
        port: state.port,
        startedAt: state.startedAt,
        token: tokenState.token ?? undefined,
        tokenName: tokenState.tokenName ?? undefined,
        tokenStorage: tokenState.tokenStorage,
        vaultPath: state.vaultPath,
        version: state.version,
      } satisfies StoredDaemonState,
      null,
      2,
    ) + "\n",
  );
}

export async function deleteDaemonState(statePath: string): Promise<void> {
  const state = readDaemonState(statePath);
  await deleteStoredDaemonToken(state);

  if (existsSync(statePath)) {
    rmSync(statePath, { force: true });
  }
}

/** Opens a session per request, with the current keychain seal record so a swapped-in older vault file is caught. */
async function openSessionFromRootKey(session: DaemonSession): Promise<VaultSession> {
  return new VaultSession(new AuthoDatabase(session.vaultPath), Buffer.from(session.rootKey), {
    sealBound: session.sealBound,
    sealRecord: await loadSealRecord(session.vaultPath),
    source: "daemon",
  });
}

async function readJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "cache-control": "no-store",
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "x-request-id": typeof data === "object" && data !== null && "requestId" in data && typeof data.requestId === "string" ? data.requestId : crypto.randomUUID(),
    },
    status,
  });
}

function unauthorized(): Response {
  return json({ error: "Unauthorized daemon request" }, 401);
}

function getBearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) {
    return null;
  }
  return header.slice("Bearer ".length);
}

type ServeOptions = {
  host: string;
  port: number;
  statePath: string;
  vaultPath: string;
};

type DaemonClientOptions = {
  statePath: string;
};

export async function startDaemonServer(options: ServeOptions): Promise<void> {
  if (!["127.0.0.1", "localhost", "::1"].includes(options.host)) throw new Error("Daemon must bind to loopback");
  const sessions = new Map<string, DaemonSession>();
  const leaseKeys = new LeaseKeyRegistry();
  const keyring = new LeaseKeyring(options.statePath);
  await keyring.cleanup(true);
  const startedAt = new Date().toISOString();
  const token = randomId(24);

  const cleanupExpiredSessions = (): void => {
    const now = Date.now();
    for (const [id, session] of sessions.entries()) {
      if (Date.parse(session.expiresAt) <= now) {
        session.rootKey.fill(0);
        sessions.delete(id);
      }
    }
  };

  let server: Bun.Server<undefined> | null = null;
  let sweeping = false;
  let stopping = false;
  let issuing = false;
  let requestWindow = Date.now();
  let leaseRequests = 0;
  const sweepLeaseKeys = async (): Promise<void> => {
    if (sweeping) return;
    sweeping = true;
    try {
      if (leaseKeys.list().length > 0) {
        const db = new AuthoDatabase(options.vaultPath);
        try {
          for (const grant of leaseKeys.list()) {
            const lease = db.findLease(grant.leaseId);
            if (!lease || lease.revokedAt || leaseKeys.expired(grant) || Date.parse(lease.expiresAt) <= Date.now()) {
              leaseKeys.revoke(grant.leaseId);
              await keyring.forget(grant.leaseId).catch(() => undefined);
            }
          }
        } finally {
          db.close();
        }
      }
      await keyring.cleanup();
    } finally {
      sweeping = false;
    }
  };
  const sweepTimer = setInterval(() => {
    cleanupExpiredSessions();
    void sweepLeaseKeys().catch(() => undefined);
  }, 1000);

  const shutdown = (): void => {
    if (stopping) return;
    stopping = true;
    clearInterval(sweepTimer);
    leaseKeys.clear();
    for (const session of sessions.values()) session.rootKey.fill(0);
    sessions.clear();
    void keyring.cleanup(true).catch(() => undefined).then(() => deleteDaemonState(options.statePath)).finally(async () => {
      await server?.stop(false);
      process.exit(0);
    });
  };

  const auth = (request: Request): Response | null => {
    const provided = getBearerToken(request);
    if (!provided || Buffer.byteLength(provided) !== Buffer.byteLength(token) || !timingSafeEqual(Buffer.from(provided), Buffer.from(token))) {
      return unauthorized();
    }
    return null;
  };

  server = Bun.serve({
    maxRequestBodySize: 128 * 1024,
    async fetch(request) {
      cleanupExpiredSessions();

      const url = new URL(request.url);
      if (stopping) return json({ error: "Daemon is stopping" }, 503);
      const hosts = new Set([`127.0.0.1:${server?.port}`, `localhost:${server?.port}`, `[::1]:${server?.port}`]);
      if (!hosts.has(request.headers.get("host") ?? "")) return json({ error: "Invalid daemon host" }, 421);
      if (request.headers.has("origin") || (request.headers.get("sec-fetch-site") ?? "none") !== "none") {
        return json({ error: "Browser requests are not supported by the daemon" }, 403);
      }
      if (request.method === "GET" && url.pathname === "/health") {
        return json({
          ok: true,
          running: true,
          startedAt,
        });
      }

      if (url.pathname.startsWith("/lease/")) {
        const requestId = crypto.randomUUID();
        const fail = (error: string, status: number): Response => json({ error, requestId }, status);
        if (Date.now() - requestWindow >= 1000) { requestWindow = Date.now(); leaseRequests = 0; }
        if (++leaseRequests > 120) return fail("Too many lease requests", 429);
        if (request.method !== "POST") return fail("Method not allowed", 405);
        if (request.headers.get("content-type")?.split(";")[0]?.trim().toLowerCase() !== "application/json") return fail("Expected application/json", 400);
        if (url.pathname === "/lease/revoke-key") {
          if (auth(request)) return fail("Unauthorized daemon request", 401);
          try {
            const body = leaseObject(await request.json(), ["leaseId"]);
            if (typeof body.leaseId !== "string" || !/^[a-f0-9]{32}$/.test(body.leaseId)) throw new LeaseInputError("Invalid lease ID");
            leaseKeys.revoke(body.leaseId);
            await keyring.forget(body.leaseId);
            return json({ revoked: true });
          } catch (error) {
            if (error instanceof LeaseInputError || error instanceof SyntaxError) return fail("Invalid revocation request", 400);
            return fail("Lease key invalidated; OS keyring cleanup pending", 503);
          }
        }
        if (url.pathname === "/lease/issue") {
          if (auth(request)) return fail("Unauthorized daemon request", 401);
          if (issuing) return fail("Lease issuance is busy; retry shortly", 429);
          issuing = true;
          let vaultSession: VaultSession | undefined;
          let createdLeaseId: string | undefined;
          let issuedLeaseId: string | undefined;
          try {
            const input = parseLeaseIssue(await request.json());
            vaultSession = VaultService.unlock(options.vaultPath, {
              ...input.credentials,
              sealRecord: await loadSealRecord(options.vaultPath),
              source: "daemon",
            }, { recordUnlock: false });
            let leaseId = input.leaseId;
            if (!leaseId) {
              const lease = vaultSession.createLease({
                name: input.name!, noLinks: true, secretRefs: input.secretRefs!, ttlSeconds: input.ttlSeconds!,
              });
              leaseId = lease.id;
              createdLeaseId = lease.id;
            }
            await keyring.forget(leaseId);
            const issued = leaseKeys.issue(vaultSession, leaseId, options.vaultPath);
            issuedLeaseId = leaseId;
            if (input.remember) await keyring.save(leaseId, issued.lease.expiresAt, issued.leaseKey);
            return json({ ...issued.lease, keyStored: input.remember, leaseKey: input.remember ? undefined : issued.leaseKey });
          } catch (error) {
            if (issuedLeaseId) {
              leaseKeys.revoke(issuedLeaseId);
              await keyring.forget(issuedLeaseId).catch(() => undefined);
            }
            if (createdLeaseId && vaultSession) vaultSession.revokeLease(createdLeaseId);
            if (error instanceof LeaseInputError || error instanceof SyntaxError) return fail(error instanceof SyntaxError ? "Invalid JSON" : error.message, 400);
            return fail("Lease key could not be issued; check credentials, lease, vault integrity and OS keyring availability", 403);
          } finally {
            if (vaultSession) await closeSessionAndRecordSeal(options.vaultPath, vaultSession);
            issuing = false;
          }
        }

        const grant = leaseKeys.get(getBearerToken(request));
        if (!grant) return fail("Invalid or expired lease key", 401);
        if (url.pathname !== "/lease/env" && url.pathname !== "/lease/show") return fail("Forbidden lease operation", 403);
        const rootKey = Buffer.from(grant.rootKey);
        let vaultSession: VaultSession | undefined;
        try {
          const body: unknown = await request.json();
          vaultSession = new VaultSession(new AuthoDatabase(grant.vaultPath), rootKey, {
            sealBound: grant.sealBound,
            sealRecord: await loadSealRecord(grant.vaultPath),
            source: "daemon",
          });
          if (leaseKeys.expired(grant) || leaseKeys.get(getBearerToken(request)) !== grant) return fail("Invalid or expired lease key", 401);
          if (url.pathname === "/lease/show") {
            leaseObject(body, []);
            return json(vaultSession.inspectLeaseKey(grant));
          }
          return json(vaultSession.renderLeaseEnv(parseLeaseMappings(body), grant));
        } catch (error) {
          if (error instanceof LeaseInputError || error instanceof SyntaxError) return fail(error instanceof SyntaxError ? "Invalid JSON" : error.message, 400);
          return fail("Lease access denied", 403);
        } finally {
          if (vaultSession) await closeSessionAndRecordSeal(grant.vaultPath, vaultSession);
          rootKey.fill(0);
        }
      }

      const authResponse = auth(request);
      if (authResponse) {
        return authResponse;
      }

      try {
        if (request.method === "POST" && url.pathname === "/status") {
          const db = new AuthoDatabase(options.vaultPath);
          try {
            const config = db.getVaultConfig();
            const status: VaultStatus = {
              activeLeaseCount: db.countActiveLeases(new Date().toISOString()),
              auditEventCount: db.countAuditEvents(),
              initialized: config !== null,
              projectFile: null,
              projectMappings: [],
              secretCount: db.countSecrets(),
              unlocked: sessions.size > 0,
              vaultPath: options.vaultPath,
            };
            return json({
              activeSessions: sessions.size,
              daemonStartedAt: startedAt,
              status,
            });
          } finally {
            db.close();
          }
        }

        if (request.method === "POST" && url.pathname === "/unlock") {
          const body = await readJson<{ password: string; totp?: string; ttlSeconds?: number }>(request);
          const ttlSeconds = body.ttlSeconds ?? 900;
          if (ttlSeconds <= 0 || ttlSeconds > 86400) {
            return json({ error: "Unlock ttl must be between 1 and 86400 seconds" }, 400);
          }

          const { rootKey, sealBound } = VaultService.unlockRootKey(options.vaultPath, {
            password: body.password,
            sealRecord: await loadSealRecord(options.vaultPath),
            source: "daemon",
            totp: body.totp,
          });
          const sessionId = randomId();
          const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
          sessions.set(sessionId, {
            expiresAt,
            id: sessionId,
            rootKey,
            sealBound,
            vaultPath: options.vaultPath,
          });

          return json({
            expiresAt,
            sessionId,
          });
        }

        if (request.method === "POST" && url.pathname === "/lock") {
          const body = await readJson<{ sessionId: string }>(request);
          sessions.get(body.sessionId)?.rootKey.fill(0);
          sessions.delete(body.sessionId);
          return json({ locked: true, sessionId: body.sessionId });
        }

        if (request.method === "POST" && url.pathname === "/env/render") {
          const body = await readJson<{
            leaseId?: string;
            mappings: EnvMapping[];
            sessionId: string;
          }>(request);
          const session = sessions.get(body.sessionId);
          if (!session) {
            return json({ error: `Unknown daemon session: ${body.sessionId}` }, 404);
          }

          const vaultSession = await openSessionFromRootKey(session);
          try {
            return json(vaultSession.renderEnv(body.mappings, body.leaseId));
          } finally {
            await closeSessionAndRecordSeal(session.vaultPath, vaultSession);
          }
        }

        if (request.method === "POST" && url.pathname === "/exec") {
          const body = await readJson<{
            cmd: string[];
            leaseId?: string;
            mappings: EnvMapping[];
            sessionId: string;
          }>(request);
          const session = sessions.get(body.sessionId);
          if (!session) {
            return json({ error: `Unknown daemon session: ${body.sessionId}` }, 404);
          }

          const vaultSession = await openSessionFromRootKey(session);
          try {
            return json(vaultSession.runExec(body));
          } finally {
            await closeSessionAndRecordSeal(session.vaultPath, vaultSession);
          }
        }

        if (request.method === "POST" && url.pathname === "/shutdown") {
          shutdown();
          return json({ ok: true, stopped: true });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return json({ error: message }, 400);
      }

      return json({ error: "Not found" }, 404);
    },
    hostname: options.host,
    port: options.port,
  });

  await writeDaemonState(options.statePath, {
    pid: process.pid,
    port: server.port ?? options.port,
    startedAt,
    token,
    vaultPath: options.vaultPath,
    version: 1,
  });
  writeTextFileSecure(`${options.statePath}.endpoint.json`, JSON.stringify({ port: server.port, startedAt }) + "\n");

  const onSignal = (): void => {
    shutdown();
  };
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);

  await new Promise(() => {
    // keep the process alive until shutdown
  });
}

async function waitForDaemonStateDeletion(statePath: string): Promise<boolean> {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    if (!existsSync(statePath)) {
      return true;
    }
    await Bun.sleep(25);
  }

  return !existsSync(statePath);
}
async function daemonRequest<T>(state: DaemonState, path: string, body: unknown): Promise<T> {
  const token = await resolveDaemonToken(state);
  const response = await fetch(`http://127.0.0.1:${state.port}${path}`, {
    body: JSON.stringify(body ?? {}),
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const data = (await response.json()) as { error?: string };
  if (!response.ok) {
    throw new Error(data.error ?? `Daemon request failed: ${response.status}`);
  }
  return data as T;
}

export type LeaseKeyIssueResult = LeaseState & { keyStored: boolean; leaseKey?: string };
export type LeaseKeyInfo = ReturnType<VaultSession["inspectLeaseKey"]>;

export async function daemonRevokeLeaseKey(options: DaemonClientOptions & { leaseId: string }): Promise<void> {
  const state = readDaemonState(options.statePath);
  if (!state) return;
  await daemonRequest(state, "/lease/revoke-key", { leaseId: options.leaseId });
}

export async function daemonIssueLeaseKey(options: DaemonClientOptions & LeaseIssueInput): Promise<LeaseKeyIssueResult> {
  const state = readDaemonState(options.statePath);
  if (!state) throw new Error("Start the Autho daemon before issuing a lease key");
  const { password, totp, recovery, passkey } = options.credentials;
  return daemonRequest(state, "/lease/issue", {
    credentials: { password, totp, recovery, passkey },
    leaseId: options.leaseId,
    name: options.name,
    remember: options.remember,
    secretRefs: options.secretRefs,
    ttlSeconds: options.ttlSeconds,
  });
}

export async function leaseKeyRequest<T>(options: DaemonClientOptions & { leaseKey: string; path: "/lease/env" | "/lease/show"; mappings?: EnvMapping[] }): Promise<T> {
  if (!/^autho_lease_[a-f0-9]{64}$/.test(options.leaseKey)) throw new Error("Invalid lease key");
  const path = `${options.statePath}.endpoint.json`;
  if (!existsSync(path)) throw new Error("Autho daemon endpoint not found; start the daemon and issue a lease key");
  const endpoint: unknown = JSON.parse(readFileSync(path, "utf8"));
  const port = (endpoint as { port?: unknown } | null)?.port;
  if (!Number.isInteger(port) || (port as number) < 1 || (port as number) > 65535) throw new Error("Invalid daemon endpoint");
  const response = await fetch(`http://127.0.0.1:${port}${options.path}`, {
    body: JSON.stringify(options.path === "/lease/show" ? {} : { mappings: options.mappings }),
    headers: { authorization: `Bearer ${options.leaseKey}`, "content-type": "application/json" },
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  const data = await response.json() as { error?: string };
  if (!response.ok) throw new Error(data.error ?? "Lease request failed");
  return data as T;
}

export async function daemonStatus(options: DaemonClientOptions): Promise<{
  activeSessions: number;
  daemonStartedAt: string;
  status: VaultStatus;
}> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/status", {});
}

export async function daemonUnlock(options: DaemonClientOptions & { password: string; totp?: string; ttlSeconds?: number }): Promise<{ expiresAt: string; sessionId: string }> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/unlock", {
    password: options.password,
    totp: options.totp,
    ttlSeconds: options.ttlSeconds,
  });
}

export async function daemonLock(options: DaemonClientOptions & { sessionId: string }): Promise<{ locked: boolean; sessionId: string }> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/lock", { sessionId: options.sessionId });
}

export async function daemonRenderEnv(options: DaemonClientOptions & { leaseId?: string; mappings: EnvMapping[]; sessionId: string }): Promise<Record<string, string>> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/env/render", options);
}

export async function daemonExec(options: DaemonClientOptions & { cmd: string[]; leaseId?: string; mappings: EnvMapping[]; sessionId: string }): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/exec", options);
}

export async function daemonStop(options: DaemonClientOptions): Promise<{ ok: true; stopped: true }> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }

  try {
    const result = (await daemonRequest(state, "/shutdown", {})) as { ok: true; stopped: true };
    await waitForDaemonStateDeletion(options.statePath);
    return result;
  } catch (error) {
    if (await waitForDaemonStateDeletion(options.statePath)) {
      return { ok: true, stopped: true };
    }
    throw error;
  }
}

