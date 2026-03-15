import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";

import { AuthoDatabase } from "../../storage/src/index.ts";
import { randomId, unlockRootKey } from "../../crypto/src/index.ts";
import { VaultSession, type EnvMapping, type VaultStatus } from "./index.ts";
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

function openSessionFromRootKey(rootKey: Buffer, vaultPath: string): VaultSession {
  return new VaultSession(new AuthoDatabase(vaultPath), rootKey);
}

function unlockVaultRootKey(vaultPath: string, password: string): Buffer {
  const db = new AuthoDatabase(vaultPath);

  try {
    const config = db.getVaultConfig();
    if (!config) {
      throw new Error(`Vault is not initialized at ${vaultPath}`);
    }

    return unlockRootKey(password, config);
  } finally {
    db.close();
  }
}

async function readJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
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
  const sessions = new Map<string, DaemonSession>();
  const startedAt = new Date().toISOString();
  const token = randomId(24);

  const cleanupExpiredSessions = (): void => {
    const now = Date.now();
    for (const [id, session] of sessions.entries()) {
      if (Date.parse(session.expiresAt) <= now) {
        sessions.delete(id);
      }
    }
  };

  let server: Bun.Server | null = null;

  const shutdown = (): void => {
    void deleteDaemonState(options.statePath);
    server?.stop(true);
  };

  const auth = (request: Request): Response | null => {
    if (getBearerToken(request) !== token) {
      return unauthorized();
    }
    return null;
  };

  server = Bun.serve({
    async fetch(request) {
      cleanupExpiredSessions();

      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/health") {
        return json({
          ok: true,
          running: true,
          startedAt,
        });
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
          const body = await readJson<{ password: string; ttlSeconds?: number }>(request);
          const ttlSeconds = body.ttlSeconds ?? 900;
          if (ttlSeconds <= 0 || ttlSeconds > 86400) {
            return json({ error: "Unlock ttl must be between 1 and 86400 seconds" }, 400);
          }

          const rootKey = unlockVaultRootKey(options.vaultPath, body.password);
          const sessionId = randomId();
          const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
          sessions.set(sessionId, {
            expiresAt,
            id: sessionId,
            rootKey,
            vaultPath: options.vaultPath,
          });

          return json({
            expiresAt,
            sessionId,
          });
        }

        if (request.method === "POST" && url.pathname === "/lock") {
          const body = await readJson<{ sessionId: string }>(request);
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

          const vaultSession = openSessionFromRootKey(session.rootKey, session.vaultPath);
          try {
            return json(vaultSession.renderEnv(body.mappings, body.leaseId));
          } finally {
            vaultSession.close();
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

          const vaultSession = openSessionFromRootKey(session.rootKey, session.vaultPath);
          try {
            return json(vaultSession.runExec(body));
          } finally {
            vaultSession.close();
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
    port: server.port,
    startedAt,
    token,
    vaultPath: options.vaultPath,
    version: 1,
  });

  const onSignal = (): void => {
    shutdown();
    process.exit(0);
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
  });
  const data = (await response.json()) as { error?: string };
  if (!response.ok) {
    throw new Error(data.error ?? `Daemon request failed: ${response.status}`);
  }
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

export async function daemonUnlock(options: DaemonClientOptions & { password: string; ttlSeconds?: number }): Promise<{ expiresAt: string; sessionId: string }> {
  const state = readDaemonState(options.statePath);
  if (!state) {
    throw new Error(`Daemon state not found: ${options.statePath}`);
  }
  return daemonRequest(state, "/unlock", {
    password: options.password,
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
    const result = await daemonRequest(state, "/shutdown", {});
    await waitForDaemonStateDeletion(options.statePath);
    return result;
  } catch (error) {
    if (await waitForDaemonStateDeletion(options.statePath)) {
      return { ok: true, stopped: true };
    }
    throw error;
  }
}

