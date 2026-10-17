import { resolve } from "node:path";

import { defaultVaultPath, numberPreference } from "../../../packages/core/src/index.ts";
import { HttpError, matchRoute, type ApiContext } from "./api.ts";
import {
  CSRF_HEADER,
  REQUEST_HEADER,
  UnlockThrottle,
  allowedHosts,
  hostAllowed,
  isLoopbackHost,
  newToken,
  pageCsp,
  sameOrigin,
  securityHeaders,
  withNonce,
} from "./security.ts";
import { SessionStore, type WebSession } from "./sessions.ts";
import { UI_HTML } from "./ui.generated.ts";

export type WebServerOptions = {
  host?: string;
  port?: number;
  vaultPath?: string;
};

export type WebServer = {
  port: number;
  url: string;
  stop(): void;
};

const MAX_BODY = 64 * 1024;
/** Legacy JSON imports can be large. */
const MAX_IMPORT_BODY = 8 * 1024 * 1024;
const SWEEP_MS = 15_000;

function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    headers: securityHeaders({ "content-type": "application/json; charset=utf-8", ...headers }),
    status,
  });
}

function cookieValue(request: Request, name: string): string | undefined {
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return undefined;
}

async function readBody(request: Request, limit: number): Promise<Record<string, unknown>> {
  if (request.method === "GET" || request.method === "HEAD") return {};
  const length = Number(request.headers.get("content-length") ?? 0);
  if (length > limit) throw new HttpError(413, "Request is too large");
  const text = await request.text();
  if (text === "") return {};
  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "Send JSON");
  }
  if (Buffer.byteLength(text) > limit) throw new HttpError(413, "Request is too large");
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "Malformed JSON");
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new HttpError(400, "Send a JSON object");
  return parsed as Record<string, unknown>;
}

/** Vault errors are plain Errors; map the common ones to a fitting status. */
function errorStatus(error: unknown): { status: number; message: string } {
  if (error instanceof HttpError) return { status: error.status, message: error.message };
  const message = error instanceof Error ? error.message : String(error);
  if (error instanceof Error && error.name === "VaultTamperedError") return { status: 409, message };
  if (/not found/i.test(message)) return { status: 404, message };
  return { status: 400, message };
}

/**
 * Inside a container "localhost" is the container itself, so the image sets
 * AUTHO_WEB_CONTAINER=1 to allow binding all interfaces there. Requests must
 * still be addressed to localhost, so the port should only be published on the
 * host's loopback (`-p 127.0.0.1:8061:8061`).
 */
function bindAllowed(host: string): boolean {
  if (isLoopbackHost(host)) return true;
  return process.env.AUTHO_WEB_CONTAINER === "1" && (host === "0.0.0.0" || host === "::");
}

/** The port the browser sees when a container publishes ours on another one (`-p 127.0.0.1:9000:8061`). */
function publicPort(): number | null {
  const value = Number(process.env.AUTHO_WEB_PUBLIC_PORT);
  return Number.isInteger(value) && value > 0 && value < 65536 ? value : null;
}

export function createWebServer(options: WebServerOptions = {}): WebServer {
  const host = options.host ?? "localhost";
  if (!bindAllowed(host)) {
    throw new Error(`The web UI only listens on this machine (localhost); refusing --host ${host}`);
  }
  const vaultPath = resolve(options.vaultPath ?? defaultVaultPath());
  const requestedPort = options.port ?? numberPreference("webPort");

  const sessions = new SessionStore({
    idleMs: () => numberPreference("idleLockSeconds") * 1000,
    onAdminEnd: (handle) => handle.close(),
  });
  const ctx: ApiContext = { sessions, throttle: new UnlockThrottle(), vaultPath };
  let hosts = allowedHosts(requestedPort);
  let cookieName = `autho_session_${requestedPort}`;

  function sessionCookie(session: WebSession | null): string {
    const base = `${cookieName}=${session?.id ?? ""}; Path=/; HttpOnly; SameSite=Strict`;
    return session ? base : `${base}; Max-Age=0`;
  }

  function page(): Response {
    const nonce = newToken(16);
    return new Response(withNonce(UI_HTML, nonce), {
      headers: securityHeaders({ "content-security-policy": pageCsp(nonce), "content-type": "text/html; charset=utf-8" }),
    });
  }

  async function api(request: Request, url: URL): Promise<Response> {
    if (!sameOrigin(request, hosts) || request.headers.get(REQUEST_HEADER) !== "1") {
      return json({ error: "Cross-origin request refused" }, 403);
    }
    const match = matchRoute(request.method, url.pathname);
    if (match === null) return json({ error: "Not found" }, 404);
    if (match === "method") return json({ error: "Method not allowed" }, 405);

    const sessionId = cookieValue(request, cookieName);
    const session = sessions.touch(sessionId, request.headers.get(CSRF_HEADER));
    if (match.route.auth && !session) {
      return json({ error: "Locked" }, 401, { "set-cookie": sessionCookie(null) });
    }

    try {
      const body = await readBody(request, url.pathname === "/api/import" ? MAX_IMPORT_BODY : MAX_BODY);
      const reply = await match.route.handler(ctx, { body, params: match.params, query: url.searchParams, session });
      const headers: Record<string, string> = {};
      // Lock and a fresh unlock end whatever session this browser's cookie names, even
      // without its CSRF token (another tab, a reload): a session nobody can reach must
      // not keep its root key alive. Ending a session is the only thing the cookie alone can do.
      if (reply.session === "ended") {
        sessions.end(sessionId);
        headers["set-cookie"] = sessionCookie(null);
      } else if (reply.session) {
        sessions.end(sessionId);
        headers["set-cookie"] = sessionCookie(reply.session);
      }
      return json({ data: reply.data }, reply.status ?? 200, headers);
    } catch (error) {
      const { status, message } = errorStatus(error);
      return json({ error: message }, status, error instanceof HttpError ? error.headers : {});
    }
  }

  async function fetch(request: Request): Promise<Response> {
    if (!hostAllowed(request, hosts)) {
      return new Response("Unknown host", { headers: securityHeaders({ "content-type": "text/plain" }), status: 421 });
    }
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, url);
    if (request.method !== "GET" && request.method !== "HEAD") return json({ error: "Method not allowed" }, 405);
    if (url.pathname === "/health") return json({ ok: true });
    if (url.pathname === "/" || url.pathname === "/index.html") return page();
    return json({ error: "Not found" }, 404);
  }

  // Passkeys are bound to "localhost", which resolves to either address family; serve both on one port.
  const servers: ReturnType<typeof Bun.serve>[] = [];
  const primaryHost = host === "localhost" ? "127.0.0.1" : host;
  const serveOptions = {
    fetch,
    // Unexpected failures (vault I/O, bugs) get a plain message, never Bun's stack-trace page.
    error: () => json({ error: "Internal error" }, 500),
    // Refuse oversized bodies at the socket, including chunked ones with no Content-Length.
    maxRequestBodySize: MAX_IMPORT_BODY + 1024,
  };
  servers.push(Bun.serve({ ...serveOptions, hostname: primaryHost, port: requestedPort }));
  const port = servers[0]!.port!;
  if (host === "localhost") {
    try {
      servers.push(Bun.serve({ ...serveOptions, hostname: "::1", port }));
    } catch {
      // No IPv6 loopback here: 127.0.0.1 is enough.
    }
  }
  const exposed = publicPort();
  hosts = exposed === null ? allowedHosts(port) : new Set([...allowedHosts(port), ...allowedHosts(exposed)]);
  cookieName = `autho_session_${port}`;

  const sweeper = setInterval(() => sessions.sweep(), SWEEP_MS);
  sweeper.unref?.();

  return {
    port,
    url: `http://localhost:${exposed ?? port}`,
    stop() {
      clearInterval(sweeper);
      sessions.endAll();
      for (const server of servers) server.stop(true);
    },
  };
}

export async function startWebServer(options: WebServerOptions = {}): Promise<void> {
  const server = createWebServer(options);
  const shutdown = () => {
    server.stop();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  console.log(`Autho web UI: ${server.url}`);
  console.log("Open it with \"localhost\" (not 127.0.0.1) so passkeys work. Ctrl+C stops it and locks the vault.");
  await new Promise(() => {});
}
