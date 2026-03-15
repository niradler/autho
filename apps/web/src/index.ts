#!/usr/bin/env bun

import { randomBytes } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { AuthoDatabase } from "../../../packages/storage/src/index.ts";
import { unlockRootKey } from "../../../packages/crypto/src/index.ts";
import { VaultSession, defaultVaultPath } from "../../../packages/core/src/index.ts";

type SessionState = {
  expiresAt: string;
  rootKey: Buffer;
};

function parseArgs(argv: string[]): { options: Record<string, string | boolean>; positionals: string[] } {
  const options: Record<string, string | boolean> = {};
  const positionals: string[] = [];

  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }

    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      options[key] = true;
      continue;
    }

    options[key] = next;
    index += 1;
  }

  return { options, positionals };
}

function getString(options: Record<string, string | boolean>, key: string): string | undefined {
  const value = options[key];
  return typeof value === "string" ? value : undefined;
}

function json(data: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(JSON.stringify(data, null, 2), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(headers ?? {}),
    },
    status,
  });
}

function html(body: string): Response {
  return new Response(body, {
    headers: {
      "content-type": "text/html; charset=utf-8",
    },
  });
}

function parseCookies(request: Request): Record<string, string> {
  const cookieHeader = request.headers.get("cookie") ?? "";
  return Object.fromEntries(
    cookieHeader
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      }),
  );
}

function loadRootKey(vaultPath: string, password: string): Buffer {
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

function openSession(vaultPath: string, rootKey: Buffer): VaultSession {
  return new VaultSession(new AuthoDatabase(vaultPath), rootKey);
}

function requireSession(request: Request, sessions: Map<string, SessionState>): { id: string; rootKey: Buffer } {
  const cookies = parseCookies(request);
  const sessionId = cookies.autho_session;
  if (!sessionId) {
    throw new Error("Missing web session");
  }
  const session = sessions.get(sessionId);
  if (!session) {
    throw new Error("Unknown web session");
  }
  if (Date.parse(session.expiresAt) <= Date.now()) {
    sessions.delete(sessionId);
    throw new Error("Expired web session");
  }
  return { id: sessionId, rootKey: session.rootKey };
}

async function readJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

function page(): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Autho</title>
  <style>
    :root { color-scheme: light; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; background: #f5f1e8; color: #1f2937; }
    main { max-width: 760px; margin: 0 auto; padding: 32px 20px 64px; }
    section { background: #fffdf8; border: 1px solid #d6cbb8; border-radius: 16px; padding: 20px; margin-bottom: 16px; box-shadow: 0 8px 30px rgba(83,58,18,0.08); }
    h1 { margin-top: 0; font-size: 2rem; }
    input, select, button { font: inherit; padding: 10px 12px; border-radius: 10px; border: 1px solid #bca889; }
    button { background: #1f4d3a; color: white; border: none; cursor: pointer; }
    form { display: flex; gap: 8px; flex-wrap: wrap; }
    pre { background: #1f2937; color: #f9fafb; padding: 12px; border-radius: 12px; overflow: auto; }
    ul { padding-left: 18px; }
  </style>
</head>
<body>
  <main>
    <section>
      <h1>Autho Local Web</h1>
      <p>Local-only Bun web UI for vault unlock and secret browsing.</p>
      <form id="unlock-form">
        <input id="password" type="password" placeholder="Master password" required />
        <button type="submit">Unlock</button>
      </form>
    </section>
    <section>
      <h2>Secrets</h2>
      <button id="refresh">Refresh</button>
      <ul id="secret-list"></ul>
      <pre id="output"></pre>
    </section>
  </main>
  <script>
    const output = document.getElementById('output');
    const secretList = document.getElementById('secret-list');
    async function refresh() {
      const response = await fetch('/api/secrets');
      if (!response.ok) {
        output.textContent = await response.text();
        return;
      }
      const data = await response.json();
      secretList.innerHTML = '';
      data.data.forEach((secret) => {
        const item = document.createElement('li');
        item.textContent = secret.name + " (" + secret.type + ")";
        secretList.appendChild(item);
      });
      output.textContent = JSON.stringify(data, null, 2);
    }
    document.getElementById('unlock-form').addEventListener('submit', async (event) => {
      event.preventDefault();
      const response = await fetch('/api/session/unlock', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ password: document.getElementById('password').value })
      });
      output.textContent = await response.text();
      if (response.ok) {
        await refresh();
      }
    });
    document.getElementById('refresh').addEventListener('click', refresh);
  </script>
</body>
</html>`;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  const [command] = args.positionals;
  if (command !== "serve") {
    throw new Error("Web server supports only: serve");
  }

  const vaultPath = resolve(getString(args.options, "vault") ?? defaultVaultPath());
  const host = getString(args.options, "host") ?? "127.0.0.1";
  const port = Number(getString(args.options, "port") ?? "8061");
  const sessions = new Map<string, SessionState>();

  const cleanup = () => {
    for (const [id, session] of sessions.entries()) {
      if (Date.parse(session.expiresAt) <= Date.now()) {
        sessions.delete(id);
      }
    }
  };

  const server = Bun.serve({
    fetch: async (request) => {
      cleanup();
      const url = new URL(request.url);

      try {
        if (request.method === "GET" && url.pathname === "/health") {
          return json({ ok: true, running: true, vaultPath });
        }

        if (request.method === "GET" && url.pathname === "/") {
          return html(page());
        }

        if (request.method === "POST" && url.pathname === "/api/session/unlock") {
          const body = await readJson<{ password: string; ttlSeconds?: number }>(request);
          const ttlSeconds = body.ttlSeconds ?? 3600;
          if (ttlSeconds <= 0 || ttlSeconds > 86400) {
            return json({ error: "Session TTL must be between 1 and 86400 seconds" }, 400);
          }
          const rootKey = loadRootKey(vaultPath, body.password);
          const sessionId = randomBytes(16).toString("hex");
          const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
          sessions.set(sessionId, { expiresAt, rootKey });
          return json(
            { expiresAt, sessionId },
            200,
            { "set-cookie": `autho_session=${sessionId}; HttpOnly; SameSite=Strict; Path=/; Secure` },
          );
        }

        if (request.method === "POST" && url.pathname === "/api/session/lock") {
          const cookies = parseCookies(request);
          if (cookies.autho_session) {
            sessions.delete(cookies.autho_session);
          }
          return json({ locked: true }, 200, { "set-cookie": "autho_session=; Max-Age=0; Path=/; Secure" });
        }

        if (url.pathname.startsWith("/api/")) {
          const webSession = requireSession(request, sessions);
          const session = openSession(vaultPath, webSession.rootKey);
          try {
            if (request.method === "GET" && url.pathname === "/api/status") {
              return json({
                initialized: true,
                secretCount: session.listSecrets().length,
                unlocked: true,
                vaultPath,
              });
            }

            if (request.method === "GET" && url.pathname === "/api/secrets") {
              return json({ data: session.listSecrets() });
            }

            if (request.method === "GET" && url.pathname.startsWith("/api/secrets/")) {
              const ref = decodeURIComponent(url.pathname.slice("/api/secrets/".length));
              return json({ data: session.getSecret(ref) });
            }

            if (request.method === "POST" && url.pathname === "/api/secrets") {
              const body = await readJson<{
                algorithm?: string;
                description?: string;
                digits?: number;
                name: string;
                type: string;
                url?: string;
                username?: string;
                value: string;
              }>(request);
              return json({
                data: session.addSecret({
                  metadata: Object.fromEntries(
                    Object.entries({
                      algorithm: body.algorithm,
                      description: body.description,
                      digits: body.digits,
                      url: body.url,
                    }).filter(([, value]) => value !== undefined),
                  ),
                  name: body.name,
                  type: body.type,
                  username: body.username,
                  value: body.value,
                }),
              }, 201);
            }

            if (request.method === "DELETE" && url.pathname.startsWith("/api/secrets/")) {
              const ref = decodeURIComponent(url.pathname.slice("/api/secrets/".length));
              return json({ data: session.removeSecret(ref) });
            }

            if (request.method === "GET" && url.pathname.startsWith("/api/otp/")) {
              const ref = decodeURIComponent(url.pathname.slice("/api/otp/".length));
              return json({ data: session.generateOtp(ref) });
            }
          } finally {
            session.close();
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        const status = /session/i.test(message) ? 401 : 400;
        return json({ error: message }, status);
      }

      return json({ error: "Not found" }, 404);
    },
    hostname: host,
    port,
  });

  process.on("SIGINT", () => process.exit(0));
  process.on("SIGTERM", () => process.exit(0));

  console.log(`Autho web server listening on http://${host}:${server.port}`);
  await new Promise(() => {});
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

