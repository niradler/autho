import { randomBytes, timingSafeEqual } from "node:crypto";

import { openUrl } from "./tui/util.ts";

/**
 * WebAuthn needs a browser, so passkey and security-key ceremonies run on a
 * one-shot loopback page. The browser derives a PRF (hmac-secret) value on the
 * authenticator; that value — never stored — unwraps the vault root key.
 * We do not verify signatures: decryption with the PRF output proves possession.
 */

export type RegisterRequest = {
  mode: "register";
  /** Shown by the authenticator, e.g. "autho (vault.db)". */
  userName: string;
  /** Credential ids already registered, so the same key isn't added twice. */
  excludeCredentialIds: string[];
  /** base64url, at least 16 bytes. Stored with the passkey. */
  prfSalt: string;
};

export type AuthenticateRequest = {
  mode: "authenticate";
  credentials: { credentialId: string; prfSalt: string; transports?: string[] }[];
};

export type CeremonyRequest = RegisterRequest | AuthenticateRequest;

export type CeremonyResult = { credentialId: string; prfOutput: string; transports?: string[] };

export type CeremonyServer = {
  url: string;
  result: Promise<CeremonyResult>;
  close: () => void;
};

const RP_ID = "localhost";
const B64URL = /^[A-Za-z0-9_-]+$/;

export function newPrfSalt(): string {
  return randomBytes(32).toString("base64url");
}

/** Starts the loopback server. The URL carries a one-time token; the page is single-use. */
export function startCeremonyServer(request: CeremonyRequest, options: { timeoutMs?: number; signal?: AbortSignal } = {}): CeremonyServer {
  const token = randomBytes(32).toString("base64url");
  const tokenBytes = Buffer.from(token);
  let settled = false;
  let resolve!: (value: CeremonyResult) => void;
  let reject!: (error: Error) => void;
  const result = new Promise<CeremonyResult>((res, rej) => { resolve = res; reject = rej; });
  // Callers may never await (e.g. tests that only probe the server).
  result.catch(() => {});

  const servers: ReturnType<typeof Bun.serve>[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;

  const close = () => {
    if (timer) clearTimeout(timer);
    for (const server of servers.splice(0)) server.stop(true);
  };
  const finish = (outcome: { ok: CeremonyResult } | { error: Error }) => {
    if (settled) return;
    settled = true;
    // Let the response flush before tearing the servers down.
    setTimeout(close, 50);
    if ("ok" in outcome) resolve(outcome.ok);
    else reject(outcome.error);
  };

  const fetch = async (req: Request, server: { port?: number }): Promise<Response> => {
    const origin = `http://${RP_ID}:${server.port}`;
    const url = new URL(req.url);
    // Host check blocks DNS rebinding; the token blocks other local pages.
    if (req.headers.get("host") !== `${RP_ID}:${server.port}`) return text(403, "Forbidden");
    const [, first, action, ...rest] = url.pathname.split("/");
    if (!first || rest.length > 0 || !sameToken(first, tokenBytes)) return text(404, "Not found");

    if (req.method === "GET" && action === undefined) {
      if (settled) return text(410, "This link has already been used. Run the autho command again.");
      return page(request, `/${token}`);
    }
    if (req.method !== "POST" || (action !== "result" && action !== "error")) return text(404, "Not found");
    if (req.headers.get("origin") !== origin) return text(403, "Forbidden");
    if (settled) return text(410, "Gone");

    let body: unknown;
    try {
      body = await req.json();
    } catch {
      return text(400, "Bad request");
    }
    if (action === "error") {
      const message = typeof (body as { message?: unknown })?.message === "string" ? (body as { message: string }).message : "Passkey ceremony failed";
      finish({ error: new Error(message.slice(0, 300)) });
      return text(200, "ok");
    }
    const parsed = parseResult(body, request);
    if (!parsed) return text(400, "Bad request");
    finish({ ok: parsed });
    return text(200, "ok");
  };

  servers.push(Bun.serve({ hostname: "127.0.0.1", port: 0, fetch }));
  const port = servers[0]!.port;
  try {
    // Some systems resolve localhost to ::1 first; serve both on the same port.
    servers.push(Bun.serve({ hostname: "::1", port, fetch }));
  } catch {
    // IPv6 loopback unavailable: IPv4 alone is fine.
  }

  const timeoutMs = options.timeoutMs ?? 180_000;
  timer = setTimeout(() => finish({ error: new Error("Timed out waiting for the browser") }), timeoutMs);
  if (options.signal?.aborted) finish({ error: new Error("Cancelled") });
  options.signal?.addEventListener("abort", () => finish({ error: new Error("Cancelled") }), { once: true });

  return { url: `http://${RP_ID}:${port}/${token}`, result, close };
}

/** Opens the browser (or prints the link) and waits for the authenticator. */
export async function runPasskeyCeremony(
  request: CeremonyRequest,
  options: { onUrl?: (url: string, opened: boolean) => void; timeoutMs?: number; open?: (url: string) => boolean; signal?: AbortSignal } = {},
): Promise<CeremonyResult> {
  const server = startCeremonyServer(request, { timeoutMs: options.timeoutMs, signal: options.signal });
  try {
    const opened = (options.open ?? openUrl)(server.url);
    options.onUrl?.(server.url, opened);
    return await server.result;
  } finally {
    server.close();
  }
}

function sameToken(candidate: string, expected: Buffer): boolean {
  const bytes = Buffer.from(candidate);
  return bytes.length === expected.length && timingSafeEqual(bytes, expected);
}

function parseResult(body: unknown, request: CeremonyRequest): CeremonyResult | null {
  if (!body || typeof body !== "object") return null;
  const { credentialId, prfOutput, transports } = body as Record<string, unknown>;
  if (typeof credentialId !== "string" || !B64URL.test(credentialId) || credentialId.length > 1400) return null;
  if (typeof prfOutput !== "string" || Buffer.from(prfOutput, "base64url").length !== 32) return null;
  if (request.mode === "authenticate" && !request.credentials.some((c) => c.credentialId === credentialId)) return null;
  const cleanTransports = Array.isArray(transports)
    ? transports.filter((t): t is string => typeof t === "string" && /^[a-z-]{1,20}$/.test(t)).slice(0, 8)
    : undefined;
  return { credentialId, prfOutput, transports: cleanTransports };
}

function text(status: number, body: string): Response {
  return new Response(body, { status, headers: { "cache-control": "no-store", "content-type": "text/plain; charset=utf-8" } });
}

function page(request: CeremonyRequest, base: string): Response {
  const nonce = randomBytes(16).toString("base64");
  const options = request.mode === "register"
    ? { mode: "register", rpId: RP_ID, userId: randomBytes(16).toString("base64url"), userName: request.userName, exclude: request.excludeCredentialIds, prfSalt: request.prfSalt }
    : { mode: "authenticate", rpId: RP_ID, credentials: request.credentials };
  // JSON in a <script type=application/json> block: escape "<" so it can't close the tag.
  const json = JSON.stringify(options).replace(/</g, "\\u003c");
  const title = request.mode === "register" ? "Add a passkey to autho" : "Unlock autho";
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style nonce="${nonce}">
body{font:16px/1.5 system-ui,sans-serif;background:#0f1117;color:#e6e6e6;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px;box-sizing:border-box}
main{max-width:420px;width:100%;text-align:center}
h1{font-size:20px;margin:0 0 8px}
p{color:#9aa0aa;margin:0 0 20px}
button{font:inherit;background:#7aa2f7;color:#0f1117;border:0;border-radius:8px;padding:10px 20px;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
#status{margin-top:20px;min-height:3em}
.ok{color:#9ece6a}.err{color:#f7768e}
</style></head>
<body><main>
<h1>${title}</h1>
<p>${request.mode === "register" ? "Use a passkey or plug in your security key. It must support the PRF (hmac-secret) extension." : "Use the passkey or security key you registered with this vault."}</p>
<button id="go" autofocus>Continue</button>
<div id="status" role="status"></div>
</main>
<script type="application/json" id="opts">${json}</script>
<script nonce="${nonce}">
(() => {
  const opts = JSON.parse(document.getElementById("opts").textContent);
  const base = ${JSON.stringify(base)};
  const status = document.getElementById("status");
  const button = document.getElementById("go");
  const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4)), (c) => c.charCodeAt(0));
  const challenge = () => crypto.getRandomValues(new Uint8Array(32));
  const show = (message, cls) => { status.textContent = message; status.className = cls || ""; };
  const post = (path, body) => fetch(base + "/" + path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const noPrf = "This browser or authenticator does not support the PRF extension needed to encrypt the vault. Try a recent Chrome, Edge or Safari, or a FIDO2 security key.";

  async function register() {
    const salt = unb64(opts.prfSalt);
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: opts.rpId, name: "autho" },
      user: { id: unb64(opts.userId), name: opts.userName, displayName: opts.userName },
      challenge: challenge(),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { userVerification: "required", residentKey: "preferred" },
      attestation: "none",
      timeout: 120000,
      excludeCredentials: opts.exclude.map((id) => ({ type: "public-key", id: unb64(id) })),
      extensions: { prf: { eval: { first: salt } } },
    } });
    const ext = cred.getClientExtensionResults();
    if (!ext.prf || ext.prf.enabled === false) throw new Error(noPrf);
    let out = ext.prf.results && ext.prf.results.first;
    if (!out) {
      // Many authenticators only evaluate the PRF during an assertion.
      show("One more touch to finish setting up…");
      const assertion = await navigator.credentials.get({ publicKey: {
        rpId: opts.rpId, challenge: challenge(), userVerification: "required", timeout: 120000,
        allowCredentials: [{ type: "public-key", id: cred.rawId }],
        extensions: { prf: { eval: { first: salt } } },
      } });
      const r = assertion.getClientExtensionResults().prf;
      out = r && r.results && r.results.first;
    }
    if (!out) throw new Error(noPrf);
    const transports = cred.response.getTransports ? cred.response.getTransports() : [];
    return { credentialId: b64(cred.rawId), prfOutput: b64(out), transports };
  }

  async function authenticate() {
    const byCred = {};
    for (const c of opts.credentials) byCred[c.credentialId] = { first: unb64(c.prfSalt) };
    const assertion = await navigator.credentials.get({ publicKey: {
      rpId: opts.rpId, challenge: challenge(), userVerification: "required", timeout: 120000,
      allowCredentials: opts.credentials.map((c) => ({ type: "public-key", id: unb64(c.credentialId), transports: c.transports })),
      extensions: { prf: { evalByCredential: byCred } },
    } });
    const r = assertion.getClientExtensionResults().prf;
    const out = r && r.results && r.results.first;
    if (!out) throw new Error(noPrf);
    return { credentialId: b64(assertion.rawId), prfOutput: b64(out) };
  }

  button.addEventListener("click", async () => {
    button.disabled = true;
    show("Waiting for your passkey or security key…");
    try {
      if (!window.PublicKeyCredential) throw new Error("This browser does not support passkeys.");
      const result = opts.mode === "register" ? await register() : await authenticate();
      const res = await post("result", result);
      if (!res.ok) throw new Error("autho rejected the response (" + res.status + ").");
      show("Done — you can close this tab and return to the terminal.", "ok");
    } catch (e) {
      const message = e && e.name === "NotAllowedError" ? "Cancelled or timed out. Press Continue to try again." : (e && e.message) || String(e);
      show(message, "err");
      if (e && e.name === "NotAllowedError") { button.disabled = false; return; }
      post("error", { message }).catch(() => {});
    }
  });
})();
</script>
</body></html>`;
  return new Response(html, {
    headers: {
      "cache-control": "no-store",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
      "content-type": "text/html; charset=utf-8",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
    },
  });
}
