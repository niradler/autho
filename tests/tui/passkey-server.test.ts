import { afterEach, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";

import { newPrfSalt, startCeremonyServer, type CeremonyServer } from "../../apps/cli/src/passkey.ts";

let server: CeremonyServer | null = null;

afterEach(() => {
  server?.close();
  server = null;
});

const credentialId = randomBytes(16).toString("base64url");
const prfOutput = randomBytes(32).toString("base64url");

function start() {
  server = startCeremonyServer({ mode: "authenticate", credentials: [{ credentialId, prfSalt: newPrfSalt() }] }, { timeoutMs: 10_000 });
  const url = new URL(server.url);
  return { server, url, origin: url.origin };
}

const post = (url: string, body: unknown, origin: string) =>
  fetch(url, { method: "POST", headers: { "content-type": "application/json", origin }, body: JSON.stringify(body) });

test("serves the page only with the token, on localhost", async () => {
  const { server, url } = start();
  const res = await fetch(server.url);
  expect(res.status).toBe(200);
  expect(res.headers.get("content-security-policy")).toContain("script-src 'nonce-");
  expect(await res.text()).toContain(credentialId);

  expect((await fetch(`${url.origin}/wrong-token`)).status).toBe(404);
  // Any host other than localhost:port is refused (DNS rebinding).
  expect((await fetch(server.url.replace("localhost", "127.0.0.1"))).status).toBe(403);
});

test("rejects posts from another origin or with bad data", async () => {
  const { server, origin } = start();
  expect((await post(`${server.url}/result`, { credentialId, prfOutput }, "http://evil.example")).status).toBe(403);
  expect((await post(`${server.url}/result`, { credentialId, prfOutput: "short" }, origin)).status).toBe(400);
  expect((await post(`${server.url}/result`, { credentialId: "unknown", prfOutput }, origin)).status).toBe(400);
});

test("accepts one result and refuses reuse", async () => {
  const { server, origin } = start();
  const res = await post(`${server.url}/result`, { credentialId, prfOutput, transports: ["usb", "<bad>"] }, origin);
  expect(res.status).toBe(200);
  expect(await server.result).toEqual({ credentialId, prfOutput, transports: ["usb"] });
  const again = await post(`${server.url}/result`, { credentialId, prfOutput }, origin).catch(() => null);
  // Either refused or already shut down — never accepted twice.
  if (again) expect(again.status).toBe(410);
});

test("browser errors reject the ceremony", async () => {
  const { server, origin } = start();
  await post(`${server.url}/error`, { message: "no PRF" }, origin);
  await expect(server.result).rejects.toThrow("no PRF");
});

test("times out", async () => {
  server = startCeremonyServer({ mode: "register", userName: "autho", excludeCredentialIds: [], prfSalt: newPrfSalt() }, { timeoutMs: 50 });
  await expect(server.result).rejects.toThrow("Timed out");
});
