import { describe, expect, test } from "bun:test";

import type { VaultAdmin } from "../../packages/core/src/index.ts";
import { allowedHosts, sameOrigin, tokensEqual, UnlockThrottle, withNonce } from "../../apps/web/src/security.ts";
import { createWebServer } from "../../apps/web/src/server.ts";
import { ADMIN_TTL_MS, MAX_SESSION_MS, SessionStore } from "../../apps/web/src/sessions.ts";

function clock(start = 1_000_000) {
  const state = { now: start };
  return { advance: (ms: number) => { state.now += ms; }, now: () => state.now };
}

function store(idleMs = 60_000) {
  const time = clock();
  const released: VaultAdmin[] = [];
  const sessions = new SessionStore({ idleMs: () => idleMs, now: time.now, onAdminEnd: (handle) => released.push(handle) });
  return { released, sessions, time };
}

const fakeAdmin = () => ({}) as VaultAdmin;

describe("SessionStore", () => {
  test("touch needs the matching CSRF token", () => {
    const { sessions } = store();
    const session = sessions.create(Buffer.alloc(32, 7), false);
    expect(sessions.touch(session.id, null)).toBeNull();
    expect(sessions.touch(session.id, "wrong")).toBeNull();
    expect(sessions.touch(undefined, session.csrf)).toBeNull();
    expect(sessions.touch(session.id, session.csrf)).toBe(session);
  });

  test("idle sessions end and their root key is zeroed", () => {
    const { sessions, time } = store(60_000);
    const key = Buffer.alloc(32, 7);
    const session = sessions.create(key, false);
    time.advance(59_000);
    expect(sessions.touch(session.id, session.csrf)).toBe(session);
    time.advance(59_000);
    expect(sessions.touch(session.id, session.csrf)).toBe(session);
    time.advance(60_000);
    expect(sessions.touch(session.id, session.csrf)).toBeNull();
    expect(key.every((byte) => byte === 0)).toBe(true);
    expect(sessions.size).toBe(0);
  });

  test("the hard cap ends even an active session", () => {
    const { sessions, time } = store(0);
    const session = sessions.create(Buffer.alloc(32, 7), false);
    expect(sessions.expiresAt(session).idleAt).toBeNull();
    time.advance(MAX_SESSION_MS - 1);
    expect(sessions.touch(session.id, session.csrf)).toBe(session);
    time.advance(1);
    expect(sessions.touch(session.id, session.csrf)).toBeNull();
  });

  test("admin grants expire and are released", () => {
    const { released, sessions, time } = store(0);
    const session = sessions.create(Buffer.alloc(32, 7), false);
    const handle = fakeAdmin();
    sessions.grantAdmin(session, handle);
    session.pendingTotp = { secret: "s", uri: "u" };
    expect(sessions.admin(session)).toBe(handle);
    time.advance(ADMIN_TTL_MS);
    expect(sessions.admin(session)).toBeNull();
    expect(released).toEqual([handle]);
    expect(session.pendingTotp).toBeNull();
  });

  test("ending a session releases its admin handle", () => {
    const { released, sessions } = store();
    const key = Buffer.alloc(32, 7);
    const session = sessions.create(key, false);
    const handle = fakeAdmin();
    sessions.grantAdmin(session, handle);
    sessions.endAll();
    expect(released).toEqual([handle]);
    expect(key.every((byte) => byte === 0)).toBe(true);
  });
});

describe("UnlockThrottle", () => {
  test("allows a few misses, then backs off exponentially, and resets on success", () => {
    const time = clock();
    const throttle = new UnlockThrottle(3, 10_000, time.now);
    throttle.fail();
    throttle.fail();
    expect(throttle.retryAfterMs()).toBe(0);
    throttle.fail();
    expect(throttle.retryAfterMs()).toBe(1000);
    throttle.fail();
    expect(throttle.retryAfterMs()).toBe(2000);
    for (let i = 0; i < 10; i++) throttle.fail();
    expect(throttle.retryAfterMs()).toBe(10_000);
    time.advance(10_000);
    expect(throttle.retryAfterMs()).toBe(0);
    throttle.succeed();
    throttle.fail();
    expect(throttle.retryAfterMs()).toBe(0);
  });

  test("only one attempt runs at a time, so parallel guesses can't race the backoff", () => {
    const time = clock();
    const throttle = new UnlockThrottle(1, 10_000, time.now);
    expect(throttle.begin()).toBe(true);
    expect(throttle.begin()).toBe(false);
    throttle.fail();
    expect(throttle.begin()).toBe(false);
    time.advance(1000);
    expect(throttle.begin()).toBe(true);
    throttle.succeed();
    expect(throttle.begin()).toBe(true);
  });
});

describe("request checks", () => {
  const hosts = allowedHosts(4000);
  const request = (headers: Record<string, string>) => new Request("http://localhost:4000/api/x", { headers });

  test("same-origin needs Origin to match the Host it was sent to", () => {
    expect(sameOrigin(request({ host: "localhost:4000", origin: "http://localhost:4000" }), hosts)).toBe(true);
    expect(sameOrigin(request({ host: "localhost:4000", origin: "http://127.0.0.1:4000" }), hosts)).toBe(false);
    expect(sameOrigin(request({ host: "localhost:4000", origin: "http://localhost:4001" }), hosts)).toBe(false);
    expect(sameOrigin(request({ host: "localhost:4000", origin: "null" }), hosts)).toBe(false);
    expect(sameOrigin(request({ host: "localhost:4000", "sec-fetch-site": "same-site" }), hosts)).toBe(false);
    expect(sameOrigin(request({ host: "localhost:4000", "sec-fetch-site": "same-origin" }), hosts)).toBe(true);
  });

  test("tokens compare by value and length", () => {
    expect(tokensEqual("abc", "abc")).toBe(true);
    expect(tokensEqual("abd", "abc")).toBe(false);
    expect(tokensEqual("ab", "abc")).toBe(false);
    expect(tokensEqual(null, "abc")).toBe(false);
  });

  test("every inline script gets the nonce", () => {
    expect(withNonce('<script type="module">a</script><script>b</script><scripts>', "n1")).toBe(
      '<script nonce="n1" type="module">a</script><script nonce="n1">b</script><scripts>',
    );
  });
});

describe("bind address", () => {
  test("only loopback, unless the container image allows all interfaces", async () => {
    const previous = { container: process.env.AUTHO_WEB_CONTAINER, exposed: process.env.AUTHO_WEB_PUBLIC_PORT };
    try {
      delete process.env.AUTHO_WEB_CONTAINER;
      expect(() => createWebServer({ host: "0.0.0.0", port: 0 })).toThrow(/refusing --host 0.0.0.0/);
      process.env.AUTHO_WEB_CONTAINER = "1";
      expect(() => createWebServer({ host: "192.168.1.5", port: 0 })).toThrow(/refusing/);

      process.env.AUTHO_WEB_PUBLIC_PORT = "18999";
      const server = createWebServer({ host: "0.0.0.0", port: 0 });
      try {
        expect(server.url).toBe("http://localhost:18999");
        const at = (host: string) => fetch(`http://127.0.0.1:${server.port}/health`, { headers: { host } });
        expect((await at(`localhost:${server.port}`)).status).toBe(200);
        expect((await at("localhost:18999")).status).toBe(200);
        expect((await at("evil.example:18999")).status).toBe(421);
      } finally {
        server.stop();
      }
    } finally {
      if (previous.container === undefined) delete process.env.AUTHO_WEB_CONTAINER;
      else process.env.AUTHO_WEB_CONTAINER = previous.container;
      if (previous.exposed === undefined) delete process.env.AUTHO_WEB_PUBLIC_PORT;
      else process.env.AUTHO_WEB_PUBLIC_PORT = previous.exposed;
    }
  });
});
