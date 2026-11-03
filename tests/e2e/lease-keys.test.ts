import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Database } from "bun:sqlite";
import { afterAll, beforeAll, expect, test } from "bun:test";

import { VaultService } from "../../packages/core/src/index.ts";

const directory = mkdtempSync(join(tmpdir(), "autho-agent-flow-"));
const vaultPath = join(directory, "vault.db");
const statePath = join(directory, "daemon.json");
const password = "isolated-owner-password";
const baseEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("AUTHO_")));
const env = { ...baseEnv, AUTHO_HOME: directory, AUTHO_DISABLE_OS_SECRETS: "1" };
let daemon: ReturnType<typeof Bun.spawn>;
let port: number;
let adminToken: string;

function cli(args: string[], extraEnv: Record<string, string> = {}) {
  const child = Bun.spawnSync(["bun", "--no-env-file", "run", "apps/cli/src/index.ts", ...args, "--state-file", statePath], {
    cwd: join(import.meta.dir, "../.."), env: { ...env, ...extraEnv }, stdout: "pipe", stderr: "pipe", timeout: 10_000,
  });
  return { code: child.exitCode, stdout: child.stdout.toString(), stderr: child.stderr.toString() };
}

async function start(): Promise<void> {
  daemon = Bun.spawn(["bun", "--no-env-file", "run", "apps/daemon/src/index.ts", "serve", "--vault", vaultPath, "--state-file", statePath], {
    cwd: join(import.meta.dir, "../.."), env, stdout: "pipe", stderr: "pipe",
  });
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    if (existsSync(statePath)) {
      const state = JSON.parse(readFileSync(statePath, "utf8")) as { port: number; token: string };
      try {
        if ((await fetch(`http://127.0.0.1:${state.port}/health`)).ok && existsSync(`${statePath}.endpoint.json`)) {
          port = state.port; adminToken = state.token; return;
        }
      } catch { /* Wait for readiness. */ }
    }
    await Bun.sleep(25);
  }
  throw new Error("Daemon did not become ready");
}

async function request(path: string, key: string, body: unknown = {}): Promise<Response> {
  return fetch(`http://127.0.0.1:${port}${path}`, {
    method: "POST", headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body), signal: AbortSignal.timeout(5000),
  });
}

async function issue(ttlSeconds = 60) {
  const response = await request("/lease/issue", adminToken, {
    credentials: { password }, name: "agent", secretRefs: ["github", "otp"], ttlSeconds,
  });
  expect(response.status).toBe(200);
  return await response.json() as { id: string; leaseKey: string; expiresAt: string };
}

beforeAll(async () => {
  VaultService.initialize(vaultPath, password);
  const owner = VaultService.unlock(vaultPath, password);
  owner.addSecret({ name: "github", type: "password", value: "scoped-github-value" });
  owner.addSecret({ name: "private", type: "note", value: "never-approved-value" });
  owner.addSecret({ name: "otp", type: "otp", value: "JBSWY3DPEHPK3PXP" });
  owner.close();
  await start();
});

afterAll(async () => {
  if (daemon) { daemon.kill(); await daemon.exited; }
});

test("should let an agent read selected secrets without master credentials and reject other secrets", async () => {
  const issued = await issue();
  const agentEnv = { AUTHO_LEASE_KEY: issued.leaseKey, AUTHO_MASTER_PASSWORD: "deliberately-wrong-password" };
  const read = cli(["secrets", "get", "--ref", "github", "--json"], agentEnv);
  expect(read.code).toBe(0);
  expect(JSON.parse(read.stdout).value).toBe("scoped-github-value");
  const blocked = cli(["secrets", "get", "--ref", "private"], agentEnv);
  expect(blocked.code).toBe(1);
  expect(blocked.stderr).toContain("denied");
  expect(blocked.stdout + blocked.stderr).not.toContain("never-approved-value");
  expect(cli(["secrets", "list"], agentEnv).code).toBe(1);
  expect(cli(["lease", "create", "--secret", "private", "--ttl", "99999"], agentEnv).code).toBe(1);
  const otp = cli(["otp", "code", "--ref", "otp", "--json"], agentEnv);
  expect(JSON.parse(otp.stdout).code).toMatch(/^\d{6}$/);
  expect(otp.stdout).not.toContain("JBSWY3DPEHPK3PXP");
  expect(cli(["otp", "code", "--ref", "github"], agentEnv).code).toBe(1);
  expect(cli(["secrets", "get", "--ref", "github", "--password", "owner"], agentEnv).code).toBe(1);
  expect(cli(["secrets", "get", "--ref", "github", "--lease-key", "do-not-accept-argv"], { AUTHO_MASTER_PASSWORD: password }).code).toBe(1);
});

test("should create a key through the owner CLI and run exec locally without passing the lease key", () => {
  const created = cli(["lease", "create", "--key", "--vault", vaultPath, "--secret", "github", "--ttl", "60", "--json"], { AUTHO_MASTER_PASSWORD: password });
  expect(created.code).toBe(0);
  const issued = JSON.parse(created.stdout) as { leaseKey: string };
  const keyFile = join(directory, "agent.key");
  writeFileSync(keyFile, issued.leaseKey, { mode: 0o600 });
  // state-file precedes -- so it is not part of the child command.
  const child = Bun.spawnSync(["bun", "--no-env-file", "run", "apps/cli/src/index.ts", "exec", "--state-file", statePath,
    "--lease-key-file", keyFile, "--map", "GITHUB_TOKEN=github", "--", "bun", "--no-env-file", "-e",
    "process.stdout.write(JSON.stringify({value:process.env.GITHUB_TOKEN,key:process.env.AUTHO_LEASE_KEY,master:process.env.AUTHO_MASTER_PASSWORD,cwd:process.cwd()}))"],
  { cwd: join(import.meta.dir, "../.."), env, stdout: "pipe", stderr: "pipe", timeout: 10_000 });
  expect(child.exitCode).toBe(0);
  const result = JSON.parse(child.stdout.toString());
  expect(result.value).toBe("scoped-github-value");
  expect("key" in result).toBe(false);
  expect("master" in result).toBe(false);
  expect(result.cwd).toBe(process.cwd());
});

test("should reject missing, forged and substituted keys and every admin endpoint", async () => {
  const issued = await issue();
  for (const key of ["", "autho_lease_" + "0".repeat(64), adminToken]) {
    expect((await request("/lease/env", key, { mappings: [{ envName: "VALUE", secretRef: "github" }] })).status).toBe(401);
  }
  for (const path of ["/unlock", "/status", "/env/render", "/exec", "/shutdown", "/lock", "/lease/issue", "/lease/revoke-key"]) {
    expect((await request(path, issued.leaseKey)).status).toBe(401);
  }
  expect((await request("/lease/unknown", issued.leaseKey)).status).toBe(403);
  const agent = cli(["lease", "show", "--lease", "f".repeat(32)], { AUTHO_LEASE_KEY: issued.leaseKey });
  expect(agent.code).toBe(1);
  expect(agent.stderr).toContain("does not match");
});

test("should replace a key through the owner CLI without extending its deadline", async () => {
  const issued = await issue();
  const replaced = cli(["lease", "key", "--lease", issued.id, "--vault", vaultPath, "--json"], { AUTHO_MASTER_PASSWORD: password });
  expect(replaced.code).toBe(0);
  const next = JSON.parse(replaced.stdout) as { expiresAt: string; leaseKey: string };
  expect(next.expiresAt).toBe(issued.expiresAt);
  expect(next.leaseKey === issued.leaseKey).toBe(false);
  expect((await request("/lease/show", issued.leaseKey)).status).toBe(401);
  expect((await request("/lease/show", next.leaseKey)).status).toBe(200);
});

test("should show help to an agent without using its credential", () => {
  const response = cli(["--help"], { AUTHO_LEASE_KEY: "invalid-credential" });
  expect(response.code).toBe(0);
  expect(response.stdout).toContain("lease-keyring");
});

test("should check expiry again after a slow request body finishes", async () => {
  const issued = await issue(1);
  const bytes = new TextEncoder().encode(JSON.stringify({ mappings: [{ envName: "VALUE", secretRef: "github" }] }));
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes.slice(0, 10));
      setTimeout(() => {
        controller.enqueue(bytes.slice(10));
        controller.close();
      }, Math.max(0, Date.parse(issued.expiresAt) - Date.now()) + 80);
    },
  });
  const response = await fetch(`http://127.0.0.1:${port}/lease/env`, {
    method: "POST", body,
    headers: { authorization: `Bearer ${issued.leaseKey}`, "content-type": "application/json" },
    signal: AbortSignal.timeout(5000),
  });
  expect(response.status).toBe(401);
  expect((await response.text()).includes("scoped-github-value")).toBe(false);
});

test("should reject caller-supplied permissions, expiry and session IDs", async () => {
  const issued = await issue();
  for (const field of ["ttlSeconds", "expiresAt", "leaseId", "sessionId", "secretIds", "rootKey", "cmd"]) {
    const response = await request("/lease/env", issued.leaseKey, { mappings: [{ envName: "VALUE", secretRef: "github" }], [field]: "override" });
    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(JSON.stringify(await response.json())).not.toContain(issued.leaseKey);
  }
  expect((await request("/lease/issue", adminToken, { credentials: { password }, secretRefs: ["github"], ttlSeconds: 1.5 })).status).toBe(400);
  const origin = await fetch(`http://127.0.0.1:${port}/lease/env`, {
    method: "POST", headers: { origin: "https://untrusted.example", authorization: `Bearer ${issued.leaseKey}` },
  });
  expect(origin.status).toBe(403);
});

test("should deny access after revocation and expiry", async () => {
  const revoked = await issue();
  const owner = VaultService.unlock(vaultPath, password);
  owner.revokeLease(revoked.id); owner.close();
  const denied = await request("/lease/env", revoked.leaseKey, { mappings: [{ envName: "VALUE", secretRef: "github" }] });
  expect([401, 403]).toContain(denied.status);
  const expiring = await issue(1);
  await Bun.sleep(Math.max(0, Date.parse(expiring.expiresAt) - Date.now()) + 40);
  expect((await request("/lease/show", expiring.leaseKey)).status).toBe(401);
});

test("should not widen an issued key when another secret is linked later", async () => {
  const issued = await issue();
  const owner = VaultService.unlock(vaultPath, password);
  owner.linkSecrets("github", "private"); owner.close();
  expect((await request("/lease/env", issued.leaseKey, { mappings: [{ envName: "VALUE", secretRef: "private" }] })).status).toBe(403);
  const shown = await (await request("/lease/show", issued.leaseKey)).json() as { coverage: { name: string }[] };
  expect(shown.coverage.map((secret) => secret.name).sort()).toEqual(["github", "otp"]);
});

test("should fail closed if keyring saving is requested but unavailable", async () => {
  const before = VaultService.unlock(vaultPath, password);
  const existing = new Set(before.listLeases(1000).map((lease) => lease.id));
  before.close();
  const response = await request("/lease/issue", adminToken, {
    credentials: { password }, secretRefs: ["github"], ttlSeconds: 60, remember: true,
  });
  expect(response.status).toBe(403);
  expect(JSON.stringify(await response.json())).not.toContain("autho_lease_");
  expect(readFileSync(`${statePath}.leases.json`, "utf8")).not.toContain("autho_lease_");
  const owner = VaultService.unlock(vaultPath, password);
  const leases = owner.listLeases(1000);
  owner.close();
  const created = leases.filter((lease) => !existing.has(lease.id));
  expect(created).toHaveLength(1);
  expect(created[0].revokedAt !== null).toBe(true);
});

test("should keep keys out of daemon state and audit records and invalidate them on restart", async () => {
  const issued = await issue();
  expect(readFileSync(statePath, "utf8")).not.toContain(issued.leaseKey);
  expect(readFileSync(`${statePath}.endpoint.json`, "utf8")).not.toContain(adminToken);
  const owner = VaultService.unlock(vaultPath, password);
  const audit = owner.listAudit({ leaseRef: issued.id }); owner.close();
  expect(audit.some((event) => event.eventType === "lease.key_issued")).toBe(true);
  expect(JSON.stringify(audit)).not.toContain(issued.leaseKey);
  const stopped = await request("/shutdown", adminToken);
  expect(stopped.ok).toBe(true);
  await daemon.exited;
  await start();
  expect((await request("/lease/show", issued.leaseKey)).status).toBe(401);
});

test("should deny lease reads when vault permissions were edited outside Autho", async () => {
  const issued = await issue();
  const database = new Database(vaultPath);
  database.query("UPDATE leases SET expires_at = ? WHERE id = ?").run("2099-01-01T00:00:00.000Z", issued.id);
  database.close();
  const response = await request("/lease/env", issued.leaseKey, { mappings: [{ envName: "VALUE", secretRef: "github" }] });
  expect(response.status).toBe(403);
  const error = JSON.stringify(await response.json());
  expect(error).not.toContain("scoped-github-value");
  expect(error).not.toContain(vaultPath);
});
