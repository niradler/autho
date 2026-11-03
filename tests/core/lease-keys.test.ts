import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { expect, test } from "bun:test";

import { VaultService } from "../../packages/core/src/index.ts";
import { LeaseKeyring, type LeaseKeyringBackend } from "../../packages/core/src/lease-keyring.ts";
import { LeaseKeyRegistry } from "../../packages/core/src/lease-keys.ts";
import { parseLeaseIssue, parseLeaseMappings } from "../../packages/core/src/lease-validation.ts";

function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "autho-lease-key-"));
  const vaultPath = join(directory, "vault.db");
  VaultService.initialize(vaultPath, "isolated-test-password");
  const session = VaultService.unlock(vaultPath, "isolated-test-password");
  session.addSecret({ name: "github", type: "password", value: "scoped-value" });
  session.addSecret({ name: "private", type: "note", value: "outside-value" });
  return { directory, session, vaultPath };
}

test("should bind a key to its approved IDs and cap its lifetime even when the clock moves backwards", () => {
  const { session, vaultPath } = fixture();
  try {
    const lease = session.createLease({ name: "agent", noLinks: true, secretRefs: ["github"], ttlSeconds: 60 });
    let wall = Date.now();
    let elapsed = 0;
    const registry = new LeaseKeyRegistry(() => wall, () => elapsed);
    const issued = registry.issue(session, lease.id, vaultPath);
    const grant = registry.get(issued.leaseKey)!;
    expect(grant.rootKey).toHaveLength(32);
    expect(session.renderLeaseEnv([{ envName: "VALUE", secretRef: "github" }], grant)).toEqual({ VALUE: "scoped-value" });
    expect(() => session.renderLeaseEnv([{ envName: "VALUE", secretRef: "private" }], grant)).toThrow("approved");
    expect(registry.get("wrong")).toBeNull();
    wall -= 3600_000;
    elapsed = 60_001;
    expect(registry.get(issued.leaseKey)).toBeNull();
    registry.revoke(lease.id);
    expect(grant.rootKey.every((byte) => byte === 0)).toBe(true);
  } finally { session.close(); }
});

test("should freeze link coverage, respect unlinking and deny a revoked lease", () => {
  const { session, vaultPath } = fixture();
  try {
    const lease = session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 60 });
    const registry = new LeaseKeyRegistry();
    const issued = registry.issue(session, lease.id, vaultPath);
    const grant = registry.get(issued.leaseKey)!;
    session.linkSecrets("github", "private");
    expect(() => session.renderLeaseEnv([{ envName: "VALUE", secretRef: "private" }], grant)).toThrow("approved");
    const replaced = registry.issue(session, lease.id, vaultPath);
    expect(registry.get(issued.leaseKey)).toBeNull();
    const withLink = registry.get(replaced.leaseKey)!;
    expect(session.renderLeaseEnv([{ envName: "VALUE", secretRef: "private" }], withLink).VALUE).toBe("outside-value");
    session.unlinkSecrets("github", "private");
    expect(() => session.renderLeaseEnv([{ envName: "VALUE", secretRef: "private" }], withLink)).toThrow("does not allow");
    expect(session.inspectLeaseKey(withLink).coverage.map((secret) => secret.name)).toEqual(["github"]);
    session.revokeLease(lease.id);
    expect(() => session.inspectLeaseKey(withLink)).toThrow("revoked");
    registry.clear();
  } finally { session.close(); }
});

test("should validate issuance, reject broadening fields and validate mappings before use", () => {
  const valid = { credentials: { password: "owner" }, name: "agent", secretRefs: ["github"], ttlSeconds: 900 };
  expect(parseLeaseIssue(valid).remember).toBe(false);
  for (const ttlSeconds of [0, -1, 0.1, Number.NaN, Number.POSITIVE_INFINITY, "900", 2_592_001]) {
    expect(() => parseLeaseIssue({ ...valid, ttlSeconds })).toThrow("TTL");
  }
  expect(() => parseLeaseIssue({ ...valid, remember: "true" })).toThrow();
  expect(() => parseLeaseIssue({ ...valid, credentials: { password: "owner", rootKey: "override" } })).toThrow();
  expect(() => parseLeaseIssue({ ...valid, leaseId: "a".repeat(32) })).toThrow("extended");
  expect(() => parseLeaseMappings({ mappings: [], leaseId: "other" })).toThrow();
  expect(() => parseLeaseMappings({ mappings: [{ envName: "invalid=name", secretRef: "github" }] })).toThrow();
  expect(() => parseLeaseMappings({ mappings: [{ envName: "__proto__", secretRef: "github" }, { envName: "__PROTO__", secretRef: "github" }] })).toThrow();
});

test("should bind permission to a secret ID when its name is reused", () => {
  const { session, vaultPath } = fixture();
  try {
    const lease = session.createLease({ name: "agent", noLinks: true, secretRefs: ["github"], ttlSeconds: 60 });
    const registry = new LeaseKeyRegistry();
    const issued = registry.issue(session, lease.id, vaultPath);
    const grant = registry.get(issued.leaseKey)!;
    session.updateSecret("github", { name: "renamed-github" });
    session.addSecret({ name: "github", type: "password", value: "replacement-not-approved" });
    expect(() => session.renderLeaseEnv([{ envName: "VALUE", secretRef: "github" }], grant)).toThrow("approved");
    expect(session.renderLeaseEnv([{ envName: "VALUE", secretRef: "renamed-github" }], grant).VALUE).toBe("scoped-value");
    registry.clear();
  } finally { session.close(); }
});

function keyringFixture() {
  const values = new Map<string, string>();
  let unavailable = false;
  const backend: LeaseKeyringBackend = {
    async get(name) { return values.get(name) ?? null; },
    async set(name, value) { if (unavailable) throw new Error("keyring unavailable"); values.set(name, value); },
    async delete(name) { if (unavailable) throw new Error("keyring unavailable"); values.delete(name); },
  };
  const path = join(mkdtempSync(join(tmpdir(), "autho-keyring-")), "daemon.json");
  return { keyring: new LeaseKeyring(path, backend), path, values, fail: (value: boolean) => { unavailable = value; } };
}

test("should store only the lease credential in the keyring and keep it out of the cleanup index", async () => {
  const { keyring, path, values } = keyringFixture();
  const id = "a".repeat(32);
  await keyring.save(id, new Date(Date.now() + 60_000).toISOString(), "test-lease-credential");
  expect(await keyring.load(id)).toBe("test-lease-credential");
  expect(readFileSync(`${path}.leases.json`, "utf8")).not.toContain("test-lease-credential");
  expect(await keyring.cleanup()).toBe(true);
  expect(values.size).toBe(1);
  await keyring.forget(id);
  expect(values.size).toBe(0);
  await expect(keyring.load(id)).rejects.toThrow("No saved key");
});

test("should retry failed cleanup and invalidate saved keys across daemon restarts", async () => {
  const { keyring, values, fail } = keyringFixture();
  const id = "b".repeat(32);
  await keyring.save(id, new Date(Date.now() + 60_000).toISOString(), "test-lease-credential");
  fail(true);
  expect(await keyring.cleanup(true)).toBe(false);
  fail(false);
  await expect(keyring.load(id)).rejects.toThrow("expired");
  expect(values.size).toBe(0);
  expect(await keyring.cleanup()).toBe(true);
});

test("should fail keyring saving without writing a plaintext credential fallback", async () => {
  const { keyring, path, values, fail } = keyringFixture();
  fail(true);
  await expect(keyring.save("c".repeat(32), new Date(Date.now() + 60_000).toISOString(), "never-on-disk")).rejects.toThrow();
  expect(values.size).toBe(0);
  expect(readFileSync(`${path}.leases.json`, "utf8")).not.toContain("never-on-disk");
});
