import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, type VaultSession } from "../../packages/core/src/index.ts";

const PASSWORD = "correct-horse-battery";
const OTP_SEED = "JBSWY3DPEHPK3PXP";

let dir: string;
let session: VaultSession;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-linking-"));
  const vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, PASSWORD);
  session = VaultService.unlock(vaultPath, PASSWORD);
  session.addSecret({ name: "github", type: "password", username: "nir", value: "gh-password" });
  session.addSecret({ name: "github-otp", type: "otp", value: OTP_SEED });
  session.addSecret({ name: "github-recovery", type: "note", value: "recovery-codes" });
});

afterEach(() => {
  session.close();
  rmSync(dir, { recursive: true, force: true });
});

function auditTypes(): string[] {
  return session.listAudit({ limit: 200 }).map((event) => event.eventType);
}

test("link shows the secret under the primary, and the primary on the linked secret", () => {
  const result = session.linkSecrets("github", "github-otp");
  expect(result.created).toBe(true);

  expect(session.getLinks("github").links.map((s) => s.name)).toEqual(["github-otp"]);
  expect(session.getLinks("github-otp").linkedFrom.map((s) => s.name)).toEqual(["github"]);
  expect(session.listSecretIndex().find((s) => s.name === "github")?.linkCount).toBe(1);
  expect(auditTypes()).toContain("secret.linked");
});

test("linking twice is a no-op and a secret can't link to itself", () => {
  session.linkSecrets("github", "github-otp");
  expect(session.linkSecrets("github", "github-otp").created).toBe(false);
  expect(session.getLinks("github").links).toHaveLength(1);
  expect(() => session.linkSecrets("github", "github")).toThrow("itself");
});

test("unlink removes the link and fails when there is none", () => {
  session.linkSecrets("github", "github-otp");
  session.unlinkSecrets("github", "github-otp");
  expect(session.getLinks("github").links).toEqual([]);
  expect(() => session.unlinkSecrets("github", "github-otp")).toThrow("not linked");
});

test("deleting a primary keeps its linked secrets by default", () => {
  session.linkSecrets("github", "github-otp");
  const result = session.removeSecret("github");
  expect(result.removedLinked).toEqual([]);
  expect(session.getSecret("github-otp").value).toBe(OTP_SEED);
  expect(session.getLinks("github-otp").linkedFrom).toEqual([]);
});

test("--with-linked deletes linked secrets, except ones another primary still links to", () => {
  session.addSecret({ name: "gitlab", type: "password", value: "gl-password" });
  session.linkSecrets("github", "github-otp");
  session.linkSecrets("github", "github-recovery");
  session.linkSecrets("gitlab", "github-recovery");

  const result = session.removeSecret("github", { withLinked: true });
  expect(result.removedLinked.map((s) => s.name)).toEqual(["github-otp"]);
  expect(result.keptLinked.map((s) => s.name)).toEqual(["github-recovery"]);
  expect(() => session.getSecret("github-otp")).toThrow("not found");
  expect(session.getLinks("gitlab").links.map((s) => s.name)).toEqual(["github-recovery"]);
});

test("a lease on the primary covers linked secrets live, and audits the linked read", () => {
  const lease = session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 300 });
  const mappings = [{ envName: "OTP", secretRef: "github-otp" }];
  expect(() => session.renderEnv(mappings, lease.id)).toThrow("does not allow");

  // Linking after the lease was created extends it.
  session.linkSecrets("github", "github-otp");
  expect(session.showLease(lease.id).coverage.map((c) => [c.name, c.via?.name ?? null])).toEqual([
    ["github", null],
    ["github-otp", "github"],
  ]);
  expect(session.renderEnv(mappings, lease.id).OTP).toMatch(/^\d{6}$/);
  expect(auditTypes()).toContain("lease.link_access");

  // Unlinking takes the access away again.
  session.unlinkSecrets("github", "github-otp");
  expect(() => session.renderEnv(mappings, lease.id)).toThrow("does not allow");
});

test("a lease created with noLinks covers only the named secrets", () => {
  session.linkSecrets("github", "github-otp");
  const lease = session.createLease({ name: "agent", noLinks: true, secretRefs: ["github"], ttlSeconds: 300 });
  expect(session.showLease(lease.id).coverage.map((c) => c.name)).toEqual(["github"]);
  expect(() => session.renderEnv([{ envName: "OTP", secretRef: "github-otp" }], lease.id)).toThrow("does not allow");
});

test("env injects an OTP secret's current code, never its seed", () => {
  const env = session.renderEnv([{ envName: "OTP", secretRef: "github-otp" }]);
  expect(env.OTP).not.toBe(OTP_SEED);
  expect(env.OTP).toBe(session.generateOtp("github-otp", { audit: false }).code);
});

test("a display-only OTP refresh is not audited; a normal one is", () => {
  session.generateOtp("github-otp", { audit: false });
  expect(auditTypes()).not.toContain("otp.generated");
  session.generateOtp("github-otp");
  expect(auditTypes()).toContain("otp.generated");
});
