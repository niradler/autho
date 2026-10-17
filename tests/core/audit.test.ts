import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, type VaultSession } from "../../packages/core/src/index.ts";
import { AuthoDatabase } from "../../packages/storage/src/index.ts";

const PASSWORD = "correct-horse-battery";

let dir: string;
let vaultPath: string;
let session: VaultSession;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-audit-"));
  vaultPath = join(dir, "vault.db");
  process.env.AUTHO_AUDIT_RETENTION_DAYS = "90";
  VaultService.initialize(vaultPath, PASSWORD, "cli");
  session = VaultService.unlock(vaultPath, { password: PASSWORD, source: "tui" });
});

afterEach(() => {
  session.close();
  delete process.env.AUTHO_AUDIT_RETENTION_DAYS;
  rmSync(dir, { recursive: true, force: true });
});

test("events are stamped with the source of the session", () => {
  session.addSecret({ name: "github", type: "password", value: "hunter2" });
  session.getSecret("github");
  const events = session.listAudit({ limit: 50 });
  const created = events.find((e) => e.eventType === "secret.created")!;
  expect(created).toMatchObject({ message: "Created github", source: "tui" });
  expect(events.find((e) => e.eventType === "secret.read")).toMatchObject({ message: "Read github", source: "tui" });
  expect(events.find((e) => e.eventType === "auth.unlock.password")?.source).toBe("tui");
  expect(session.listAudit({ source: "cli", limit: 50 }).every((e) => e.source === "cli")).toBe(true);
  expect(session.listAudit({ source: "tui", limit: 50 }).some((e) => e.eventType === "secret.read")).toBe(true);
});

test("describeSecret fills a form without logging a read", () => {
  session.addSecret({ name: "github", type: "password", value: "hunter2" });
  expect(session.describeSecret("github").value).toBe("");
  expect(session.listAudit({ eventType: "secret.read", limit: 50 })).toHaveLength(0);
});

test("one-shot unlocks can skip the unlock event", () => {
  const before = session.listAudit({ eventType: "auth.unlock", limit: 100 }).length;
  VaultService.unlock(vaultPath, { password: PASSWORD, source: "cli" }, { recordUnlock: false }).close();
  expect(session.listAudit({ eventType: "auth.unlock", limit: 100 })).toHaveLength(before);
});

test("failed unlocks are logged with the method, never the input", () => {
  expect(() => VaultService.unlock(vaultPath, { password: "wrong-password-123", source: "web" })).toThrow("Invalid vault password");
  const failed = session.listAudit({ eventType: "auth.unlock.failed", limit: 10 });
  expect(failed).toHaveLength(1);
  expect(failed[0]).toMatchObject({ metadata: { method: "password" }, source: "web" });
  expect(JSON.stringify(failed[0])).not.toContain("wrong-password-123");
});

test("env injection through a lease names the secrets and the lease", () => {
  session.addSecret({ name: "db-pass", type: "password", value: "s3cret" });
  const lease = session.createLease({ name: "ci", secretRefs: ["db-pass"], ttlSeconds: 600 });
  session.renderEnv([{ envName: "DB_PASS", secretRef: "db-pass" }], lease.id);

  const [rendered] = session.listAudit({ eventType: "env.rendered", limit: 10 });
  expect(rendered!.leaseId).toBe(lease.id);
  expect(rendered!.message).toContain("db-pass");
  expect(rendered!.message).toContain("ci");
  expect(JSON.stringify(rendered)).not.toContain("s3cret");

  expect(session.listAudit({ leaseRef: "ci", limit: 50 }).map((e) => e.eventType)).toContain("env.rendered");
  expect(session.listAudit({ secretRef: "db-pass", limit: 50 }).map((e) => e.eventType)).toEqual(
    expect.arrayContaining(["secret.created", "lease.created", "env.rendered"]),
  );
});

test("events older than the retention window are pruned on unlock", () => {
  const db = new AuthoDatabase(vaultPath);
  const old = (days: number) => new Date(Date.now() - days * 86_400_000).toISOString();
  for (const [id, days] of [["old", 120], ["recent", 10]] as const) {
    db.insertAudit({ createdAt: old(days), eventType: "test.event", id, leaseId: null, message: id, metadata: "{}", source: null, subjectRef: null, subjectType: "vault" });
  }
  db.close();

  VaultService.unlock(vaultPath, { password: PASSWORD, source: "cli" }, { recordUnlock: false }).close();
  expect(session.listAudit({ eventType: "test.", limit: 10 }).map((e) => e.id)).toEqual(["recent"]);
});

test("retention 0 keeps everything", () => {
  process.env.AUTHO_AUDIT_RETENTION_DAYS = "0";
  const db = new AuthoDatabase(vaultPath);
  db.insertAudit({ createdAt: new Date(Date.now() - 5000 * 86_400_000).toISOString(), eventType: "test.event", id: "ancient", leaseId: null, message: "x", metadata: "{}", source: null, subjectRef: null, subjectType: "vault" });
  db.close();

  VaultService.unlock(vaultPath, { password: PASSWORD }, { recordUnlock: false }).close();
  expect(session.listAudit({ eventType: "test.", limit: 10 }).map((e) => e.id)).toEqual(["ancient"]);
});
