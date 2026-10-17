import { afterEach, beforeEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { copyFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, VaultTamperedError, type VaultSession } from "../../packages/core/src/index.ts";
import { createVaultConfig } from "../../packages/crypto/src/index.ts";

const PASSWORD = "correct-horse-battery";

let dir: string;
let vaultPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-seal-"));
  vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, PASSWORD);
  withSession((session) => {
    session.addSecret({ name: "github", type: "password", value: "gh-password" });
    session.addSecret({ name: "aws", type: "password", value: "aws-password" });
  });
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function withSession<T>(fn: (session: VaultSession) => T): T {
  const session = VaultService.unlock(vaultPath, PASSWORD);
  try {
    return fn(session);
  } finally {
    session.close();
  }
}

/** Edits the SQLite file directly, the way someone without the vault key would. */
function rawEdit(fn: (db: Database) => void): void {
  const db = new Database(vaultPath);
  try {
    fn(db);
  } finally {
    db.close();
  }
}

function secretId(name: string): string {
  return withSession((session) => session.getSecret(name).id);
}

function auditTypes(session: VaultSession): string[] {
  return session.listAudit(200).map((event) => event.eventType);
}

test("a new vault is sealed and stays intact across changes", () => {
  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    session.linkSecrets("github", "aws");
    session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 300 });
    expect(session.verifySeal().state).toBe("intact");
  });
});

test("a link inserted outside autho is caught and blocks writes and env", () => {
  const [github, aws] = [secretId("github"), secretId("aws")];
  const leaseId = withSession((session) => session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 300 }).id);
  rawEdit((db) =>
    db.query("INSERT INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)").run(github, aws, new Date().toISOString()),
  );

  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state).toBe("tampered");
    if (seal.state !== "tampered") return;
    expect(seal.diffTrusted).toBe(true);
    expect(seal.changes).toEqual([{ change: "added", rowId: `${github}>${aws}`, table: "secret_links" }]);

    expect(() => session.renderEnv([{ envName: "AWS", secretRef: "aws" }], leaseId)).toThrow(VaultTamperedError);
    expect(() => session.addSecret({ name: "new", type: "note", value: "x" })).toThrow(VaultTamperedError);
    // Taking access away still works.
    expect(session.revokeLease(leaseId).revokedAt).not.toBeNull();
  });
});

test("a lease edited outside autho is caught", () => {
  const leaseId = withSession((session) => session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 300 }).id);
  rawEdit((db) => db.query("UPDATE leases SET expires_at = '2999-01-01T00:00:00.000Z' WHERE id = ?1").run(leaseId));

  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state === "tampered" && seal.changes).toEqual([{ change: "modified", rowId: leaseId, table: "leases" }]);
  });
});

test("deleting the seal is caught, not mistaken for an old vault", () => {
  rawEdit((db) => {
    db.query("DELETE FROM meta WHERE key = 'vault.seal'").run();
    db.query("DELETE FROM seal_rows").run();
  });
  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state).toBe("tampered");
    expect(seal.state === "tampered" && seal.reason).toBe("the seal was removed");
  });
});

test("a vault from before sealing is sealed on its first password unlock", () => {
  const { rootKey } = VaultService.unlockRootKey(vaultPath, { password: PASSWORD });
  const { config } = createVaultConfig(PASSWORD, rootKey, { sealed: false });
  rawEdit((db) => {
    db.query("UPDATE meta SET value = ?1 WHERE key = 'vault.config'").run(JSON.stringify(config));
    db.query("DELETE FROM meta WHERE key = 'vault.seal'").run();
    db.query("DELETE FROM seal_rows").run();
  });

  withSession((session) => {
    expect(session.sealBound).toBe(true);
    expect(session.verifySeal().state).toBe("intact");
    expect(auditTypes(session)).toContain("vault.sealed.initial");
    expect(session.getSecret("github").value).toBe("gh-password");
  });
});

test("reseal quarantine drops the added link, revokes leases, and unblocks the vault", () => {
  const [github, aws] = [secretId("github"), secretId("aws")];
  const leaseId = withSession((session) => session.createLease({ name: "agent", secretRefs: ["github"], ttlSeconds: 300 }).id);
  rawEdit((db) =>
    db.query("INSERT INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)").run(github, aws, new Date().toISOString()),
  );

  const result = VaultService.reseal(vaultPath, { password: PASSWORD }, "quarantine");
  expect(result.wasIntact).toBe(false);
  expect(result.undone).toEqual([{ change: "added", rowId: `${github}>${aws}`, table: "secret_links" }]);
  expect(result.kept).toEqual([]);
  expect(result.revokedLeases).toBe(1);

  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    expect(session.getLinks("github").links).toEqual([]);
    expect(session.showLease(leaseId).lease.revokedAt).not.toBeNull();
    expect(auditTypes(session)).toContain("vault.reseal.quarantine");
  });
});

test("reseal accept keeps the change and re-signs", () => {
  const [github, aws] = [secretId("github"), secretId("aws")];
  rawEdit((db) =>
    db.query("INSERT INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)").run(github, aws, new Date().toISOString()),
  );

  const result = VaultService.reseal(vaultPath, { password: PASSWORD }, "accept");
  expect(result.undone).toEqual([]);
  expect(result.kept).toHaveLength(1);
  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    expect(session.getLinks("github").links.map((s) => s.name)).toEqual(["aws"]);
  });
});

test("quarantine puts back a renamed secret and a deleted one from their sealed copies", () => {
  const [github, aws] = [secretId("github"), secretId("aws")];
  rawEdit((db) => {
    db.query("UPDATE secrets SET name = 'renamed' WHERE id = ?1").run(github);
    db.query("DELETE FROM secrets WHERE id = ?1").run(aws);
  });

  const result = VaultService.reseal(vaultPath, { password: PASSWORD }, "quarantine");
  expect(result.diffTrusted).toBe(true);
  expect(result.kept).toEqual([]);
  expect(result.undone).toHaveLength(2);

  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    expect(session.getSecret("github").value).toBe("gh-password");
    expect(session.getSecret("aws").value).toBe("aws-password");
    expect(() => session.getSecret("renamed")).toThrow();
  });
});

test("quarantine with an edited seal list deletes only access rows, never secrets", () => {
  const [github, aws] = [secretId("github"), secretId("aws")];
  rawEdit((db) => {
    // Hide github from the seal list so it looks "added", and add a link.
    db.query("DELETE FROM seal_rows WHERE row_id = ?1").run(github);
    db.query("INSERT INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)").run(github, aws, new Date().toISOString());
  });

  const result = VaultService.reseal(vaultPath, { password: PASSWORD }, "quarantine");
  expect(result.diffTrusted).toBe(false);
  expect(result.undone).toEqual([{ change: "added", rowId: `${github}>${aws}`, table: "secret_links" }]);
  expect(result.kept).toEqual([{ change: "added", rowId: github, table: "secrets" }]);

  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    expect(session.getSecret("github").value).toBe("gh-password");
    expect(session.getLinks("github").links).toEqual([]);
  });
});

test("an older copy of the vault file is caught with the seal record, and reseal clears it", () => {
  const backup = join(dir, "backup.db");
  copyFileSync(vaultPath, backup);
  const record = withSession((session) => {
    session.addSecret({ name: "later", type: "note", value: "x" });
    return session.sealCheckpoint();
  });
  expect(record).not.toBeNull();
  copyFileSync(backup, vaultPath);

  // Without the record the old copy looks fine; with it, it's a rollback.
  withSession((session) => expect(session.verifySeal().state).toBe("intact"));
  const session = VaultService.unlock(vaultPath, { password: PASSWORD, sealRecord: record });
  try {
    const seal = session.verifySeal();
    expect(seal.state === "tampered" && seal.reason).toBe("the vault file was replaced with an older copy");
    expect(() => session.addSecret({ name: "blocked", type: "note", value: "x" })).toThrow(VaultTamperedError);
  } finally {
    session.close();
  }

  const result = VaultService.reseal(vaultPath, { password: PASSWORD, sealRecord: record }, "accept");
  expect(result.sealRecord!.counter).toBeGreaterThan(record!.counter);
  const after = VaultService.unlock(vaultPath, { password: PASSWORD, sealRecord: result.sealRecord });
  try {
    expect(after.verifySeal().state).toBe("intact");
  } finally {
    after.close();
  }
});

test("with a seal record, a missing seal next to a pre-seal wrap is reported, not re-sealed", () => {
  const record = withSession((session) => session.sealCheckpoint());
  const { rootKey } = VaultService.unlockRootKey(vaultPath, { password: PASSWORD });
  const { config } = createVaultConfig(PASSWORD, rootKey, { sealed: false });
  rawEdit((db) => {
    db.query("UPDATE meta SET value = ?1 WHERE key = 'vault.config'").run(JSON.stringify(config));
    db.query("DELETE FROM meta WHERE key = 'vault.seal'").run();
    db.query("DELETE FROM seal_rows").run();
  });

  const session = VaultService.unlock(vaultPath, { password: PASSWORD, sealRecord: record });
  try {
    expect(session.sealBound).toBe(false);
    const seal = session.verifySeal();
    expect(seal.state === "tampered" && seal.reason).toBe("the seal was removed");
    expect(auditTypes(session)).not.toContain("vault.sealed.initial");
  } finally {
    session.close();
  }
});

test("reseal on an intact vault does nothing", () => {
  expect(VaultService.reseal(vaultPath, { password: PASSWORD }, "quarantine").wasIntact).toBe(true);
});

test("changing the password keeps the vault sealed", () => {
  VaultService.changePassword(vaultPath, { password: PASSWORD }, "a-brand-new-passphrase");
  const session = VaultService.unlock(vaultPath, "a-brand-new-passphrase");
  try {
    expect(session.sealBound).toBe(true);
    expect(session.verifySeal().state).toBe("intact");
  } finally {
    session.close();
  }
});
