import { afterEach, beforeEach, expect, test } from "bun:test";
import { Database } from "bun:sqlite";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, VaultTamperedError, type VaultSession } from "../../packages/core/src/index.ts";

const PASSWORD = "correct-horse-battery";

let dir: string;
let vaultPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-groups-"));
  vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, PASSWORD);
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

function auditTypes(session: VaultSession): string[] {
  return session.listAudit({ limit: 200 }).map((event) => event.eventType);
}

test("groups are created, listed by name with counts, and unique ignoring case", () => {
  withSession((session) => {
    session.createGroup("work");
    const homelab = session.createGroup("  homelab ");
    expect(homelab.name).toBe("homelab");
    expect(() => session.createGroup("HomeLab")).toThrow("Group already exists");

    session.addSecret({ group: "HOMELAB", name: "proxmox", type: "password", value: "pw" });
    session.addSecret({ name: "loose", type: "note", value: "x" });

    expect(session.listGroups().map((g) => [g.name, g.secretCount])).toEqual([["homelab", 1], ["work", 0]]);
    expect(session.getGroup("homelab").id).toBe(homelab.id);
    expect(auditTypes(session)).toContain("group.created");
    expect(session.verifySeal().state).toBe("intact");
  });
});

test("group names are validated and (ungrouped) is reserved", () => {
  withSession((session) => {
    expect(() => session.createGroup("   ")).toThrow("Group name is required");
    expect(() => session.createGroup("x".repeat(65))).toThrow("longer than 64");
    expect(() => session.createGroup("bad\nname")).toThrow("control characters");
    expect(() => session.createGroup("(Ungrouped)")).toThrow("reserved");
  });
});

test("secrets only join existing groups, and moves are audited as secret.grouped", () => {
  withSession((session) => {
    session.createGroup("homelab");
    session.createGroup("work");
    expect(() => session.addSecret({ group: "homleab", name: "typo", type: "note", value: "x" })).toThrow("Group not found");
    expect(session.listSecrets().map((s) => s.name)).not.toContain("typo");

    const created = session.addSecret({ group: "homelab", name: "nas", type: "password", value: "pw" });
    expect(created.group).toBe("homelab");

    expect(session.updateSecret("nas", { group: "work" }).group).toBe("work");
    expect(session.describeSecret("nas").group).toBe("work");
    // Other edits leave the group alone.
    expect(session.updateSecret("nas", { value: "pw2" }).group).toBe("work");
    expect(session.updateSecret("nas", { group: null }).group).toBeNull();
    expect(() => session.updateSecret("nas", { group: "missing" })).toThrow("Group not found");

    const grouped = session.listAudit({ eventType: "secret.grouped", limit: 10 });
    expect(grouped.map((e) => e.metadata.groupName)).toEqual([null, "work", "homelab"]);
  });
});

test("the secret index carries the group for list filtering", () => {
  withSession((session) => {
    session.createGroup("homelab");
    session.addSecret({ group: "homelab", name: "proxmox", type: "password", value: "pw" });
    session.addSecret({ name: "loose", type: "note", value: "x" });
    const byName = Object.fromEntries(session.listSecretIndex().map((s) => [s.name, s.group]));
    expect(byName).toEqual({ loose: null, proxmox: "homelab" });
  });
});

test("renaming keeps membership; a case-only rename is allowed", () => {
  withSession((session) => {
    session.createGroup("homelab");
    session.createGroup("work");
    session.addSecret({ group: "homelab", name: "nas", type: "password", value: "pw" });

    expect(() => session.renameGroup("homelab", "WORK")).toThrow("Group already exists");
    expect(session.renameGroup("homelab", "Homelab").name).toBe("Homelab");
    expect(session.renameGroup("homelab", "lab").secretCount).toBe(1);
    expect(session.describeSecret("nas").group).toBe("lab");
    expect(auditTypes(session).filter((t) => t === "group.renamed")).toHaveLength(2);
  });
});

test("deleting a group ungroups its secrets and never deletes them", () => {
  withSession((session) => {
    session.createGroup("homelab");
    session.addSecret({ group: "homelab", name: "a", type: "note", value: "1" });
    session.addSecret({ group: "homelab", name: "b", type: "note", value: "2" });

    expect(session.removeGroup("homelab").ungrouped).toBe(2);
    expect(session.listGroups()).toEqual([]);
    expect(session.listSecrets().map((s) => [s.name, s.group])).toEqual([["a", null], ["b", null]]);
    const deleted = session.listAudit({ eventType: "group.deleted", limit: 1 })[0];
    expect(deleted?.metadata).toEqual({ name: "homelab", ungrouped: 2 });
    expect(session.verifySeal().state).toBe("intact");
  });
});

test("a group row edited outside autho is reported as tampered and blocks writes", () => {
  const id = withSession((session) => session.createGroup("homelab").id);
  rawEdit((db) => db.query("UPDATE groups SET name = 'evil' WHERE id = ?1").run(id));

  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state).toBe("tampered");
    if (seal.state !== "tampered") return;
    expect(seal.changes).toEqual([{ change: "modified", rowId: id, table: "groups" }]);
    expect(() => session.createGroup("other")).toThrow(VaultTamperedError);
  });
});

test("a group inserted outside autho is reported as tampered", () => {
  withSession((session) => session.createGroup("homelab"));
  rawEdit((db) =>
    db.query("INSERT INTO groups (id, name, created_at, updated_at) VALUES ('g1', 'planted', 'x', 'x')").run(),
  );
  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state === "tampered" && seal.changes).toEqual([{ change: "added", rowId: "g1", table: "groups" }]);
  });
});

test("moving a secret into a group outside autho is reported as tampered", () => {
  const { groupId, secretId } = withSession((session) => ({
    groupId: session.createGroup("homelab").id,
    secretId: session.addSecret({ name: "aws", type: "password", value: "pw" }).id,
  }));
  rawEdit((db) => db.query("UPDATE secrets SET group_id = ?1 WHERE id = ?2").run(groupId, secretId));

  withSession((session) => {
    const seal = session.verifySeal();
    expect(seal.state === "tampered" && seal.changes).toEqual([{ change: "modified", rowId: secretId, table: "secrets" }]);
  });
});

test("quarantine puts a tampered group back", () => {
  const id = withSession((session) => {
    const group = session.createGroup("homelab");
    session.addSecret({ group: "homelab", name: "nas", type: "note", value: "x" });
    return group.id;
  });
  rawEdit((db) => {
    db.query("UPDATE groups SET name = 'evil' WHERE id = ?1").run(id);
    db.query("UPDATE secrets SET group_id = NULL").run();
  });

  const result = VaultService.reseal(vaultPath, { password: PASSWORD }, "quarantine");
  expect(result.kept).toEqual([]);
  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    expect(session.listGroups().map((g) => [g.name, g.secretCount])).toEqual([["homelab", 1]]);
  });
});

test("a vault sealed before groups existed stays intact after the upgrade", () => {
  withSession((session) => session.addSecret({ name: "aws", type: "password", value: "pw" }));
  // Put the file back in its pre-groups shape: no groups table, no group_id column.
  rawEdit((db) => {
    db.exec("DROP INDEX secrets_group_id");
    db.exec("ALTER TABLE secrets DROP COLUMN group_id");
    db.exec("DROP TABLE groups");
  });

  withSession((session) => {
    expect(session.verifySeal().state).toBe("intact");
    session.createGroup("homelab");
    session.updateSecret("aws", { group: "homelab" });
    expect(session.verifySeal().state).toBe("intact");
  });
});
