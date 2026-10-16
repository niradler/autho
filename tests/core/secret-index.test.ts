import { afterEach, beforeEach, expect, test } from "bun:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService, type VaultSession } from "../../packages/core/src/index.ts";

let dir: string;
let session: VaultSession;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-index-"));
  const vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, "correct-horse-battery");
  session = VaultService.unlock(vaultPath, "correct-horse-battery");
});

afterEach(() => {
  session.close();
  rmSync(dir, { recursive: true, force: true });
});

test("listSecretIndex returns display fields but never secret values", () => {
  session.addSecret({ name: "github", type: "password", username: "octocat", value: "hunter2", metadata: { url: "https://github.com", description: "work" } });
  session.addSecret({ name: "diary", type: "note", value: "dear diary" });

  const index = session.listSecretIndex();
  expect(index.map((e) => e.name).sort()).toEqual(["diary", "github"]);
  const github = index.find((e) => e.name === "github")!;
  expect(github).toMatchObject({ username: "octocat", url: "https://github.com", description: "work", type: "password" });
  expect(index.find((e) => e.name === "diary")).toMatchObject({ username: null, url: null, description: null });

  const serialized = JSON.stringify(index);
  expect(serialized).not.toContain("hunter2");
  expect(serialized).not.toContain("dear diary");
  expect("value" in github).toBe(false);
});

test("listSecretIndex is audited once per call", () => {
  session.addSecret({ name: "a", type: "password", value: "1" });
  session.addSecret({ name: "b", type: "password", value: "2" });
  session.listSecretIndex();
  const events = session.listAudit(100).filter((e) => e.eventType === "secret.index");
  expect(events).toHaveLength(1);
});
