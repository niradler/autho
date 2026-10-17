import { afterEach, beforeEach, expect, test } from "bun:test";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { VaultService } from "../../packages/core/src/index.ts";

const PASSWORD = "correct-horse-battery";

let dir: string;
let vaultPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-passkey-"));
  vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, PASSWORD);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

const b64 = (bytes: Buffer) => bytes.toString("base64url");

function register(label = "YubiKey") {
  const credentialId = b64(randomBytes(16));
  const prfOutput = b64(randomBytes(32));
  const info = VaultService.addPasskey(vaultPath, { password: PASSWORD }, {
    credentialId,
    label,
    prfOutput,
    prfSalt: b64(randomBytes(32)),
    transports: ["usb"],
  });
  return { credentialId, info, prfOutput };
}

test("a registered passkey unlocks the vault and is audited", () => {
  const setup = VaultService.unlock(vaultPath, PASSWORD);
  setup.addSecret({ name: "github", type: "password", value: "hunter2" });
  setup.close();

  const { credentialId, prfOutput, info } = register();
  expect(info.label).toBe("YubiKey");
  expect("wrappedRootKey" in info).toBe(false);

  const session = VaultService.unlock(vaultPath, { password: "", passkey: { credentialId, prfOutput } });
  try {
    expect(session.getSecret("github").value).toBe("hunter2");
    const events = session.listAudit({ limit: 50 }).map((e) => e.eventType);
    expect(events).toContain("auth.passkey.added");
    expect(events).toContain("auth.unlock.passkey");
  } finally {
    session.close();
  }
});

test("a wrong PRF output or unknown credential does not unlock", () => {
  const { credentialId } = register();
  expect(() => VaultService.unlock(vaultPath, { password: "", passkey: { credentialId, prfOutput: b64(randomBytes(32)) } }))
    .toThrow("Passkey did not unlock the vault");
  expect(() => VaultService.unlock(vaultPath, { password: "", passkey: { credentialId: "nope", prfOutput: b64(randomBytes(32)) } }))
    .toThrow("not registered");
  expect(() => VaultService.unlock(vaultPath, { password: "", passkey: { credentialId, prfOutput: b64(randomBytes(8)) } }))
    .toThrow();
});

test("adding requires valid credentials and rejects duplicates", () => {
  const { credentialId } = register();
  const input = { credentialId, label: "again", prfOutput: b64(randomBytes(32)), prfSalt: b64(randomBytes(32)) };
  expect(() => VaultService.addPasskey(vaultPath, { password: "wrong" }, { ...input, credentialId: "other" })).toThrow();
  expect(() => VaultService.addPasskey(vaultPath, { password: PASSWORD }, input)).toThrow("already registered");
  expect(VaultService.listPasskeys(vaultPath)).toHaveLength(1);
});

test("list exposes public details only and remove revokes access", () => {
  const first = register("laptop");
  register("phone");

  const listed = VaultService.listPasskeys(vaultPath);
  expect(listed.map((p) => p.label).sort()).toEqual(["laptop", "phone"]);
  expect(JSON.stringify(listed)).not.toContain("ciphertext");

  const removed = VaultService.removePasskey(vaultPath, { password: PASSWORD }, "laptop");
  expect(removed.id).toBe(first.info.id);
  expect(VaultService.listPasskeys(vaultPath).map((p) => p.label)).toEqual(["phone"]);
  expect(() => VaultService.unlock(vaultPath, { password: "", passkey: { credentialId: first.credentialId, prfOutput: first.prfOutput } }))
    .toThrow("not registered");
  expect(() => VaultService.removePasskey(vaultPath, { password: PASSWORD }, "laptop")).toThrow("No passkey");

  const session = VaultService.unlock(vaultPath, PASSWORD);
  try {
    expect(session.listAudit({ limit: 50 }).map((e) => e.eventType)).toContain("auth.passkey.removed");
  } finally {
    session.close();
  }
});

test("the PRF output is never stored in the vault file", () => {
  const { prfOutput } = register();
  const raw = readFileSync(vaultPath);
  expect(raw.includes(Buffer.from(prfOutput))).toBe(false);
  expect(raw.includes(Buffer.from(prfOutput, "base64url"))).toBe(false);
});
