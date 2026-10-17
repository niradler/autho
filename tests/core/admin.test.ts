import { afterEach, beforeEach, expect, test } from "bun:test";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { MIN_PASSWORD_LENGTH, VaultService } from "../../packages/core/src/index.ts";

const PASSWORD = "correct-horse-battery";
const NEW_PASSWORD = "a-brand-new-passphrase";

let dir: string;
let vaultPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "autho-admin-"));
  vaultPath = join(dir, "vault.db");
  VaultService.initialize(vaultPath, PASSWORD);
  const session = VaultService.unlock(vaultPath, PASSWORD);
  session.addSecret({ name: "api", type: "note", value: "kept-across-password-change" });
  session.close();
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

/** Current code for a TOTP secret, computed by a throwaway vault's OTP entry. */
function totpCode(secret: string): string {
  const scratch = join(dir, "codes.db");
  if (!existsSync(scratch)) VaultService.initialize(scratch, PASSWORD);
  const session = VaultService.unlock(scratch, PASSWORD);
  try {
    const name = `otp-${Math.random()}`;
    session.addSecret({ name, type: "otp", value: secret });
    return session.generateOtp(name).code;
  } finally {
    session.close();
  }
}

function readNote(password: string, totp?: string): string {
  const session = VaultService.unlock(vaultPath, { password, totp });
  try {
    return session.getSecret("api").value;
  } finally {
    session.close();
  }
}

test("authorize rejects a wrong password", () => {
  expect(() => VaultService.authorize(vaultPath, { password: "wrong-password" })).toThrow();
});

test("changePassword re-wraps the key: the new password unlocks, the old one does not", () => {
  const admin = VaultService.authorize(vaultPath, { password: PASSWORD });
  try {
    admin.changePassword(NEW_PASSWORD);
    expect(admin.masterPassword()).toBe(NEW_PASSWORD);
  } finally {
    admin.close();
  }
  expect(readNote(NEW_PASSWORD)).toBe("kept-across-password-change");
  expect(() => VaultService.unlock(vaultPath, PASSWORD)).toThrow();
});

test("changePassword enforces the minimum length and leaves the vault untouched", () => {
  const admin = VaultService.authorize(vaultPath, { password: PASSWORD });
  try {
    expect(() => admin.changePassword("x".repeat(MIN_PASSWORD_LENGTH - 1))).toThrow(/at least/);
  } finally {
    admin.close();
  }
  expect(readNote(PASSWORD)).toBe("kept-across-password-change");
});

test("with two-factor codes on, changing the password keeps the code working", () => {
  const { secret } = VaultService.setupTotp(vaultPath);
  VaultService.enableTotp(vaultPath, { password: PASSWORD }, secret, totpCode(secret));

  expect(() => VaultService.authorize(vaultPath, { password: PASSWORD })).toThrow();
  const admin = VaultService.authorize(vaultPath, { password: PASSWORD, totp: totpCode(secret) });
  try {
    admin.changePassword(NEW_PASSWORD);
  } finally {
    admin.close();
  }

  expect(readNote(NEW_PASSWORD, totpCode(secret))).toBe("kept-across-password-change");
  expect(() => VaultService.unlock(vaultPath, { password: PASSWORD, totp: totpCode(secret) })).toThrow();
});

test("one admin handle runs several changes and is unusable after close", () => {
  const admin = VaultService.authorize(vaultPath, { password: PASSWORD });
  const { fileContent } = admin.generateRecovery();
  expect(fileContent.length).toBeGreaterThan(0);
  admin.revokeRecovery();
  admin.changePassword(NEW_PASSWORD);
  admin.close();
  expect(() => admin.changePassword("another-password")).toThrow();
  expect(VaultService.getAuthConfig(vaultPath)?.recovery).toBeUndefined();

  const session = VaultService.unlock(vaultPath, NEW_PASSWORD);
  try {
    const events = session.listAudit(50).map((e) => e.eventType);
    expect(events).toContain("auth.password.changed");
  } finally {
    session.close();
  }
});
