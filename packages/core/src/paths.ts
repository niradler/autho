import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

function normalizePath(path: string): string {
  return resolve(path).replace(/\\/g, "/");
}

function tryChmod(path: string, mode: number): void {
  if (process.platform === "win32") {
    return;
  }

  try {
    chmodSync(path, mode);
  } catch {
    // best-effort hardening only
  }
}

export function authoHomeDir(): string {
  return normalizePath(process.env.AUTHO_HOME ?? join(homedir(), ".autho"));
}

export function defaultVaultPath(): string {
  return normalizePath(join(authoHomeDir(), "vault.db"));
}

export function defaultProjectFilePath(): string {
  return normalizePath(join(authoHomeDir(), "project.json"));
}

export function defaultDaemonStatePath(): string {
  return normalizePath(join(authoHomeDir(), "daemon.json"));
}

export function ensurePrivateDir(path: string): void {
  mkdirSync(path, { mode: 0o700, recursive: true });
  tryChmod(path, 0o700);
}

export function ensurePrivateParent(path: string): void {
  ensurePrivateDir(dirname(path));
}

export function hardenFilePermissions(path: string): void {
  tryChmod(path, 0o600);
}

export function writeTextFileSecure(path: string, content: string): void {
  ensurePrivateParent(path);
  writeFileSync(path, content, { encoding: "utf8", mode: 0o600 });
  hardenFilePermissions(path);
}

export function writeBinaryFileSecure(path: string, content: Uint8Array | Buffer): void {
  ensurePrivateParent(path);
  writeFileSync(path, content, { mode: 0o600 });
  hardenFilePermissions(path);
}
