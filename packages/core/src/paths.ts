import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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

// ── Config ────────────────────────────────────────────────────────────

export type AuthoConfig = {
  vaultDir?: string;
  defaultLeaseTtl?: string;
  editor?: string;
  autoLock?: boolean;
  autoLockTimeout?: string;
};

const configCache: { value: AuthoConfig | null; loaded: boolean } = { value: null, loaded: false };

export function authoConfigDir(): string {
  return normalizePath(process.env.AUTHO_HOME ?? join(homedir(), ".autho"));
}

export function configFilePath(): string {
  return normalizePath(join(authoConfigDir(), "config.json"));
}

export function loadConfig(): AuthoConfig {
  if (configCache.loaded) return configCache.value ?? {};
  const path = configFilePath();
  if (!existsSync(path)) {
    configCache.loaded = true;
    configCache.value = {};
    return {};
  }
  try {
    const raw = JSON.parse(readFileSync(path, "utf8"));
    configCache.loaded = true;
    configCache.value = raw;
    return raw;
  } catch {
    configCache.loaded = true;
    configCache.value = {};
    return {};
  }
}

export function saveConfig(config: AuthoConfig): void {
  const path = configFilePath();
  ensurePrivateParent(path);
  writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { encoding: "utf8", mode: 0o600 });
  hardenFilePermissions(path);
  configCache.value = config;
  configCache.loaded = true;
}

export function resetConfigCache(): void {
  configCache.loaded = false;
  configCache.value = null;
}

// ── Path resolution ───────────────────────────────────────────────────

export function authoHomeDir(): string {
  if (process.env.AUTHO_HOME) {
    return normalizePath(process.env.AUTHO_HOME);
  }
  const config = loadConfig();
  if (config.vaultDir) {
    return normalizePath(config.vaultDir);
  }
  return normalizePath(join(homedir(), ".autho"));
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
