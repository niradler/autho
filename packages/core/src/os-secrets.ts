import { createHash, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";

const VAULT_PASSWORD_SERVICE = "autho.vault";
const USER_SECRETS_SERVICE = "autho";
const PIN_SERVICE = "autho.pin";

function vaultPasswordName(vaultPath: string): string {
  return createHash("sha256").update(resolve(vaultPath)).digest("hex");
}

export function osSecretsDisabled(): boolean {
  return process.env.AUTHO_DISABLE_OS_SECRETS === "1";
}

/**
 * Store the master password for a vault in the OS secret store.
 * Returns true on success, false if the backend is unavailable or disabled.
 */
export async function storeVaultPassword(vaultPath: string, password: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    await Bun.secrets.set({
      name: vaultPasswordName(vaultPath),
      service: VAULT_PASSWORD_SERVICE,
      value: password,
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Load the master password for a vault from the OS secret store.
 * Returns null if not stored, backend unavailable, or disabled.
 */
export async function loadVaultPassword(vaultPath: string): Promise<string | null> {
  if (osSecretsDisabled()) {
    return null;
  }

  try {
    const password = await Bun.secrets.get({
      name: vaultPasswordName(vaultPath),
      service: VAULT_PASSWORD_SERVICE,
    });
    return password ?? null;
  } catch {
    return null;
  }
}

/**
 * Delete the master password for a vault from the OS secret store.
 * Returns true if deleted, false if not found or unavailable.
 */
export async function deleteVaultPassword(vaultPath: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    return await Bun.secrets.delete({
      name: vaultPasswordName(vaultPath),
      service: VAULT_PASSWORD_SERVICE,
    });
  } catch {
    return false;
  }
}

/**
 * Store a named secret in the OS secret store.
 * Returns true on success, false if the backend is unavailable or disabled.
 */
export async function setOsSecret(name: string, value: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    await Bun.secrets.set({ name, service: USER_SECRETS_SERVICE, value });
    return true;
  } catch {
    return false;
  }
}

/**
 * Retrieve a named secret from the OS secret store.
 * Returns null if not found, backend unavailable, or disabled.
 */
export async function getOsSecret(name: string): Promise<string | null> {
  if (osSecretsDisabled()) {
    return null;
  }

  try {
    const value = await Bun.secrets.get({ name, service: USER_SECRETS_SERVICE });
    return value ?? null;
  } catch {
    return null;
  }
}

/**
 * Delete a named secret from the OS secret store.
 * Returns true if deleted, false if not found or unavailable.
 */
export async function deleteOsSecret(name: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    return await Bun.secrets.delete({ name, service: USER_SECRETS_SERVICE });
  } catch {
    return false;
  }
}

/**
 * Hash a PIN with a random salt and store the result in the OS secret store.
 * Stored format: "<salt_base64>:<hash_base64>"
 * Returns true on success, false if backend unavailable or disabled.
 */
export async function storePinHash(vaultPath: string, pin: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    const salt = randomBytes(16);
    const hash = scryptSync(pin, salt as unknown as Uint8Array, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const value = `${salt.toString("base64")}:${hash.toString("base64")}`;
    await Bun.secrets.set({ name: vaultPasswordName(vaultPath), service: PIN_SERVICE, value });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a PIN against the stored hash for a vault.
 * Returns true if the PIN matches, false if it doesn't or nothing is stored.
 */
export async function verifyPin(vaultPath: string, pin: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    const stored = await Bun.secrets.get({ name: vaultPasswordName(vaultPath), service: PIN_SERVICE });
    if (!stored) return false;

    const colonIdx = stored.indexOf(":");
    if (colonIdx === -1) return false;

    const salt = Buffer.from(stored.slice(0, colonIdx), "base64");
    const expectedHash = Buffer.from(stored.slice(colonIdx + 1), "base64");
    const actualHash = scryptSync(pin, salt as unknown as Uint8Array, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

    return timingSafeEqual(actualHash as unknown as Uint8Array, expectedHash as unknown as Uint8Array);
  } catch {
    return false;
  }
}

/**
 * Returns true if a PIN hash is stored for the given vault, false otherwise.
 */
export async function hasPinSet(vaultPath: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    const stored = await Bun.secrets.get({ name: vaultPasswordName(vaultPath), service: PIN_SERVICE });
    return stored != null;
  } catch {
    return false;
  }
}

/**
 * Delete the stored PIN hash for a vault.
 * Returns true if deleted, false if not found or unavailable.
 */
export async function deletePin(vaultPath: string): Promise<boolean> {
  if (osSecretsDisabled()) {
    return false;
  }

  try {
    return await Bun.secrets.delete({ name: vaultPasswordName(vaultPath), service: PIN_SERVICE });
  } catch {
    return false;
  }
}
