import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  hkdfSync,
  randomBytes,
  scryptSync,
} from "node:crypto";

export type EncryptedBlob = {
  algorithm: "aes-256-gcm";
  ciphertext: string;
  iv: string;
  tag: string;
};

export type VaultKdfConfig = {
  keyLength: number;
  name: "scrypt";
  salt: string;
  N: number;
  p: number;
  r: number;
};

export type VaultConfig = {
  createdAt: string;
  kdf: VaultKdfConfig;
  version: 1;
  wrappedRootKey: EncryptedBlob;
};

const DEFAULT_KDF: VaultKdfConfig = {
  keyLength: 32,
  name: "scrypt",
  salt: "",
  N: 1 << 17,
  p: 1,
  r: 8,
};

function toBuffer(value: Buffer | string): Buffer {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, "utf8");
}

export function randomId(size = 16): string {
  return randomBytes(size).toString("hex");
}

export function deriveKeyFromPassword(
  password: string,
  config: VaultKdfConfig,
): Buffer {
  return scryptSync(password, Buffer.from(config.salt, "base64"), config.keyLength, {
    maxmem: 256 * 1024 * 1024,
    N: config.N,
    p: config.p,
    r: config.r,
  });
}

/**
 * HKDF-SHA256 for inputs that are already high-entropy keys, such as a
 * WebAuthn PRF output. Never use this for passwords: they need scrypt.
 */
export function deriveKeyFromSecret(secret: Buffer, salt: Buffer, info: string, length = 32): Buffer {
  if (secret.length < 32) {
    throw new Error("Key material must be at least 32 bytes");
  }
  return Buffer.from(hkdfSync("sha256", secret, salt, Buffer.from(info, "utf8"), length));
}

export function encryptWithKey(
  value: Buffer | string,
  key: Buffer,
  aad: string,
): EncryptedBlob {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(aad, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(toBuffer(value)), cipher.final()]);

  return {
    algorithm: "aes-256-gcm",
    ciphertext: ciphertext.toString("base64"),
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
  };
}

export function decryptWithKey(
  blob: EncryptedBlob,
  key: Buffer,
  aad: string,
): Buffer {
  const decipher = createDecipheriv(
    blob.algorithm,
    key,
    Buffer.from(blob.iv, "base64"),
  );
  decipher.setAAD(Buffer.from(aad, "utf8"));
  decipher.setAuthTag(Buffer.from(blob.tag, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(blob.ciphertext, "base64")),
    decipher.final(),
  ]);
}

const ROOT_AAD = "autho:vault-root";
/**
 * AAD for a root key wrapped by a vault that carries an integrity seal. It
 * records "this vault is sealed" where only the password holder can change
 * it, so deleting the seal can't pass for a vault that predates sealing.
 */
const SEALED_ROOT_AAD = "autho:vault-root:sealed";

/** Wraps a root key under an already-derived password key. */
export function wrapRootKey(rootKey: Buffer, passwordKey: Buffer, sealed: boolean): EncryptedBlob {
  return encryptWithKey(rootKey, passwordKey, sealed ? SEALED_ROOT_AAD : ROOT_AAD);
}

/** Wraps a new (or, for a password change, the existing) root key under `password`. */
export function createVaultConfig(password: string, rootKey: Buffer = randomBytes(32), options?: { sealed?: boolean }): {
  config: VaultConfig;
  rootKey: Buffer;
} {
  const kdf: VaultKdfConfig = {
    ...DEFAULT_KDF,
    salt: randomBytes(16).toString("base64"),
  };
  const key = deriveKeyFromPassword(password, kdf);

  return {
    config: {
      createdAt: new Date().toISOString(),
      kdf,
      version: 1,
      wrappedRootKey: wrapRootKey(rootKey, key, options?.sealed ?? false),
    },
    rootKey,
  };
}

/** Unwraps the root key with an already-derived password key, and reports which wrap it was. */
export function unwrapRootKey(config: VaultConfig, passwordKey: Buffer): { rootKey: Buffer; sealed: boolean } {
  try {
    return { rootKey: decryptWithKey(config.wrappedRootKey, passwordKey, SEALED_ROOT_AAD), sealed: true };
  } catch {
    return { rootKey: decryptWithKey(config.wrappedRootKey, passwordKey, ROOT_AAD), sealed: false };
  }
}

export function unlockRootKey(password: string, config: VaultConfig): Buffer {
  return unwrapRootKey(config, deriveKeyFromPassword(password, config.kdf)).rootKey;
}

// ---------------------------------------------------------------------------
// TOTP helpers
// ---------------------------------------------------------------------------

function decodeBase32(input: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (const char of normalized) {
    const index = alphabet.indexOf(char);
    if (index === -1) {
      throw new Error("OTP secret must be valid base32");
    }
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return Uint8Array.from(output);
}

function generateTotpCode(
  secret: string,
  options: { algorithm?: string; digits?: number } | undefined,
  now: number,
): string {
  const algorithm = (options?.algorithm ?? "sha1").toLowerCase();
  const digits = options?.digits ?? 6;
  const key = decodeBase32(secret);
  const counter = Math.floor(now / 30_000);
  const message = Buffer.alloc(8);
  let cursor = counter;

  for (let index = 7; index >= 0; index -= 1) {
    message[index] = cursor & 0xff;
    cursor >>= 8;
  }

  const hash = createHmac(algorithm, Buffer.from(key)).update(message).digest();
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);
  const mod = 10 ** digits;

  return String(binary % mod).padStart(digits, "0");
}

export function generateTotpSecret(): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes = randomBytes(20);
  let bits = 0;
  let value = 0;
  let result = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      result += alphabet[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 0x1f];
  }

  return result;
}

export function totpUri(secret: string, issuer: string, account: string): string {
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function verifyTotpCode(
  secret: string,
  code: string,
  opts?: { algorithm?: string; digits?: number },
): boolean {
  const digits = opts?.digits ?? 6;
  if (code.length !== digits) {
    return false;
  }
  const now = Date.now();

  for (const offset of [-30_000, 0, 30_000]) {
    if (generateTotpCode(secret, opts, now + offset) === code) {
      return true;
    }
  }

  return false;
}


