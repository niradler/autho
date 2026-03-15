import {
  createCipheriv,
  createDecipheriv,
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
  N: 1 << 14,
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
    maxmem: 64 * 1024 * 1024,
    N: config.N,
    p: config.p,
    r: config.r,
  });
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

export function createVaultConfig(password: string): {
  config: VaultConfig;
  rootKey: Buffer;
} {
  const rootKey = randomBytes(32);
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
      wrappedRootKey: encryptWithKey(rootKey, key, "autho:vault-root"),
    },
    rootKey,
  };
}

export function unlockRootKey(password: string, config: VaultConfig): Buffer {
  const key = deriveKeyFromPassword(password, config.kdf);

  return decryptWithKey(config.wrappedRootKey, key, "autho:vault-root");
}


