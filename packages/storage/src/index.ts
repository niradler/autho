import { Database } from "bun:sqlite";
import { chmodSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import type { EncryptedBlob, VaultConfig, VaultKdfConfig } from "../../crypto/src/index.ts";

export type VaultAuth = {
  version: 1;
  totp?: {
    encryptedSecret: EncryptedBlob;
    algorithm: "SHA1" | "SHA256" | "SHA512";
    digits: 6 | 8;
    period: 30;
  };
  recovery?: {
    wrappedRootKey: EncryptedBlob;
    kdf: VaultKdfConfig;
    createdAt: string;
  };
};

export type SecretRow = {
  createdAt: string;
  id: string;
  name: string;
  payload: string;
  type: string;
  updatedAt: string;
  wrappedKey: string;
};

export type LeaseRow = {
  createdAt: string;
  expiresAt: string;
  id: string;
  name: string;
  revokedAt: string | null;
  secretRefs: string;
};

export type AuditRow = {
  createdAt: string;
  eventType: string;
  id: string;
  message: string;
  metadata: string;
  subjectRef: string | null;
  subjectType: string;
};

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
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

export class AuthoDatabase {
  private readonly db: Database;

  constructor(private readonly vaultPath: string) {
    if (vaultPath !== ":memory:") {
      mkdirSync(dirname(vaultPath), { mode: 0o700, recursive: true });
      tryChmod(dirname(vaultPath), 0o700);
    }

    this.db = new Database(vaultPath, { create: true, strict: true });
    this.migrate();
    this.hardenStorageFiles();
  }

  close(): void {
    this.hardenStorageFiles();
    this.db.close();
  }

  private hardenStorageFiles(): void {
    if (this.vaultPath === ":memory:") {
      return;
    }

    for (const path of [this.vaultPath, `${this.vaultPath}-shm`, `${this.vaultPath}-wal`]) {
      if (existsSync(path)) {
        tryChmod(path, 0o600);
      }
    }
  }

  private migrate(): void {
    this.db.exec(`
      PRAGMA journal_mode = WAL;

      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS secrets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        payload TEXT NOT NULL,
        wrapped_key TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS leases (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        secret_refs TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        revoked_at TEXT,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        subject_type TEXT NOT NULL,
        subject_ref TEXT,
        message TEXT NOT NULL,
        metadata TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
  }

  getVaultConfig(): VaultConfig | null {
    const row = this.db
      .query("SELECT value FROM meta WHERE key = ?1")
      .get("vault.config") as { value: string } | null;

    return row ? parseJson<VaultConfig>(row.value) : null;
  }

  setVaultConfig(config: VaultConfig): void {
    this.db
      .query("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")
      .run("vault.config", JSON.stringify(config));
  }

  getVaultAuth(): VaultAuth | null {
    const row = this.db
      .query("SELECT value FROM meta WHERE key = ?1")
      .get("vault.auth") as { value: string } | null;
    return row ? parseJson<VaultAuth>(row.value) : null;
  }

  setVaultAuth(auth: VaultAuth): void {
    this.db
      .query("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)")
      .run("vault.auth", JSON.stringify(auth));
  }

  countSecrets(): number {
    const row = this.db.query("SELECT COUNT(*) AS count FROM secrets").get() as { count: number };
    return row.count;
  }

  countActiveLeases(nowIso: string): number {
    const row = this.db
      .query(
        `SELECT COUNT(*) AS count
         FROM leases
         WHERE revoked_at IS NULL AND expires_at > ?1`,
      )
      .get(nowIso) as { count: number };
    return row.count;
  }

  countAuditEvents(): number {
    const row = this.db.query("SELECT COUNT(*) AS count FROM audit_events").get() as { count: number };
    return row.count;
  }

  insertSecret(secret: SecretRow): void {
    this.db
      .query(
        `INSERT INTO secrets (id, name, type, payload, wrapped_key, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      )
      .run(
        secret.id,
        secret.name,
        secret.type,
        secret.payload,
        secret.wrappedKey,
        secret.createdAt,
        secret.updatedAt,
      );
  }

  listSecrets(): SecretRow[] {
    return this.db
      .query(
        `SELECT
           id,
           name,
           type,
           payload,
           wrapped_key AS wrappedKey,
           created_at AS createdAt,
           updated_at AS updatedAt
         FROM secrets
         ORDER BY created_at ASC`,
      )
      .all() as SecretRow[];
  }

  findSecret(ref: string): SecretRow | null {
    const row = this.db
      .query(
        `SELECT
           id,
           name,
           type,
           payload,
           wrapped_key AS wrappedKey,
           created_at AS createdAt,
           updated_at AS updatedAt
         FROM secrets
         WHERE id = ?1 OR name = ?1
         LIMIT 1`,
      )
      .get(ref) as SecretRow | null;

    return row ?? null;
  }

  updateSecret(id: string, updates: { name?: string; payload?: string; type?: string; updatedAt: string }): void {
    const parts: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (updates.name !== undefined) {
      parts.push(`name = ?${idx}`);
      values.push(updates.name);
      idx++;
    }
    if (updates.type !== undefined) {
      parts.push(`type = ?${idx}`);
      values.push(updates.type);
      idx++;
    }
    if (updates.payload !== undefined) {
      parts.push(`payload = ?${idx}`);
      values.push(updates.payload);
      idx++;
    }
    parts.push(`updated_at = ?${idx}`);
    values.push(updates.updatedAt);
    idx++;

    values.push(id);
    this.db.query(`UPDATE secrets SET ${parts.join(", ")} WHERE id = ?${idx}`).run(...values);
  }

  deleteSecret(id: string): void {
    this.db.query("DELETE FROM secrets WHERE id = ?1").run(id);
  }

  insertLease(lease: LeaseRow): void {
    this.db
      .query(
        `INSERT INTO leases (id, name, secret_refs, expires_at, revoked_at, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
      )
      .run(
        lease.id,
        lease.name,
        lease.secretRefs,
        lease.expiresAt,
        lease.revokedAt,
        lease.createdAt,
      );
  }

  findLease(id: string): LeaseRow | null {
    const row = this.db
      .query(
        `SELECT
           id,
           name,
           secret_refs AS secretRefs,
           expires_at AS expiresAt,
           revoked_at AS revokedAt,
           created_at AS createdAt
         FROM leases
         WHERE id = ?1
         LIMIT 1`,
      )
      .get(id) as LeaseRow | null;

    return row ?? null;
  }

  revokeLease(id: string, revokedAt: string): void {
    this.db
      .query("UPDATE leases SET revoked_at = ?2 WHERE id = ?1")
      .run(id, revokedAt);
  }

  insertAudit(event: AuditRow): void {
    this.db
      .query(
        `INSERT INTO audit_events (id, event_type, subject_type, subject_ref, message, metadata, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      )
      .run(
        event.id,
        event.eventType,
        event.subjectType,
        event.subjectRef,
        event.message,
        event.metadata,
        event.createdAt,
      );
  }

  listAudit(limit: number): AuditRow[] {
    return this.db
      .query(
        `SELECT
           id,
           event_type AS eventType,
           subject_type AS subjectType,
           subject_ref AS subjectRef,
           message,
           metadata,
           created_at AS createdAt
         FROM audit_events
         ORDER BY created_at DESC
         LIMIT ?1`,
      )
      .all(limit) as AuditRow[];
  }
}
