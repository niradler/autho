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
  /** WebAuthn credentials whose PRF output wraps the root key. */
  passkeys?: VaultPasskey[];
};

export type VaultPasskey = {
  id: string;
  /** base64url credential ID, passed to the browser as allowCredentials. */
  credentialId: string;
  label: string;
  /** base64url PRF input. Not secret: the authenticator's key is what matters. */
  prfSalt: string;
  wrappedRootKey: EncryptedBlob;
  createdAt: string;
  transports?: string[];
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
  /** 1 when the lease also covers secrets linked from its secrets. */
  includeLinks: number;
  name: string;
  revokedAt: string | null;
  secretRefs: string;
};

export type LinkRow = {
  createdAt: string;
  linkedId: string;
  primaryId: string;
};

/** Stored signature of one protected row, kept to tell which rows changed. */
export type SealRow = {
  mac: string;
  rowId: string;
  /** JSON copy of the row as sealed; null for rows sealed before copies were kept. */
  snapshot: string | null;
  tableName: string;
};

/**
 * Columns of each table the vault seal covers. Listed explicitly, so adding a
 * column later doesn't silently change what an existing seal signed.
 */
const PROTECTED_COLUMNS = {
  leases: ["id", "name", "secret_refs", "expires_at", "revoked_at", "created_at", "include_links"],
  meta: ["key", "value"],
  secret_links: ["primary_id", "linked_id", "created_at"],
  secrets: ["id", "name", "type", "payload", "wrapped_key", "created_at", "updated_at"],
} as const;

type ProtectedTable = keyof typeof PROTECTED_COLUMNS;

function protectedTable(tableName: string): ProtectedTable {
  if (!Object.hasOwn(PROTECTED_COLUMNS, tableName)) {
    throw new Error(`Not a sealed table: ${tableName}`);
  }
  return tableName as ProtectedTable;
}

/** WHERE clause and values that select one protected row by its seal row id. */
function protectedRowWhere(table: ProtectedTable, rowId: string): { sql: string; values: string[] } {
  if (table === "secret_links") {
    const [primaryId, linkedId] = rowId.split(">");
    return { sql: "primary_id = ?1 AND linked_id = ?2", values: [primaryId ?? "", linkedId ?? ""] };
  }
  return { sql: `${table === "meta" ? "key" : "id"} = ?1`, values: [rowId] };
}

/** A row the vault seal covers, as plain column values. */
export type ProtectedRow = {
  row: Record<string, unknown>;
  rowId: string;
  tableName: string;
};

/** Meta key holding the vault seal; the seal never covers itself. */
export const SEAL_META_KEY = "vault.seal";

export type AuditRow = {
  createdAt: string;
  eventType: string;
  id: string;
  /** The lease the access went through, when there was one. */
  leaseId: string | null;
  message: string;
  metadata: string;
  /** The interface that made the change: cli, tui, web or daemon. Null on events from before sources were recorded. */
  source: string | null;
  subjectRef: string | null;
  subjectType: string;
};

/** Narrows an audit listing; `eventType` matches a prefix, so "secret." finds every secret event. */
export type AuditFilter = {
  eventType?: string;
  leaseId?: string;
  limit: number;
  /** Matches events about the secret and env/exec/lease events that list it. */
  secretId?: string;
  source?: string;
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

  /** Runs `fn` in one SQLite transaction: all of its writes land, or none do. */
  transaction<T>(fn: () => T): T {
    return this.db.transaction(fn)();
  }

  /**
   * Like transaction(), but takes the write lock up front (BEGIN IMMEDIATE),
   * so a check made at the start still holds when the writes land.
   */
  immediateTransaction<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate();
  }

  get inTransaction(): boolean {
    return this.db.inTransaction;
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

      CREATE TABLE IF NOT EXISTS secret_links (
        primary_id TEXT NOT NULL,
        linked_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (primary_id, linked_id)
      );
      CREATE INDEX IF NOT EXISTS secret_links_linked ON secret_links (linked_id);

      CREATE TABLE IF NOT EXISTS seal_rows (
        table_name TEXT NOT NULL,
        row_id TEXT NOT NULL,
        mac TEXT NOT NULL,
        PRIMARY KEY (table_name, row_id)
      );
    `);

    const leaseColumns = this.db.query("PRAGMA table_info(leases)").all() as { name: string }[];
    if (!leaseColumns.some((column) => column.name === "include_links")) {
      this.db.exec("ALTER TABLE leases ADD COLUMN include_links INTEGER NOT NULL DEFAULT 1");
    }
    const sealRowColumns = this.db.query("PRAGMA table_info(seal_rows)").all() as { name: string }[];
    if (!sealRowColumns.some((column) => column.name === "row_json")) {
      this.db.exec("ALTER TABLE seal_rows ADD COLUMN row_json TEXT");
    }
    const auditColumns = this.db.query("PRAGMA table_info(audit_events)").all() as { name: string }[];
    if (!auditColumns.some((column) => column.name === "source")) {
      this.db.exec("ALTER TABLE audit_events ADD COLUMN source TEXT");
    }
    if (!auditColumns.some((column) => column.name === "lease_id")) {
      this.db.exec("ALTER TABLE audit_events ADD COLUMN lease_id TEXT");
    }
    this.db.exec("CREATE INDEX IF NOT EXISTS audit_events_created_at ON audit_events (created_at)");
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
    const values: string[] = [];
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

  /** Deletes a secret and every link to or from it. */
  deleteSecret(id: string): void {
    this.db.query("DELETE FROM secret_links WHERE primary_id = ?1 OR linked_id = ?1").run(id);
    this.db.query("DELETE FROM secrets WHERE id = ?1").run(id);
  }

  insertLink(link: LinkRow): void {
    this.db
      .query("INSERT OR IGNORE INTO secret_links (primary_id, linked_id, created_at) VALUES (?1, ?2, ?3)")
      .run(link.primaryId, link.linkedId, link.createdAt);
  }

  /** Returns true when a link was removed. */
  deleteLink(primaryId: string, linkedId: string): boolean {
    return (
      this.db.query("DELETE FROM secret_links WHERE primary_id = ?1 AND linked_id = ?2").run(primaryId, linkedId)
        .changes > 0
    );
  }

  hasLink(primaryId: string, linkedId: string): boolean {
    return (
      this.db.query("SELECT 1 FROM secret_links WHERE primary_id = ?1 AND linked_id = ?2").get(primaryId, linkedId) !==
      null
    );
  }

  /** Links where `id` is the primary. */
  listLinksFrom(id: string): LinkRow[] {
    return this.db
      .query(
        `SELECT primary_id AS primaryId, linked_id AS linkedId, created_at AS createdAt
         FROM secret_links WHERE primary_id = ?1 ORDER BY created_at ASC`,
      )
      .all(id) as LinkRow[];
  }

  /** Links where `id` is the linked secret. */
  listLinksTo(id: string): LinkRow[] {
    return this.db
      .query(
        `SELECT primary_id AS primaryId, linked_id AS linkedId, created_at AS createdAt
         FROM secret_links WHERE linked_id = ?1 ORDER BY created_at ASC`,
      )
      .all(id) as LinkRow[];
  }

  listLinks(): LinkRow[] {
    return this.db
      .query("SELECT primary_id AS primaryId, linked_id AS linkedId, created_at AS createdAt FROM secret_links")
      .all() as LinkRow[];
  }

  insertLease(lease: LeaseRow): void {
    this.db
      .query(
        `INSERT INTO leases (id, name, secret_refs, expires_at, revoked_at, created_at, include_links)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
      )
      .run(
        lease.id,
        lease.name,
        lease.secretRefs,
        lease.expiresAt,
        lease.revokedAt,
        lease.createdAt,
        lease.includeLinks,
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
           created_at AS createdAt,
           include_links AS includeLinks
         FROM leases
         WHERE id = ?1
         LIMIT 1`,
      )
      .get(id) as LeaseRow | null;

    return row ?? null;
  }

  /** Newest first. */
  listLeases(limit: number): LeaseRow[] {
    return this.db
      .query(
        `SELECT
           id,
           name,
           secret_refs AS secretRefs,
           expires_at AS expiresAt,
           revoked_at AS revokedAt,
           created_at AS createdAt,
           include_links AS includeLinks
         FROM leases
         ORDER BY created_at DESC
         LIMIT ?1`,
      )
      .all(limit) as LeaseRow[];
  }

  revokeLease(id: string, revokedAt: string): void {
    this.db
      .query("UPDATE leases SET revoked_at = ?2 WHERE id = ?1")
      .run(id, revokedAt);
  }

  /** Revokes every lease that is still active. Returns how many were revoked. */
  revokeActiveLeases(nowIso: string): number {
    return this.db
      .query("UPDATE leases SET revoked_at = ?1 WHERE revoked_at IS NULL AND expires_at > ?1")
      .run(nowIso).changes;
  }

  /** Every row the vault seal covers, with the columns in PROTECTED_COLUMNS. */
  listProtectedRows(): ProtectedRow[] {
    const select = (table: ProtectedTable) => `SELECT ${PROTECTED_COLUMNS[table].join(", ")} FROM ${table}`;
    const secrets = this.db.query(select("secrets")).all() as Record<string, unknown>[];
    const links = this.db.query(select("secret_links")).all() as Record<string, unknown>[];
    const leases = this.db.query(select("leases")).all() as Record<string, unknown>[];
    const meta = this.db.query(`${select("meta")} WHERE key != ?1`).all(SEAL_META_KEY) as Record<string, unknown>[];

    return [
      ...secrets.map((row) => ({ row, rowId: String(row.id), tableName: "secrets" })),
      ...links.map((row) => ({ row, rowId: `${row.primary_id}>${row.linked_id}`, tableName: "secret_links" })),
      ...leases.map((row) => ({ row, rowId: String(row.id), tableName: "leases" })),
      ...meta.map((row) => ({ row, rowId: String(row.key), tableName: "meta" })),
    ];
  }

  getSeal(): string | null {
    const row = this.db.query("SELECT value FROM meta WHERE key = ?1").get(SEAL_META_KEY) as { value: string } | null;
    return row?.value ?? null;
  }

  /** Stores the seal and the per-row signatures (and row copies) it was computed from. */
  setSeal(seal: string, rows: SealRow[]): void {
    this.db.query("INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)").run(SEAL_META_KEY, seal);
    this.db.exec("DELETE FROM seal_rows");
    const insert = this.db.query("INSERT INTO seal_rows (table_name, row_id, mac, row_json) VALUES (?1, ?2, ?3, ?4)");
    for (const row of rows) {
      insert.run(row.tableName, row.rowId, row.mac, row.snapshot);
    }
  }

  listSealRows(): SealRow[] {
    return this.db
      .query("SELECT table_name AS tableName, row_id AS rowId, mac, row_json AS snapshot FROM seal_rows")
      .all() as SealRow[];
  }

  /** Deletes one sealed row by its seal row id. The seal itself can't be deleted this way. */
  deleteProtectedRow(tableName: string, rowId: string): void {
    const table = protectedTable(tableName);
    if (table === "meta" && rowId === SEAL_META_KEY) {
      throw new Error("The seal is not a protected row");
    }
    const where = protectedRowWhere(table, rowId);
    this.db.query(`DELETE FROM ${table} WHERE ${where.sql}`).run(...where.values);
  }

  /** Inserts a sealed row from a copy, using only the table's sealed columns. */
  insertProtectedRow(tableName: string, row: Record<string, unknown>): void {
    const table = protectedTable(tableName);
    const columns = PROTECTED_COLUMNS[table];
    if (table === "meta" && row.key === SEAL_META_KEY) {
      throw new Error("The seal is not a protected row");
    }
    const placeholders = columns.map((_, index) => `?${index + 1}`).join(", ");
    const values = columns.map((column) => (row[column] ?? null) as string | number | null);
    this.db.query(`INSERT INTO ${table} (${columns.join(", ")}) VALUES (${placeholders})`).run(...values);
  }

  insertAudit(event: AuditRow): void {
    this.db
      .query(
        `INSERT INTO audit_events (id, event_type, subject_type, subject_ref, message, metadata, created_at, source, lease_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
      )
      .run(
        event.id,
        event.eventType,
        event.subjectType,
        event.subjectRef,
        event.message,
        event.metadata,
        event.createdAt,
        event.source,
        event.leaseId,
      );
  }

  listAudit(filter: AuditFilter): AuditRow[] {
    const conditions: string[] = [];
    const values: string[] = [];
    if (filter.source) {
      values.push(filter.source);
      conditions.push(`source = ?${values.length}`);
    }
    if (filter.eventType) {
      values.push(`${filter.eventType.replace(/[\\%_]/g, "\\$&")}%`);
      conditions.push(`event_type LIKE ?${values.length} ESCAPE '\\'`);
    }
    if (filter.leaseId) {
      values.push(filter.leaseId);
      conditions.push(`lease_id = ?${values.length}`);
    }
    if (filter.secretId) {
      values.push(filter.secretId, `%"id":"${filter.secretId.replace(/[\\%_"]/g, "")}"%`);
      conditions.push(`(subject_ref = ?${values.length - 1} OR metadata LIKE ?${values.length})`);
    }
    const where = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";
    return this.db
      .query(
        `SELECT
           id,
           event_type AS eventType,
           subject_type AS subjectType,
           subject_ref AS subjectRef,
           message,
           metadata,
           source,
           lease_id AS leaseId,
           created_at AS createdAt
         FROM audit_events
         ${where}
         ORDER BY created_at DESC
         LIMIT ?${values.length + 1}`,
      )
      .all(...values, filter.limit) as AuditRow[];
  }

  /** Deletes audit events older than `beforeIso`; returns how many went. */
  pruneAudit(beforeIso: string): number {
    return this.db.query("DELETE FROM audit_events WHERE created_at < ?1").run(beforeIso).changes;
  }
}
