import { createHmac, timingSafeEqual } from "node:crypto";

import {
  deriveKeyFromPassword,
  deriveKeyFromSecret,
  unwrapRootKey,
  wrapRootKey,
  randomId,
} from "../../crypto/src/index.ts";
import type { AuthoDatabase, ProtectedRow, SealRow } from "../../storage/src/index.ts";

/**
 * Vault seal: an HMAC over every row that decides what can be read (secrets,
 * links, leases and vault settings), keyed from the root key. Anything that
 * edits the SQLite file without the key can't produce a matching seal, so a
 * hand-edited lease or link is caught before it grants access.
 *
 * Audit events are not sealed: they are written constantly and don't decide
 * access.
 *
 * Version 2 adds a vault id and a counter that goes up on every write, both
 * under the root MAC. The caller keeps the last counter it saw outside the
 * file (the OS keychain, see SealRecord), so an older copy of the whole file
 * - which carries a valid seal of its own - is caught as a rollback.
 */

/** Row signatures haven't changed format since version 1. */
const ROW_MAC_VERSION = 1;
const SEAL_VERSION = 2;
const SEAL_INFO = "autho:vault-seal";

type StoredSeal = { counter?: number; mac: string; sealedAt: string; vaultId?: string; version: number };

/** The newest seal autho has seen for a vault, kept outside the vault file. */
export type SealRecord = { counter: number; vaultId: string };

export type SealChange = {
  change: "added" | "modified" | "removed";
  rowId: string;
  table: string;
};

export type SealState =
  | { state: "intact" }
  /** No seal yet (a vault from before sealing, not yet unlocked with the password). */
  | { state: "unsealed" }
  | {
      state: "tampered";
      changes: SealChange[];
      /** False when the stored per-row signatures were edited too, so `changes` can't be relied on. */
      diffTrusted: boolean;
      reason: string;
    };

export class VaultTamperedError extends Error {
  constructor(readonly seal: Extract<SealState, { state: "tampered" }>) {
    super(
      `Vault was modified outside autho (${seal.reason}). Run \`autho vault verify\` to see what changed, then \`autho vault reseal\`.`,
    );
    this.name = "VaultTamperedError";
  }
}

export function sealKey(rootKey: Buffer): Buffer {
  return deriveKeyFromSecret(rootKey, Buffer.from(`${SEAL_INFO}:v1`, "utf8"), SEAL_INFO);
}

function canonical(row: Record<string, unknown>): string {
  return JSON.stringify(Object.keys(row).sort().map((key) => [key, row[key] ?? null]));
}

function computeRowMac(key: Buffer, row: ProtectedRow): string {
  return createHmac("sha256", key)
    .update(`${ROW_MAC_VERSION}\0${row.tableName}\0${row.rowId}\0${canonical(row.row)}`)
    .digest("base64");
}

/** Signs one row and keeps a copy of it, so quarantine can put it back later. */
function rowMac(key: Buffer, row: ProtectedRow): SealRow {
  return { mac: computeRowMac(key, row), rowId: row.rowId, snapshot: JSON.stringify(row.row), tableName: row.tableName };
}

function rowKey(row: { rowId: string; tableName: string }): string {
  return `${row.tableName}\0${row.rowId}`;
}

function rootMac(key: Buffer, seal: Pick<StoredSeal, "counter" | "vaultId" | "version">, rows: SealRow[]): string {
  const lines = rows.map((row) => `${rowKey(row)}\0${row.mac}`).sort();
  const header = seal.version === 1 ? "autho-seal:v1" : `autho-seal:v2\n${seal.vaultId}\n${seal.counter}`;
  return createHmac("sha256", key).update(`${header}\n${lines.join("\n")}`).digest("base64");
}

function validSeal(seal: StoredSeal): boolean {
  if (seal.version === 1) return true;
  return seal.version === 2 && Number.isSafeInteger(seal.counter) && typeof seal.vaultId === "string" && seal.vaultId !== "";
}

function sameMac(a: string, b: string): boolean {
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  return left.length === right.length && timingSafeEqual(left, right);
}

function readSeal(db: AuthoDatabase): StoredSeal | null {
  const raw = db.getSeal();
  if (raw === null) return null;
  try {
    return JSON.parse(raw) as StoredSeal;
  } catch {
    return { mac: "", sealedAt: "", version: -1 };
  }
}

function diffRows(stored: SealRow[], current: SealRow[]): SealChange[] {
  const before = new Map(stored.map((row) => [rowKey(row), row]));
  const after = new Map(current.map((row) => [rowKey(row), row]));
  const changes: SealChange[] = [];
  for (const [id, row] of after) {
    const old = before.get(id);
    if (!old) changes.push({ change: "added", rowId: row.rowId, table: row.tableName });
    else if (!sameMac(old.mac, row.mac)) changes.push({ change: "modified", rowId: row.rowId, table: row.tableName });
  }
  for (const [id, row] of before) {
    if (!after.has(id)) changes.push({ change: "removed", rowId: row.rowId, table: row.tableName });
  }
  return changes;
}

/**
 * Checks the stored seal against the current rows. `expectSealed` is true
 * when the root key's wrap says this vault was sealed, so a missing seal
 * means someone deleted it rather than an old vault. `record` is the newest
 * seal seen for this vault path (from the OS keychain); with it, a missing
 * seal or an older counter is caught even without the wrap marker.
 */
export function verifySeal(db: AuthoDatabase, key: Buffer, expectSealed: boolean, record?: SealRecord | null): SealState {
  const stored = readSeal(db);
  if (!stored) {
    if (!expectSealed && !record) return { state: "unsealed" };
    return { changes: [], diffTrusted: false, reason: "the seal was removed", state: "tampered" };
  }
  if (!validSeal(stored)) {
    return { changes: [], diffTrusted: false, reason: "unknown seal format", state: "tampered" };
  }

  const current = db.listProtectedRows().map((row) => rowMac(key, row));
  if (sameMac(rootMac(key, stored, current), stored.mac)) {
    return rolledBack(stored, record) ? ROLLED_BACK : { state: "intact" };
  }

  const storedRows = db.listSealRows();
  const diffTrusted = sameMac(rootMac(key, stored, storedRows), stored.mac);
  return {
    changes: diffRows(storedRows, current),
    diffTrusted,
    reason: "rows changed without the vault key",
    state: "tampered",
  };
}

const ROLLED_BACK: SealState = {
  changes: [],
  diffTrusted: false,
  reason: "the vault file was replaced with an older copy",
  state: "tampered",
};

/**
 * An intact seal older than the one on record. A different vault id is a
 * different vault at the same path (re-created), not a rollback; a version 1
 * seal has no id and predates the record, so it is older by definition.
 */
function rolledBack(stored: StoredSeal, record: SealRecord | null | undefined): boolean {
  if (!record) return false;
  if (stored.vaultId !== undefined && stored.vaultId !== record.vaultId) return false;
  return (stored.counter ?? 0) < record.counter;
}

/** The vault id and counter of the stored seal; null before version 2. */
export function currentSealRecord(db: AuthoDatabase): SealRecord | null {
  const stored = readSeal(db);
  if (!stored || stored.version !== 2 || !validSeal(stored)) return null;
  return { counter: stored.counter!, vaultId: stored.vaultId! };
}

/**
 * Signs the current rows. Call inside the transaction that made the change.
 * The counter goes up by one, or to `minCounter` when that is higher (a
 * reseal must land above the counter on record). Returns the new record.
 */
export function writeSeal(db: AuthoDatabase, key: Buffer, options?: { minCounter?: number }): SealRecord {
  const previous = readSeal(db);
  const previousCounter = Number.isSafeInteger(previous?.counter) ? previous!.counter! : 0;
  const vaultId = typeof previous?.vaultId === "string" && previous.vaultId !== "" ? previous.vaultId : randomId();
  const counter = Math.max(previousCounter + 1, options?.minCounter ?? 0);

  const rows = db.listProtectedRows().map((row) => rowMac(key, row));
  const header = { counter, vaultId, version: SEAL_VERSION };
  const seal: StoredSeal = { ...header, mac: rootMac(key, header, rows), sealedAt: new Date().toISOString() };
  db.setSeal(JSON.stringify(seal), rows);
  return { counter, vaultId };
}

/**
 * The row as it was when sealed, if its stored copy still matches its
 * signature. Only a copy autho wrote passes, so quarantine can restore it.
 */
export function sealedSnapshot(key: Buffer, sealRow: SealRow): Record<string, unknown> | null {
  if (!sealRow.snapshot) return null;
  let row: unknown;
  try {
    row = JSON.parse(sealRow.snapshot);
  } catch {
    return null;
  }
  if (typeof row !== "object" || row === null || Array.isArray(row)) return null;
  const record = row as Record<string, unknown>;
  const mac = computeRowMac(key, { row: record, rowId: sealRow.rowId, tableName: sealRow.tableName });
  return sameMac(mac, sealRow.mac) ? record : null;
}

/**
 * Unwraps the root key with the master password. A vault from before sealing
 * is sealed here (trust on first use): its rows are signed and the root key
 * is re-wrapped with the "sealed" marker, so deleting the seal later is
 * caught instead of passing for an old vault. Runs only on a password unlock,
 * because re-wrapping needs the password key. Skipped when `record` says this
 * path already had a sealed vault: then the missing seal is reported instead.
 */
export function unlockWithPassword(
  db: AuthoDatabase,
  password: string,
  beforeUnwrap?: (passwordKey: Buffer) => void,
  record?: SealRecord | null,
  source: string | null = null,
): { rootKey: Buffer; sealBound: boolean } {
  const config = db.getVaultConfig();
  if (!config) {
    throw new Error("Vault is not initialized");
  }
  const passwordKey = deriveKeyFromPassword(password, config.kdf);
  beforeUnwrap?.(passwordKey);
  const { rootKey, sealed } = unwrapRootKey(config, passwordKey);
  if (sealed) {
    return { rootKey, sealBound: true };
  }
  if (record) {
    return { rootKey, sealBound: false };
  }

  const sealedNow = db.immediateTransaction(() => {
    // A seal next to an unsealed wrap means the settings were swapped back;
    // leave it for verify to report instead of blessing it.
    if (db.getSeal() !== null) return false;
    db.setVaultConfig({ ...config, wrappedRootKey: wrapRootKey(rootKey, passwordKey, true) });
    writeSeal(db, sealKey(rootKey));
    db.insertAudit({
      createdAt: new Date().toISOString(),
      eventType: "vault.sealed.initial",
      id: randomId(),
      leaseId: null,
      message: "Vault sealed for the first time",
      metadata: JSON.stringify({}),
      source,
      subjectRef: null,
      subjectType: "vault",
    });
    return true;
  });
  return { rootKey, sealBound: sealedNow };
}
