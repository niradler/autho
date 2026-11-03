import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { osSecretsDisabled } from "./os-secrets.ts";
import { writeTextFileSecure } from "./paths.ts";

const SERVICE = "autho.lease";

export type LeaseKeyringBackend = {
  get(name: string): Promise<string | null>;
  set(name: string, value: string): Promise<void>;
  delete(name: string): Promise<void>;
};

const osBackend: LeaseKeyringBackend = {
  async get(name) {
    if (osSecretsDisabled()) throw new Error("OS keyring is disabled");
    return await Bun.secrets.get({ name, service: SERVICE }) ?? null;
  },
  async set(name, value) {
    if (osSecretsDisabled()) throw new Error("OS keyring is disabled");
    await Bun.secrets.set({ name, service: SERVICE, value });
  },
  async delete(name) {
    if (osSecretsDisabled()) throw new Error("OS keyring is disabled");
    await Bun.secrets.delete({ name, service: SERVICE });
  },
};

type SavedLease = { expiresAt: string; leaseId: string };

export class LeaseKeyring {
  private pending: Promise<unknown> = Promise.resolve();

  constructor(private readonly statePath: string, private readonly backend: LeaseKeyringBackend = osBackend) {}

  private name(leaseId: string): string {
    if (!/^[a-f0-9]{32}$/.test(leaseId)) throw new Error("Invalid lease ID");
    return createHash("sha256").update(`${resolve(this.statePath)}\0${leaseId}`).digest("hex");
  }

  private entries(): SavedLease[] {
    const path = `${this.statePath}.leases.json`;
    if (!existsSync(path)) return [];
    const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
    if (!Array.isArray(parsed) || parsed.length > 4096) throw new Error("Invalid saved lease index");
    return parsed.map((entry: unknown) => {
      if (!entry || typeof entry !== "object") throw new Error("Invalid saved lease index");
      const { expiresAt, leaseId } = entry as Record<string, unknown>;
      if (typeof leaseId !== "string" || typeof expiresAt !== "string" || !Number.isFinite(Date.parse(expiresAt))) {
        throw new Error("Invalid saved lease index");
      }
      this.name(leaseId);
      return { expiresAt, leaseId };
    });
  }

  private write(entries: SavedLease[]): void {
    writeTextFileSecure(`${this.statePath}.leases.json`, JSON.stringify(entries) + "\n");
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.pending.then(operation);
    this.pending = result.catch(() => undefined);
    return result;
  }

  async save(leaseId: string, expiresAt: string, key: string): Promise<void> {
    return this.serialize(async () => {
      if (!Number.isFinite(Date.parse(expiresAt)) || Date.parse(expiresAt) <= Date.now()) throw new Error("Lease key expired");
      const entries = this.entries().filter((entry) => entry.leaseId !== leaseId);
      // Record the cleanup obligation before storing the credential, including crash recovery.
      this.write([...entries, { expiresAt, leaseId }]);
      await this.backend.set(this.name(leaseId), key);
    });
  }

  async load(leaseId: string): Promise<string> {
    return this.serialize(async () => {
      const entry = this.entries().find((saved) => saved.leaseId === leaseId);
      if (!entry) throw new Error("No saved key for this lease");
      if (Date.parse(entry.expiresAt) <= Date.now()) {
        await this.backend.delete(this.name(leaseId));
        throw new Error("Saved lease key expired");
      }
      const key = await this.backend.get(this.name(leaseId));
      if (!key) throw new Error("Lease key is unavailable in the OS keyring");
      return key;
    });
  }

  async forget(leaseId: string): Promise<void> {
    return this.serialize(async () => {
      const entries = this.entries();
      if (!entries.some((entry) => entry.leaseId === leaseId)) return;
      this.write(entries.map((entry) => entry.leaseId === leaseId ? { ...entry, expiresAt: new Date(0).toISOString() } : entry));
      await this.backend.delete(this.name(leaseId));
      this.write(entries.filter((entry) => entry.leaseId !== leaseId));
    });
  }

  async cleanup(all = false): Promise<boolean> {
    return this.serialize(async () => {
      const kept: SavedLease[] = [];
      for (const entry of this.entries()) {
        if (!all && Date.parse(entry.expiresAt) > Date.now()) {
          kept.push(entry);
          continue;
        }
        try {
          await this.backend.delete(this.name(entry.leaseId));
        } catch {
          kept.push({ ...entry, expiresAt: new Date(0).toISOString() });
        }
      }
      if (existsSync(`${this.statePath}.leases.json`)) this.write(kept);
      return all ? kept.length === 0 : kept.every((entry) => Date.parse(entry.expiresAt) > Date.now());
    });
  }
}
