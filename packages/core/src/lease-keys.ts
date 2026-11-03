import { createHash } from "node:crypto";

import { randomId } from "../../crypto/src/index.ts";
import type { LeaseState, VaultSession } from "./index.ts";

export type LeaseKeyGrant = {
  deadline: number;
  expiresAt: string;
  leaseId: string;
  rootKey: Buffer;
  sealBound: boolean;
  secretIds: string[];
  vaultPath: string;
};

export class LeaseKeyRegistry {
  private readonly grants = new Map<string, LeaseKeyGrant>();

  constructor(private readonly now: () => number = Date.now, private readonly monotonic: () => number = () => performance.now()) {}

  issue(session: VaultSession, leaseId: string, vaultPath: string): { lease: LeaseState; leaseKey: string } {
    if (this.grants.size >= 256) throw new Error("Too many active lease keys");
    const { coverage, lease } = session.approveLeaseKey(leaseId);
    const remaining = Date.parse(lease.expiresAt) - this.now();
    if (!Number.isFinite(remaining) || remaining <= 0) throw new Error("Lease key expired");
    this.revoke(leaseId);
    const leaseKey = `autho_lease_${randomId(32)}`;
    this.grants.set(this.hash(leaseKey), {
      deadline: this.monotonic() + remaining,
      expiresAt: lease.expiresAt,
      leaseId,
      rootKey: session.getRootKey(),
      sealBound: session.sealBound,
      secretIds: coverage.map((secret) => secret.id),
      vaultPath,
    });
    return { lease, leaseKey };
  }

  get(key: string | null): LeaseKeyGrant | null {
    if (!key || !/^autho_lease_[a-f0-9]{64}$/.test(key)) return null;
    const grant = this.grants.get(this.hash(key));
    if (!grant) return null;
    if (this.expired(grant)) return null;
    return grant;
  }

  expired(grant: LeaseKeyGrant): boolean {
    return this.now() >= Date.parse(grant.expiresAt) || this.monotonic() >= grant.deadline;
  }

  list(): LeaseKeyGrant[] {
    return [...this.grants.values()];
  }

  revoke(leaseId: string): void {
    for (const [hash, grant] of this.grants) {
      if (grant.leaseId !== leaseId) continue;
      grant.rootKey.fill(0);
      this.grants.delete(hash);
    }
  }

  clear(): void {
    for (const grant of this.list()) this.revoke(grant.leaseId);
  }

  private hash(key: string): string {
    return createHash("sha256").update(key).digest("hex");
  }
}
