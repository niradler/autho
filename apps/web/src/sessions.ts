import type { VaultAdmin } from "../../../packages/core/src/index.ts";
import { newToken, tokensEqual } from "./security.ts";

/** How long a re-authorization for security settings lasts. */
export const ADMIN_TTL_MS = 5 * 60_000;
/** Hard cap on a session, however active it is. */
export const MAX_SESSION_MS = 12 * 60 * 60_000;

export type WebSession = {
  id: string;
  csrf: string;
  rootKey: Buffer;
  /** The root key's wrap says the vault is sealed. */
  sealBound: boolean;
  createdAt: number;
  lastSeen: number;
  /** Set by a fresh credential check; closed when it expires or the session ends. */
  admin: { handle: VaultAdmin; expiresAt: number } | null;
  /** TOTP secret shown during setup, waiting for a confirming code. */
  pendingTotp: { secret: string; uri: string } | null;
  /** Passkey registration in flight: the salt we handed out. */
  pendingPasskey: { prfSalt: string } | null;
};

/**
 * In-memory sessions holding the vault root key. Keys are zeroed as soon as a
 * session ends, whether by lock, idle timeout or the hard cap.
 */
export class SessionStore {
  private readonly sessions = new Map<string, WebSession>();

  private readonly idleMs: () => number;
  private readonly onAdminEnd: (handle: VaultAdmin) => void;
  private readonly now: () => number;

  constructor(options: {
    /** Idle lock in ms, read on every check so a changed preference applies; 0 means only the hard cap. */
    idleMs: () => number;
    /** Called with each admin handle as it is released, to save its seal record and close it. */
    onAdminEnd: (handle: VaultAdmin) => void;
    now?: () => number;
  }) {
    this.idleMs = options.idleMs;
    this.onAdminEnd = options.onAdminEnd;
    this.now = options.now ?? (() => Date.now());
  }

  create(rootKey: Buffer, sealBound: boolean): WebSession {
    const at = this.now();
    const session: WebSession = {
      id: newToken(),
      csrf: newToken(),
      rootKey,
      sealBound,
      createdAt: at,
      lastSeen: at,
      admin: null,
      pendingTotp: null,
      pendingPasskey: null,
    };
    this.sessions.set(session.id, session);
    return session;
  }

  /** Finds a live session and marks it active. Null when missing, expired or the token doesn't match. */
  touch(id: string | undefined, csrf: string | null): WebSession | null {
    this.sweep();
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session || !tokensEqual(csrf, session.csrf)) return null;
    session.lastSeen = this.now();
    return session;
  }

  end(id: string | undefined): void {
    if (!id) return;
    const session = this.sessions.get(id);
    if (!session) return;
    this.sessions.delete(id);
    this.dropAdmin(session);
    session.rootKey.fill(0);
  }

  endAll(): void {
    for (const id of [...this.sessions.keys()]) this.end(id);
  }

  /** The admin handle when its authorization is still fresh. */
  admin(session: WebSession): VaultAdmin | null {
    if (session.admin && session.admin.expiresAt <= this.now()) this.dropAdmin(session);
    return session.admin?.handle ?? null;
  }

  grantAdmin(session: WebSession, handle: VaultAdmin): number {
    this.dropAdmin(session);
    const expiresAt = this.now() + ADMIN_TTL_MS;
    session.admin = { handle, expiresAt };
    return expiresAt;
  }

  dropAdmin(session: WebSession): void {
    if (!session.admin) return;
    const { handle } = session.admin;
    session.admin = null;
    session.pendingTotp = null;
    session.pendingPasskey = null;
    this.onAdminEnd(handle);
  }

  expiresAt(session: WebSession): { idleAt: number | null; hardAt: number } {
    const idle = this.idleMs();
    return { idleAt: idle > 0 ? session.lastSeen + idle : null, hardAt: session.createdAt + MAX_SESSION_MS };
  }

  /** Ends idle and over-age sessions; also run on a timer so keys don't outlive an idle tab. */
  sweep(): void {
    const at = this.now();
    for (const session of [...this.sessions.values()]) {
      const { idleAt, hardAt } = this.expiresAt(session);
      if (hardAt <= at || (idleAt !== null && idleAt <= at)) this.end(session.id);
    }
  }

  get size(): number {
    this.sweep();
    return this.sessions.size;
  }
}
