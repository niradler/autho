import { randomBytes, timingSafeEqual } from "node:crypto";

/**
 * The web UI holds an unlocked vault, so every request is treated as hostile
 * until it proves it comes from our own page:
 * - Host must be a loopback name for our port (blocks DNS rebinding).
 * - API calls must be same-origin (Origin / Sec-Fetch-Site) and carry a custom
 *   header, which a cross-site form or <img> can't send without a preflight.
 * - Authenticated calls also need the session's CSRF token. Cookies are not
 *   isolated by port, so the cookie alone must never be enough.
 */

const LOOPBACK_HOSTS = ["localhost", "127.0.0.1", "[::1]"];

export function isLoopbackHost(host: string): boolean {
  return host === "localhost" || host === "::1" || host === "[::1]" || /^127(\.\d{1,3}){3}$/.test(host);
}

export function allowedHosts(port: number): Set<string> {
  return new Set(LOOPBACK_HOSTS.map((host) => `${host}:${port}`));
}

export function hostAllowed(request: Request, hosts: Set<string>): boolean {
  const host = request.headers.get("host");
  return host !== null && hosts.has(host.toLowerCase());
}

/** Same-origin check for API calls. Browsers always send Origin on POST/PUT/DELETE; GETs send Sec-Fetch-Site. */
export function sameOrigin(request: Request, hosts: Set<string>): boolean {
  const origin = request.headers.get("origin");
  if (origin !== null) {
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      return false;
    }
    if (parsed.protocol !== "http:" || !hosts.has(parsed.host.toLowerCase())) return false;
    // The origin must match the Host the request was sent to, not just any loopback name.
    if (parsed.host.toLowerCase() !== request.headers.get("host")?.toLowerCase()) return false;
  }
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") return false;
  // No Origin and no Sec-Fetch-Site: not a browser (curl, tests). It still needs the custom header and the CSRF token.
  return true;
}

export function newToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function tokensEqual(candidate: string | null | undefined, expected: string): boolean {
  if (!candidate) return false;
  const a = Buffer.from(candidate);
  const b = Buffer.from(expected);
  return a.length === b.length && timingSafeEqual(a, b);
}

export const CSRF_HEADER = "x-autho-csrf";
/** Sent by our page on every API call, including unlock (which has no session yet). */
export const REQUEST_HEADER = "x-autho-request";

const BASE_HEADERS: Record<string, string> = {
  "cache-control": "no-store",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-create=(self), publickey-credentials-get=(self)",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

export function securityHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return { ...BASE_HEADERS, ...extra };
}

/**
 * Scripts only run with this response's nonce. Styles allow 'unsafe-inline'
 * because the UI's component libraries set positioning styles at runtime;
 * CSS can't run code, and connect-src 'self' keeps it from calling out.
 */
export function pageCsp(nonce: string): string {
  return [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/** Adds the nonce to every inline <script> in the built page. */
export function withNonce(html: string, nonce: string): string {
  return html.replace(/<script(?=[\s>])/g, `<script nonce="${nonce}"`);
}

/**
 * Slows down password guessing: after a few misses each attempt waits longer,
 * up to a cap. Local-only server, so one global counter is enough.
 */
export class UnlockThrottle {
  private failures = 0;
  private blockedUntil = 0;
  private busy = false;

  constructor(private readonly freeAttempts = 5, private readonly maxDelayMs = 5 * 60_000, private readonly now = () => Date.now()) {}

  /** Milliseconds until the next attempt is allowed; 0 when it may go ahead. */
  retryAfterMs(): number {
    return Math.max(0, this.blockedUntil - this.now());
  }

  /**
   * Claims the one attempt slot, synchronously, before any await: otherwise a
   * burst of parallel guesses would all pass the delay check before the first
   * failure is counted. False while blocked or while another attempt runs.
   */
  begin(): boolean {
    if (this.busy || this.retryAfterMs() > 0) return false;
    this.busy = true;
    return true;
  }

  fail(): void {
    this.busy = false;
    this.failures += 1;
    if (this.failures >= this.freeAttempts) {
      const delay = Math.min(this.maxDelayMs, 1000 * 2 ** (this.failures - this.freeAttempts));
      this.blockedUntil = this.now() + delay;
    }
  }

  succeed(): void {
    this.busy = false;
    this.failures = 0;
    this.blockedUntil = 0;
  }
}
