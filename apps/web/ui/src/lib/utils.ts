import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import type { SecretType } from "./api.ts";

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

export const MASK = "••••••••••••";

/** Same glyphs and colours as the TUI. */
export const TYPE_META: Record<SecretType, { glyph: string; label: string; color: string }> = {
  password: { glyph: "●", label: "Login", color: "text-accent" },
  note: { glyph: "■", label: "Secure note", color: "text-info" },
  otp: { glyph: "◆", label: "OTP", color: "text-success" },
};

/** Random password from an unambiguous alphabet, using rejection sampling (matches the TUI). */
export function generatePassword(length = 24, symbols = true): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" + (symbols ? "!@#$%^&*-_=+" : "");
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) out += alphabet[byte % alphabet.length];
    }
  }
  return out;
}

/** Subsequence fuzzy score, as in the TUI: higher is better, null when it doesn't match. */
export function fuzzyScore(query: string, target: string): number | null {
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  if (!q) return 0;
  const direct = t.indexOf(q);
  if (direct !== -1) return 1000 - direct;
  let score = 0;
  let ti = 0;
  let run = 0;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found === -1) return null;
    run = found === ti ? run + 1 : 0;
    const wordStart = found === 0 || /[\s\-_./@]/.test(t[found - 1] ?? "");
    score += 1 + run * 2 + (wordStart ? 3 : 0);
    ti = found + 1;
  }
  return score;
}

export function fuzzyFilter<T>(items: T[], query: string, fields: (item: T) => Array<string | null | undefined>): T[] {
  if (!query.trim()) return items;
  const scored: Array<{ item: T; score: number }> = [];
  for (const item of items) {
    let best: number | null = null;
    fields(item).forEach((field, index) => {
      if (!field) return;
      const s = fuzzyScore(query, field);
      // Earlier fields (name) weigh more than later ones (url, description).
      if (s !== null) best = best === null ? s - index * 5 : Math.max(best, s - index * 5);
    });
    if (best !== null) scored.push({ item, score: best });
  }
  return scored.sort((a, b) => b.score - a.score).map((entry) => entry.item);
}

export function hostOf(url: string): string {
  return url.replace(/^[a-z]+:\/\//i, "").replace(/\/$/, "");
}

export function isHttpUrl(url: string | null | undefined): url is string {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

/** "123 456" like the TUI. */
export function formatOtp(code: string): string {
  return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function relativeTime(iso: string, now = Date.now()): string {
  const diff = Date.parse(iso) - now;
  const abs = Math.abs(diff);
  const units: [number, Intl.RelativeTimeFormatUnit][] = [[86_400_000, "day"], [3_600_000, "hour"], [60_000, "minute"], [1000, "second"]];
  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  for (const [ms, unit] of units) {
    if (abs >= ms || unit === "second") return rtf.format(Math.round(diff / ms), unit);
  }
  return iso;
}

export function formatDuration(seconds: number): string {
  if (seconds % 86_400 === 0 && seconds >= 86_400) return `${seconds / 86_400}d`;
  if (seconds % 3600 === 0 && seconds >= 3600) return `${seconds / 3600}h`;
  if (seconds % 60 === 0 && seconds >= 60) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Parses "90", "15m", "2h", "1d" into seconds; null when it isn't a duration. */
export function parseDuration(text: string): number | null {
  const match = /^\s*(\d+)\s*([smhd]?)\s*$/i.exec(text);
  if (!match) return null;
  const factor = { "": 1, s: 1, m: 60, h: 3600, d: 86_400 }[match[2]!.toLowerCase() as "" | "s" | "m" | "h" | "d"];
  return Number(match[1]) * factor;
}

export function isMac(): boolean {
  return /mac|iphone|ipad/i.test(navigator.platform || navigator.userAgent);
}

/** True while typing in a field, so single-key shortcuts stay out of the way. */
export function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName);
}
