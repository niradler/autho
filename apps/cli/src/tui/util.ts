import { spawn } from "node:child_process";

import type { KeyEvent } from "@opentui/core";

/** Opens an http(s) URL in the default browser without going through a shell. */
export function openUrl(url: string): boolean {
  if (!/^https?:\/\//i.test(url)) {
    return false;
  }
  const [cmd, args] = process.platform === "win32"
    ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
    : process.platform === "darwin"
      ? ["open", [url]]
      : ["xdg-open", [url]];
  try {
    spawn(cmd, args, { detached: true, stdio: "ignore", windowsHide: true }).unref();
    return true;
  } catch {
    return false;
  }
}

/** Random password from an unambiguous alphabet, using rejection sampling. */
export function generatePassword(length = 24, symbols = true): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789" + (symbols ? "!@#$%^&*-_=+" : "");
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    for (const byte of crypto.getRandomValues(new Uint8Array(length * 2))) {
      if (byte < limit && out.length < length) {
        out += alphabet[byte % alphabet.length];
      }
    }
  }
  return out;
}

/**
 * Subsequence fuzzy score: every query char must appear in order.
 * Higher is better; consecutive runs and word-start hits score extra.
 * Returns null when the query doesn't match.
 */
export function fuzzyScore(query: string, target: string): number | null {
  const q = query.toLowerCase();
  const t = target.toLowerCase();
  if (!q) {
    return 0;
  }
  const direct = t.indexOf(q);
  if (direct !== -1) {
    return 1000 - direct;
  }
  let score = 0;
  let ti = 0;
  let run = 0;
  for (const ch of q) {
    const found = t.indexOf(ch, ti);
    if (found === -1) {
      return null;
    }
    run = found === ti ? run + 1 : 0;
    const wordStart = found === 0 || /[\s\-_./@]/.test(t[found - 1] ?? "");
    score += 1 + run * 2 + (wordStart ? 3 : 0);
    ti = found + 1;
  }
  return score;
}

export function fuzzyFilter<T>(items: T[], query: string, fields: (item: T) => Array<string | null | undefined>): T[] {
  if (!query.trim()) {
    return items;
  }
  const scored: Array<{ item: T; score: number }> = [];
  for (const item of items) {
    let best: number | null = null;
    fields(item).forEach((field, index) => {
      if (!field) {
        return;
      }
      const s = fuzzyScore(query, field);
      // Earlier fields (name) weigh more than later ones (url, description).
      if (s !== null) {
        const weighted = s - index * 5;
        best = best === null ? weighted : Math.max(best, weighted);
      }
    });
    if (best !== null) {
      scored.push({ item, score: best });
    }
  }
  return scored.sort((a, b) => b.score - a.score).map((entry) => entry.item);
}

/**
 * Text a key event types, or null for shortcuts, arrows and function keys.
 * Multi-character sequences are accepted: terminals without bracketed paste
 * deliver a paste as one chunk, and dropping it was the old paste bug.
 */
export function typedText(key: KeyEvent): string | null {
  if (key.ctrl || key.meta || key.super) {
    return null;
  }
  const seq = key.sequence;
  if (!seq) {
    return null;
  }
  for (const ch of seq) {
    const code = ch.codePointAt(0) ?? 0;
    if (code < 32 || code === 0x7f || (code >= 0x80 && code < 0xa0)) {
      return null;
    }
  }
  return seq;
}

export function isEnter(key: KeyEvent): boolean {
  return key.name === "return" || key.name === "enter";
}

/** Normalises pasted text for a single-line field. */
export function cleanPaste(text: string, multiline = false): string {
  const stripped = text.replace(/\r\n?/g, "\n");
  return multiline ? stripped.replace(/\n+$/, "") : stripped.replace(/\n/g, "");
}

export function truncate(text: string, width: number): string {
  if (width <= 1) {
    return "";
  }
  return text.length > width ? `${text.slice(0, width - 1)}…` : text;
}

export function hostOf(url: string): string {
  return url.replace(/^[a-z]+:\/\//i, "").replace(/\/$/, "");
}

/** "in 42m", "3h ago": compact, so it fits list rows. */
export function relativeTime(iso: string, now = Date.now()): string {
  const diff = Date.parse(iso) - now;
  if (Number.isNaN(diff)) return iso;
  const abs = Math.abs(diff);
  // Pick the unit after rounding, so 59m59s reads "1h", not "60m".
  const units: [ms: number, unit: string, max: number][] = [[1000, "s", 60], [60_000, "m", 60], [3_600_000, "h", 24], [86_400_000, "d", Infinity]];
  const [ms, unit] = units.find(([size, , max]) => Math.round(abs / size) < max)!;
  const amount = `${Math.round(abs / ms)}${unit}`;
  return diff >= 0 ? `in ${amount}` : `${amount} ago`;
}

/** Local "YYYY-MM-DD HH:MM". */
export function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function formatDuration(seconds: number): string {
  if (seconds >= 86_400 && seconds % 86_400 === 0) return `${seconds / 86_400}d`;
  if (seconds >= 3600 && seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds >= 60 && seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/** Parses "90", "15m", "2h", "1d" into seconds; null when it isn't a duration. */
export function parseDuration(text: string): number | null {
  const match = /^\s*(\d+)\s*([smhd]?)\s*$/i.exec(text);
  if (!match) return null;
  const factor = { "": 1, s: 1, m: 60, h: 3600, d: 86_400 }[match[2]!.toLowerCase() as "" | "s" | "m" | "h" | "d"];
  return Number(match[1]) * factor;
}
