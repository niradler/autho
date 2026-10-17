import { loadConfig, saveConfig, type AuthoConfig } from "./paths.ts";

/**
 * User preferences kept in config.json. Each one can be overridden for a
 * single run with an environment variable, which always wins.
 */
export type PreferenceKey =
  | "revealSeconds"
  | "clipboardClearSeconds"
  | "idleLockSeconds"
  | "passwordLength"
  | "passwordSymbols"
  | "mouse"
  | "defaultLeaseTtl"
  | "daemonTtlSeconds"
  | "webPort";

type NumberSpec = {
  kind: "number";
  key: PreferenceKey;
  label: string;
  help: string;
  unit?: "s";
  default: number;
  min: number;
  max: number;
  env?: string;
  /** Text shown for 0, e.g. "off". */
  zero?: string;
};

type BooleanSpec = {
  kind: "boolean";
  key: PreferenceKey;
  label: string;
  help: string;
  default: boolean;
  env?: string;
};

export type PreferenceSpec = NumberSpec | BooleanSpec;

export const PREFERENCES: readonly PreferenceSpec[] = [
  { kind: "number", key: "revealSeconds", label: "Reveal timeout", help: "How long a revealed value stays on screen", unit: "s", default: 30, min: 5, max: 600, env: "AUTHO_TUI_REVEAL_SECONDS" },
  { kind: "number", key: "clipboardClearSeconds", label: "Clipboard clear", help: "Copied secrets are wiped from the clipboard after this long", unit: "s", default: 30, min: 5, max: 600, env: "AUTHO_CLIPBOARD_CLEAR_SECONDS" },
  { kind: "number", key: "idleLockSeconds", label: "Auto-lock", help: "Lock the TUI after this much inactivity (0 = never)", unit: "s", default: 300, min: 0, max: 86_400, env: "AUTHO_TUI_LOCK_SECONDS", zero: "never" },
  { kind: "number", key: "passwordLength", label: "Generated length", help: "Length of passwords made with ctrl+g", default: 24, min: 12, max: 128 },
  { kind: "boolean", key: "passwordSymbols", label: "Use symbols", help: "Include !@#$%^&*-_=+ in generated passwords", default: true },
  { kind: "boolean", key: "mouse", label: "Mouse", help: "Click and drag-select in the TUI (off = your terminal's own selection). Applies on next start", default: true },
  { kind: "number", key: "defaultLeaseTtl", label: "Lease TTL", help: "Used by `lease create` when --ttl is not given (0 = always ask)", unit: "s", default: 0, min: 0, max: 2_592_000, zero: "required" },
  { kind: "number", key: "daemonTtlSeconds", label: "Daemon session", help: "How long `daemon unlock` keeps the vault open without --ttl", unit: "s", default: 900, min: 60, max: 86_400 },
  { kind: "number", key: "webPort", label: "Web UI port", help: "Port for `autho web serve` when --port is not given", default: 8061, min: 1024, max: 65_535 },
];

export type PreferenceSource = "env" | "config" | "default";

export function preferenceSpec(key: string): PreferenceSpec | undefined {
  return PREFERENCES.find((spec) => spec.key === key);
}

function parseBoolean(raw: unknown): boolean | undefined {
  if (typeof raw === "boolean") return raw;
  if (raw === "true" || raw === "1" || raw === "on") return true;
  if (raw === "false" || raw === "0" || raw === "off") return false;
  return undefined;
}

function parseNumber(spec: NumberSpec, raw: unknown): number | undefined {
  const value = typeof raw === "number" ? raw : typeof raw === "string" && raw.trim() !== "" ? Number(raw) : Number.NaN;
  return Number.isInteger(value) && value >= spec.min && value <= spec.max ? value : undefined;
}

/** Parses and range-checks a user-typed value. Throws with a readable message. */
export function parsePreference(key: PreferenceKey, raw: string): number | boolean {
  const spec = preferenceSpec(key);
  if (!spec) throw new Error(`Unknown setting: ${key}`);
  if (spec.kind === "boolean") {
    const value = parseBoolean(raw.trim().toLowerCase());
    if (value === undefined) throw new Error(`${spec.label} must be true or false`);
    return value;
  }
  const value = parseNumber(spec, raw.trim());
  if (value === undefined) throw new Error(`${spec.label} must be a whole number from ${spec.min} to ${spec.max}`);
  return value;
}

function configValue(spec: PreferenceSpec, config: AuthoConfig): number | boolean | undefined {
  // Older configs turned the idle lock off with `autoLock: false`.
  if (spec.key === "idleLockSeconds" && config.idleLockSeconds === undefined && config.autoLock === false) return 0;
  const raw = config[spec.key];
  return spec.kind === "boolean" ? parseBoolean(raw) : parseNumber(spec, raw);
}

export function resolvePreference(key: PreferenceKey, env: Record<string, string | undefined> = process.env): { value: number | boolean; source: PreferenceSource } {
  const spec = preferenceSpec(key)!;
  const fromEnv = spec.env ? env[spec.env] : undefined;
  if (fromEnv !== undefined && fromEnv !== "") {
    const value = spec.kind === "boolean" ? parseBoolean(fromEnv) : parseNumber({ ...spec, min: 0, max: Number.MAX_SAFE_INTEGER }, fromEnv);
    if (value !== undefined) return { value, source: "env" };
  }
  const fromConfig = configValue(spec, loadConfig());
  if (fromConfig !== undefined) return { value: fromConfig, source: "config" };
  return { value: spec.default, source: "default" };
}

export function numberPreference(key: PreferenceKey): number {
  return resolvePreference(key).value as number;
}

export function booleanPreference(key: PreferenceKey): boolean {
  return resolvePreference(key).value as boolean;
}

/** Saves a preference; `null` removes it so the default applies again. */
export function setPreference(key: PreferenceKey, value: number | boolean | null): void {
  const next: AuthoConfig = { ...loadConfig() };
  if (value === null) delete next[key];
  else (next as Record<string, unknown>)[key] = value;
  if (key === "idleLockSeconds") delete next.autoLock;
  saveConfig(next);
}

export function formatPreference(key: PreferenceKey, value: number | boolean): string {
  const spec = preferenceSpec(key)!;
  if (spec.kind === "boolean") return value ? "on" : "off";
  if (value === 0 && spec.zero) return spec.zero;
  return spec.unit === "s" ? formatSeconds(value as number) : String(value);
}

function formatSeconds(seconds: number): string {
  if (seconds % 3600 === 0 && seconds >= 3600) return `${seconds / 3600}h`;
  if (seconds % 60 === 0 && seconds >= 60) return `${seconds / 60}m`;
  return `${seconds}s`;
}
