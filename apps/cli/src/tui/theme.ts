export const theme = {
  accent: "#FFD700",
  bg: "#0d0d0d",
  panel: "#141414",
  panelAlt: "#1c1c1c",
  border: "#333333",
  borderFocus: "#FFD700",
  text: "#EEEEEE",
  muted: "#AAAAAA",
  dim: "#777777",
  success: "#33CC77",
  danger: "#FF5555",
  info: "#55BBFF",
  revealed: "#7CFC00",
  /** Selected rows: a dark lift with gold text. */
  selection: "#222222",
  /** Text drawn on top of accent/success/danger fills. */
  onAccent: "#000000",
  chip: "#262626",
  input: "#111111",
  inputFocus: "#1a1a1a",
  dangerBg: "#331111",
} as const;

/** Fixed-width mask so the UI never leaks a stored secret's length. */
export const MASK = "••••••••••••";

export const TIMINGS = {
  /** Second Ctrl+C within this window quits. */
  quitWindowMs: 2000,
  /** Revealed values hide again after this long. */
  revealMs: 30_000,
  /** Copied secrets are wiped from the clipboard after this long. */
  clipboardClearMs: 30_000,
  /** Vault locks after this much inactivity. */
  idleLockMs: 5 * 60_000,
  toastMs: 3500,
};

export function typeLabel(type: string): string {
  switch (type) {
    case "password": return "Login";
    case "note": return "Secure note";
    case "otp": return "OTP";
    default: return type;
  }
}

// Single-width glyphs only: emoji widths differ between terminals and break alignment.
export function typeBadge(type: string): { glyph: string; color: string } {
  switch (type) {
    case "password": return { glyph: "●", color: theme.accent };
    case "note": return { glyph: "■", color: theme.info };
    case "otp": return { glyph: "◆", color: theme.success };
    default: return { glyph: "·", color: theme.muted };
  }
}
