import { createCliRenderer } from "@opentui/core";
import { createRoot, useKeyboard, useRenderer, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  VaultService,
  defaultVaultPath,
} from "../../../packages/core/src/index.ts";
import type { UnlockCredentials, VaultSession } from "../../../packages/core/src/index.ts";
import { hasPinSet, loadVaultPassword, verifyPin } from "../../../packages/core/src/os-secrets.ts";

// ─── Types ───────────────────────────────────────────────────────────

type Screen = "unlock" | "home" | "detail" | "create" | "edit";
type SecretType = "password" | "note" | "otp";

interface SecretRecord {
  id: string;
  name: string;
  type: string;
  username?: string;
  value?: string;
  metadata?: Record<string, unknown>;
  createdAt?: string;
}

function typeLabel(type: string): string {
  switch (type) {
    case "password": return "Login";
    case "note": return "Secure Note";
    case "otp": return "OTP Secret";
    default: return type;
  }
}

interface Toast {
  message: string;
  type: "success" | "error";
}

// ─── Shared Components ───────────────────────────────────────────────

function Header({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <box width="100%" paddingLeft={2} paddingTop={1} paddingBottom={1} borderBottom borderColor="#333333">
      <text fg="#FFD700"><strong>{title}</strong></text>
      {subtitle ? <text fg="#555555"> {subtitle}</text> : null}
    </box>
  );
}

function StatusBar({ message }: { message: string }) {
  return (
    <box width="100%" height={1} backgroundColor="#1a1a1a" paddingLeft={1} paddingRight={1}>
      <text fg="#666666">{message}</text>
    </box>
  );
}

function ToastBar({ toast }: { toast: Toast | null }) {
  if (!toast) return null;
  const color = toast.type === "success" ? "#00CC66" : "#FF4444";
  const icon = toast.type === "success" ? "+" : "!";
  return (
    <box width="100%" height={1} backgroundColor={color} paddingLeft={1}>
      <text fg="#000000"><strong> {icon} {toast.message}</strong></text>
    </box>
  );
}

function KeyValue({ label, value, labelColor = "#888888", valueColor = "#FFFFFF" }: {
  label: string; value: string; labelColor?: string; valueColor?: string;
}) {
  return (
    <box flexDirection="row" gap={1}>
      <text fg={labelColor} width={14}>{label}</text>
      <text fg={valueColor}>{value}</text>
    </box>
  );
}

function useToast() {
  const [toast, setToast] = useState<Toast | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const show = useCallback((message: string, type: "success" | "error" = "success") => {
    if (timerRef.current) clearTimeout(timerRef.current);
    setToast({ message, type });
    timerRef.current = setTimeout(() => setToast(null), 3000);
  }, []);
  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current); }, []);
  return { toast, show };
}

// ─── Unlock System ───────────────────────────────────────────────────

function tryUnlockWithPassword(vaultPath: string, password: string): VaultSession | null {
  try {
    return VaultService.unlock(vaultPath, { password });
  } catch {
    return null;
  }
}

function tryUnlockWithRecovery(vaultPath: string, token: string): VaultSession | null {
  try {
    return VaultService.unlock(vaultPath, { password: "", recovery: token });
  } catch {
    return null;
  }
}

// ─── Password Method ─────────────────────────────────────────────────

function PasswordMethod({ onSubmit, onError, vaultPath: _vaultPath }: {
  onSubmit: (password: string) => void;
  onError: (error: string) => void;
  vaultPath?: string; // kept for compat, unused here
}) {
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useKeyboard((key) => {
    if (key.eventType !== "press" && key.eventType !== "repeat") return;
    if (submitting) return;

    if (key.name === "enter" || key.name === "return") {
      if (!password) return;
      setSubmitting(true);
      onSubmit(password);
      return;
    }
    if (key.name === "backspace") { setPassword((p) => p.slice(0, -1)); return; }
    if (key.ctrl || key.meta || key.name === "escape" || key.name === "tab" ||
        key.name === "up" || key.name === "down" || key.name === "left" || key.name === "right" ||
        key.name === "home" || key.name === "end" || key.name === "delete" || key.name === "insert" ||
        key.name === "pageup" || key.name === "pagedown" ||
        (key.name.startsWith("f") && /^f\d+$/.test(key.name))) return;
    const char = key.sequence;
    if (char && char.length === 1 && char.charCodeAt(0) >= 32) setPassword((p) => p + char);
  });

  void onError; // available for parent to use

  return (
    <box flexDirection="row" gap={1} marginTop={1}>
      <text fg="#AAAAAA">Password </text>
      <box backgroundColor="#111111" flexGrow={1} paddingX={1} height={1}>
        <text fg="#FFD700">{password ? "*".repeat(password.length) : ""}</text>
      </box>
      {submitting ? <text fg="#FFD700"> ...</text> : null}
    </box>
  );
}

// ─── PIN Method ───────────────────────────────────────────────────────

function PinMethod({ vaultPath, password, onVerified, onError }: {
  vaultPath: string;
  password: string;
  onVerified: (password: string) => void;
  onError: (error: string) => void;
}) {
  const [pin, setPin] = useState("");
  const [verifying, setVerifying] = useState(false);

  useKeyboard((key) => {
    if (key.eventType !== "press" && key.eventType !== "repeat") return;
    if (verifying) return;

    if (key.name === "enter" || key.name === "return") {
      if (!pin) return;
      setVerifying(true);
      verifyPin(vaultPath, pin).then((ok) => {
        if (ok) {
          onVerified(password);
        } else {
          onError("Wrong PIN");
          setPin("");
          setVerifying(false);
        }
      });
      return;
    }
    if (key.name === "backspace") { setPin((p) => p.slice(0, -1)); return; }
    if (key.ctrl || key.meta || key.name === "escape" || key.name === "tab" ||
        key.name === "up" || key.name === "down" || key.name === "left" || key.name === "right" ||
        key.name === "home" || key.name === "end" || key.name === "delete" || key.name === "insert" ||
        key.name === "pageup" || key.name === "pagedown" ||
        (key.name.startsWith("f") && /^f\d+$/.test(key.name))) return;
    const char = key.sequence;
    if (char && char.length === 1 && char.charCodeAt(0) >= 32) setPin((p) => p + char);
  });

  return (
    <box flexDirection="row" gap={1} marginTop={1}>
      <text fg="#AAAAAA">PIN      </text>
      <box backgroundColor="#111111" flexGrow={1} paddingX={1} height={1}>
        <text fg="#FFD700">{pin ? "*".repeat(pin.length) : ""}</text>
      </box>
      {verifying ? <text fg="#FFD700"> ...</text> : null}
    </box>
  );
}

// ─── TOTP Method ──────────────────────────────────────────────────────

function TotpMethod({ onSubmit, onError: _onError }: {
  onSubmit: (totp: string) => void;
  onError: (error: string) => void;
}) {
  const [code, setCode] = useState("");
  const [remaining, setRemaining] = useState(0);

  // Countdown timer
  useEffect(() => {
    const update = () => {
      const secs = Math.ceil((30_000 - (Date.now() % 30_000)) / 1000);
      setRemaining(secs);
    };
    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, []);

  useKeyboard((key) => {
    if (key.eventType !== "press" && key.eventType !== "repeat") return;

    if (key.name === "enter" || key.name === "return") {
      if (code.length !== 6) return;
      onSubmit(code);
      return;
    }
    if (key.name === "backspace") { setCode((c) => c.slice(0, -1)); return; }
    if (key.ctrl || key.meta || key.name === "escape" || key.name === "tab" ||
        key.name === "up" || key.name === "down" || key.name === "left" || key.name === "right" ||
        key.name === "home" || key.name === "end" || key.name === "delete" || key.name === "insert" ||
        key.name === "pageup" || key.name === "pagedown" ||
        (key.name.startsWith("f") && /^f\d+$/.test(key.name))) return;
    const char = key.sequence;
    if (char && /^\d$/.test(char) && code.length < 6) {
      const next = code + char;
      setCode(next);
      if (next.length === 6) {
        onSubmit(next);
      }
    }
  });

  return (
    <box flexDirection="column" gap={1} marginTop={1}>
      <box flexDirection="row" gap={1}>
        <text fg="#AAAAAA">Auth code </text>
        <box backgroundColor="#111111" flexGrow={1} paddingX={1} height={1}>
          <text fg="#FFD700">{code || "_".repeat(6)}</text>
        </box>
        <text fg={remaining <= 5 ? "#FF4444" : "#555555"}> {remaining}s</text>
      </box>
      <text fg="#555555">Enter 6-digit authenticator code</text>
    </box>
  );
}

// ─── Unlock Screen ───────────────────────────────────────────────────

function UnlockScreen({ onUnlock, vaultPath }: {
  onUnlock: (session: VaultSession) => void; vaultPath: string;
}) {
  const [step, setStep] = useState<"loading" | "password" | "pin" | "totp" | "unlocking">("loading");
  const [error, setError] = useState("");
  const [password, setPasswordState] = useState("");
  const [pinNeeded, setPinNeeded] = useState(false);
  const [totpNeeded, setTotpNeeded] = useState(false);

  // On mount: determine steps + try silent unlock
  useEffect(() => {
    let cancelled = false;
    (async () => {
      // Try recovery file env var
      const recoveryFile = process.env.AUTHO_RECOVERY_FILE;
      if (recoveryFile) {
        try {
          const { readFileSync } = await import("node:fs");
          const content = readFileSync(recoveryFile, "utf8");
          const lines = content.split("\n");
          const idx = lines.findIndex((l) => l.trim() === "RECOVERY TOKEN:");
          if (idx !== -1) {
            const rawToken = lines.slice(idx + 1).find((l) => l.trim() !== "") ?? "";
            const token = rawToken.replace(/-/g, "").toLowerCase();
            if (token) {
              const session = tryUnlockWithRecovery(vaultPath, token);
              if (!cancelled && session) { onUnlock(session); return; }
              if (!cancelled) setError("Recovery file failed — enter password instead");
            } else {
              if (!cancelled) setError("Recovery file is malformed — enter password instead");
            }
          } else {
            if (!cancelled) setError("Recovery file is malformed — enter password instead");
          }
        } catch {
          if (!cancelled) setError("Recovery file could not be read — enter password instead");
        }
      }

      // Check which steps are needed
      const pinSet = await hasPinSet(vaultPath);
      if (!cancelled) setPinNeeded(pinSet);

      const authConfig = VaultService.getAuthConfig(vaultPath);
      if (!cancelled) setTotpNeeded(authConfig?.totp !== undefined);

      if (!pinSet) {
        // Try OS keychain
        const pw = await loadVaultPassword(vaultPath);
        if (!cancelled && pw && !authConfig?.totp) {
          // Can silently unlock: password from keychain, no PIN, no TOTP
          const session = tryUnlockWithPassword(vaultPath, pw);
          if (!cancelled && session) { onUnlock(session); return; }
        }
        if (!cancelled && pw) {
          // Has keychain password but TOTP required — pre-fill password, skip to totp
          setPasswordState(pw);
          if (!cancelled) setStep(authConfig?.totp ? "totp" : "password");
          return;
        }
      }

      if (!cancelled) setStep("password");
    })();
    return () => { cancelled = true; };
  }, [vaultPath, onUnlock]);

  const doUnlock = useCallback((pw: string, totp: string | undefined) => {
    const creds: UnlockCredentials = { password: pw, totp };
    try {
      const session = VaultService.unlock(vaultPath, creds);
      onUnlock(session);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setStep("password");
      setPasswordState("");
    }
  }, [vaultPath, onUnlock]);

  // Handler: password collected → move to next step
  const handlePasswordSubmit = useCallback((pw: string) => {
    setPasswordState(pw);
    if (pinNeeded) {
      setStep("pin");
    } else if (totpNeeded) {
      setStep("totp");
    } else {
      setStep("unlocking");
      doUnlock(pw, undefined);
    }
  }, [pinNeeded, totpNeeded, doUnlock]);

  // Handler: PIN verified → move to next step
  const handlePinVerified = useCallback((pw: string) => {
    if (totpNeeded) {
      setStep("totp");
    } else {
      setStep("unlocking");
      doUnlock(pw, undefined);
    }
  }, [totpNeeded, doUnlock]);

  // Handler: TOTP code collected → unlock
  const handleTotpSubmit = useCallback((totp: string) => {
    setStep("unlocking");
    doUnlock(password, totp);
  }, [password, doUnlock]);

  if (step === "loading" || step === "unlocking") {
    return (
      <box flexDirection="column" alignItems="center" justifyContent="center" width="100%" height="100%">
        <text fg="#FFD700">{step === "loading" ? "Unlocking..." : "Verifying..."}</text>
      </box>
    );
  }

  return (
    <box flexDirection="column" alignItems="center" justifyContent="center" width="100%" height="100%">
      <box flexDirection="column" border borderStyle="rounded" padding={2} width={52} gap={1}>
        <ascii-font text="autho" font="tiny" color="#FFD700" />
        <text fg="#888888">Unlock your vault</text>
        {error ? <box backgroundColor="#331111" paddingX={1} width="100%"><text fg="#FF4444">{error}</text></box> : null}
        {step === "password" && (
          <PasswordMethod vaultPath={vaultPath} onSubmit={handlePasswordSubmit} onError={setError} />
        )}
        {step === "pin" && (
          <PinMethod vaultPath={vaultPath} password={password} onVerified={handlePinVerified} onError={setError} />
        )}
        {step === "totp" && (
          <TotpMethod onSubmit={handleTotpSubmit} onError={setError} />
        )}
        <text fg="#444444">Enter to unlock | Ctrl+C to exit</text>
      </box>
    </box>
  );
}

// ─── Home Screen (search + list + create) ────────────────────────────

function buildDescription(s: SecretRecord, availableWidth: number): string {
  const label = typeLabel(s.type);
  // Always start with the type label
  let desc = label;

  // Try adding username
  if (s.username) {
    const withUser = `${label} · ${s.username}`;
    if (withUser.length <= availableWidth) {
      desc = withUser;
    } else {
      return desc;
    }
  }

  // Try adding URL
  const url = s.metadata?.url ? String(s.metadata.url) : "";
  if (url) {
    // Strip protocol for brevity
    const shortUrl = url.replace(/^https?:\/\//, "");
    const withUrl = `${desc} · ${shortUrl}`;
    if (withUrl.length <= availableWidth) {
      desc = withUrl;
    } else {
      return desc;
    }
  }

  // Try adding description
  const note = s.metadata?.description ? String(s.metadata.description) : "";
  if (note) {
    const withNote = `${desc} · ${note}`;
    if (withNote.length <= availableWidth) {
      desc = withNote;
    } else {
      const budget = availableWidth - desc.length - 5;
      if (budget > 5) {
        desc = `${desc} — ${note.slice(0, budget)}…`;
      }
    }
  }

  return desc;
}

function HomeScreen({ session, onSelect, onCreate, toast }: {
  session: VaultSession;
  onSelect: (secret: SecretRecord) => void;
  onCreate: () => void;
  toast: Toast | null;
}) {
  const renderer = useRenderer();
  const { width: termWidth } = useTerminalDimensions();
  const [secrets, setSecrets] = useState<SecretRecord[]>([]);
  const [query, setQuery] = useState("");
  const [searchFocused, setSearchFocused] = useState(false);

  const reload = useCallback(() => {
    try {
      const summaries = session.listSecrets() as SecretRecord[];
      // Enrich with full details for richer list descriptions
      const enriched = summaries.map((s) => {
        try {
          return session.getSecret(s.id) as SecretRecord;
        } catch {
          return s;
        }
      });
      setSecrets(enriched);
    } catch {
      setSecrets([]);
    }
  }, [session]);

  useEffect(reload, [reload]);

  const filtered = useMemo(() => {
    if (!query) return secrets;
    const q = query.toLowerCase();
    return secrets.filter((s) =>
      s.name.toLowerCase().includes(q) ||
      s.type.toLowerCase().includes(q) ||
      (s.username && s.username.toLowerCase().includes(q)) ||
      (s.metadata?.url && String(s.metadata.url).toLowerCase().includes(q)) ||
      (s.metadata?.description && String(s.metadata.description).toLowerCase().includes(q)),
    );
  }, [secrets, query]);

  // Description width = terminal width minus padding (4), select indicator (2), name estimate, gap
  const descWidth = Math.max(20, termWidth - 30);

  const options = useMemo(() =>
    filtered.map((s) => ({
      name: s.name,
      description: buildDescription(s, descWidth),
      value: s.id,
    })),
  [filtered, descWidth]);

  useKeyboard((key) => {
    if (key.eventType !== "press") return;
    // 'q' to quit only when search is not focused
    if (key.name === "q" && !searchFocused) {
      session.close();
      renderer.destroy();
      return;
    }
    // 'n' to create new
    if (key.name === "n" && !searchFocused) {
      onCreate();
      return;
    }
    // '/' to focus search
    if (key.name === "/" && !searchFocused) {
      setSearchFocused(true);
      return;
    }
    // Escape from search goes back to list
    if (key.name === "escape" && searchFocused) {
      setSearchFocused(false);
      setQuery("");
      return;
    }
    // Escape from list quits
    if (key.name === "escape" && !searchFocused) {
      session.close();
      renderer.destroy();
      return;
    }
    // Tab toggles focus
    if (key.name === "tab") {
      setSearchFocused((f) => !f);
      return;
    }
  });

  return (
    <box flexDirection="column" width="100%" height="100%">
      <Header title="Autho" subtitle={`${secrets.length} secrets`} />

      {/* Search + Create row */}
      <box flexDirection="row" paddingX={2} paddingTop={1} gap={2} alignItems="center">
        <input
          value={query}
          onChange={setQuery}
          placeholder="/ search..."
          focused={searchFocused}
          flexGrow={1}
          backgroundColor="#111111"
          focusedBackgroundColor="#1a1a1a"
          textColor="#FFFFFF"
          placeholderColor="#444444"
        />
        <text fg="#555555">[n] new</text>
      </box>

      {/* Secret list */}
      <box flexGrow={1} paddingX={2} paddingTop={1}>
        {filtered.length === 0 ? (
          <box padding={1}>
            <text fg="#555555">{secrets.length === 0 ? "No secrets yet. Press [n] to create one." : "No matches."}</text>
          </box>
        ) : (
          <select
            options={options}
            onSelect={(index: number) => onSelect(filtered[index])}
            focused={!searchFocused}
            height={Math.min(filtered.length * 2 + 1, 18)}
            selectedBackgroundColor="#222222"
            selectedTextColor="#FFD700"
          />
        )}
      </box>

      <ToastBar toast={toast} />
      <StatusBar message="↑↓ navigate  Enter open  / search  n new  q quit" />
    </box>
  );
}

// ─── Secret Detail Screen ────────────────────────────────────────────

function DetailScreen({ session, secret, onBack, onDeleted, onEdit }: {
  session: VaultSession;
  secret: SecretRecord;
  onBack: () => void;
  onDeleted: (msg: string) => void;
  onEdit: () => void;
}) {
  const renderer = useRenderer();
  const [revealing, setRevealing] = useState(false);
  const [copied, setCopied] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [otpResult, setOtpResult] = useState<{ code: string; expiresAt: string } | null>(null);
  const [otpCountdown, setOtpCountdown] = useState(0);
  const [error, setError] = useState("");
  const hideTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const countdownRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch full detail
  let detail: SecretRecord;
  try { detail = session.getSecret(secret.name ?? secret.id) as SecretRecord; }
  catch { detail = secret; }

  const isOtp = detail.type === "otp";

  // Clean up timers on unmount
  useEffect(() => () => {
    if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
    if (countdownRef.current) clearInterval(countdownRef.current);
  }, []);

  // Live countdown for OTP
  useEffect(() => {
    if (!otpResult) {
      if (countdownRef.current) clearInterval(countdownRef.current);
      return;
    }
    const update = () => {
      const remaining = Math.max(0, Math.ceil((new Date(otpResult.expiresAt).getTime() - Date.now()) / 1000));
      setOtpCountdown(remaining);
      if (remaining <= 0 && countdownRef.current) {
        clearInterval(countdownRef.current);
      }
    };
    update();
    countdownRef.current = setInterval(update, 1000);
    return () => { if (countdownRef.current) clearInterval(countdownRef.current); };
  }, [otpResult]);

  // Hold 's' to reveal: each press/repeat resets a 300ms timer.
  // When no more 's' events arrive (key released), the timer fires and hides.
  // This works on all terminals — no key release event needed.
  useKeyboard((key) => {
    if (key.name === "s" && !confirmDelete && (key.eventType === "press" || key.eventType === "repeat")) {
      setRevealing(true);
      if (hideTimerRef.current) clearTimeout(hideTimerRef.current);
      hideTimerRef.current = setTimeout(() => setRevealing(false), 600);
      return;
    }

    // Only handle press events for everything else
    if (key.eventType !== "press") return;

    if (key.name === "escape") {
      if (confirmDelete) { setConfirmDelete(false); return; }
      if (otpResult) { setOtpResult(null); return; }
      onBack();
      return;
    }

    // 'c' to copy value to clipboard
    if (key.name === "c" && !confirmDelete) {
      const toCopy = otpResult ? otpResult.code : (detail.value ?? "");
      if (toCopy) {
        renderer.copyToClipboardOSC52(toCopy);
        setCopied(otpResult ? "OTP code" : "Value");
        setTimeout(() => setCopied(""), 2000);
      }
      return;
    }

    // 'e' to edit
    if (key.name === "e" && !confirmDelete && !otpResult) {
      onEdit();
      return;
    }

    // 'd' to start delete
    if (key.name === "d" && !confirmDelete && !otpResult) {
      setConfirmDelete(true);
      return;
    }

    // 'o' to generate OTP
    if (key.name === "o" && isOtp && !confirmDelete) {
      try {
        const result = session.generateOtp(detail.name) as { code: string; expiresAt: string };
        setOtpResult(result);
        setError("");
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
      return;
    }

    // 'r' to regenerate OTP
    if (key.name === "r" && otpResult) {
      try {
        const result = session.generateOtp(detail.name) as { code: string; expiresAt: string };
        setOtpResult(result);
        setError("");
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
      return;
    }
  });

  // Delete confirm
  if (confirmDelete) {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="Delete" subtitle={detail.name} />
        <box padding={2} flexDirection="column" gap={1}>
          <box border borderStyle="rounded" borderColor="#FF4444" padding={1} flexDirection="column" gap={0}>
            <text fg="#FF4444"><strong>Permanently delete this secret?</strong></text>
            <KeyValue label="Name" value={detail.name} valueColor="#FFD700" />
            <KeyValue label="Type" value={detail.type} />
          </box>
          <select
            options={[
              { name: "Cancel", description: "Keep the secret", value: "cancel" },
              { name: "Delete forever", description: "Cannot be undone", value: "delete" },
            ]}
            onSelect={(_i: number, opt: { value?: string }) => {
              if (opt.value === "delete") {
                try {
                  session.removeSecret(detail.name ?? detail.id);
                  onDeleted(`"${detail.name}" deleted`);
                } catch (e) {
                  onDeleted(`Error: ${e instanceof Error ? e.message : String(e)}`);
                }
              } else {
                setConfirmDelete(false);
              }
            }}
            focused
            height={4}
            selectedBackgroundColor="#222222"
            selectedTextColor="#FF4444"
          />
        </box>
        <StatusBar message="↑↓ navigate  Enter confirm  Esc cancel" />
      </box>
    );
  }

  // Masked value
  let maskedValue = "—";
  if (detail.value) {
    maskedValue = revealing ? detail.value : "*".repeat(Math.min(detail.value.length, 32));
  }

  // Build status bar hints
  const hints = ["Hold s reveal", "c copy", "e edit", "d delete"];
  if (isOtp) hints.push(otpResult ? "r regen" : "o OTP");
  hints.push("Esc back");

  return (
    <box flexDirection="column" width="100%" height="100%">
      <Header title={detail.name} subtitle={typeLabel(detail.type)} />

      <box flexDirection="column" flexGrow={1} padding={2} gap={1}>
        {/* Secret info card */}
        <box flexDirection="column" border borderStyle="rounded" borderColor="#333333" padding={1} gap={0} width="100%">
          <KeyValue label="Name" value={detail.name} valueColor="#FFD700" />
          <KeyValue label="Type" value={typeLabel(detail.type)} />
          <KeyValue label="ID" value={detail.id} valueColor="#555555" />
          {detail.username ? <KeyValue label="Username" value={detail.username} /> : null}
          <KeyValue label="Value" value={maskedValue} valueColor={revealing ? "#00FF00" : "#FF4444"} />
          {detail.metadata?.url ? <KeyValue label="URL" value={String(detail.metadata.url)} /> : null}
          {detail.metadata?.description ? <KeyValue label="Description" value={String(detail.metadata.description)} /> : null}
        </box>

        {/* Reveal hint */}
        <text fg={revealing ? "#00FF00" : "#666666"}>
          {revealing ? "Revealing — release [s] to hide" : "Hold [s] to reveal secret value"}
        </text>

        {/* OTP display */}
        {otpResult ? (
          <box border borderStyle="rounded" borderColor="#00CC66" paddingX={2} height={3} flexDirection="row" alignItems="center" gap={2}>
            <text fg="#888888">OTP</text>
            <text fg="#00FF00"><strong>{otpResult.code}</strong></text>
            <text fg={otpCountdown <= 5 ? "#FF4444" : "#888888"}>
              {otpCountdown > 0 ? `${otpCountdown}s` : "expired"}
            </text>
            <text fg="#555555">[r] refresh</text>
          </box>
        ) : null}

        {error ? <text fg="#FF4444">{error}</text> : null}

        {/* Copied toast */}
        {copied ? <text fg="#00CC66">{copied} copied to clipboard</text> : null}

        {/* Action hints */}
        <box flexDirection="row" gap={3} marginTop={1}>
          <text fg="#00CC66">[c] Copy</text>
          <text fg="#FFD700">[e] Edit</text>
          <text fg="#FF4444">[d] Delete</text>
          {isOtp ? <text fg="#00CCFF">[o] Generate OTP</text> : null}
        </box>
      </box>

      <StatusBar message={hints.join("  ")} />
    </box>
  );
}

// ─── Create Screen (wizard) ──────────────────────────────────────────

// Wizard steps by type:
//   Login:       type → name → password → username → url → description → save
//   Secure Note: type → name → note → description → save
//   OTP:         type → name → totp secret → username → description → save

function CreateScreen({ session, onDone, onBack }: {
  session: VaultSession; onDone: (msg: string) => void; onBack: () => void;
}) {
  const [step, setStep] = useState(0);
  const [secretType, setSecretType] = useState<SecretType>("password");
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [username, setUsername] = useState("");
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");

  const typeOptions = [
    { name: "Login", description: "Username, password, and URL", value: "password" },
    { name: "Secure Note", description: "Encrypted text note", value: "note" },
    { name: "OTP Secret", description: "TOTP key for 2FA codes", value: "otp" },
  ];

  // Steps: 0=type, 1=name, 2=value, 3=username(login/otp), 4=url(login only), 5=description, 6=save(same as desc)
  const steps: string[] = (() => {
    switch (secretType) {
      case "password": return ["type", "name", "value", "username", "url", "description"];
      case "note":     return ["type", "name", "value", "description"];
      case "otp":      return ["type", "name", "value", "username", "description"];
      default:         return ["type", "name", "value", "description"];
    }
  })();

  const currentField = steps[step] ?? "description";
  const totalSteps = steps.length;

  const label = typeLabel(secretType);

  const doCreate = useCallback(() => {
    try {
      const metadata = Object.fromEntries(
        Object.entries({
          description: description || undefined,
          url: url || undefined,
        }).filter(([, v]) => v !== undefined),
      );
      session.addSecret({
        metadata,
        name,
        type: secretType,
        username: username || undefined,
        value,
      });
      onDone(`"${name}" created`);
    } catch (e) {
      onDone(`Error: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [session, name, value, secretType, username, url, description, onDone]);

  useKeyboard((key) => {
    if (key.eventType !== "press") return;
    if (key.name === "escape") {
      if (step > 0) setStep((s) => s - 1);
      else onBack();
    }
  });

  const progress = `${step + 1}/${totalSteps}`;
  const nextStep = () => setStep((s) => s + 1);

  // Shared input row helper
  const inputRow = (label: string, val: string, onChange: (v: string) => void, onSubmit: () => void, placeholder: string) => (
    <box flexDirection="row" gap={1}>
      <text fg="#AAAAAA" width={12}>{label}</text>
      <input value={val} onChange={onChange} onSubmit={onSubmit}
        placeholder={placeholder} focused flexGrow={1}
        backgroundColor="#111111" focusedBackgroundColor="#1a1a1a" textColor="#FFFFFF" />
    </box>
  );

  // Step 0: type
  if (step === 0) {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={progress} />
        <box paddingLeft={2} paddingTop={1}><text fg="#888888">What type of secret?</text></box>
        <box flexGrow={1} paddingLeft={2} paddingTop={1}>
          <select
            options={typeOptions}
            onSelect={(_i: number, opt: { value?: string }) => {
              setSecretType((opt.value ?? "password") as SecretType);
              nextStep();
            }}
            focused height={6}
            selectedBackgroundColor="#222222" selectedTextColor="#FFD700"
          />
        </box>
        <StatusBar message="Enter select  Esc cancel" />
      </box>
    );
  }

  // Name
  if (currentField === "name") {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={`${progress} · ${label}`} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">Give it a name</text>
          {inputRow("Name", name, setName, () => { if (name.trim()) nextStep(); }, "e.g. github-login")}
        </box>
        <StatusBar message="Enter next  Esc back" />
      </box>
    );
  }

  // Value
  if (currentField === "value") {
    const hint = secretType === "password" ? "Enter the password"
      : secretType === "otp" ? "Enter the TOTP base32 secret key"
      : "Enter the note content";
    const placeholder = secretType === "password" ? "password..."
      : secretType === "otp" ? "e.g. JBSWY3DPEHPK3PXP"
      : "note content...";
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={`${progress} · ${name}`} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">{hint}</text>
          {inputRow(secretType === "note" ? "Note" : "Value", value, setValue,
            () => { if (value.trim()) nextStep(); }, placeholder)}
        </box>
        <StatusBar message="Enter next  Esc back" />
      </box>
    );
  }

  // Username (login + otp)
  if (currentField === "username") {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={`${progress} · optional`} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">Username or email (optional)</text>
          {inputRow("Username", username, setUsername, nextStep, "skip with Enter")}
        </box>
        <StatusBar message="Enter next (empty = skip)  Esc back" />
      </box>
    );
  }

  // URL (login only)
  if (currentField === "url") {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={`${progress} · optional`} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">Website URL (optional)</text>
          {inputRow("URL", url, setUrl, nextStep, "e.g. https://github.com")}
        </box>
        <StatusBar message="Enter next (empty = skip)  Esc back" />
      </box>
    );
  }

  // Description (final step — Enter saves)
  if (currentField === "description") {
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title="New Secret" subtitle={`${progress} · save`} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">Description (optional) — Enter to save</text>
          {inputRow("Description", description, setDescription, doCreate, "skip with Enter")}
          <box flexDirection="column" border borderStyle="rounded" borderColor="#333333" padding={1} marginTop={1} gap={0}>
            <text fg="#555555"><strong>Summary</strong></text>
            <KeyValue label="Type" value={label} />
            <KeyValue label="Name" value={name} valueColor="#FFD700" />
            <KeyValue label="Value" value={"*".repeat(Math.min(value.length, 20))} valueColor="#FF4444" />
            {username ? <KeyValue label="Username" value={username} /> : null}
            {url ? <KeyValue label="URL" value={url} /> : null}
          </box>
        </box>
        <StatusBar message="Enter save  Esc back" />
      </box>
    );
  }

  return null;
}

// ─── Edit Screen ─────────────────────────────────────────────────────

type EditField = "name" | "value" | "username" | "url" | "description";

const EDIT_FIELDS: { key: EditField; label: string; forTypes: SecretType[] }[] = [
  { key: "name", label: "Name", forTypes: ["password", "note", "otp"] },
  { key: "value", label: "Value", forTypes: ["password", "note", "otp"] },
  { key: "username", label: "Username", forTypes: ["password", "otp"] },
  { key: "url", label: "URL", forTypes: ["password"] },
  { key: "description", label: "Description", forTypes: ["password", "note", "otp"] },
];

function EditScreen({ session, secret, onDone, onBack }: {
  session: VaultSession;
  secret: SecretRecord;
  onDone: (msg: string) => void;
  onBack: () => void;
}) {
  // Load fresh detail
  let detail: SecretRecord;
  try { detail = session.getSecret(secret.id) as SecretRecord; }
  catch { detail = secret; }

  const secretType = detail.type as SecretType;
  const fields = EDIT_FIELDS.filter((f) => f.forTypes.includes(secretType));

  const [editing, setEditing] = useState<EditField | null>(null);
  const [values, setValues] = useState<Record<string, string>>({
    name: detail.name,
    value: detail.value ?? "",
    username: detail.username ?? "",
    url: detail.metadata?.url ? String(detail.metadata.url) : "",
    description: detail.metadata?.description ? String(detail.metadata.description) : "",
  });
  const [inputVal, setInputVal] = useState("");
  const inputValRef = useRef("");
  const [editGeneration, setEditGeneration] = useState(0);

  const doSave = useCallback(() => {
    try {
      const updates: Record<string, string | Record<string, unknown>> = {};
      if (values.name !== detail.name) updates.name = values.name;
      if (values.value !== (detail.value ?? "")) updates.value = values.value;
      if (values.username !== (detail.username ?? "")) updates.username = values.username;

      const metaUpdates: Record<string, string | undefined> = {};
      const oldUrl = detail.metadata?.url ? String(detail.metadata.url) : "";
      const oldDesc = detail.metadata?.description ? String(detail.metadata.description) : "";
      if (values.url !== oldUrl) metaUpdates.url = values.url || undefined;
      if (values.description !== oldDesc) metaUpdates.description = values.description || undefined;
      if (Object.keys(metaUpdates).length > 0) updates.metadata = metaUpdates;

      if (Object.keys(updates).length === 0) {
        onDone("No changes");
        return;
      }
      session.updateSecret(detail.id, updates);
      onDone(`"${values.name}" updated`);
    } catch (e) {
      onDone(`Error: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [values, detail, session, onDone]);

  useKeyboard((key) => {
    if (key.eventType !== "press") return;
    if (key.name === "escape") {
      if (editing) {
        setEditing(null);
      } else {
        onBack();
      }
    }
    // Ctrl+S to save from field list
    if (key.ctrl && key.name === "s" && !editing) {
      doSave();
    }
  });

  // Editing a single field
  if (editing) {
    const fieldDef = fields.find((f) => f.key === editing);
    return (
      <box flexDirection="column" width="100%" height="100%">
        <Header title={`Edit ${fieldDef?.label ?? editing}`} subtitle={detail.name} />
        <box padding={2} flexDirection="column" gap={1}>
          <text fg="#888888">Current: <span fg="#555555">{values[editing] || "(empty)"}</span></text>
          <box flexDirection="row" gap={1}>
            <text fg="#AAAAAA" width={12}>New value</text>
            <input
              value={inputVal}
              onChange={(v: string) => { setInputVal(v); inputValRef.current = v; }}
              onSubmit={() => {
                const saved = inputValRef.current;
                const field = editing;
                if (field) {
                  setValues((prev) => ({ ...prev, [field]: saved }));
                }
                setEditing(null);
                setInputVal("");
                inputValRef.current = "";
                setEditGeneration((g) => g + 1);
              }}
              placeholder={values[editing] || "enter new value..."}
              focused
              flexGrow={1}
              backgroundColor="#111111"
              focusedBackgroundColor="#1a1a1a"
              textColor="#FFFFFF"
            />
          </box>
        </box>
        <StatusBar message="Enter save field  Esc cancel" />
      </box>
    );
  }

  // Field list
  const options = fields.map((f) => {
    let display: string;
    if (f.key === "value") {
      display = values[f.key] ? "***" : "(empty)";
    } else {
      display = values[f.key] || "(empty)";
    }
    return {
      name: `${f.label}: ${display}`,
      description: "Enter to edit",
      value: f.key,
    };
  });

  return (
    <box flexDirection="column" width="100%" height="100%">
      <Header title="Edit Secret" subtitle={detail.name} />
      <box flexGrow={1} paddingX={2} paddingTop={1}>
        <select
          options={options}
          key={editGeneration}
          onSelect={(_i: number, opt: { value?: string }) => {
            const val = opt.value ?? "";
            const current = values[val] ?? "";
            setEditing(val as EditField);
            setInputVal(current);
            inputValRef.current = current;
          }}
          focused
          height={Math.min(options.length * 2 + 1, 14)}
          selectedBackgroundColor="#222222"
          selectedTextColor="#FFD700"
        />
      </box>
      <box paddingX={2} paddingBottom={1}>
        <box
          border borderStyle="rounded" borderColor="#FFD700"
          paddingX={2} height={3}
          flexDirection="row" alignItems="center" gap={2}
          onMouseDown={doSave}
        >
          <text fg="#FFD700"><strong>Ctrl+S Save</strong></text>
        </box>
      </box>
      <StatusBar message="Enter edit field  Ctrl+S save  Esc back" />
    </box>
  );
}

// ─── App Root ────────────────────────────────────────────────────────

function App({ vaultPath }: { vaultPath: string }) {
  const [screen, setScreen] = useState<Screen>("unlock");
  const [session, setSession] = useState<VaultSession | null>(null);
  const [selectedSecret, setSelectedSecret] = useState<SecretRecord | null>(null);
  const { toast, show: showToast } = useToast();
  // Bump to force HomeScreen to reload secrets
  const [refreshKey, setRefreshKey] = useState(0);

  const goHome = useCallback(() => {
    setScreen("home");
    setSelectedSecret(null);
    setRefreshKey((k) => k + 1);
  }, []);

  const handleDone = useCallback((msg: string) => {
    goHome();
    showToast(msg, msg.startsWith("Error:") ? "error" : "success");
  }, [goHome, showToast]);

  if (screen === "unlock") {
    return (
      <UnlockScreen vaultPath={vaultPath} onUnlock={(s) => { setSession(s); setScreen("home"); }} />
    );
  }

  if (!session) return <box padding={2}><text fg="#FF4444">No session.</text></box>;

  switch (screen) {
    case "home":
      return (
        <HomeScreen
          key={refreshKey}
          session={session}
          onSelect={(s) => { setSelectedSecret(s); setScreen("detail"); }}
          onCreate={() => setScreen("create")}
          toast={toast}
        />
      );
    case "detail":
      return selectedSecret ? (
        <DetailScreen
          session={session}
          secret={selectedSecret}
          onBack={goHome}
          onDeleted={handleDone}
          onEdit={() => setScreen("edit")}
        />
      ) : <HomeScreen key={refreshKey} session={session} onSelect={(s) => { setSelectedSecret(s); setScreen("detail"); }} onCreate={() => setScreen("create")} toast={toast} />;
    case "edit":
      return selectedSecret ? (
        <EditScreen
          session={session}
          secret={selectedSecret}
          onDone={handleDone}
          onBack={() => setScreen("detail")}
        />
      ) : <HomeScreen key={refreshKey} session={session} onSelect={(s) => { setSelectedSecret(s); setScreen("detail"); }} onCreate={() => setScreen("create")} toast={toast} />;
    case "create":
      return <CreateScreen session={session} onDone={handleDone} onBack={goHome} />;
    default:
      return <HomeScreen key={refreshKey} session={session} onSelect={(s) => { setSelectedSecret(s); setScreen("detail"); }} onCreate={() => setScreen("create")} toast={toast} />;
  }
}

// ─── Entry ───────────────────────────────────────────────────────────

export async function runTui(vaultPath?: string): Promise<void> {
  const vault = vaultPath ?? defaultVaultPath();
  const renderer = await createCliRenderer({ exitOnCtrlC: true });
  createRoot(renderer).render(<App vaultPath={vault} />);
}
