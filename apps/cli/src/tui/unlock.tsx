import { readFileSync } from "node:fs";

import { useKeyboard } from "@opentui/react";
import { useCallback, useEffect, useState } from "react";

import { VaultService } from "../../../../packages/core/src/index.ts";
import type { UnlockCredentials, VaultSession } from "../../../../packages/core/src/index.ts";
import { hasPinSet, loadVaultPassword, verifyPin } from "../../../../packages/core/src/os-secrets.ts";
import { Centered, SecretInput, useNow, type KeyHint } from "./components.tsx";
import { useApp, useScreenContext } from "./context.tsx";
import { theme } from "./theme.ts";

type Step = "loading" | "password" | "pin" | "totp" | "unlocking";

const MAX_PIN_ATTEMPTS = 5;

/** Reads the token from a recovery file written by `autho recovery generate`. */
export function readRecoveryToken(path: string): string | null {
  const lines = readFileSync(path, "utf8").split(/\r?\n/);
  const idx = lines.findIndex((line) => line.trim() === "RECOVERY TOKEN:");
  if (idx === -1) {
    return null;
  }
  const raw = lines.slice(idx + 1).find((line) => line.trim() !== "") ?? "";
  const token = raw.trim().replace(/-/g, "").toLowerCase();
  return token || null;
}

export function UnlockScreen({ vaultPath, onUnlock, setHints, notice }: {
  vaultPath: string;
  onUnlock: (session: VaultSession) => void;
  setHints: (hints: KeyHint[]) => void;
  notice?: string;
}) {
  const app = useApp();
  const [step, setStep] = useState<Step>("loading");
  const [error, setError] = useState(notice ?? "");
  const [password, setPassword] = useState("");
  const [pin, setPin] = useState("");
  const [totp, setTotp] = useState("");
  // Password that came from the OS keychain; never shown, only used to unlock.
  const [storedPassword, setStoredPassword] = useState<string | null>(null);
  const [needs, setNeeds] = useState({ pin: false, totp: false });
  const [pinAttempts, setPinAttempts] = useState(0);

  useScreenContext([], null);

  const finish = useCallback((creds: UnlockCredentials) => {
    setStep("unlocking");
    try {
      onUnlock(VaultService.unlock(vaultPath, creds));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setPassword("");
      setTotp("");
      setStoredPassword(null);
      setStep("password");
    }
  }, [vaultPath, onUnlock]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const recoveryFile = process.env.AUTHO_RECOVERY_FILE;
      if (recoveryFile) {
        try {
          const token = readRecoveryToken(recoveryFile);
          if (token) {
            try {
              const session = VaultService.unlock(vaultPath, { password: "", recovery: token });
              if (!cancelled) onUnlock(session);
              return;
            } catch {
              if (!cancelled) setError("Recovery file did not unlock the vault — enter your password");
            }
          } else if (!cancelled) {
            setError("Recovery file is malformed — enter your password");
          }
        } catch {
          if (!cancelled) setError("Recovery file could not be read — enter your password");
        }
      }

      const pinSet = await hasPinSet(vaultPath);
      const totpSet = VaultService.getAuthConfig(vaultPath)?.totp !== undefined;
      const keychain = await loadVaultPassword(vaultPath);
      if (cancelled) return;
      setNeeds({ pin: pinSet, totp: totpSet });

      if (keychain) {
        setStoredPassword(keychain);
        // Same order as the CLI: keychain password, then PIN, then TOTP.
        if (pinSet) { setStep("pin"); return; }
        if (totpSet) { setStep("totp"); return; }
        finish({ password: keychain });
        return;
      }
      setStep("password");
    })();
    return () => { cancelled = true; };
  }, [vaultPath, onUnlock, finish]);

  const afterPassword = (pw: string) => {
    if (needs.pin) { setStep("pin"); return; }
    if (needs.totp) { setStep("totp"); return; }
    finish({ password: pw });
  };

  const submitPassword = (pw: string) => {
    if (!pw) return;
    setError("");
    afterPassword(pw);
  };

  const submitPin = (value: string) => {
    if (!value) return;
    setStep("unlocking");
    void verifyPin(vaultPath, value).then((ok) => {
      setPin("");
      if (!ok) {
        const attempts = pinAttempts + 1;
        setPinAttempts(attempts);
        if (attempts >= MAX_PIN_ATTEMPTS) {
          // Too many misses: stop trusting the keychain shortcut for this run.
          setStoredPassword(null);
          setNeeds((n) => ({ ...n, pin: false }));
          setError("Too many wrong PINs — enter your master password");
          setStep("password");
          return;
        }
        setError(`Wrong PIN (${MAX_PIN_ATTEMPTS - attempts} attempts left)`);
        setStep("pin");
        return;
      }
      setError("");
      const pw = storedPassword ?? password;
      if (needs.totp) { setStep("totp"); return; }
      finish({ password: pw });
    });
  };

  const submitTotp = (code: string) => {
    if (!/^\d{6,8}$/.test(code)) {
      setError("Enter the 6-digit code from your authenticator app");
      return;
    }
    finish({ password: storedPassword ?? password, totp: code });
  };

  useKeyboard((key) => {
    if (!app.active) return;
    // From the keychain shortcut, Tab falls back to typing the master password.
    if (key.name === "tab" && storedPassword && (step === "pin" || step === "totp")) {
      key.preventDefault();
      setStoredPassword(null);
      setError("");
      setStep("password");
    }
  });

  useEffect(() => {
    const hints: KeyHint[] = [["enter", "unlock"]];
    if (step === "password" || step === "pin") hints.push(["ctrl+r", "show"]);
    if (storedPassword && (step === "pin" || step === "totp")) hints.push(["tab", "use password"]);
    hints.push(["ctrl+c ×2", "quit"]);
    setHints(hints);
  }, [step, storedPassword, setHints]);

  const now = useNow(1000, step === "totp");
  const remaining = Math.ceil((30_000 - (now % 30_000)) / 1000);
  const focused = app.active;

  return (
    <Centered>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.border} paddingX={2} paddingY={1} width={56} gap={1} title=" autho " titleAlignment="center">
        <text fg={theme.muted}>{step === "pin" ? "Quick unlock with your PIN" : step === "totp" ? "Two-factor code" : "Unlock your vault"}</text>
        {error ? <text fg={theme.danger}>{error}</text> : null}
        {step === "loading" || step === "unlocking" ? (
          <text fg={theme.accent}>{step === "loading" ? "Checking unlock options…" : "Unlocking…"}</text>
        ) : null}
        {step === "password" ? (
          <box flexDirection="row" gap={1}>
            <text fg={theme.muted} width={10}>Password</text>
            <SecretInput value={password} onChange={setPassword} onSubmit={submitPassword} focused={focused} placeholder="master password" />
          </box>
        ) : null}
        {step === "pin" ? (
          <box flexDirection="row" gap={1}>
            <text fg={theme.muted} width={10}>PIN</text>
            <SecretInput value={pin} onChange={setPin} onSubmit={submitPin} focused={focused} placeholder="PIN" />
          </box>
        ) : null}
        {step === "totp" ? (
          <box flexDirection="row" gap={1}>
            <text fg={theme.muted} width={10}>Code</text>
            <SecretInput
              value={totp}
              onChange={(v) => {
                const digits = v.replace(/\D/g, "").slice(0, 8);
                setTotp(digits);
                if (digits.length === 6) submitTotp(digits);
              }}
              onSubmit={submitTotp}
              focused={focused}
              placeholder="6 digits"
            />
            <text fg={remaining <= 5 ? theme.danger : theme.dim}>{remaining}s</text>
          </box>
        ) : null}
      </box>
    </Centered>
  );
}
