import { Fingerprint, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";

import { api, ApiError, errorMessage, type AuthInfo, type SecurityStatus } from "../lib/api.ts";
import { authenticatePasskey, passkeyProblem } from "../lib/webauthn.ts";
import { useApp } from "../context.tsx";
import { Button } from "./ui/button.tsx";
import { Dialog, DialogContent, DialogFooter } from "./ui/dialog.tsx";
import { Field, Input } from "./ui/field.tsx";
import { Spinner } from "./ui/panel.tsx";

type Action = (status: SecurityStatus | null) => void | Promise<void>;

/**
 * Security changes need a fresh proof of identity, like the TUI's admin
 * prompt. `withAdmin(fn)` runs fn straight away while the grant is fresh,
 * otherwise asks for the password (and code) or a passkey first. A 403 from
 * the server (grant expired meanwhile) re-opens the prompt and retries once.
 */
export function useAdminGate(onStatus?: (status: SecurityStatus) => void): {
  withAdmin: (fn: Action) => void;
  adminUntil: number | null;
  setAdminUntil: (until: number | null) => void;
  gate: ReactNode;
} {
  const [adminUntil, setAdminUntil] = useState<number | null>(null);
  const [pending, setPending] = useState<Action | null>(null);
  const retried = useRef(false);

  const run = useCallback(async (fn: Action, status: SecurityStatus | null) => {
    try {
      await fn(status);
      retried.current = false;
    } catch (error) {
      if (error instanceof ApiError && error.status === 403 && !retried.current) {
        retried.current = true;
        setAdminUntil(null);
        setPending(() => fn);
        return;
      }
      retried.current = false;
      throw error;
    }
  }, []);

  const withAdmin = useCallback((fn: Action) => {
    if (adminUntil !== null && adminUntil - Date.now() > 5000) {
      void run(fn, null).catch(() => {});
      return;
    }
    setPending(() => fn);
  }, [adminUntil, run]);

  const gate = (
    <Dialog open={pending !== null} onOpenChange={(open) => !open && setPending(null)}>
      {pending ? (
        <AuthorizeDialog
          onAuthorized={(status) => {
            const fn = pending;
            setPending(null);
            setAdminUntil(status.adminUntil);
            onStatus?.(status);
            void run(fn, status).catch(() => {});
          }}
        />
      ) : null}
    </Dialog>
  );

  return { withAdmin, adminUntil, setAdminUntil, gate };
}

function AuthorizeDialog({ onAuthorized }: { onAuthorized: (status: SecurityStatus) => void }) {
  const [auth, setAuth] = useState<AuthInfo | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const { setModalOpen } = useApp();

  useEffect(() => {
    setModalOpen(true);
    api.auth().then(setAuth, (e) => setError(errorMessage(e)));
    return () => setModalOpen(false);
  }, [setModalOpen]);

  const authorize = async (body: Record<string, unknown>) => {
    setBusy(true);
    setError("");
    try {
      onAuthorized(await api.authorize(body));
    } catch (e) {
      setError(e instanceof DOMException && e.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out" : errorMessage(e));
      if (body.method === "password") {
        setPassword("");
        setTotp("");
      }
      setBusy(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (password) void authorize({ method: "password", password, totp: auth?.totp ? totp : undefined });
  };

  const usePasskey = async () => {
    if (!auth) return;
    setBusy(true);
    setError("");
    try {
      const result = await authenticatePasskey(auth.rpId, auth.passkeys);
      await authorize({ method: "passkey", ...result });
    } catch (e) {
      setError(e instanceof DOMException && e.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out" : errorMessage(e));
      setBusy(false);
    }
  };

  const canPasskey = auth !== null && auth.passkeys.length > 0 && passkeyProblem(auth.rpId) === null;

  return (
    <DialogContent title={<span className="flex items-center gap-2"><ShieldCheck className="size-4" />Confirm it's you</span>} description="Security changes need your master password. You won't be asked again for 5 minutes.">
      {!auth && !error ? (
        <div className="flex justify-center py-6"><Spinner /></div>
      ) : (
        <form onSubmit={submit} className="flex flex-col gap-4">
          <input type="text" name="username" autoComplete="username" value={`autho:${auth?.vault ?? ""}`} readOnly hidden />
          <Field label="Master password" htmlFor="admin-password">
            <Input id="admin-password" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} maxLength={1024} />
          </Field>
          {auth?.totp ? (
            <Field label="Authenticator code" htmlFor="admin-totp">
              <Input id="admin-totp" inputMode="numeric" autoComplete="one-time-code" placeholder="123 456" className="font-mono tracking-[0.3em]" value={totp} onChange={(e) => setTotp(e.target.value.replace(/[^\d ]/g, "").slice(0, 9))} disabled={busy} />
            </Field>
          ) : null}
          {error ? <p role="alert" className="text-sm text-danger">✗ {error}</p> : null}
          <DialogFooter className="mt-1">
            {canPasskey ? (
              <Button type="button" variant="secondary" onClick={() => void usePasskey()} disabled={busy} className="mr-auto">
                <Fingerprint />Use passkey
              </Button>
            ) : null}
            <Button type="submit" variant="primary" disabled={busy || !password || (auth?.totp === true && totp.replace(/\s/g, "").length < 6)}>
              {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}Confirm
            </Button>
          </DialogFooter>
        </form>
      )}
    </DialogContent>
  );
}
