import { FileKey, Fingerprint, KeyRound, Lock, TriangleAlert } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";

import { Button } from "../components/ui/button.tsx";
import { Field, Input } from "../components/ui/field.tsx";
import { Spinner } from "../components/ui/panel.tsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs.tsx";
import { api, errorMessage, type AuthInfo, type SessionInfo } from "../lib/api.ts";
import { authenticatePasskey, passkeyProblem } from "../lib/webauthn.ts";

export function Logo({ className = "" }: { className?: string }) {
  return <span className={`inline-flex items-center rounded-sm bg-accent px-1.5 font-mono font-bold text-on-accent ${className}`}>autho</span>;
}

export function UnlockScreen({ onUnlocked }: { onUnlocked: (session: SessionInfo) => void }) {
  const [auth, setAuth] = useState<AuthInfo | null>(null);
  const [loadError, setLoadError] = useState("");
  const [method, setMethod] = useState("password");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [recoveryFile, setRecoveryFile] = useState<{ name: string; content: string } | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    api.auth().then(setAuth, (e) => setLoadError(errorMessage(e)));
  }, []);

  useEffect(() => {
    if (auth && method === "password") passwordRef.current?.focus();
  }, [auth, method]);

  const unlock = async (body: Record<string, unknown>) => {
    setBusy(true);
    setError("");
    try {
      onUnlocked(await api.unlock(body));
    } catch (e) {
      setError(errorMessage(e));
      if (body.method === "password") {
        setPassword("");
        setTotp("");
        passwordRef.current?.focus();
      }
    } finally {
      setBusy(false);
    }
  };

  const submitPassword = (event: FormEvent) => {
    event.preventDefault();
    if (!password) return;
    void unlock({ method: "password", password, totp: auth?.totp ? totp : undefined });
  };

  const usePasskey = async () => {
    if (!auth) return;
    setError("");
    setBusy(true);
    try {
      const result = await authenticatePasskey(auth.rpId, auth.passkeys);
      await unlock({ method: "passkey", ...result });
    } catch (e) {
      setError(e instanceof DOMException && e.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out" : errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const pickRecovery = async (file: File | undefined) => {
    setError("");
    if (!file) return setRecoveryFile(null);
    if (file.size > 4096) return setError("That file is too large to be an autho recovery file");
    setRecoveryFile({ name: file.name, content: await file.text() });
  };

  const problem = auth ? passkeyProblem(auth.rpId) : null;
  const wrongHost = auth && location.hostname !== auth.rpId;

  return (
    <div className="flex min-h-full items-center justify-center bg-[radial-gradient(ellipse_at_top,#1a1700_0%,transparent_55%)] p-6">
      <div className="w-full max-w-sm animate-in">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <div className="flex size-14 items-center justify-center rounded-2xl border border-accent/30 bg-accent/10 text-accent">
            <Lock className="size-6" />
          </div>
          <Logo className="text-lg" />
          <p className="font-mono text-xs text-dim">{auth?.vault ?? "vault"} · locked</p>
        </div>

        {loadError ? (
          <Notice tone="danger">{loadError}</Notice>
        ) : !auth ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : !auth.initialized ? (
          <Notice tone="info">
            There's no vault here yet. Run <code className="font-mono text-accent">autho init</code> in a terminal, then reload.
          </Notice>
        ) : (
          <div className="rounded-xl border border-border bg-panel p-5 shadow-2xl shadow-black/50">
            <Tabs value={method} onValueChange={(v) => { setMethod(v); setError(""); }}>
              {auth.passkeys.length > 0 || auth.recovery ? (
                <TabsList className="mb-5 flex w-full">
                  <TabsTrigger value="password"><KeyRound />Password</TabsTrigger>
                  {auth.passkeys.length > 0 ? <TabsTrigger value="passkey"><Fingerprint />Passkey</TabsTrigger> : null}
                  {auth.recovery ? <TabsTrigger value="recovery"><FileKey />Recovery</TabsTrigger> : null}
                </TabsList>
              ) : null}

              <TabsContent value="password">
                <form onSubmit={submitPassword} className="flex flex-col gap-4">
                  {/* Lets password managers pair the field with this vault. */}
                  <input type="text" name="username" autoComplete="username" value={`autho:${auth.vault}`} readOnly hidden />
                  <Field label="Master password" htmlFor="password">
                    <Input
                      id="password"
                      ref={passwordRef}
                      type="password"
                      autoComplete="current-password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={busy}
                      maxLength={1024}
                    />
                  </Field>
                  {auth.totp ? (
                    <Field label="Authenticator code" htmlFor="totp">
                      <Input
                        id="totp"
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        placeholder="123 456"
                        className="font-mono tracking-[0.3em]"
                        value={totp}
                        onChange={(e) => setTotp(e.target.value.replace(/[^\d ]/g, "").slice(0, 9))}
                        disabled={busy}
                      />
                    </Field>
                  ) : null}
                  <Button type="submit" variant="primary" size="lg" disabled={busy || !password || (auth.totp && totp.replace(/\s/g, "").length < 6)}>
                    {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}
                    Unlock
                  </Button>
                </form>
              </TabsContent>

              <TabsContent value="passkey" className="flex flex-col gap-4">
                <p className="text-sm text-muted">
                  Use one of your registered passkeys or security keys: {auth.passkeys.map((p) => p.label).join(", ")}.
                </p>
                {problem ? <Notice tone="info">{problem}</Notice> : null}
                <Button variant="primary" size="lg" onClick={() => void usePasskey()} disabled={busy || problem !== null}>
                  {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : <Fingerprint />}
                  {busy ? "Waiting for your passkey…" : "Unlock with passkey"}
                </Button>
              </TabsContent>

              <TabsContent value="recovery">
                <form
                  className="flex flex-col gap-4"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (recoveryFile) void unlock({ method: "recovery", recoveryFile: recoveryFile.content });
                  }}
                >
                  <p className="text-sm text-muted">Choose the recovery file you saved when you set it up. It never leaves this machine.</p>
                  <label className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed border-border-focus bg-input px-4 py-6 text-center transition-colors hover:border-accent">
                    <FileKey className="size-6 text-dim" />
                    <span className="text-sm text-text">{recoveryFile?.name ?? "Choose recovery file…"}</span>
                    <input type="file" accept=".txt,text/plain" className="sr-only" onChange={(e) => void pickRecovery(e.target.files?.[0])} />
                  </label>
                  <Button type="submit" variant="primary" size="lg" disabled={busy || !recoveryFile}>Unlock with recovery file</Button>
                </form>
              </TabsContent>
            </Tabs>

            {error ? <p role="alert" className="mt-4 flex items-start gap-2 text-sm text-danger"><span>✗</span>{error}</p> : null}
          </div>
        )}

        {wrongHost ? (
          <p className="mt-4 text-center text-xs text-dim">
            Tip: open <a className="text-accent hover:underline" href={`http://${auth!.rpId}:${location.port}/`}>{`http://${auth!.rpId}:${location.port}`}</a> so passkeys work.
          </p>
        ) : null}
        <p className="mt-8 text-center text-xs text-dim">Local only · this page talks to autho on your machine</p>
      </div>
    </div>
  );
}

export function Notice({ tone, children }: { tone: "info" | "danger" | "success"; children: ReactNode }) {
  const styles = {
    info: "border-info/30 bg-info/5 text-info",
    danger: "border-danger/40 bg-danger-bg text-danger",
    success: "border-success/30 bg-success/5 text-success",
  }[tone];
  return (
    <div className={`flex items-start gap-2.5 rounded-lg border px-3.5 py-3 text-sm ${styles}`}>
      <TriangleAlert className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 text-text/90">{children}</div>
    </div>
  );
}
