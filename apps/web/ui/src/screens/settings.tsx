import QRCode from "qrcode";
import { Copy, Download, Fingerprint } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { toast } from "sonner";

import { useAdminGate } from "../components/admin-gate.tsx";
import { ConfirmDialog } from "../components/confirm-dialog.tsx";
import { Button } from "../components/ui/button.tsx";
import { Dialog, DialogContent, DialogFooter } from "../components/ui/dialog.tsx";
import { Field, Input } from "../components/ui/field.tsx";
import { Panel, Spinner } from "../components/ui/panel.tsx";
import { Switch } from "../components/ui/switch.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { api, ApiError, errorMessage, type PreferenceRow, type SecurityStatus, type Settings } from "../lib/api.ts";
import { cn, formatDate, isTypingTarget } from "../lib/utils.ts";
import { passkeyProblem, passkeysSupported, registerPasskey } from "../lib/webauthn.ts";

const SECTIONS = [
  { id: "storage", label: "Storage" },
  { id: "security", label: "Security" },
  { id: "behaviour", label: "Behaviour" },
  { id: "agents", label: "Agents & services" },
  { id: "about", label: "About" },
] as const;
type SectionId = (typeof SECTIONS)[number]["id"];

const BEHAVIOUR_KEYS = ["revealSeconds", "clipboardClearSeconds", "idleLockSeconds", "passwordLength", "passwordSymbols", "mouse"];
const AGENT_KEYS = ["defaultLeaseTtl", "daemonTtlSeconds", "webPort", "webWithTui"];

type SettingsDialog =
  | { kind: "number"; pref: PreferenceRow }
  | { kind: "vaultDir" }
  | { kind: "password" }
  | { kind: "pin" }
  | { kind: "totp"; secret: string; uri: string }
  | { kind: "passkey" }
  | { kind: "recovery"; content: string }
  | { kind: "confirm"; title: string; body?: string; action: string; run: () => Promise<void> };

export function SettingsScreen() {
  const app = useApp();
  const [settings, setSettings] = useState<Settings | null>(null);
  const [section, setSection] = useState<SectionId>("security");
  const [dialog, setDialog] = useState<SettingsDialog | null>(null);
  const { setModalOpen } = app;

  const setSecurity = useCallback((security: SecurityStatus) => {
    setSettings((current) => (current ? { ...current, security } : current));
  }, []);
  const { withAdmin, setAdminUntil, adminUntil, gate } = useAdminGate(setSecurity);

  const load = useCallback(async () => {
    try {
      const next = await api.settings();
      setSettings(next);
      setAdminUntil(next.security.adminUntil);
    } catch (error) {
      toast.error(errorMessage(error));
    }
  }, [setAdminUntil]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    setModalOpen(dialog !== null);
    return () => setModalOpen(false);
  }, [dialog, setModalOpen]);

  /** Runs a change and toasts the outcome; a 403 is rethrown so the admin gate can re-prompt. */
  const attempt = useCallback(async (fn: () => Promise<SecurityStatus | void>, done?: string) => {
    try {
      const status = await fn();
      if (status) {
        setSecurity(status);
        setAdminUntil(status.adminUntil);
      }
      if (done) toast.success(done);
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) throw error;
      toast.error(errorMessage(error));
    }
  }, [setSecurity, setAdminUntil]);

  const savePreference = useCallback(async (pref: PreferenceRow, value: number | boolean | null) => {
    try {
      const result = await api.setPreference(pref.key, value);
      app.setPrefs(result.prefs);
      setSettings((current) => current && {
        ...current,
        preferences: current.preferences.map((p) => (p.key === pref.key ? { ...p, value: value ?? p.default, display: result.display, source: result.source as PreferenceRow["source"] } : p)),
      });
      if (result.source === "env") toast(`Saved — ${pref.env} still overrides it for now`);
      else toast.success(`${pref.label}: ${result.display}`);
      return true;
    } catch (error) {
      // The confirmation lapsed while the dialog was open: the next try asks again.
      if (error instanceof ApiError && error.status === 403) setAdminUntil(null);
      toast.error(errorMessage(error));
      return false;
    }
  }, [app, setAdminUntil]);

  // Arrow keys / tab-like switching between sections, like the TUI's left/right.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || app.paletteOpen || app.modalOpen || event.ctrlKey || event.metaKey || event.altKey || isTypingTarget(event.target)) return;
      const index = SECTIONS.findIndex((s) => s.id === section);
      if (event.key === "ArrowRight" || event.key === "l" || event.key === "]") {
        event.preventDefault();
        setSection(SECTIONS[(index + 1) % SECTIONS.length]!.id);
      } else if (event.key === "ArrowLeft" || event.key === "h" || event.key === "[") {
        event.preventDefault();
        setSection(SECTIONS[(index - 1 + SECTIONS.length) % SECTIONS.length]!.id);
      } else if (event.key === "Escape") {
        app.go("vault");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [section, app]);

  const commands = useMemo<Command[]>(() => SECTIONS.map((s) => ({ id: `section:${s.id}`, title: `Settings · ${s.label}`, group: "Settings", run: () => setSection(s.id) })), []);
  const hints = useMemo<KeyHint[]>(() => [["←→", "section"], ["tab", "field"], ["esc", "back"]], []);
  useScreen(commands, hints);

  if (!settings) {
    return <Panel className="h-full"><div className="flex h-full items-center justify-center"><Spinner /></div></Panel>;
  }

  const { security, paths } = settings;
  const prefRows = (keys: string[]) => keys
    .map((key) => settings.preferences.find((p) => p.key === key))
    .filter((p): p is PreferenceRow => p !== undefined)
    .map((pref) => {
      const guard = (fn: () => void) => (pref.guarded ? withAdmin(fn) : fn());
      return (
        <PreferenceItem
          key={pref.key}
          pref={pref}
          onEdit={() => guard(() => setDialog({ kind: "number", pref }))}
          onToggle={(v) => guard(() => void savePreference(pref, v))}
          onReset={() => guard(() => void savePreference(pref, null))}
        />
      );
    });

  const confirm = (title: string, action: string, run: () => Promise<void>, body?: string) => setDialog({ kind: "confirm", title, action, run, body });

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 md:grid-cols-[13rem_1fr] sm:gap-4">
      <nav className="flex gap-1 overflow-x-auto md:flex-col" aria-label="Settings sections">
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            type="button"
            onClick={() => setSection(s.id)}
            aria-current={section === s.id ? "page" : undefined}
            className={cn(
              "shrink-0 cursor-pointer rounded-md border-l-2 px-3 py-2 text-left text-sm transition-colors",
              section === s.id ? "border-accent bg-selection text-accent" : "border-transparent text-muted hover:bg-selection/50 hover:text-text",
            )}
          >
            {s.label}
          </button>
        ))}
      </nav>

      <Panel
        title={SECTIONS.find((s) => s.id === section)!.label}
        actions={section === "security" && adminUntil && adminUntil > Date.now() ? (
          <Button variant="ghost" size="sm" onClick={() => void attempt(() => api.release().then((s) => { setAdminUntil(null); return s; }), "Confirmation dropped")}>
            <span className="text-success">●</span> confirmed · end now
          </Button>
        ) : undefined}
        bodyClassName="overflow-y-auto"
      >
        <div className="divide-y divide-border">
          {section === "storage" ? (
            <>
              <PathItem label="Vault file" path={paths.vault} help="The vault this session has open" />
              <Item
                label="Vault folder"
                value={<span className="break-all font-mono text-xs">{paths.home} <span className="text-dim">· {paths.envHome ? "AUTHO_HOME" : paths.vaultDir ? "config" : "default"}</span></span>}
                help={paths.envHome ? "AUTHO_HOME is set, so it decides the folder — unset it to change this here" : "Where vault.db, project.json and daemon.json live. Files are not moved; restart autho after changing it"}
                action={paths.envHome ? undefined : <Button size="sm" variant="secondary" onClick={() => withAdmin(() => setDialog({ kind: "vaultDir" }))}>Change</Button>}
              />
              <PathItem label="Config file" path={paths.config} help="Settings on this page are saved here" />
              <PathItem label="Project file" path={paths.project} help="Default env mappings for `env`, `exec` and the daemon" />
              <PathItem label="Daemon state" path={paths.daemon} help="Port and token of a running `autho daemon serve`" />
            </>
          ) : null}

          {section === "security" ? (
            <>
              <Item label="Master password" value={<span className="font-mono text-muted">••••••••</span>} help="Re-wraps the vault key under a new password; secrets are not re-encrypted"
                action={<Button size="sm" variant="secondary" onClick={() => withAdmin(() => setDialog({ kind: "password" }))}>Change</Button>} />
              <Item
                label="Remember password"
                value={<OnOff on={security.keychain} unavailable={!security.osStore} />}
                help={security.osStore ? "Keep the master password in the OS keychain so this device unlocks without typing it" : "The OS secret store is off (AUTHO_DISABLE_OS_SECRETS)"}
                action={security.osStore ? (
                  <Switch
                    checked={security.keychain}
                    aria-label="Remember password"
                    onCheckedChange={(on) => on
                      ? withAdmin((status) => {
                        if (status && !status.adminHasPassword) {
                          toast.error("Confirm with your master password (not a passkey) to save it in the keychain");
                          return;
                        }
                        return attempt(() => api.saveKeychain(), "Password saved to the keychain");
                      })
                      : void attempt(() => api.forgetKeychain(), "Password removed from the keychain")}
                  />
                ) : undefined}
              />
              <Item
                label="PIN"
                value={security.osStore ? <OnOff on={security.pin} onLabel="set" /> : <OnOff on={false} unavailable />}
                help={security.osStore ? "A short PIN asked before the keychain password is used on this device" : "The OS secret store is off (AUTHO_DISABLE_OS_SECRETS)"}
                action={security.osStore ? (
                  <div className="flex gap-1.5">
                    {security.pin ? <Button size="sm" variant="ghost" onClick={() => withAdmin(() => confirm("Remove the PIN?", "Remove", () => attempt(() => api.removePin(), "PIN removed")))}>Remove</Button> : null}
                    <Button size="sm" variant="secondary" onClick={() => withAdmin(() => setDialog({ kind: "pin" }))}>{security.pin ? "Change" : "Set"}</Button>
                  </div>
                ) : undefined}
              />
              <Item
                label="Two-factor code"
                value={<OnOff on={security.totp} />}
                help="Ask for an authenticator app code at every unlock"
                action={
                  <Switch
                    checked={security.totp}
                    aria-label="Two-factor code"
                    onCheckedChange={(on) => withAdmin(async () => {
                      if (on) {
                        const setup = await api.totpSetup();
                        setDialog({ kind: "totp", ...setup });
                      } else {
                        confirm("Turn off two-factor codes?", "Turn off", () => attempt(() => api.totpDisable(), "Two-factor codes turned off"));
                      }
                    })}
                  />
                }
              />
              <Item
                label="Passkeys"
                value={security.passkeys.length ? `${security.passkeys.length} registered` : <span className="text-muted">none</span>}
                help="Unlock with a passkey or hardware security key instead of the password"
                action={<Button size="sm" variant="secondary" onClick={() => withAdmin(() => setDialog({ kind: "passkey" }))}><Fingerprint />Add</Button>}
              >
                {security.passkeys.length ? (
                  <ul className="mt-3 flex flex-col gap-1.5">
                    {security.passkeys.map((p) => (
                      <li key={p.id} className="flex items-center gap-3 rounded-md border border-border bg-panel-alt px-3 py-2">
                        <Fingerprint className="size-4 text-accent" />
                        <span className="min-w-0 flex-1 truncate text-sm text-text">{p.label}</span>
                        <span className="text-xs text-dim">added {formatDate(p.createdAt)}</span>
                        <Button size="sm" variant="ghost" className="hover:text-danger" onClick={() => withAdmin(() => confirm(`Remove passkey "${p.label}"?`, "Remove", () => attempt(() => api.removePasskey(p.id), `Removed "${p.label}"`)))}>Remove</Button>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </Item>
              <Item
                label="Recovery file"
                value={security.recoveryAt ? <span className="text-success">created {formatDate(security.recoveryAt)}</span> : <span className="text-muted">none</span>}
                help="A file that unlocks the vault if you forget the password. Making a new one replaces the old one"
                action={
                  <div className="flex gap-1.5">
                    {security.recoveryAt ? (
                      <Button size="sm" variant="ghost" onClick={() => withAdmin(() => confirm("Revoke the recovery file?", "Revoke", () => attempt(() => api.revokeRecovery(), "Recovery file revoked"), "The current recovery file stops working."))}>Revoke</Button>
                    ) : null}
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => withAdmin(async () => {
                        const make = async () => {
                          const { fileContent, security: status } = await api.createRecovery();
                          setSecurity(status);
                          setDialog({ kind: "recovery", content: fileContent });
                        };
                        if (security.recoveryAt) confirm("Replace the recovery file?", "Replace", () => attempt(make), "The old recovery file stops working.");
                        else await attempt(make);
                      })}
                    >
                      {security.recoveryAt ? "Replace" : "Create"}
                    </Button>
                  </div>
                }
              />
            </>
          ) : null}

          {section === "behaviour" ? prefRows(BEHAVIOUR_KEYS) : null}
          {section === "agents" ? prefRows(AGENT_KEYS) : null}

          {section === "about" ? (
            <>
              <Item label="autho" value={<span className="font-mono">{settings.about.version}</span>} help="Installed version" />
              <Item label="Runtime" value={<span className="font-mono">Bun {settings.about.bun} · {settings.about.platform}</span>} />
              <Item label="OS secret store" value={security.osStore ? "available" : <span className="text-dim">off (AUTHO_DISABLE_OS_SECRETS)</span>} help="Used for the remembered password and the PIN" />
              <Item label="Web UI" value={<span className="font-mono">{location.origin}</span>} help="Local only: bound to loopback, same-origin requests only, locks when idle" />
            </>
          ) : null}
        </div>
      </Panel>

      <Dialog open={dialog !== null} onOpenChange={(open) => !open && setDialog(null)}>
        {dialog?.kind === "number" ? <NumberDialog pref={dialog.pref} onSave={async (v) => { if (await savePreference(dialog.pref, v)) setDialog(null); }} /> : null}
        {dialog?.kind === "vaultDir" ? (
          <VaultDirDialog current={paths.vaultDir} onDone={(home) => { setDialog(null); setSettings((s) => s && { ...s, paths: { ...s.paths, home } }); void load(); }} />
        ) : null}
        {dialog?.kind === "password" ? (
          <TwoFieldDialog
            title="New master password"
            description="At least 8 characters. Secrets are not re-encrypted; the vault key is re-wrapped."
            labels={["New password", "Repeat it"]}
            type="password"
            autoComplete="new-password"
            mismatch="The passwords do not match"
            submit="Change password"
            onSubmit={(value) => attempt(() => api.changePassword(value), "Master password changed").then(() => setDialog(null))}
          />
        ) : null}
        {dialog?.kind === "pin" ? (
          <TwoFieldDialog
            title="PIN for this device"
            description="4–12 digits, asked before the remembered password is used."
            labels={["PIN", "Repeat it"]}
            type="password"
            inputMode="numeric"
            pattern={/^\d{4,12}$/}
            patternError="Use 4 to 12 digits"
            mismatch="The PINs do not match"
            submit="Save PIN"
            onSubmit={(value) => attempt(() => api.setPin(value), "PIN saved").then(() => setDialog(null))}
          />
        ) : null}
        {dialog?.kind === "totp" ? (
          <TotpDialog secret={dialog.secret} uri={dialog.uri} onEnable={(code) => attempt(() => api.totpEnable(code), "Two-factor codes turned on").then(() => setDialog(null))} />
        ) : null}
        {dialog?.kind === "passkey" ? (
          <PasskeyDialog onAdded={(status, label) => { setSecurity(status); setDialog(null); toast.success(`Added "${label}"`); }} />
        ) : null}
        {dialog?.kind === "recovery" ? <RecoveryDialog content={dialog.content} vault={app.session.vault.name} onClose={() => setDialog(null)} /> : null}
        {dialog?.kind === "confirm" ? (
          <ConfirmDialog title={dialog.title} body={dialog.body} action={dialog.action} onConfirm={async () => { setDialog(null); await dialog.run(); }} onCancel={() => setDialog(null)} />
        ) : null}
      </Dialog>
      {gate}
    </div>
  );
}

// ── Rows ──────────────────────────────────────────────────────────

function Item({ label, value, help, action, children }: { label: string; value?: ReactNode; help?: string; action?: ReactNode; children?: ReactNode }) {
  return (
    <div className="px-4 py-3.5">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
            <span className="text-sm font-medium text-text">{label}</span>
            {value !== undefined ? <span className="min-w-0 text-sm text-text/90">{value}</span> : null}
          </div>
          {help ? <p className="mt-1 text-xs text-dim">{help}</p> : null}
        </div>
        {action ? <div className="shrink-0">{action}</div> : null}
      </div>
      {children}
    </div>
  );
}

function PathItem({ label, path, help }: { label: string; path: string; help: string }) {
  const { copy } = useApp();
  return (
    <Item
      label={label}
      value={<span className="break-all font-mono text-xs">{path}</span>}
      help={help}
      action={<Button size="icon-sm" variant="ghost" onClick={() => void copy(label, path)} aria-label={`Copy ${label}`}><Copy /></Button>}
    />
  );
}

function OnOff({ on, onLabel = "on", unavailable }: { on: boolean; onLabel?: string; unavailable?: boolean }) {
  if (unavailable) return <span className="text-dim">unavailable</span>;
  return <span className={on ? "text-success" : "text-muted"}>{on ? onLabel : "off"}</span>;
}

function PreferenceItem({ pref, onEdit, onToggle, onReset }: { pref: PreferenceRow; onEdit: () => void; onToggle: (value: boolean) => void; onReset: () => void }) {
  const source = pref.source === "env" ? <span className="text-info">· {pref.env}</span> : pref.source === "default" ? <span className="text-dim">· default</span> : null;
  return (
    <Item
      label={pref.label}
      value={<span className={cn("font-mono", pref.source === "default" ? "text-muted" : "text-text")}>{pref.display} {source}</span>}
      help={pref.help + (pref.source === "env" ? ` — set by ${pref.env}, which overrides the saved value` : "")}
      action={
        <div className="flex items-center gap-1.5">
          {pref.source === "config" ? <Button size="sm" variant="ghost" onClick={onReset}>Reset</Button> : null}
          {pref.kind === "boolean" ? (
            <Switch checked={pref.value === true} onCheckedChange={onToggle} aria-label={pref.label} />
          ) : (
            <Button size="sm" variant="secondary" onClick={onEdit}>Change</Button>
          )}
        </div>
      }
    />
  );
}

// ── Dialogs ───────────────────────────────────────────────────────

function NumberDialog({ pref, onSave }: { pref: PreferenceRow; onSave: (value: number) => Promise<void> }) {
  const [text, setText] = useState(String(pref.value));
  const [error, setError] = useState("");
  const submit = (event: FormEvent) => {
    event.preventDefault();
    const value = Number(text.trim());
    if (!/^\d+$/.test(text.trim()) || !Number.isSafeInteger(value)) return setError("Enter a whole number");
    if (pref.min !== undefined && value < pref.min && !(value === 0 && pref.zero)) return setError(`At least ${pref.min}${pref.zero ? ` (or 0 for ${pref.zero})` : ""}`);
    if (pref.max !== undefined && value > pref.max) return setError(`At most ${pref.max}`);
    void onSave(value);
  };
  const hint = [pref.unit === "s" ? "In seconds" : null, pref.zero ? `0 = ${pref.zero}` : null, `default ${String(pref.default)}`].filter(Boolean).join(" · ");
  return (
    <DialogContent title={pref.label} description={pref.help}>
      <form onSubmit={submit}>
        <Field label={pref.unit === "s" ? "Seconds" : "Value"} htmlFor="pref-value" hint={hint} error={error}>
          <Input id="pref-value" autoFocus inputMode="numeric" value={text} onChange={(e) => { setText(e.target.value); setError(""); }} className="font-mono" />
        </Field>
        <DialogFooter><Button type="submit" variant="primary">Save</Button></DialogFooter>
      </form>
    </DialogContent>
  );
}

function VaultDirDialog({ current, onDone }: { current: string | null; onDone: (home: string) => void }) {
  const [path, setPath] = useState(current ?? "");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const save = async (value: string | null) => {
    setBusy(true);
    try {
      const result = await api.setVaultDir(value);
      toast.success(value ? `Vault folder set to ${result.home}` : "Vault folder reset to the default", {
        description: result.missingVault ? "There's no vault.db there yet. Restart autho to use it." : "Restart autho to use it.",
      });
      onDone(result.home);
    } catch (e) {
      setError(errorMessage(e));
      setBusy(false);
    }
  };
  return (
    <DialogContent title="Vault folder" description="Where vault.db, project.json and daemon.json live. Files are not moved.">
      <form onSubmit={(e) => { e.preventDefault(); if (path.trim()) void save(path.trim()); }}>
        <Field label="Folder" htmlFor="vault-dir" error={error} hint="An absolute path; ~ is expanded">
          <Input id="vault-dir" autoFocus value={path} onChange={(e) => { setPath(e.target.value); setError(""); }} className="font-mono" maxLength={1024} />
        </Field>
        <DialogFooter>
          {current ? <Button type="button" variant="ghost" className="mr-auto" disabled={busy} onClick={() => void save(null)}>Use default</Button> : null}
          <Button type="submit" variant="primary" disabled={busy || !path.trim()}>Save</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function TwoFieldDialog(props: {
  title: string;
  description: string;
  labels: [string, string];
  type: "password";
  autoComplete?: string;
  inputMode?: "numeric";
  pattern?: RegExp;
  patternError?: string;
  mismatch: string;
  submit: string;
  onSubmit: (value: string) => Promise<void>;
}) {
  const [first, setFirst] = useState("");
  const [second, setSecond] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (props.pattern && !props.pattern.test(first)) return setError(props.patternError ?? "Invalid value");
    if (first !== second) {
      setSecond("");
      return setError(props.mismatch);
    }
    setBusy(true);
    await props.onSubmit(first).finally(() => setBusy(false));
  };
  return (
    <DialogContent title={props.title} description={props.description}>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-4">
        <Field label={props.labels[0]} htmlFor="two-first">
          <Input id="two-first" autoFocus type={props.type} inputMode={props.inputMode} autoComplete={props.autoComplete ?? "off"} value={first} onChange={(e) => { setFirst(e.target.value); setError(""); }} maxLength={1024} />
        </Field>
        <Field label={props.labels[1]} htmlFor="two-second" error={error}>
          <Input id="two-second" type={props.type} inputMode={props.inputMode} autoComplete={props.autoComplete ?? "off"} value={second} onChange={(e) => { setSecond(e.target.value); setError(""); }} maxLength={1024} />
        </Field>
        <DialogFooter className="mt-1">
          <Button type="submit" variant="primary" disabled={busy || !first || !second}>{busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}{props.submit}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function TotpDialog({ secret, uri, onEnable }: { secret: string; uri: string; onEnable: (code: string) => Promise<void> }) {
  const [qr, setQr] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const { copy } = useApp();

  useEffect(() => {
    QRCode.toDataURL(uri, { margin: 1, width: 384, errorCorrectionLevel: "M", color: { dark: "#0d0d0dff", light: "#eeeeeeff" } })
      .then(setQr, () => setQr(""));
  }, [uri]);

  return (
    <DialogContent title="Turn on two-factor codes" description="Scan the code with an authenticator app, then enter the 6-digit code it shows.">
      <form
        className="flex flex-col items-center gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          setBusy(true);
          void onEnable(code.replace(/\s/g, "")).finally(() => setBusy(false));
        }}
      >
        {qr ? (
          <img src={qr} alt="QR code for your authenticator app" className="size-48 rounded-lg [image-rendering:pixelated]" />
        ) : (
          <div className="flex size-48 items-center justify-center rounded-lg bg-panel-alt"><Spinner /></div>
        )}
        <button type="button" onClick={() => void copy("Setup key", secret, true)} className="flex cursor-pointer items-center gap-2 rounded-md bg-chip px-3 py-1.5 font-mono text-xs tracking-wider text-muted hover:text-text" title="Copy setup key">
          {secret.replace(/(.{4})/g, "$1 ").trim()} <Copy className="size-3.5" />
        </button>
        <Field label="Code from the app" htmlFor="totp-code" className="w-full">
          <Input id="totp-code" autoFocus inputMode="numeric" autoComplete="one-time-code" placeholder="123 456" className="text-center font-mono text-lg tracking-[0.3em]" value={code} onChange={(e) => setCode(e.target.value.replace(/[^\d ]/g, "").slice(0, 9))} />
        </Field>
        <DialogFooter className="mt-0 w-full">
          <Button type="submit" variant="primary" disabled={busy || code.replace(/\s/g, "").length < 6}>{busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}Turn on</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function PasskeyDialog({ onAdded }: { onAdded: (status: SecurityStatus, label: string) => void }) {
  const [label, setLabel] = useState(() => (/mac/i.test(navigator.platform) ? "Touch ID" : /win/i.test(navigator.platform) ? "Windows Hello" : "Passkey"));
  const [stage, setStage] = useState<"idle" | "create" | "confirm">("idle");
  const [error, setError] = useState("");
  const [problem, setProblem] = useState<string | null>(() => (passkeysSupported() ? null : "This browser doesn't support passkeys"));

  useEffect(() => {
    if (!passkeysSupported()) return;
    api.auth().then((auth) => setProblem(passkeyProblem(auth.rpId)), () => {});
  }, []);

  const add = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setStage("create");
    try {
      const options = await api.passkeyOptions();
      const result = await registerPasskey(options, () => setStage("confirm"));
      const { security } = await api.addPasskey({ ...result, label: label.trim() || "Passkey" });
      onAdded(security, label.trim() || "Passkey");
    } catch (e) {
      setError(e instanceof DOMException && e.name === "NotAllowedError" ? "The passkey prompt was cancelled or timed out" : e instanceof DOMException && e.name === "InvalidStateError" ? "That authenticator is already registered" : errorMessage(e));
      setStage("idle");
    }
  };

  return (
    <DialogContent title="Add a passkey" description="Your authenticator must support the PRF extension (most platform passkeys and recent security keys do).">
      <form onSubmit={(e) => void add(e)} className="flex flex-col gap-4">
        <Field label="Name" htmlFor="passkey-label" hint="So you can tell your passkeys apart">
          <Input id="passkey-label" autoFocus value={label} onChange={(e) => setLabel(e.target.value)} maxLength={64} disabled={stage !== "idle"} />
        </Field>
        {problem ? <p className="text-sm text-info">{problem}</p> : null}
        {stage === "confirm" ? <p className="text-sm text-muted">Touch your authenticator once more to finish.</p> : null}
        {error ? <p role="alert" className="text-sm text-danger">✗ {error}</p> : null}
        <DialogFooter className="mt-1">
          <Button type="submit" variant="primary" disabled={stage !== "idle" || problem !== null}>
            {stage !== "idle" ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : <Fingerprint />}
            {stage === "idle" ? "Create passkey" : "Waiting for your authenticator…"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

function RecoveryDialog({ content, vault, onClose }: { content: string; vault: string; onClose: () => void }) {
  const [saved, setSaved] = useState(false);
  const href = useMemo(() => URL.createObjectURL(new Blob([content], { type: "text/plain" })), [content]);
  useEffect(() => () => URL.revokeObjectURL(href), [href]);
  const filename = `autho-recovery-${vault.replace(/\.db$/, "").replace(/[^\w.-]/g, "_")}.txt`;
  return (
    <DialogContent title="Save your recovery file" description="Anyone with this file can unlock the vault. Keep it offline, somewhere safe. It is shown only once." hideClose onEscapeKeyDown={(e) => !saved && e.preventDefault()} onPointerDownOutside={(e) => e.preventDefault()}>
      <div className="flex flex-col gap-4">
        <Button asChild variant="primary" size="lg">
          <a href={href} download={filename} onClick={() => setSaved(true)}><Download />Download {filename}</a>
        </Button>
        <p className="text-xs text-dim">Unlock with it from the Recovery tab on the unlock page, or with <code className="font-mono">autho unlock --recovery-file</code>.</p>
        <DialogFooter className="mt-0">
          <Button variant={saved ? "secondary" : "ghost"} onClick={onClose} disabled={!saved}>{saved ? "Done" : "Download it first"}</Button>
        </DialogFooter>
      </div>
    </DialogContent>
  );
}
