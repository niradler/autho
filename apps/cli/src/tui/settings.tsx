import { existsSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import {
  MIN_PASSWORD_LENGTH,
  PREFERENCES,
  VaultService,
  authoHomeDir,
  configFilePath,
  defaultDaemonStatePath,
  defaultProjectFilePath,
  formatPreference,
  loadConfig,
  parsePreference,
  resolvePreference,
  saveConfig,
  setPreference,
  type PasskeyInfo,
  type PreferenceKey,
  type SealRecord,
  type VaultAdmin,
} from "../../../../packages/core/src/index.ts";
import {
  deletePin,
  deleteVaultPassword,
  hasPinSet,
  loadSealRecord,
  loadVaultPassword,
  osSecretsDisabled,
  saveSealRecord,
  storePinHash,
  storeVaultPassword,
} from "../../../../packages/core/src/os-secrets.ts";
import pkg from "../../package.json";
import { newPrfSalt, runPasskeyCeremony } from "../passkey.ts";
import { SecretInput, TextField, type KeyHint } from "./components.tsx";
import { handlePageKey, useApp, useScreenContext, type Command, type CopyTarget, type Timings } from "./context.tsx";
import { theme } from "./theme.ts";
import type { PasskeyRunner } from "./unlock.tsx";
import { isEnter, truncate } from "./util.ts";

enum Section {
  Storage = "Storage",
  Security = "Security",
  Behaviour = "Behaviour",
  Agents = "Agents & services",
  About = "About",
}

const SECTIONS: Section[] = [Section.Storage, Section.Security, Section.Behaviour, Section.Agents, Section.About];

const BEHAVIOUR_KEYS: PreferenceKey[] = ["revealSeconds", "clipboardClearSeconds", "idleLockSeconds", "passwordLength", "passwordSymbols", "mouse"];
const AGENT_KEYS: PreferenceKey[] = ["defaultLeaseTtl", "daemonTtlSeconds", "webPort", "webWithTui"];

/** The web UI the TUI serves alongside itself: its address, or why there is none. */
export type WebStatus = { url: string | null; note: string };

/** Preferences the running TUI picks up straight away. */
const LIVE_TIMINGS: Partial<Record<PreferenceKey, keyof Timings>> = {
  revealSeconds: "revealMs",
  clipboardClearSeconds: "clipboardClearMs",
  idleLockSeconds: "idleLockMs",
};

type Row = {
  id: string;
  label: string;
  value: string;
  color?: string;
  help: string;
  /** Verb shown at the right, e.g. "change"; rows without one are read-only. */
  verb?: string;
  run?: () => void;
  /** Ctrl+C copies this (paths). */
  copy?: string;
  /** Long paths keep their end (the file name) when they don't fit. */
  path?: boolean;
};

type SecurityStatus = { keychain: boolean; pin: boolean; totp: boolean; passkeys: PasskeyInfo[]; recoveryAt: string | null };

type Dialog =
  | { kind: "auth"; then: (admin: VaultAdmin) => void }
  | { kind: "number"; key: PreferenceKey }
  | { kind: "vaultDir" }
  | { kind: "newPassword" }
  | { kind: "pin" }
  | { kind: "totp"; secret: string; uri: string }
  | { kind: "passkeyLabel" }
  | { kind: "passkeyWait"; url: string }
  | { kind: "recoveryPath" }
  | { kind: "confirm"; title: string; danger?: boolean; run: () => void };

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/**
 * One page for everything configurable: where files live, how the vault
 * unlocks, TUI behaviour and agent defaults. Changing how the vault unlocks
 * asks for the master password once per visit; the handle is dropped when
 * the screen closes or the vault locks.
 */
export function SettingsScreen({ vaultPath, setHints, onBack, passkeyRunner = runPasskeyCeremony, web }: {
  vaultPath: string;
  setHints: (hints: KeyHint[]) => void;
  onBack: () => void;
  passkeyRunner?: PasskeyRunner;
  web?: WebStatus;
}) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const [section, setSection] = useState<Section>(Section.Storage);
  // Sidebar first, like OS settings: arrows pick a section, → / enter / tab go into it.
  const [focus, setFocus] = useState<"nav" | "rows">("nav");
  const [rowIndex, setRowIndex] = useState(0);
  const [dialog, setDialog] = useState<Dialog | null>(null);
  const [error, setError] = useState("");
  const [fields, setFields] = useState<string[]>(["", ""]);
  // Keys can arrive before React commits a render, so submit reads this, not `fields`.
  const fieldsRef = useRef<string[]>(["", ""]);
  const [field, setField] = useState(0);
  const [status, setStatus] = useState<SecurityStatus | null>(null);
  // Bumped after saving a preference so rows re-read config.json.
  const [, setRevision] = useState(0);
  const admin = useRef<VaultAdmin | null>(null);
  const passkeyAbort = useRef<AbortController | null>(null);
  const osStore = !osSecretsDisabled();

  const refreshStatus = useCallback(async () => {
    const auth = VaultService.getAuthConfig(vaultPath);
    const [keychain, pin] = osStore ? [(await loadVaultPassword(vaultPath)) !== null, await hasPinSet(vaultPath)] : [false, false];
    setStatus({ keychain, pin, totp: auth?.totp !== undefined, passkeys: VaultService.listPasskeys(vaultPath), recoveryAt: auth?.recovery?.createdAt ?? null });
  }, [vaultPath, osStore]);

  useEffect(() => { void refreshStatus(); }, [refreshStatus]);
  // Newest seal seen for this vault, so admin unlock refuses an older copy of the file.
  const sealRecord = useRef<SealRecord | null>(null);
  useEffect(() => { void loadSealRecord(vaultPath).then((record) => { sealRecord.current = record; }); }, [vaultPath]);

  useEffect(() => () => {
    passkeyAbort.current?.abort();
    const current = admin.current;
    admin.current = null;
    if (current) {
      current.close();
      void saveSealRecord(vaultPath, current.sealRecord());
    }
  }, [vaultPath]);

  const writeFields = (next: string[]) => {
    fieldsRef.current = next;
    setFields(next);
  };

  const open = (next: Dialog, initial: string[] = ["", ""]) => {
    setError("");
    writeFields(initial);
    setField(0);
    setDialog(next);
  };

  const close = () => {
    passkeyAbort.current?.abort();
    setDialog(null);
    setError("");
    writeFields(["", ""]);
  };

  /** Runs `fn` with an authorized handle, asking for the password first if needed. */
  const withAdmin = (fn: (handle: VaultAdmin) => void) => {
    if (admin.current) fn(admin.current);
    else open({ kind: "auth", then: fn });
  };

  /** Runs a change, reporting the outcome; errors stay in the open dialog. */
  const attempt = async (fn: () => void | string | Promise<void | string>) => {
    try {
      const done = await fn();
      close();
      await refreshStatus();
      if (done) app.toast(done);
    } catch (e) {
      setError(message(e));
    }
  };

  // ── Rows ──────────────────────────────────────────────────────────

  const preferenceRow = (key: PreferenceKey): Row => {
    const spec = PREFERENCES.find((p) => p.key === key)!;
    const { value, source } = resolvePreference(key);
    const from = source === "env" ? `  (${spec.env})` : source === "default" ? "  default" : "";
    return {
      id: key,
      label: spec.label,
      value: formatPreference(key, value) + from,
      color: source === "env" ? theme.info : source === "default" ? theme.muted : theme.text,
      help: spec.help + (source === "env" ? ` — set by ${spec.env}, which overrides the saved value` : ""),
      verb: spec.kind === "boolean" ? "toggle" : "change",
      run: spec.kind === "boolean"
        ? () => savePreference(key, !value)
        : () => open({ kind: "number", key }, [String(value), ""]),
    };
  };

  const savePreference = (key: PreferenceKey, value: number | boolean | null) => {
    setPreference(key, value);
    const resolved = resolvePreference(key);
    const timing = LIVE_TIMINGS[key];
    if (timing) app.setTimings({ [timing]: (resolved.value as number) * 1000 });
    setRevision((r) => r + 1);
    const spec = PREFERENCES.find((p) => p.key === key)!;
    if (resolved.source === "env") app.toast(`Saved — ${spec.env} still overrides it for now`, "info");
    else app.toast(`${spec.label}: ${formatPreference(key, resolved.value)}`);
  };

  const storageRows = (): Row[] => {
    const config = loadConfig();
    const homeSource = process.env.AUTHO_HOME ? "AUTHO_HOME" : config.vaultDir ? "config" : "default";
    const pathRow = (id: string, label: string, path: string, help: string): Row => ({ id, label, value: path, path: true, help, copy: path, verb: "copy", run: () => void app.copy(label, path) });
    return [
      pathRow("vault", "Vault file", vaultPath, "The vault this session has open"),
      {
        id: "vaultDir",
        label: "Vault folder",
        value: `${authoHomeDir()}  ${homeSource}`,
        color: homeSource === "default" ? theme.muted : theme.text,
        help: process.env.AUTHO_HOME
          ? "AUTHO_HOME is set, so it decides the folder — unset it to change this here"
          : "Where vault.db, project.json and daemon.json live. Files are not moved; restart autho after changing it",
        verb: process.env.AUTHO_HOME ? undefined : "change",
        run: process.env.AUTHO_HOME ? undefined : () => open({ kind: "vaultDir" }, [config.vaultDir ?? "", ""]),
        copy: authoHomeDir(),
        path: true,
      },
      pathRow("config", "Config file", configFilePath(), "Settings on this page are saved here"),
      pathRow("project", "Project file", defaultProjectFilePath(), "Default env mappings for `env`, `exec` and the daemon"),
      pathRow("daemon", "Daemon state", defaultDaemonStatePath(), "Port and token of a running `autho daemon serve`"),
    ];
  };

  const securityRows = (): Row[] => {
    if (!status) return [{ id: "loading", label: "Loading…", value: "", help: "" }];
    const onOff = (on: boolean) => (on ? "on" : "off");
    const osOnly = (row: Row): Row => (osStore ? row : { ...row, value: "unavailable", color: theme.dim, verb: undefined, run: undefined, help: "The OS secret store is off (AUTHO_DISABLE_OS_SECRETS)" });
    const rows: Row[] = [
      {
        id: "password",
        label: "Master password",
        value: "••••••••",
        color: theme.muted,
        help: "Re-wraps the vault key under a new password; secrets are not re-encrypted",
        verb: "change",
        run: () => withAdmin(() => open({ kind: "newPassword" })),
      },
      osOnly({
        id: "keychain",
        label: "Remember password",
        value: onOff(status.keychain),
        color: status.keychain ? theme.success : theme.muted,
        help: "Keep the master password in the OS keychain so this device unlocks without typing it",
        verb: "toggle",
        run: () => status.keychain
          ? void attempt(async () => { await deleteVaultPassword(vaultPath); return "Password removed from the keychain"; })
          : withAdmin((handle) => void attempt(async () => {
            if (!(await storeVaultPassword(vaultPath, handle.masterPassword()))) throw new Error("The OS keychain refused the password");
            return "Password saved to the keychain";
          })),
      }),
      osOnly({
        id: "pin",
        label: "PIN",
        value: status.pin ? "set" : "off",
        color: status.pin ? theme.success : theme.muted,
        help: "A short PIN asked before the keychain password is used on this device",
        verb: status.pin ? "change" : "set",
        run: () => withAdmin(() => open({ kind: "pin" })),
      }),
      {
        id: "totp",
        label: "Two-factor code",
        value: onOff(status.totp),
        color: status.totp ? theme.success : theme.muted,
        help: "Ask for an authenticator app code at every unlock",
        verb: status.totp ? "turn off" : "turn on",
        run: () => withAdmin(() => status.totp
          ? open({ kind: "confirm", title: "Turn off two-factor codes?", danger: true, run: () => void attempt(() => { admin.current!.removeTotp(); return "Two-factor codes turned off"; }) })
          : open({ kind: "totp", ...VaultService.setupTotp(vaultPath) })),
      },
    ];
    for (const passkey of status.passkeys) {
      rows.push({
        id: `passkey:${passkey.id}`,
        label: rows.some((r) => r.id.startsWith("passkey:")) ? "" : "Passkeys",
        value: `${passkey.label}  added ${passkey.createdAt.slice(0, 10)}`,
        help: `Unlocks without the password${passkey.transports?.length ? ` · ${passkey.transports.join(", ")}` : ""}`,
        verb: "remove",
        run: () => withAdmin(() => open({ kind: "confirm", title: `Remove passkey "${passkey.label}"?`, danger: true, run: () => void attempt(() => { admin.current!.removePasskey(passkey.id); return `Removed "${passkey.label}"`; }) })),
      });
    }
    rows.push({
      id: "passkey:add",
      label: status.passkeys.length ? "" : "Passkeys",
      value: status.passkeys.length ? "add another" : "none",
      color: theme.muted,
      help: "Register a passkey or hardware security key (opens a browser page on localhost)",
      verb: "add",
      run: () => withAdmin(() => open({ kind: "passkeyLabel" })),
    });
    rows.push({
      id: "recovery",
      label: "Recovery file",
      value: status.recoveryAt ? `created ${status.recoveryAt.slice(0, 10)}` : "none",
      color: status.recoveryAt ? theme.success : theme.muted,
      help: "A file that unlocks the vault if you forget the password. Making a new one replaces the old one",
      verb: status.recoveryAt ? "replace" : "create",
      run: () => withAdmin(() => open({ kind: "recoveryPath" }, [join(homedir(), "autho-recovery.txt"), ""])),
    });
    if (status.recoveryAt) {
      rows.push({
        id: "recovery:revoke",
        label: "",
        value: "revoke recovery file",
        color: theme.muted,
        help: "Stops the current recovery file from working",
        verb: "revoke",
        run: () => withAdmin(() => open({ kind: "confirm", title: "Revoke the recovery file?", danger: true, run: () => void attempt(() => { admin.current!.revokeRecovery(); return "Recovery file revoked"; }) })),
      });
    }
    return rows;
  };

  const webRows = (): Row[] => web ? [{
    id: "web",
    label: "Web UI",
    value: web.url ?? web.note,
    color: web.url ? theme.text : theme.dim,
    help: web.url ? `${web.note}; open it in a browser and unlock there. Ctrl+C copies the address` : "Turn on \"Web UI with TUI\" (or run `autho web serve`) to use the browser UI",
    copy: web.url ?? undefined,
  }] : [];

  const aboutRows = (): Row[] => [
    { id: "version", label: "autho", value: pkg.version, help: "Installed version" },
    { id: "runtime", label: "Runtime", value: `Bun ${Bun.version} · ${process.platform}`, help: "" },
    { id: "store", label: "OS secret store", value: osStore ? "available" : "off (AUTHO_DISABLE_OS_SECRETS)", color: osStore ? theme.text : theme.dim, help: "Used for the remembered password and the PIN" },
  ];

  const rows: Row[] = section === Section.Storage ? storageRows()
    : section === Section.Security ? securityRows()
      : section === Section.Behaviour ? BEHAVIOUR_KEYS.map(preferenceRow)
        : section === Section.Agents ? [...AGENT_KEYS.map(preferenceRow), ...webRows()]
          : aboutRows();
  const current = Math.min(rowIndex, rows.length - 1);
  const row = rows[current];

  // ── Dialog submit ─────────────────────────────────────────────────

  const submit = () => {
    if (!dialog) return;
    const [first = "", second = ""] = fieldsRef.current;
    switch (dialog.kind) {
      case "auth": {
        if (!first) return;
        if (status?.totp && field === 0) { setField(1); return; }
        try {
          admin.current = VaultService.authorize(vaultPath, { password: first, sealRecord: sealRecord.current, totp: status?.totp ? second : undefined });
        } catch (e) {
          setError(message(e));
          writeFields(["", ""]);
          setField(0);
          return;
        }
        close();
        dialog.then(admin.current);
        return;
      }
      case "number":
        try {
          savePreference(dialog.key, first.trim() === "" ? null : parsePreference(dialog.key, first));
          close();
        } catch (e) {
          setError(message(e));
        }
        return;
      case "vaultDir": {
        const config = { ...loadConfig() };
        const target = first.trim() ? resolve(first.trim()).replace(/\\/g, "/") : null;
        if (target) config.vaultDir = target;
        else delete config.vaultDir;
        saveConfig(config);
        setRevision((r) => r + 1);
        close();
        const missing = target && !existsSync(join(target, "vault.db"));
        app.toast(missing ? "Saved — no vault.db there yet; restart autho and run `autho init`" : "Saved — restart autho to use it", missing ? "info" : "success");
        return;
      }
      case "newPassword":
        if (field === 0) { setField(1); return; }
        if (first !== second) { setError("The passwords do not match"); writeFields(["", ""]); setField(0); return; }
        void attempt(async () => {
          admin.current!.changePassword(first);
          if (await loadVaultPassword(vaultPath)) await storeVaultPassword(vaultPath, first);
          return "Master password changed";
        });
        return;
      case "pin":
        if (field === 0) {
          if (!first && status?.pin) { void attempt(async () => { await deletePin(vaultPath); return "PIN removed"; }); return; }
          if (!/^\d{4,12}$/.test(first)) { setError("Use 4 to 12 digits"); return; }
          setField(1);
          return;
        }
        if (first !== second) { setError("The PINs do not match"); writeFields(["", ""]); setField(0); return; }
        void attempt(async () => {
          if (!(await storePinHash(vaultPath, first))) throw new Error("The OS keychain refused the PIN");
          return "PIN saved";
        });
        return;
      case "totp":
        void attempt(() => { admin.current!.enableTotp(dialog.secret, first.trim()); return "Two-factor codes turned on"; });
        return;
      case "passkeyLabel":
        registerPasskey(first.trim());
        return;
      case "recoveryPath": {
        const target = resolve(first.trim() || join(homedir(), "autho-recovery.txt"));
        if (existsSync(target)) { setError("That file already exists — pick another name"); return; }
        if (!existsSync(dirname(target))) { setError("That folder does not exist"); return; }
        void attempt(() => {
          const { fileContent } = admin.current!.generateRecovery();
          writeFileSync(target, fileContent, { encoding: "utf8", flag: "wx", mode: 0o600 });
          return `Recovery file written to ${target} — keep it offline`;
        });
        return;
      }
      case "confirm":
        dialog.run();
        return;
      case "passkeyWait":
        return;
    }
  };

  const registerPasskey = (label: string) => {
    const handle = admin.current!;
    const controller = new AbortController();
    passkeyAbort.current = controller;
    setError("");
    setDialog({ kind: "passkeyWait", url: "" });
    const prfSalt = newPrfSalt();
    passkeyRunner(
      { mode: "register", userName: `autho (${vaultPath.split(/[\\/]/).pop()})`, excludeCredentialIds: (status?.passkeys ?? []).map((p) => p.credentialId), prfSalt },
      { onUrl: (url) => setDialog((d) => (d?.kind === "passkeyWait" ? { kind: "passkeyWait", url } : d)), signal: controller.signal },
    ).then(
      (result) => {
        if (controller.signal.aborted) return;
        passkeyAbort.current = null;
        void attempt(() => { const info = handle.addPasskey({ ...result, label, prfSalt }); return `Added passkey "${info.label}"`; });
      },
      (e) => {
        if (passkeyAbort.current === controller) passkeyAbort.current = null;
        if (controller.signal.aborted) return;
        setDialog({ kind: "passkeyLabel" });
        writeFields([label, ""]);
        setError(message(e));
      },
    );
  };

  // ── Keys ──────────────────────────────────────────────────────────

  const switchSection = (delta: number) => {
    const next = SECTIONS[(SECTIONS.indexOf(section) + delta + SECTIONS.length) % SECTIONS.length]!;
    setSection(next);
    setRowIndex(0);
  };

  const pickSection = (next: Section) => {
    close();
    setSection(next);
    setRowIndex(0);
    setFocus("nav");
  };

  const moveRow = (delta: number) => setRowIndex(Math.min(rows.length - 1, Math.max(0, current + delta)));

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta) return;
    if (dialog) {
      if (key.name === "escape") { key.preventDefault(); close(); return; }
      if (dialog.kind === "confirm") {
        key.preventDefault();
        if (key.name === "y" || isEnter(key)) dialog.run();
        else if (key.name === "n") close();
        return;
      }
      if (key.name === "tab" && fieldCount(dialog, status) > 1) { key.preventDefault(); setField((f) => (f + 1) % 2); }
      return;
    }
    if (key.name === "q") { onBack(); return; }
    if (handlePageKey(app, key)) return;
    if (key.name === "tab") { key.preventDefault(); setFocus(focus === "nav" ? "rows" : "nav"); return; }
    if (focus === "nav") {
      switch (key.name) {
        case "up": switchSection(-1); return;
        case "down": switchSection(1); return;
        case "home": pickSection(SECTIONS[0]!); return;
        case "end": pickSection(SECTIONS[SECTIONS.length - 1]!); return;
        case "right": case "space": setFocus("rows"); return;
        case "escape": onBack(); return;
      }
      if (isEnter(key)) setFocus("rows");
      return;
    }
    switch (key.name) {
      case "up": moveRow(-1); return;
      case "down": moveRow(1); return;
      case "home": setRowIndex(0); return;
      case "end": setRowIndex(rows.length - 1); return;
      case "left": case "escape": setFocus("nav"); return;
      case "space": row?.run?.(); return;
    }
    if (isEnter(key)) row?.run?.();
  });

  const commands = useMemo<Command[]>(() => [
    ...SECTIONS.map((s) => ({ id: `settings:${s}`, title: `Settings — ${s}`, group: "Settings", run: () => pickSection(s) })),
    { id: "settings:back", title: "Back to the vault", hint: "esc", group: "Settings", run: onBack },
  ], [onBack]);
  const copyTarget: CopyTarget | null = focus === "rows" && row?.copy ? { label: row.label, read: () => row.copy ?? null, secret: false } : null;
  useScreenContext(commands, copyTarget);

  useEffect(() => {
    if (dialog?.kind === "confirm") setHints([["y", "confirm"], ["n/esc", "cancel"]]);
    else if (dialog?.kind === "passkeyWait") setHints([["esc", "cancel"]]);
    else if (dialog) setHints([["enter", "save"], ...(fieldCount(dialog, status) > 1 ? [["tab", "field"] as KeyHint] : []), ["esc", "cancel"]]);
    else if (focus === "nav") setHints([["↑↓", "section"], ["→/enter", "open"], ["esc", "back to vault"]]);
    else setHints([["↑↓", "move"], ...(row?.verb ? [["enter", row.verb] as KeyHint] : []), ...(row?.copy && row.verb !== "copy" ? [["ctrl+c", "copy"] as KeyHint] : []), ["←/esc", "sections"]]);
  }, [dialog, status, focus, row?.verb, row?.copy, setHints]);

  // ── Render ────────────────────────────────────────────────────────

  const listHeight = Math.max(3, height - 12);
  const offset = Math.max(0, Math.min(current - Math.floor(listHeight / 2), rows.length - listHeight));
  const visible = rows.slice(offset, offset + listHeight);
  const inputsFocused = app.active && dialog !== null;
  const rowsFocused = focus === "rows" || dialog !== null;
  // Nav, gaps, borders, padding, the label column and the verb.
  const valueWidth = Math.max(12, width - 64);

  return (
    <box flexDirection="row" flexGrow={1} gap={1} paddingX={1}>
      <box flexDirection="column" width={24} flexShrink={0} border borderStyle="rounded" borderColor={theme.border} title=" Settings " titleColor={theme.muted}>
        {SECTIONS.map((s) => (
          <box key={s} height={1} paddingX={1} backgroundColor={s === section ? theme.selection : undefined} onMouseDown={() => pickSection(s)}>
            <text>{s === section ? <strong fg={rowsFocused ? theme.muted : theme.accent}>› {s}</strong> : <span fg={theme.text}>  {s}</span>}</text>
          </box>
        ))}
      </box>
      <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={dialog ? theme.borderFocus : theme.border} paddingX={1} title={` ${section} `} titleColor={theme.accent}>
        {section === Section.Security ? (
          <text fg={theme.dim}>{admin.current ? "Authorized for this visit — changes apply right away." : "Changes ask for your master password once per visit."}</text>
        ) : null}
        {visible.map((r, i) => {
          const on = rowsFocused && offset + i === current;
          return (
            <box key={r.id} flexDirection="row" height={1} backgroundColor={on ? theme.selection : undefined} onMouseDown={() => { if (dialog) return; setFocus("rows"); if (on) r.run?.(); else setRowIndex(offset + i); }}>
              <text width={22} flexShrink={0} fg={on ? theme.accent : theme.muted}>{on ? "› " : "  "}{r.label}</text>
              <box flexGrow={1} flexShrink={1} overflow="hidden">
                <text fg={r.color ?? theme.text} selectable>{r.path ? truncateStart(r.value, valueWidth) : r.value}</text>
              </box>
              {r.verb ? <text flexShrink={0} fg={on ? theme.accent : theme.dim}> {r.verb} </text> : null}
            </box>
          );
        })}
        {focus === "rows" && row?.help && !dialog ? <text marginTop={1} fg={theme.dim} wrapMode="word">{row.help}</text> : null}
        {dialog ? (
          <DialogPanel dialog={dialog} totp={status?.totp ?? false} fields={fields} field={field} focused={inputsFocused} error={error}
            onChange={(i, v) => writeFields(fieldsRef.current.map((old, j) => (j === i ? v : old)))}
            onFocusField={setField} onSubmit={submit} />
        ) : null}
      </box>
    </box>
  );
}

/** Keeps the end of `text`, which for a path is the part that matters. */
function truncateStart(text: string, max: number): string {
  return text.length > max ? `…${text.slice(text.length - max + 1)}` : text;
}

function fieldCount(dialog: Dialog, status: SecurityStatus | null): number {
  if (dialog.kind === "auth") return status?.totp ? 2 : 1;
  return dialog.kind === "newPassword" || dialog.kind === "pin" ? 2 : 1;
}

function DialogPanel({ dialog, totp, fields, field, focused, error, onChange, onFocusField, onSubmit }: {
  dialog: Dialog;
  totp: boolean;
  fields: string[];
  field: number;
  focused: boolean;
  error: string;
  onChange: (index: number, value: string) => void;
  onFocusField: (index: number) => void;
  onSubmit: () => void;
}) {
  const secret = (index: number, label: string, placeholder = "") => (
    <box key={index} flexDirection="row" gap={1} height={1} onMouseDown={() => onFocusField(index)}>
      <text width={18} flexShrink={0} fg={field === index ? theme.accent : theme.muted}>{label}</text>
      <SecretInput value={fields[index] ?? ""} onChange={(v) => onChange(index, v)} onSubmit={onSubmit} focused={focused && field === index} placeholder={placeholder} />
    </box>
  );
  const text = (label: string, placeholder = "") => (
    <box flexDirection="row" gap={1} height={1}>
      <text width={18} flexShrink={0} fg={theme.accent}>{label}</text>
      <TextField value={fields[0] ?? ""} onChange={(v) => onChange(0, v)} onSubmit={onSubmit} focused={focused} placeholder={placeholder} />
    </box>
  );

  let title = "";
  let body: ReactNode = null;
  switch (dialog.kind) {
    case "auth":
      title = "Confirm it's you";
      body = <>{secret(0, "Master password")}{totp ? secret(1, "Two-factor code", "6 digits") : null}</>;
      break;
    case "number": {
      const spec = PREFERENCES.find((p) => p.key === dialog.key)!;
      title = spec.label;
      body = <>{text(spec.kind === "number" && spec.unit === "s" ? "Seconds" : "Value", "empty = default")}<text fg={theme.dim}>{spec.kind === "number" ? `${spec.min}–${spec.max}${spec.zero ? ` · 0 = ${spec.zero}` : ""} · empty resets to ${spec.default}` : ""}</text></>;
      break;
    }
    case "vaultDir":
      title = "Vault folder";
      body = <>{text("Folder", "empty = ~/.autho")}<text fg={theme.dim}>Only the setting changes — move vault.db yourself, then restart autho.</text></>;
      break;
    case "newPassword":
      title = "Change master password";
      body = <>{secret(0, "New password", `at least ${MIN_PASSWORD_LENGTH} characters`)}{secret(1, "Confirm")}</>;
      break;
    case "pin":
      title = "PIN for this device";
      body = <>{secret(0, "New PIN", "4–12 digits · empty removes it")}{secret(1, "Confirm")}</>;
      break;
    case "totp":
      title = "Turn on two-factor codes";
      body = (
        <>
          <text fg={theme.muted}>Add this key to your authenticator app, then type the code it shows.</text>
          <text fg={theme.revealed} selectable>{dialog.secret}</text>
          <text fg={theme.dim} selectable wrapMode="char">{truncate(dialog.uri, 400)}</text>
          {text("Code", "6 digits")}
        </>
      );
      break;
    case "passkeyLabel":
      title = "Add a passkey or security key";
      body = text("Name", "e.g. YubiKey, MacBook");
      break;
    case "passkeyWait":
      title = "Waiting for your browser";
      body = (
        <>
          <text fg={theme.accent}>Confirm with your passkey or touch your key.</text>
          {dialog.url ? <text fg={theme.dim} selectable>If no browser opened, visit: {dialog.url}</text> : null}
        </>
      );
      break;
    case "recoveryPath":
      title = "Write a recovery file";
      body = <>{text("Save to")}<text fg={theme.dim}>Anyone with this file can open the vault. Store it offline.</text></>;
      break;
    case "confirm":
      title = dialog.title;
      body = <text fg={theme.muted}>y = yes · n = cancel</text>;
      break;
  }

  const danger = dialog.kind === "confirm" && dialog.danger;
  return (
    <box flexDirection="column" marginTop={1} border borderStyle="rounded" borderColor={danger ? theme.danger : theme.borderFocus} paddingX={1} title={` ${title} `} titleColor={danger ? theme.danger : theme.accent}>
      {body}
      {error ? <text fg={theme.danger}>✗ {error}</text> : null}
    </box>
  );
}
