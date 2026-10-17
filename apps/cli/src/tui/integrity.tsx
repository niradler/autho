import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { homedir } from "node:os";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { VaultService } from "../../../../packages/core/src/index.ts";
import type { ResealResult, SealChange, SealState, VaultSession } from "../../../../packages/core/src/index.ts";
import { loadSealRecord, saveSealRecord } from "../../../../packages/core/src/os-secrets.ts";
import { Button, SecretInput, TextField, type KeyHint } from "./components.tsx";
import { handlePageKey, useApp, useScreenContext, type Command } from "./context.tsx";
import { theme } from "./theme.ts";
import { isEnter, truncate } from "./util.ts";

type Section = "seal" | "import";
type Mode = ResealResult["mode"];
/** The reseal waiting on the master password; seal-now is an accept on an unsealed vault. */
type Pending = { mode: Mode; label: string };

const SECTIONS: Array<{ id: Section; label: string }> = [
  { id: "seal", label: "Seal" },
  { id: "import", label: "Legacy import" },
];
const SIDEBAR_WIDTH = 22;
const WIDE_MIN_COLUMNS = 96;
const CHANGE_GLYPH: Record<SealChange["change"], { glyph: string; color: string }> = {
  added: { glyph: "+", color: theme.success },
  modified: { glyph: "~", color: theme.accent },
  removed: { glyph: "-", color: theme.danger },
};

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Accepts paths pasted with quotes and a leading ~. */
function cleanPath(input: string): string {
  const path = input.trim().replace(/^["']|["']$/g, "");
  return path === "~" || path.startsWith("~/") || path.startsWith("~\\") ? homedir() + path.slice(1) : path;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** Integrity: whether the vault was changed outside autho, re-sealing it, and importing legacy backups. */
export function IntegrityScreen({ session, vaultPath, setHints }: { session: VaultSession; vaultPath: string; setHints: (hints: KeyHint[]) => void }) {
  const app = useApp();
  const { width, height } = useTerminalDimensions();
  const wide = width >= WIDE_MIN_COLUMNS;
  const [section, setSection] = useState<Section>("seal");
  // Narrow terminals show the sidebar or the section, not both.
  const [inside, setInside] = useState(false);
  const [seal, setSeal] = useState<SealState | null>(null);
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [authField, setAuthField] = useState<0 | 1>(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<ResealResult | null>(null);
  const [path, setPath] = useState("");
  const [skipExisting, setSkipExisting] = useState(true);
  const [importField, setImportField] = useState<"path" | "skip">("path");
  const latestPath = useRef(path);
  const needsTotp = useMemo(() => VaultService.getAuthConfig(vaultPath)?.totp !== undefined, [vaultPath]);

  const verify = useCallback((announce = false) => {
    try {
      const next = session.verifySeal();
      setSeal(next);
      setCheckedAt(new Date());
      if (announce) app.toast(next.state === "intact" ? "Vault seal is intact" : next.state === "unsealed" ? "Vault is not sealed yet" : "Vault was changed outside autho", next.state === "tampered" ? "error" : next.state === "intact" ? "success" : "info");
    } catch (e) {
      app.toast(message(e), "error");
    }
  }, [session, app]);

  useEffect(() => verify(), [verify]);

  const actions: Array<Pending & { key: string; hint: string; color: string }> = seal?.state === "tampered"
    ? [
      { key: "u", hint: "undo", mode: "quarantine", label: "Undo changes and revoke leases", color: theme.danger },
      { key: "a", hint: "accept", mode: "accept", label: "I made this change — accept it", color: theme.accent },
    ]
    : seal?.state === "unsealed"
      ? [{ key: "s", hint: "seal", mode: "accept", label: "Seal the vault now", color: theme.accent }]
      : [];
  const actionKeys = actions.map((a) => a.key).join();

  const cancelAuth = () => {
    setPending(null);
    setPassword("");
    setTotp("");
    setAuthField(0);
    setError("");
  };

  const reseal = (pw: string, code: string) => {
    if (!pending || busy) return;
    if (!pw) return;
    if (needsTotp && authField === 0) { setAuthField(1); return; }
    setBusy(true);
    setError("");
    // Let "Working…" paint before the key derivation blocks the thread.
    setTimeout(() => {
      void (async () => {
        try {
          const admin = VaultService.authorize(vaultPath, { password: pw, sealRecord: await loadSealRecord(vaultPath), totp: needsTotp ? code : undefined, source: "tui" });
          try {
            const { sealRecord, ...rest } = admin.reseal(pending.mode);
            await saveSealRecord(vaultPath, sealRecord);
            setResult({ ...rest, sealRecord });
          } finally {
            admin.close();
          }
          cancelAuth();
          verify();
          app.toast(pending.mode === "quarantine" ? "Changes undone and vault re-sealed" : "Vault re-sealed");
        } catch (e) {
          setError(message(e));
          setPassword("");
          setTotp("");
          setAuthField(0);
        } finally {
          setBusy(false);
        }
      })();
    }, 0);
  };

  const runImport = () => {
    const file = cleanPath(latestPath.current);
    if (!file) { app.toast("Enter the path to a legacy backup file", "error"); return; }
    try {
      const { imported, skipped } = session.importLegacyFile(file, { skipExisting });
      app.toast(`Imported ${plural(imported, "secret")}${skipped ? `, skipped ${skipped}` : ""}`);
      latestPath.current = "";
      setPath("");
    } catch (e) {
      app.toast(message(e), "error");
    }
  };

  useKeyboard((key) => {
    if (!app.active || key.ctrl || key.meta) return;
    if (pending) {
      if (key.name === "escape" && !busy) { key.preventDefault(); cancelAuth(); }
      else if (key.name === "tab" && needsTotp) { key.preventDefault(); setAuthField((f) => (f === 0 ? 1 : 0)); }
      return;
    }
    if (section === "import" && (wide || inside)) {
      if (key.name === "escape") { key.preventDefault(); setInside(false); if (wide) setSection("seal"); return; }
      if (key.name === "tab" || (key.name === "down" && importField === "path") || (key.name === "up" && importField === "skip")) {
        key.preventDefault();
        setImportField((f) => (f === "path" ? "skip" : "path"));
        return;
      }
      if (importField === "skip") {
        if (key.name === "space" || key.name === "left" || key.name === "right") { key.preventDefault(); setSkipExisting((v) => !v); return; }
        if (isEnter(key)) { key.preventDefault(); runImport(); return; }
      } else if (isEnter(key)) {
        key.preventDefault();
        runImport();
        return;
      }
      if (importField === "path") return;
    }
    if (handlePageKey(app, key)) return;
    const action = section === "seal" ? actions.find((a) => a.key === key.name) : undefined;
    if (action) { setResult(null); setPending(action); return; }
    switch (key.name) {
      case "up": case "k": setSection("seal"); return;
      case "down": case "j": setSection("import"); return;
      case "right": case "l": case "return": case "enter":
        if (section === "import") { setInside(true); setImportField("path"); }
        else if (!wide) setInside(true);
        return;
      case "v": verify(true); return;
      case "q": app.go("vault"); return;
      case "left": case "h": if (!wide) setInside(false); return;
      case "escape":
        if (!wide && inside) setInside(false);
        else app.go("vault");
        return;
    }
  });

  const commands = useMemo<Command[]>(() => [
    { id: "integrity:verify", title: "Verify vault seal", hint: "v", group: "Integrity", run: () => { setSection("seal"); verify(true); } },
    ...actions.map((a) => ({ id: `integrity:${a.key}`, title: a.label, hint: a.key, group: "Integrity", run: () => { setSection("seal"); setResult(null); setPending(a); } })),
    { id: "integrity:import", title: "Import a legacy backup", group: "Integrity", run: () => { setSection("import"); setInside(true); setImportField("path"); } },
  ], [actionKeys, verify]);
  useScreenContext(commands, null);

  useEffect(() => {
    if (pending) setHints(busy ? [["", "working…"]] : [["enter", needsTotp && authField === 0 ? "next" : "confirm"], ...(needsTotp ? [["tab", "field"] as KeyHint] : []), ["ctrl+r", "show"], ["esc", "cancel"]]);
    else if (section === "import" && (wide || inside)) setHints(importField === "path" ? [["enter", "import"], ["tab/↓", "options"], ["esc", "back"]] : [["space", "toggle"], ["enter", "import"], ["tab/↑", "path"], ["esc", "back"]]);
    else if (!wide && inside) setHints([["v", "verify"], ...actions.map((a): KeyHint => [a.key, a.hint]), ["esc", "back"]]);
    else setHints([["↑↓", "section"], ...(section === "import" || !wide ? [["enter", "open"] as KeyHint] : []), ["v", "verify"], ...actions.map((a): KeyHint => [a.key, a.hint]), ["esc", "vault"]]);
  }, [pending, busy, needsTotp, authField, section, wide, inside, importField, actionKeys, setHints]);

  const sidebar = (
    <box flexDirection="column" width={wide ? SIDEBAR_WIDTH : "100%"} flexShrink={0} border borderStyle="rounded" borderColor={theme.border} title=" Integrity " titleColor={theme.muted}>
      {SECTIONS.map((s) => {
        const on = s.id === section;
        const badge = s.id === "seal" && seal ? sealBadge(seal) : null;
        return (
          <box key={s.id} flexDirection="row" height={1} paddingX={1} justifyContent="space-between" backgroundColor={on ? theme.selection : undefined}
            onMouseDown={() => { setSection(s.id); if (!wide || s.id === "import") setInside(true); }}>
            {on ? <text><strong fg={theme.accent}>{s.label}</strong></text> : <text fg={theme.text}>{s.label}</text>}
            {badge ? <text fg={badge.color}>{badge.glyph}</text> : null}
          </box>
        );
      })}
    </box>
  );

  const changes = seal?.state === "tampered" ? seal.changes : [];
  const changeRows = Math.max(2, height - 22);
  const sealPanel = (
    <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={pending?.mode === "quarantine" ? theme.danger : pending ? theme.borderFocus : theme.border} paddingX={1} title=" Vault seal " titleColor={theme.muted}>
      {seal ? <SealSummary seal={seal} /> : <text fg={theme.dim}>Checking…</text>}
      <text fg={theme.dim} marginTop={1} wrapMode="word">
        The seal is a signature over every row. If the vault file is changed outside autho (a sync conflict, a restored backup, a tool editing it), the seal shows what changed.
      </text>
      {checkedAt ? <text fg={theme.dim}>Checked {checkedAt.toLocaleTimeString()}</text> : null}
      {changes.length ? (
        <box flexDirection="column" marginTop={1}>
          <text fg={theme.muted}>{plural(changes.length, "change")}{seal?.state === "tampered" && !seal.diffTrusted ? <span fg={theme.danger}>  · the row signatures were edited too, so this list can't be trusted</span> : null}</text>
          <ChangeList changes={changes} rows={changeRows} />
        </box>
      ) : null}
      {result && !pending ? <ResultSummary result={result} rows={changeRows} /> : null}
      {pending ? (
        <box flexDirection="column" marginTop={1}>
          <text fg={pending.mode === "quarantine" ? theme.danger : theme.accent}><strong>{pending.label}</strong></text>
          <text fg={theme.muted} wrapMode="word">
            {pending.mode === "quarantine"
              ? "Deletes rows that were added, restores rows that were edited or removed where possible, and revokes every active lease."
              : "Signs the vault as it is now. Only do this if you know where the changes came from."}
          </text>
          <box flexDirection="row" height={1} gap={1} marginTop={1}>
            <text width={16} flexShrink={0} fg={authField === 0 ? theme.accent : theme.muted}>Master password</text>
            <SecretInput value={password} onChange={(v) => { setPassword(v); setError(""); }} onSubmit={(v) => reseal(v, totp)} focused={app.active && !busy && authField === 0} placeholder="to confirm" />
          </box>
          {needsTotp ? (
            <box flexDirection="row" height={1} gap={1}>
              <text width={16} flexShrink={0} fg={authField === 1 ? theme.accent : theme.muted}>Two-factor code</text>
              <SecretInput value={totp} onChange={(v) => { setTotp(v); setError(""); }} onSubmit={(v) => reseal(password, v)} focused={app.active && !busy && authField === 1} placeholder="6 digits" maxLength={6} />
            </box>
          ) : null}
          {busy ? <text fg={theme.info}>Working…</text> : null}
          {error ? <text fg={theme.danger}>✗ {error}</text> : null}
        </box>
      ) : actions.length ? (
        <box flexDirection="row" gap={2} marginTop={1}>
          {actions.map((a) => <Button key={a.key} hotkey={a.key} label={a.label} color={a.color} onPress={() => { setResult(null); setPending(a); }} />)}
        </box>
      ) : null}
    </box>
  );

  const importPanel = (
    <box flexDirection="column" flexGrow={1} border borderStyle="rounded" borderColor={section === "import" && (wide || inside) ? theme.borderFocus : theme.border} paddingX={1} title=" Legacy import " titleColor={theme.muted}>
      <text fg={theme.muted} wrapMode="word">Imports secrets from a legacy autho backup: a JSON array of secrets.</text>
      <box flexDirection="row" height={1} gap={1} marginTop={1} onMouseDown={() => { setSection("import"); setInside(true); setImportField("path"); }}>
        <text width={6} flexShrink={0} fg={importField === "path" ? theme.accent : theme.muted}>File</text>
        <TextField value={path} onChange={(v) => { latestPath.current = v; setPath(v); }} onSubmit={runImport} focused={app.active && !pending && section === "import" && (wide || inside) && importField === "path"} placeholder="path to backup .json — enter to import" />
      </box>
      <box height={1} marginTop={1} onMouseDown={() => { setSection("import"); setInside(true); setImportField("skip"); setSkipExisting((v) => !v); }}>
        <text>
          <span fg={importField === "skip" && section === "import" ? theme.accent : theme.muted}>{importField === "skip" && section === "import" ? "› " : "  "}</span>
          <span fg={skipExisting ? theme.success : theme.dim}>{skipExisting ? "[✓]" : "[ ]"}</span>
          <span fg={theme.text}> skip secrets that already exist</span>
        </text>
      </box>
      {!skipExisting ? <text fg={theme.dim}>  Existing secrets with the same name make the import fail.</text> : null}
    </box>
  );

  const panel = section === "seal" ? sealPanel : importPanel;
  return (
    <box flexDirection="row" flexGrow={1} width="100%" gap={1}>
      {wide || !inside ? sidebar : null}
      {wide || inside ? panel : null}
    </box>
  );
}

function sealBadge(seal: SealState): { glyph: string; color: string } {
  if (seal.state === "intact") return { glyph: "✓", color: theme.success };
  if (seal.state === "unsealed") return { glyph: "!", color: theme.accent };
  return { glyph: "✗", color: theme.danger };
}

function SealSummary({ seal }: { seal: SealState }) {
  const badge = sealBadge(seal);
  if (seal.state === "intact") return <text><span fg={badge.color}>{badge.glyph} </span><strong fg={badge.color}>Intact</strong><span fg={theme.muted}> — nothing changed outside autho</span></text>;
  if (seal.state === "unsealed") return <text><span fg={badge.color}>{badge.glyph} </span><strong fg={badge.color}>Not sealed yet</strong><span fg={theme.muted}> — this vault predates sealing</span></text>;
  return <text wrapMode="word"><span fg={badge.color}>{badge.glyph} </span><strong fg={badge.color}>Changed outside autho</strong><span fg={theme.muted}> — {seal.reason}</span></text>;
}

function ChangeList({ changes, rows }: { changes: SealChange[]; rows: number }) {
  const shown = changes.slice(0, rows);
  return (
    <box flexDirection="column">
      {shown.map((c) => {
        const g = CHANGE_GLYPH[c.change];
        return (
          <text key={`${c.table}:${c.rowId}:${c.change}`}>
            <span fg={g.color}>  {g.glyph} {c.change.padEnd(8)}</span>
            <span fg={theme.text}>{c.table.padEnd(16)}</span>
            <span fg={theme.dim}>{truncate(c.rowId, 40)}</span>
          </text>
        );
      })}
      {changes.length > shown.length ? <text fg={theme.dim}>  … and {changes.length - shown.length} more</text> : null}
    </box>
  );
}

function ResultSummary({ result, rows }: { result: ResealResult; rows: number }) {
  if (result.wasIntact) return <text marginTop={1} fg={theme.muted}>The seal was already intact; nothing to do.</text>;
  const parts = result.mode === "quarantine"
    ? [`undid ${plural(result.undone.length, "change")}`, ...(result.kept.length ? [`kept ${result.kept.length}`] : []), `revoked ${plural(result.revokedLeases, "lease")}`]
    : [result.changes.length ? `accepted ${plural(result.changes.length, "change")}` : "sealed"];
  return (
    <box flexDirection="column" marginTop={1}>
      <text><span fg={theme.success}>✓ </span><strong fg={theme.success}>Re-sealed</strong><span fg={theme.muted}> — {parts.join(", ")}</span></text>
      {result.mode === "quarantine" && result.kept.length ? (
        <box flexDirection="column">
          <text fg={theme.accent}>These couldn't be undone and are still in the vault:</text>
          <ChangeList changes={result.kept} rows={Math.max(2, rows - 2)} />
        </box>
      ) : null}
    </box>
  );
}
