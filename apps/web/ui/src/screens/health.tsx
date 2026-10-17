import { FileUp, RefreshCw, ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { toast } from "sonner";

import { useAdminGate } from "../components/admin-gate.tsx";
import { ConfirmDialog } from "../components/confirm-dialog.tsx";
import { Button } from "../components/ui/button.tsx";
import { Dialog } from "../components/ui/dialog.tsx";
import { Kbd, Panel, Spinner } from "../components/ui/panel.tsx";
import { Switch } from "../components/ui/switch.tsx";
import { useApp, useScreen, type Command, type KeyHint } from "../context.tsx";
import { api, ApiError, errorMessage, type ResealResult, type SealChange, type SealState } from "../lib/api.ts";
import { cn, isTypingTarget } from "../lib/utils.ts";

const MAX_IMPORT_BYTES = 8 * 1024 * 1024;

type Mode = "accept" | "quarantine";

/** Vault integrity (`vault verify` / `vault reseal`) and legacy JSON import. */
export function HealthScreen() {
  const app = useApp();
  const [seal, setSeal] = useState<SealState | null>(null);
  const [checking, setChecking] = useState(false);
  const [result, setResult] = useState<ResealResult | null>(null);
  const [confirm, setConfirm] = useState<Mode | null>(null);
  const { withAdmin, gate } = useAdminGate();
  const { setModalOpen } = app;

  const verify = useCallback(async (announce = false) => {
    setChecking(true);
    try {
      const next = await api.verify();
      setSeal(next);
      if (announce) {
        if (next.state === "intact") toast.success("Vault seal is intact");
        else toast.error(next.state === "unsealed" ? "Vault isn't sealed yet" : "Vault was modified outside autho");
      }
    } catch (error) {
      toast.error(errorMessage(error));
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void verify();
  }, [verify]);

  useEffect(() => {
    setModalOpen(confirm !== null);
    return () => setModalOpen(false);
  }, [confirm, setModalOpen]);

  const reseal = useCallback((mode: Mode) => {
    withAdmin(async () => {
      try {
        const outcome = await api.reseal(mode);
        setResult(outcome);
        toast.success(outcome.wasIntact ? "The seal is intact; nothing to do" : mode === "accept" ? "Vault re-sealed as it is now" : "Vault re-sealed");
        await verify();
      } catch (error) {
        if (error instanceof ApiError && error.status === 403) throw error;
        toast.error(errorMessage(error));
      }
    });
  }, [withAdmin, verify]);

  const broken = seal !== null && seal.state !== "intact";

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || app.paletteOpen || app.modalOpen || event.ctrlKey || event.metaKey || event.altKey || isTypingTarget(event.target)) return;
      if (event.key === "v" || event.key === "r") {
        event.preventDefault();
        void verify(true);
      } else if (event.key === "Escape") {
        app.go("vault");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [app, verify]);

  const commands = useMemo<Command[]>(() => [
    { id: "health:verify", title: "Verify vault seal", group: "Integrity", hint: "v", run: () => void verify(true) },
    ...(broken
      ? [
        { id: "health:quarantine", title: "Undo outside changes and re-seal", group: "Integrity", run: () => setConfirm("quarantine") },
        { id: "health:accept", title: "Accept the vault as it is and re-seal", group: "Integrity", run: () => setConfirm("accept") },
      ]
      : []),
  ], [verify, broken]);
  const hints = useMemo<KeyHint[]>(() => [["v", "verify"], ["esc", "back"]], []);
  useScreen(commands, hints);

  return (
    <div className="mx-auto flex h-full min-h-0 w-full max-w-4xl flex-col gap-3 overflow-y-auto sm:gap-4">
      <Panel
        title="Vault seal"
        actions={
          <Button size="sm" variant="ghost" onClick={() => void verify(true)} disabled={checking}>
            {checking ? <Spinner /> : <RefreshCw />}Verify <Kbd>v</Kbd>
          </Button>
        }
        className="shrink-0"
      >
        {seal === null ? (
          <div className="flex justify-center py-10"><Spinner /></div>
        ) : (
          <div className="flex flex-col gap-4 p-4">
            <SealSummary seal={seal} />
            {seal.state === "tampered" && seal.changes?.length ? <ChangeList changes={seal.changes} trusted={seal.diffTrusted !== false} /> : null}
            {broken ? (
              <div className="flex flex-col gap-3 rounded-lg border border-border bg-panel-alt p-4">
                <div className="flex flex-wrap gap-2">
                  {seal.state === "tampered" ? (
                    <Button variant="danger" onClick={() => setConfirm("quarantine")}>Undo changes and revoke leases</Button>
                  ) : null}
                  <Button variant={seal.state === "tampered" ? "secondary" : "primary"} onClick={() => setConfirm("accept")}>
                    {seal.state === "tampered" ? "I made this change — accept it" : "Seal the vault now"}
                  </Button>
                </div>
                <p className="text-xs text-dim">
                  {seal.state === "tampered"
                    ? "Undo puts edited and deleted rows back, removes added ones and revokes every active lease. Accept keeps the vault as it is. Both ask for your master password."
                    : "Sealing signs the current contents so later outside edits are caught. It asks for your master password."}
                </p>
              </div>
            ) : null}
            {result && !result.wasIntact ? <ResealSummary result={result} /> : null}
          </div>
        )}
      </Panel>

      <ImportPanel />

      <Dialog open={confirm !== null} onOpenChange={(open) => !open && setConfirm(null)}>
        {confirm === "quarantine" ? (
          <ConfirmDialog
            title="Undo the outside changes?"
            body="Edited and deleted rows are restored, added rows are removed, and every active lease is revoked."
            action="Undo and re-seal"
            onConfirm={() => { setConfirm(null); reseal("quarantine"); }}
            onCancel={() => setConfirm(null)}
          />
        ) : null}
        {confirm === "accept" ? (
          <ConfirmDialog
            title={seal?.state === "tampered" ? "Accept the vault as it is?" : "Seal the vault?"}
            body={seal?.state === "tampered" ? "Only do this if you made the change yourself. The current contents become the trusted state." : "The current contents become the trusted state."}
            action={seal?.state === "tampered" ? "Accept and re-seal" : "Seal"}
            onConfirm={() => { setConfirm(null); reseal("accept"); }}
            onCancel={() => setConfirm(null)}
          />
        ) : null}
      </Dialog>
      {gate}
    </div>
  );
}

function SealSummary({ seal }: { seal: SealState }) {
  if (seal.state === "intact") {
    return (
      <div className="flex items-start gap-3">
        <ShieldCheck className="mt-0.5 size-6 shrink-0 text-success" />
        <div>
          <p className="font-medium text-success">Seal is intact</p>
          <p className="text-sm text-muted">Nothing in the vault changed outside autho since it was last sealed.</p>
        </div>
      </div>
    );
  }
  if (seal.state === "unsealed") {
    return (
      <div className="flex items-start gap-3">
        <ShieldQuestion className="mt-0.5 size-6 shrink-0 text-info" />
        <div>
          <p className="font-medium text-info">Not sealed yet</p>
          <p className="text-sm text-muted">Without a seal, edits made outside autho can't be detected.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="flex items-start gap-3">
      <ShieldAlert className="mt-0.5 size-6 shrink-0 text-danger" />
      <div>
        <p className="font-medium text-danger">Modified outside autho</p>
        <p className="text-sm text-muted">{seal.reason ?? "The vault no longer matches its seal"}.</p>
      </div>
    </div>
  );
}

const CHANGE_STYLE: Record<SealChange["change"], string> = { added: "text-success", modified: "text-accent", removed: "text-danger" };

function ChangeList({ changes, trusted, title }: { changes: SealChange[]; trusted: boolean; title?: string }) {
  return (
    <div>
      {title ? <p className="mb-1.5 text-xs font-semibold uppercase tracking-wider text-muted">{title}</p> : null}
      {!trusted ? <p className="mb-2 text-xs text-info">The stored row signatures were edited too, so this list may be incomplete.</p> : null}
      <ul className="max-h-64 overflow-y-auto rounded-md border border-border font-mono text-xs">
        {changes.map((change) => (
          <li key={`${change.table}:${change.rowId}:${change.change}`} className="flex gap-3 border-b border-border px-3 py-1.5 last:border-b-0">
            <span className={cn("w-16 shrink-0", CHANGE_STYLE[change.change])}>{change.change}</span>
            <span className="w-24 shrink-0 text-muted">{change.table}</span>
            <span className="min-w-0 flex-1 truncate text-dim">{change.rowId}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ResealSummary({ result }: { result: ResealResult }) {
  return (
    <div className="flex flex-col gap-3 rounded-lg border border-border p-4">
      <p className="text-sm text-text">
        {result.mode === "accept" ? "Re-sealed with the vault as it was." : `Re-sealed. Revoked ${result.revokedLeases} active lease${result.revokedLeases === 1 ? "" : "s"}${result.undone.length ? `, undid ${result.undone.length} change${result.undone.length === 1 ? "" : "s"}` : ""}.`}
      </p>
      {result.kept.length ? <ChangeList title="Couldn't undo — check these by hand" changes={result.kept} trusted /> : null}
    </div>
  );
}

function ImportPanel() {
  const [file, setFile] = useState<{ name: string; entries: unknown[] } | null>(null);
  const [skipExisting, setSkipExisting] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const pick = async (picked: File | undefined) => {
    setError("");
    setFile(null);
    if (!picked) return;
    if (picked.size > MAX_IMPORT_BYTES) return setError("That file is larger than 8 MB");
    try {
      const parsed: unknown = JSON.parse(await picked.text());
      if (!Array.isArray(parsed)) return setError("A legacy backup is a JSON array of secrets");
      setFile({ name: picked.name, entries: parsed });
    } catch {
      setError("That file isn't valid JSON");
    }
  };

  const runImport = async () => {
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const { imported, skipped } = await api.importLegacy(file.entries, skipExisting);
      toast.success(`Imported ${imported} secret${imported === 1 ? "" : "s"}`, { description: skipped ? `Skipped ${skipped} that already existed` : undefined });
      setFile(null);
      if (inputRef.current) inputRef.current.value = "";
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Import legacy backup" className="shrink-0">
      <div className="flex flex-col gap-4 p-4">
        <p className="text-sm text-muted">Bring in secrets from an autho v1 JSON backup, like <code className="font-mono text-xs">autho import legacy --file</code>. The file is read in this browser and sent only to this autho.</p>
        <label
          onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => { e.preventDefault(); setDragging(false); void pick(e.dataTransfer.files[0]); }}
          className={cn(
            "flex cursor-pointer flex-col items-center gap-2 rounded-lg border border-dashed px-4 py-6 text-center transition-colors",
            dragging ? "border-accent bg-selection" : "border-border hover:border-border-focus",
          )}
        >
          <FileUp className="size-6 text-dim" />
          {file ? (
            <span className="text-sm text-text">{file.name} <span className="text-dim">· {file.entries.length} entr{file.entries.length === 1 ? "y" : "ies"}</span></span>
          ) : (
            <span className="text-sm text-muted">Drop a .json file here, or click to choose one</span>
          )}
          <input ref={inputRef} type="file" accept=".json,application/json" className="sr-only" onChange={(e) => void pick(e.target.files?.[0])} />
        </label>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <label className="flex items-center gap-3 text-sm text-text">
            <Switch checked={skipExisting} onCheckedChange={setSkipExisting} aria-label="Skip existing secrets" />
            Skip secrets that already exist
          </label>
          <Button variant="primary" onClick={() => void runImport()} disabled={!file || busy}>
            {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}Import
          </Button>
        </div>
        {!skipExisting ? <p className="text-xs text-dim">With this off, the import stops at the first name that already exists, and nothing is imported.</p> : null}
        {error ? <p role="alert" className="text-sm text-danger">✗ {error}</p> : null}
      </div>
    </Panel>
  );
}
