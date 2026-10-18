import { Eye, EyeOff, Wand2 } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { toast } from "sonner";

import { Button } from "../components/ui/button.tsx";
import { DialogContent, DialogFooter } from "../components/ui/dialog.tsx";
import { Field, Input, Textarea } from "../components/ui/field.tsx";
import { Kbd, Spinner } from "../components/ui/panel.tsx";
import { useApp } from "../context.tsx";
import { api, errorMessage, type Group, type SecretDetail, type SecretEntry, type SecretType } from "../lib/api.ts";
import { TYPE_META, cn, generatePassword, isMac } from "../lib/utils.ts";

const TYPES: SecretType[] = ["password", "note", "otp"];

function valueLabel(type: SecretType): string {
  return type === "note" ? "Note" : type === "otp" ? "Secret key" : "Password";
}

/**
 * Create and edit share one form, like the TUI. When editing, the stored
 * value is only loaded on request (ctrl+r); leaving it empty keeps it.
 */
export function SecretForm({ secret, existingNames, defaultGroupId = null, onDone }: {
  secret: SecretDetail | null;
  existingNames: string[];
  /** A new secret starts in this group (the vault's current group scope). */
  defaultGroupId?: string | null;
  onDone: (saved: SecretEntry) => void;
}) {
  const { prefs } = useApp();
  const editing = secret !== null;
  const [type, setType] = useState<SecretType>(secret?.type ?? "password");
  const [name, setName] = useState(secret?.name ?? "");
  const [value, setValue] = useState("");
  const [username, setUsername] = useState(secret?.username ?? "");
  const [url, setUrl] = useState(secret?.url ?? "");
  const [description, setDescription] = useState(secret?.description ?? "");
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [groupId, setGroupId] = useState<string | null>(secret ? secret.groupId : defaultGroupId);
  const [showValue, setShowValue] = useState(false);
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  // The stored value once loaded; saving it back unchanged is a no-op.
  const loaded = useRef<string | null>(null);
  const valueRef = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const mod = isMac() ? "⌘" : "ctrl";

  const hideValue = () => {
    setShowValue(false);
    // Drop a loaded stored value from memory unless it was edited.
    if (loaded.current !== null) {
      setValue((current) => (current === loaded.current ? "" : current));
      loaded.current = null;
    }
  };

  // Groups are picked here, never created: that happens on the Groups screen.
  useEffect(() => {
    api.groups().then(setGroups).catch((e) => setError({ message: errorMessage(e) }));
  }, []);

  // A shown value hides after the reveal preference, like everywhere else.
  useEffect(() => {
    if (!showValue || prefs.revealSeconds <= 0) return;
    const timer = window.setTimeout(hideValue, prefs.revealSeconds * 1000);
    return () => window.clearTimeout(timer);
  }, [showValue, prefs.revealSeconds]);

  const toggleValue = async () => {
    if (showValue) return hideValue();
    if (editing && !value && loaded.current === null) {
      try {
        const { value: current } = await api.reveal(secret.id);
        loaded.current = current;
        setValue(current);
      } catch (e) {
        return setError({ message: errorMessage(e) });
      }
    }
    setShowValue(true);
    valueRef.current?.focus();
  };

  const generate = () => {
    if (type !== "password") return;
    loaded.current = null;
    setValue(generatePassword(prefs.passwordLength, prefs.passwordSymbols));
    toast(`Generated a ${prefs.passwordLength}-character password`, { description: `${mod}+r to view it` });
  };

  const save = async () => {
    const trimmed = name.trim();
    if (!trimmed) return setError({ field: "name", message: "Name is required" });
    if (!editing && existingNames.includes(trimmed)) return setError({ field: "name", message: `A secret named "${trimmed}" already exists` });
    if (!editing && !value) return setError({ field: "value", message: `${valueLabel(type)} is required` });
    if (type === "password" && url.trim() && !/^https?:\/\//i.test(url.trim())) {
      return setError({ field: "url", message: "URL must start with http:// or https://" });
    }
    setBusy(true);
    setError(null);
    try {
      if (editing) {
        const updates: Record<string, unknown> = {};
        if (trimmed !== secret.name) updates.name = trimmed;
        if (value && value !== loaded.current) updates.value = value;
        if (type !== "note" && username.trim() !== (secret.username ?? "")) updates.username = username.trim();
        if (type === "password" && url.trim() !== (secret.url ?? "")) updates.url = url.trim();
        if (description.trim() !== (secret.description ?? "")) updates.description = description.trim();
        if (groupId !== secret.groupId) updates.group = groupId;
        if (Object.keys(updates).length === 0) {
          toast("No changes");
          return onDone(secret);
        }
        const saved = await api.updateSecret(secret.id, updates);
        toast.success(`Saved "${trimmed}"`);
        onDone(saved);
      } else {
        const saved = await api.createSecret({
          name: trimmed,
          type,
          value,
          username: type === "note" ? undefined : username.trim() || undefined,
          url: type === "password" ? url.trim() || undefined : undefined,
          description: description.trim() || undefined,
          group: groupId ?? undefined,
        });
        toast.success(`Created "${trimmed}"`);
        onDone(saved);
      }
    } catch (e) {
      setError({ message: errorMessage(e) });
      setBusy(false);
    }
  };

  const onSubmit = (event: FormEvent) => {
    event.preventDefault();
    void save();
  };

  const onKeyDown = (event: KeyboardEvent) => {
    const ctrl = event.ctrlKey || event.metaKey;
    if (!ctrl) return;
    const key = event.key.toLowerCase();
    if (key === "s") {
      event.preventDefault();
      void save();
    } else if (key === "g" && type === "password") {
      event.preventDefault();
      generate();
    } else if (key === "r") {
      event.preventDefault();
      void toggleValue();
    }
  };

  const fieldError = (field: string) => (error?.field === field ? error.message : undefined);
  const valueProps = {
    id: "secret-value",
    value,
    onChange: (e: { target: { value: string } }) => setValue(e.target.value),
    placeholder: editing ? "leave empty to keep the current value" : type === "otp" ? "base32 key, e.g. JBSWY3DPEHPK3PXP" : "",
    "aria-invalid": Boolean(fieldError("value")) || undefined,
    autoComplete: "new-password",
    maxLength: 65_536,
  };

  return (
    <DialogContent
      title={editing ? `Edit ${secret.name}` : "New secret"}
      className="w-[min(94vw,34rem)]"
      onKeyDown={onKeyDown}
      onOpenAutoFocus={(e) => {
        e.preventDefault();
        document.getElementById("secret-name")?.focus();
      }}
    >
      <form onSubmit={onSubmit} className="flex flex-col gap-4">
        {editing ? null : (
          <div role="radiogroup" aria-label="Type" className="grid grid-cols-3 gap-1.5">
            {TYPES.map((t) => {
              const meta = TYPE_META[t];
              const on = t === type;
              return (
                <button
                  key={t}
                  type="button"
                  role="radio"
                  aria-checked={on}
                  onClick={() => { setType(t); setError(null); }}
                  className={cn(
                    "flex cursor-pointer items-center justify-center gap-2 rounded-md border px-2 py-2 text-sm transition-colors",
                    on ? "border-accent bg-accent text-on-accent font-semibold" : "border-border bg-chip text-muted hover:text-text",
                  )}
                >
                  <span className={on ? "text-on-accent" : meta.color}>{meta.glyph}</span>{meta.label}
                </button>
              );
            })}
          </div>
        )}

        <Field label="Name" htmlFor="secret-name" error={fieldError("name")}>
          <Input id="secret-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. github" maxLength={200} aria-invalid={Boolean(fieldError("name")) || undefined} />
        </Field>

        <Field
          label="Group"
          htmlFor="secret-group"
          hint={groups && groups.length === 0 ? "Create groups on the Groups screen" : undefined}
        >
          <select
            id="secret-group"
            value={groupId ?? ""}
            onChange={(e) => setGroupId(e.target.value || null)}
            disabled={!groups || groups.length === 0}
            className="h-9 w-full cursor-pointer rounded-md border border-border bg-input px-2.5 text-sm text-text transition-colors focus:border-accent focus:bg-input-focus focus:outline-none disabled:cursor-default disabled:opacity-50"
          >
            <option value="">(none)</option>
            {(groups ?? []).map((g) => <option key={g.id} value={g.id}>{g.name}</option>)}
          </select>
        </Field>

        <Field
          label={valueLabel(type)}
          htmlFor="secret-value"
          error={fieldError("value")}
          hint={editing ? <><Kbd>{mod}+r</Kbd> loads and shows the current value</> : undefined}
        >
          <div className="flex items-start gap-1.5">
            {type === "note" ? (
              <Textarea ref={valueRef} {...valueProps} className={cn("font-mono", showValue ? "text-revealed" : "[-webkit-text-security:disc]")} />
            ) : (
              <Input ref={valueRef} {...valueProps} type={showValue ? "text" : "password"} className={cn("font-mono", showValue && "text-revealed")} />
            )}
            <Button type="button" variant="secondary" size="icon" onClick={() => void toggleValue()} aria-label={showValue ? "Hide value" : "Show value"} title={`${showValue ? "Hide" : "Show"} (${mod}+r)`}>
              {showValue ? <EyeOff /> : <Eye />}
            </Button>
            {type === "password" ? (
              <Button type="button" variant="secondary" size="icon" onClick={generate} aria-label="Generate password" title={`Generate (${mod}+g)`} className="text-info">
                <Wand2 />
              </Button>
            ) : null}
          </div>
        </Field>

        {type !== "note" ? (
          <Field label="Username" htmlFor="secret-username">
            <Input id="secret-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="optional" maxLength={512} />
          </Field>
        ) : null}

        {type === "password" ? (
          <Field label="URL" htmlFor="secret-url" error={fieldError("url")}>
            <Input id="secret-url" type="url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="optional, e.g. https://github.com" maxLength={512} aria-invalid={Boolean(fieldError("url")) || undefined} />
          </Field>
        ) : null}

        <Field label="Notes" htmlFor="secret-description">
          <Textarea id="secret-description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="optional" maxLength={8192} className="min-h-16" />
        </Field>

        {error && !error.field ? <p role="alert" className="rounded-md bg-danger-bg px-3 py-2 text-sm text-danger">✗ {error.message}</p> : null}

        <DialogFooter className="mt-1">
          <span className="mr-auto hidden text-xs text-dim sm:inline"><Kbd>{mod}+s</Kbd> save · <Kbd>esc</Kbd> cancel</span>
          <Button type="submit" variant="primary" disabled={busy}>
            {busy ? <Spinner className="border-on-accent/30 border-t-on-accent" /> : null}
            {editing ? "Save" : "Create"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}
