import { useKeyboard } from "@opentui/react";
import { useEffect, useMemo, useState, type ReactNode } from "react";

import type { SecretRecord, SecretType, VaultSession } from "../../../../packages/core/src/index.ts";
import { Button, SecretInput, TextField, type KeyHint } from "./components.tsx";
import { useApp, useScreenContext, type Command } from "./context.tsx";
import { theme, typeBadge, typeLabel } from "./theme.ts";
import { generatePassword, isEnter } from "./util.ts";

type FieldKey = "type" | "name" | "value" | "username" | "url" | "description";

const TYPES: SecretType[] = ["password", "note", "otp"];

function fieldsFor(type: SecretType): FieldKey[] {
  switch (type) {
    case "password": return ["type", "name", "value", "username", "url", "description"];
    case "otp": return ["type", "name", "value", "username", "description"];
    case "note": return ["type", "name", "value", "description"];
  }
}

function valueLabel(type: SecretType): string {
  return type === "note" ? "Note" : type === "otp" ? "Secret key" : "Password";
}

const LABELS: Record<FieldKey, string> = {
  type: "Type",
  name: "Name",
  value: "Password",
  username: "Username",
  url: "URL",
  description: "Notes",
};

/**
 * Create and edit share one form. In edit mode the stored value is never
 * loaded into the form: leaving the value field empty keeps it unchanged.
 */
export function SecretForm({ session, editing, onDone, onCancel, setHints }: {
  session: VaultSession;
  /** Existing secret (without needing its value) when editing; null to create. */
  editing: SecretRecord | null;
  onDone: (message: string, id?: string) => void;
  onCancel: () => void;
  setHints: (hints: KeyHint[]) => void;
}) {
  const app = useApp();
  const [type, setType] = useState<SecretType>(editing?.type ?? "password");
  const [values, setValues] = useState<Record<Exclude<FieldKey, "type">, string>>(() => ({
    name: editing?.name ?? "",
    value: "",
    username: editing?.username ?? "",
    url: typeof editing?.metadata.url === "string" ? editing.metadata.url : "",
    description: typeof editing?.metadata.description === "string" ? editing.metadata.description : "",
  }));
  const fields = useMemo(() => fieldsFor(type).filter((f) => !(editing && f === "type")), [type, editing]);
  const [focus, setFocus] = useState<FieldKey>(editing ? "name" : "type");
  const [error, setError] = useState("");

  const set = (key: Exclude<FieldKey, "type">) => (v: string) => setValues((prev) => ({ ...prev, [key]: v }));

  const save = () => {
    const name = values.name.trim();
    if (!name) { setError("Name is required"); setFocus("name"); return; }
    if (!editing && !values.value) { setError(`${valueLabel(type)} is required`); setFocus("value"); return; }
    const metadata: Record<string, unknown> = {};
    if (type === "password" && values.url.trim()) metadata.url = values.url.trim();
    if (values.description.trim()) metadata.description = values.description.trim();
    try {
      if (editing) {
        const updates: Parameters<VaultSession["updateSecret"]>[1] = {};
        if (name !== editing.name) updates.name = name;
        if (values.value) updates.value = values.value;
        if (type !== "note" && values.username !== (editing.username ?? "")) updates.username = values.username;
        const oldUrl = typeof editing.metadata.url === "string" ? editing.metadata.url : "";
        const oldDesc = typeof editing.metadata.description === "string" ? editing.metadata.description : "";
        if ((metadata.url ?? "") !== oldUrl || (metadata.description ?? "") !== oldDesc) {
          // undefined removes the key: core merges, then drops empty values.
          updates.metadata = { url: metadata.url, description: metadata.description };
        }
        if (Object.keys(updates).length === 0) { onDone("No changes", editing.id); return; }
        session.updateSecret(editing.id, updates);
        onDone(`Saved "${name}"`, editing.id);
      } else {
        const created = session.addSecret({
          metadata,
          name,
          type,
          username: type === "note" ? undefined : values.username.trim() || undefined,
          value: values.value,
        });
        onDone(`Created "${name}"`, created.id);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const moveFocus = (delta: number) => {
    const idx = fields.indexOf(focus);
    const next = fields[Math.min(fields.length - 1, Math.max(0, idx + delta))];
    if (next) setFocus(next);
  };

  const cycleType = (delta: number) => {
    const next = TYPES[(TYPES.indexOf(type) + delta + TYPES.length) % TYPES.length]!;
    setType(next);
  };

  const generate = () => {
    if (type !== "password") return;
    set("value")(generatePassword());
    app.toast("Generated a 24-character password — ctrl+r to view it", "info");
  };

  useKeyboard((key) => {
    if (!app.active) return;
    if (key.name === "escape") { key.preventDefault(); onCancel(); return; }
    if (key.ctrl && key.name === "s") { key.preventDefault(); save(); return; }
    if (key.ctrl && key.name === "g") { key.preventDefault(); generate(); return; }
    if (key.name === "tab") { key.preventDefault(); moveFocus(key.shift ? -1 : 1); return; }
    if (key.name === "up") { key.preventDefault(); moveFocus(-1); return; }
    if (key.name === "down") { key.preventDefault(); moveFocus(1); return; }
    if (focus === "type") {
      if (key.name === "left" || key.name === "h") cycleType(-1);
      else if (key.name === "right" || key.name === "l" || key.name === "space") cycleType(1);
      else if (isEnter(key)) moveFocus(1);
    }
  });

  // Enter on the last field saves; on others it moves on.
  const submit = () => {
    if (focus === fields[fields.length - 1]) save();
    else moveFocus(1);
  };

  const commands = useMemo<Command[]>(() => [
    { id: "save", title: editing ? "Save changes" : "Create secret", hint: "ctrl+s", group: "Form", run: save },
    ...(type === "password" ? [{ id: "gen", title: "Generate password", hint: "ctrl+g", group: "Form", run: generate }] : []),
    { id: "cancel", title: "Cancel", hint: "esc", group: "Form", run: onCancel },
  ], [editing, type, values]);
  useScreenContext(commands, null);

  useEffect(() => {
    const hints: KeyHint[] = [["tab/↑↓", "field"], ["enter", "next"], ["ctrl+s", "save"]];
    if (focus === "type") hints.splice(1, 0, ["←→", "type"]);
    if (focus === "value") hints.push(["ctrl+r", "show"]);
    if (type === "password") hints.push(["ctrl+g", "generate"]);
    hints.push(["esc", "cancel"]);
    setHints(hints);
  }, [focus, type, setHints]);

  const row = (key: FieldKey, input: ReactNode) => (
    <box key={key} flexDirection="row" gap={1} height={1}>
      <text fg={focus === key ? theme.accent : theme.muted} width={12}>{focus === key ? "› " : "  "}{key === "value" ? valueLabel(type) : LABELS[key]}</text>
      {input}
    </box>
  );

  const active = app.active;
  return (
    <box flexDirection="column" flexGrow={1} paddingX={1}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.border} paddingX={1} paddingY={1} gap={1} title={editing ? ` Edit ${editing.name} ` : " New secret "}>
        {fields.map((key) => {
          if (key === "type") {
            return row("type", (
              <box flexDirection="row" gap={1}>
                {TYPES.map((t) => {
                  const badge = typeBadge(t);
                  const on = t === type;
                  return (
                    <box key={t} paddingX={1} backgroundColor={on ? theme.selection : theme.panel} onMouseDown={() => { setType(t); setFocus("type"); }}>
                      <text fg={on ? "#FFFFFF" : theme.muted}><span fg={badge.color}>{badge.glyph}</span> {typeLabel(t)}</text>
                    </box>
                  );
                })}
              </box>
            ));
          }
          if (key === "value") {
            return row("value", (
              <box flexDirection="row" flexGrow={1} gap={1} onMouseDown={() => setFocus("value")}>
                <SecretInput
                  value={values.value}
                  onChange={set("value")}
                  onSubmit={submit}
                  focused={active && focus === "value"}
                  multiline={type === "note"}
                  placeholder={editing ? "leave empty to keep the current value" : type === "otp" ? "base32 key, e.g. JBSWY3DPEHPK3PXP" : ""}
                />
                {type === "password" ? <Button label="generate" onPress={generate} /> : null}
              </box>
            ));
          }
          const placeholders: Record<string, string> = {
            name: "e.g. github",
            username: "optional",
            url: "optional, e.g. https://github.com",
            description: "optional",
          };
          return row(key, (
            <box flexGrow={1} onMouseDown={() => setFocus(key)}>
              <TextField value={values[key]} onChange={set(key)} onSubmit={submit} focused={active && focus === key} placeholder={placeholders[key]} />
            </box>
          ));
        })}
        {error ? <text fg={theme.danger}>{error}</text> : null}
        <box flexDirection="row" gap={2}>
          <Button label={editing ? "save · ctrl+s" : "create · ctrl+s"} onPress={save} color={theme.success} />
          <Button label="cancel · esc" onPress={onCancel} color={theme.muted} />
        </box>
      </box>
    </box>
  );
}
