import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useMemo, useRef, useState } from "react";

import type { SecretIndexEntry } from "../../../../packages/core/src/index.ts";
import { Chip, TextField } from "./components.tsx";
import { theme, typeBadge, typeLabel } from "./theme.ts";
import { fuzzyFilter, isEnter, truncate } from "./util.ts";

/**
 * Overlay for linking secrets under `primary`. Enter links or unlinks the
 * highlighted secret and keeps the picker open, so several can be toggled.
 */
export function LinkPicker({ primary, entries, linkedIds, onToggle, onClose }: {
  primary: SecretIndexEntry;
  entries: SecretIndexEntry[];
  linkedIds: ReadonlySet<string>;
  onToggle: (entry: SecretIndexEntry) => void;
  onClose: () => void;
}) {
  const { width, height } = useTerminalDimensions();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  // Enter can arrive before React re-renders with the latest keystrokes.
  const latestQuery = useRef("");

  const candidates = useMemo(() => entries.filter((e) => e.id !== primary.id), [entries, primary.id]);
  const search = (q: string) => fuzzyFilter(candidates, q, (e) => [e.name, e.username, e.url, typeLabel(e.type)]);
  const results = useMemo(() => search(query), [candidates, query]);
  const current = Math.min(index, Math.max(0, results.length - 1));

  useKeyboard((key) => {
    if (key.name === "escape") { key.preventDefault(); onClose(); return; }
    if (key.name === "up") { key.preventDefault(); setIndex(Math.max(0, current - 1)); return; }
    if (key.name === "down") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 1)); return; }
    if (key.name === "pageup") { key.preventDefault(); setIndex(Math.max(0, current - 10)); return; }
    if (key.name === "pagedown") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 10)); return; }
    if (isEnter(key)) {
      key.preventDefault();
      const fresh = latestQuery.current === query ? results : search(latestQuery.current);
      const entry = fresh[latestQuery.current === query ? current : 0];
      if (entry) onToggle(entry);
    }
  });

  const boxWidth = Math.min(72, Math.max(30, width - 4));
  const rows = Math.max(3, Math.min(14, height - 8));
  const offset = Math.max(0, Math.min(current - Math.floor(rows / 2), results.length - rows));
  const visible = results.slice(offset, offset + rows);
  const inner = boxWidth - 4;

  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.borderFocus} backgroundColor={theme.panel} paddingX={1} title={` Link to ${truncate(primary.name, 40)} `} titleColor={theme.accent} titleAlignment="center">
        <box flexDirection="row" height={1} gap={1}>
          <text fg={theme.accent}><strong>›</strong></text>
          <TextField value={query} onChange={(v) => { latestQuery.current = v; setQuery(v); setIndex(0); }} focused placeholder="search secrets to link" />
        </box>
        <box flexDirection="column" marginTop={1}>
          {visible.length === 0 ? <text fg={theme.dim}>No matching secrets</text> : null}
          {visible.map((entry, i) => {
            const on = offset + i === current;
            const linked = linkedIds.has(entry.id);
            const badge = typeBadge(entry.type);
            const name = truncate(entry.name, Math.max(4, inner - 6));
            return (
              <box
                key={entry.id}
                flexDirection="row"
                height={1}
                backgroundColor={on ? theme.selection : undefined}
                onMouseDown={(event) => { event.preventDefault(); onToggle(entry); }}
                onMouseOver={() => setIndex(offset + i)}
              >
                <text>
                  <span fg={linked ? theme.success : theme.dim}>{linked ? " ✓ " : "   "}</span>
                  <span fg={badge.color}>{badge.glyph} </span>
                  {on ? <strong fg={theme.accent}>{name}</strong> : <span fg={theme.text}>{name}</span>}
                </text>
              </box>
            );
          })}
        </box>
        <text marginTop={1}><Chip label="↑↓" /><span fg={theme.muted}> move  </span><Chip label="enter" /><span fg={theme.muted}> link/unlink  </span><Chip label="esc" /><span fg={theme.muted}> done</span></text>
      </box>
    </box>
  );
}
