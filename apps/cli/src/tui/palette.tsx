import { useKeyboard, useTerminalDimensions } from "@opentui/react";
import { useMemo, useRef, useState } from "react";

import { Chip, TextField } from "./components.tsx";
import type { Command } from "./context.tsx";
import { theme } from "./theme.ts";
import { fuzzyFilter, isEnter, truncate } from "./util.ts";

// The row reads "group · title", so a query can span both, e.g. "group homelab".
const fields = (c: Command) => [c.title, c.group, c.hint, `${c.group} ${c.title}`];

/** Ctrl+K overlay: fuzzy search over the current screen's commands plus global ones. */
export function CommandPalette({ commands, onClose }: { commands: Command[]; onClose: () => void }) {
  const { width, height } = useTerminalDimensions();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);
  // Enter can arrive before React re-renders with the latest keystrokes.
  const latestQuery = useRef("");

  const results = useMemo(
    () => fuzzyFilter(commands, query, fields),
    [commands, query],
  );
  const current = Math.min(index, Math.max(0, results.length - 1));

  const run = (command: Command | undefined) => {
    if (!command) return;
    onClose();
    command.run();
  };

  useKeyboard((key) => {
    if (key.name === "escape" || (key.ctrl && key.name === "k")) { key.preventDefault(); onClose(); return; }
    if (key.name === "up") { key.preventDefault(); setIndex(Math.max(0, current - 1)); return; }
    if (key.name === "down") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 1)); return; }
    if (key.name === "pageup") { key.preventDefault(); setIndex(Math.max(0, current - 10)); return; }
    if (key.name === "pagedown") { key.preventDefault(); setIndex(Math.min(results.length - 1, current + 10)); return; }
    if (isEnter(key)) {
      key.preventDefault();
      const fresh = latestQuery.current === query ? results : fuzzyFilter(commands, latestQuery.current, fields);
      run(fresh[latestQuery.current === query ? current : 0]);
    }
  });

  const boxWidth = Math.min(72, Math.max(30, width - 4));
  const rows = Math.max(3, Math.min(14, height - 8));
  const offset = Math.max(0, Math.min(current - Math.floor(rows / 2), results.length - rows));
  const visible = results.slice(offset, offset + rows);
  const inner = boxWidth - 4;

  return (
    <box position="absolute" top={2} left={Math.max(0, Math.floor((width - boxWidth) / 2))} width={boxWidth} zIndex={100}>
      <box flexDirection="column" border borderStyle="rounded" borderColor={theme.borderFocus} backgroundColor={theme.panel} paddingX={1} title=" Commands " titleColor={theme.accent} titleAlignment="center">
        <box flexDirection="row" height={1} gap={1}>
          <text fg={theme.accent}><strong>›</strong></text>
          <TextField value={query} onChange={(v) => { latestQuery.current = v; setQuery(v); setIndex(0); }} focused placeholder="type a command or secret name" />
        </box>
        <box flexDirection="column" marginTop={1}>
          {visible.length === 0 ? <text fg={theme.dim}>No matching commands</text> : null}
          {visible.map((command, i) => {
            const on = offset + i === current;
            const hint = command.hint ?? "";
            const label = `${command.group} · `;
            const title = truncate(command.title, Math.max(4, inner - label.length - hint.length - 5));
            return (
              <box
                key={command.id}
                flexDirection="row"
                justifyContent="space-between"
                height={1}
                backgroundColor={on ? theme.selection : undefined}
                onMouseDown={(event) => { event.preventDefault(); run(command); }}
                onMouseOver={() => setIndex(offset + i)}
              >
                <text><span> </span><span fg={theme.dim}>{label}</span>{on ? <strong fg={theme.accent}>{title}</strong> : <span fg={theme.text}>{title}</span>}</text>
                {hint ? <text flexShrink={0}><span bg={theme.chip} fg={on ? theme.accent : theme.muted}> {hint} </span></text> : null}
              </box>
            );
          })}
        </box>
        <text marginTop={1}><Chip label="↑↓" /><span fg={theme.muted}> move  </span><Chip label="enter" /><span fg={theme.muted}> run  </span><Chip label="esc" /><span fg={theme.muted}> close</span></text>
      </box>
    </box>
  );
}
