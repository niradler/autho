import { useState } from "react";

import { Button } from "./ui/button.tsx";
import { DialogContent, DialogFooter } from "./ui/dialog.tsx";
import { Kbd, Spinner } from "./ui/panel.tsx";

/** A danger-styled yes/no; render inside a <Dialog>. Errors are left to onConfirm to report. */
export function ConfirmDialog({ title, body, action, onConfirm, onCancel }: { title: string; body?: string; action: string; onConfirm: () => Promise<void> | void; onCancel: () => void }) {
  const [busy, setBusy] = useState(false);
  return (
    <DialogContent danger title={title} description={body}>
      <DialogFooter className="mt-0">
        <Button variant="ghost" onClick={onCancel} disabled={busy}>Cancel <Kbd>esc</Kbd></Button>
        <Button
          variant="danger"
          autoFocus
          disabled={busy}
          onClick={() => {
            setBusy(true);
            void Promise.resolve(onConfirm()).catch(() => {}).finally(() => setBusy(false));
          }}
        >
          {busy ? <Spinner /> : null}{action}
        </Button>
      </DialogFooter>
    </DialogContent>
  );
}
