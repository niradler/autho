import { useCallback, useEffect, useState } from "react";
import { Toaster, toast } from "sonner";

import { TooltipProvider } from "./components/ui/tooltip.tsx";
import { Spinner } from "./components/ui/panel.tsx";
import { AppProvider } from "./context.tsx";
import { api, hasCsrf, setCsrf, setLockedHandler, type SessionInfo } from "./lib/api.ts";
import { Shell } from "./shell.tsx";
import { UnlockScreen } from "./screens/unlock.tsx";

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [checking, setChecking] = useState(hasCsrf);

  const onLocked = useCallback((reason?: string) => {
    setSession(null);
    if (reason) toast(reason, { icon: "›", id: "locked" });
  }, []);

  useEffect(() => {
    setLockedHandler(() => onLocked("Vault locked"));
  }, [onLocked]);

  // A reload keeps this tab's session: the token is in sessionStorage.
  useEffect(() => {
    if (!hasCsrf()) return;
    api.session()
      .then(setSession)
      .catch(() => setCsrf(null))
      .finally(() => setChecking(false));
  }, []);

  const unlocked = useCallback((info: SessionInfo) => {
    setCsrf(info.csrf);
    setSession(info);
  }, []);

  return (
    <TooltipProvider delayDuration={300}>
      {checking ? (
        <div className="flex h-full items-center justify-center"><Spinner /></div>
      ) : session ? (
        <AppProvider key={session.csrf} session={session} onLocked={onLocked}>
          <Shell />
        </AppProvider>
      ) : (
        <UnlockScreen onUnlocked={unlocked} />
      )}
      <Toaster
        theme="dark"
        position="bottom-right"
        offset={44}
        toastOptions={{
          classNames: {
            toast: "!bg-panel-alt !border !border-border !text-text !font-sans !text-sm !rounded-lg",
            description: "!text-muted",
            success: "[&_[data-icon]]:!text-success",
            error: "[&_[data-icon]]:!text-danger",
          },
        }}
      />
    </TooltipProvider>
  );
}
