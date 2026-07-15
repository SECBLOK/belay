import {
  createContext, useCallback, useContext, useEffect, useRef, useState,
  type ReactNode,
} from "react";
import { invoke } from "@tauri-apps/api/core";
import { getVersion } from "@tauri-apps/api/app";

type CheckResult = {
  available: boolean;
  version?: string;
  current?: string;
  notes?: string;
  error?: string;
};

export type UpdaterState = {
  supported: boolean | null; // null until first probe; false in the web build (no Tauri)
  available: boolean;
  version?: string; // the newer version, when available
  current?: string; // this app's own version
  notes?: string;
  checking: boolean;
  checkedAt?: number; // epoch ms of the last completed check
  error?: string;
  checkNow: () => Promise<void>;
  install: () => Promise<void>;
};

const Ctx = createContext<UpdaterState | null>(null);
// Re-check without needing a restart. The old banner only checked once on mount,
// so a release cut while the app was running was never surfaced.
const RECHECK_MS = 6 * 60 * 60 * 1000; // 6 hours

export function UpdaterProvider({ children }: { children: ReactNode }) {
  const [s, setS] = useState<Omit<UpdaterState, "checkNow" | "install">>({
    supported: null,
    available: false,
    checking: false,
  });
  const currentRef = useRef<string | undefined>(undefined);

  const checkNow = useCallback(async () => {
    setS((p) => ({ ...p, checking: true, error: undefined }));
    try {
      const r = await invoke<CheckResult>("check_update");
      setS((p) => ({
        ...p,
        supported: true,
        checking: false,
        available: !!r?.available,
        version: r?.available ? r?.version : undefined,
        current: r?.current ?? currentRef.current ?? p.current,
        notes: r?.notes,
        error: r?.error,
        checkedAt: Date.now(),
      }));
    } catch (e) {
      // A throw means no Tauri bridge (web build): mark unsupported and stay quiet.
      setS((p) => ({
        ...p,
        supported: p.supported ?? false,
        checking: false,
        error: p.supported ? String((e as { message?: string })?.message ?? e) : undefined,
      }));
    }
  }, []);

  const install = useCallback(async () => {
    await invoke("install_update");
  }, []);

  useEffect(() => {
    let live = true;
    // Learn our own version once (for the "you're on the latest (vX)" line).
    Promise.resolve()
      .then(() => getVersion())
      .then((v) => {
        if (!live) return;
        currentRef.current = v;
        setS((p) => ({ ...p, supported: true, current: p.current ?? v }));
      })
      .catch(() => { /* web build - checkNow marks it unsupported */ });
    checkNow();
    const id = setInterval(() => { if (live) checkNow(); }, RECHECK_MS);
    return () => { live = false; clearInterval(id); };
  }, [checkNow]);

  return <Ctx.Provider value={{ ...s, checkNow, install }}>{children}</Ctx.Provider>;
}

// Fail-soft when rendered without a provider (e.g. a view mounted in isolation
// in a test): report "unsupported" so the update UI simply renders nothing,
// rather than throwing. In the real app <UpdaterProvider> wraps everything.
const DISABLED: UpdaterState = {
  supported: false,
  available: false,
  checking: false,
  checkNow: async () => {},
  install: async () => {},
};

export function useUpdater(): UpdaterState {
  return useContext(Ctx) ?? DISABLED;
}
