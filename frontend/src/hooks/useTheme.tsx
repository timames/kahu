import { useCallback, useSyncExternalStore } from "react";

const STORAGE_KEY = "kahu_theme";

function getTheme(): "dark" | "light" {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch { /* ignore */ }
  return "dark";
}

function applyTheme(theme: "dark" | "light") {
  document.documentElement.classList.toggle("light", theme === "light");
}

// Initialize on load
applyTheme(getTheme());

const listeners = new Set<() => void>();

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useTheme() {
  const theme = useSyncExternalStore(subscribe, getTheme);

  const toggle = useCallback(() => {
    const next = getTheme() === "dark" ? "light" : "dark";
    localStorage.setItem(STORAGE_KEY, next);
    applyTheme(next);
    listeners.forEach((cb) => cb());
  }, []);

  return { theme, toggle };
}
