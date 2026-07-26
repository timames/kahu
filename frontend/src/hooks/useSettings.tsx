import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

interface Settings {
  gamification: boolean;
  adminGamificationOverride: boolean | null; // null = no override, true/false = forced
}

interface SettingsContextValue {
  settings: Settings;
  gamificationEnabled: boolean;
  toggleGamification: () => void;
  setAdminOverride: (value: boolean | null) => void;
}

const STORAGE_KEY = "kahu-settings";

function loadSettings(): Settings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as Settings;
  } catch { /* ignore */ }
  return { gamification: true, adminGamificationOverride: null };
}

function saveSettings(s: Settings) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(s));
}

const SettingsContext = createContext<SettingsContextValue | null>(null);

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [settings, setSettings] = useState<Settings>(loadSettings);

  const gamificationEnabled =
    settings.adminGamificationOverride !== null
      ? settings.adminGamificationOverride
      : settings.gamification;

  const toggleGamification = useCallback(() => {
    setSettings((prev) => {
      const next = { ...prev, gamification: !prev.gamification };
      saveSettings(next);
      return next;
    });
  }, []);

  const setAdminOverride = useCallback((value: boolean | null) => {
    setSettings((prev) => {
      const next = { ...prev, adminGamificationOverride: value };
      saveSettings(next);
      return next;
    });
  }, []);

  return (
    <SettingsContext.Provider value={{ settings, gamificationEnabled, toggleGamification, setAdminOverride }}>
      {children}
    </SettingsContext.Provider>
  );
}

export function useSettings() {
  const ctx = useContext(SettingsContext);
  if (!ctx) throw new Error("useSettings must be used within SettingsProvider");
  return ctx;
}
