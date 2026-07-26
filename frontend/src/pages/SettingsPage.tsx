import { useSettings } from "@/hooks/useSettings";
import { Settings, Gamepad2, Shield } from "lucide-react";

export function SettingsPage() {
  const { settings, gamificationEnabled, toggleGamification, setAdminOverride } = useSettings();

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-6">Settings</h1>

      {/* Gamification */}
      <section className="bg-kahu-card border border-kahu-border rounded-xl p-5 mb-4">
        <div className="flex items-center gap-3 mb-4">
          <Gamepad2 size={20} className="text-kahu-accent" />
          <h2 className="text-sm font-semibold text-white">Gamification</h2>
        </div>

        <div className="space-y-4">
          {/* User toggle */}
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-white">Enable gamification</div>
              <div className="text-xs text-slate-500">XP, streaks, badges, and score ring</div>
            </div>
            <Toggle
              checked={settings.gamification}
              onChange={toggleGamification}
              disabled={settings.adminGamificationOverride !== null}
            />
          </div>

          {/* Admin override */}
          <div className="border-t border-kahu-border pt-4">
            <div className="flex items-center gap-2 mb-2">
              <Shield size={14} className="text-slate-500" />
              <span className="text-xs text-slate-500 font-medium">Admin Override</span>
            </div>
            <div className="flex gap-2">
              <OverrideBtn
                active={settings.adminGamificationOverride === null}
                onClick={() => setAdminOverride(null)}
              >
                User Choice
              </OverrideBtn>
              <OverrideBtn
                active={settings.adminGamificationOverride === true}
                onClick={() => setAdminOverride(true)}
              >
                Force On
              </OverrideBtn>
              <OverrideBtn
                active={settings.adminGamificationOverride === false}
                onClick={() => setAdminOverride(false)}
              >
                Force Off
              </OverrideBtn>
            </div>
          </div>

          <div className="text-xs text-slate-500">
            Current state: gamification is{" "}
            <span className={gamificationEnabled ? "text-green-400" : "text-red-400"}>
              {gamificationEnabled ? "enabled" : "disabled"}
            </span>
          </div>
        </div>
      </section>

      {/* About */}
      <section className="bg-kahu-card border border-kahu-border rounded-xl p-5">
        <div className="flex items-center gap-3 mb-3">
          <Settings size={20} className="text-slate-500" />
          <h2 className="text-sm font-semibold text-white">About</h2>
        </div>
        <div className="space-y-1 text-sm text-slate-400">
          <div>Kahu Core v0.1.0</div>
          <div className="text-xs text-slate-600">On-premises AI security operations by ComplyHI</div>
        </div>
      </section>
    </div>
  );
}

function Toggle({
  checked,
  onChange,
  disabled = false,
}: {
  checked: boolean;
  onChange: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      onClick={onChange}
      disabled={disabled}
      className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
        disabled ? "opacity-40 cursor-not-allowed" : "cursor-pointer"
      } ${checked ? "bg-kahu-accent" : "bg-kahu-border"}`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
          checked ? "translate-x-6" : "translate-x-1"
        }`}
      />
    </button>
  );
}

function OverrideBtn({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
        active
          ? "bg-kahu-accent text-white"
          : "bg-kahu-elevated text-slate-400 hover:text-white"
      }`}
    >
      {children}
    </button>
  );
}
