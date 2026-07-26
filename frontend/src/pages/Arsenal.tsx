import { useState } from "react";
import { Swords, Lock, Unlock, AlertTriangle } from "lucide-react";

export function Arsenal() {
  const [unlocked, setUnlocked] = useState(false);

  if (!unlocked) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-6">
        <div className="w-20 h-20 rounded-2xl bg-red-500/10 flex items-center justify-center">
          <Lock size={32} className="text-red-400" />
        </div>
        <div className="text-center max-w-sm">
          <h1 className="text-xl font-semibold text-white mb-2">Arsenal</h1>
          <p className="text-sm text-slate-400 mb-4">
            Arsenal mode enables offensive security tools for authorized penetration testing.
            This action is logged.
          </p>
          <div className="flex items-center gap-2 text-amber-400 text-xs bg-amber-400/10 px-3 py-2 rounded-lg mb-4">
            <AlertTriangle size={12} />
            Only use on systems you are authorized to test.
          </div>
          <button
            onClick={() => setUnlocked(true)}
            className="bg-red-500 text-white rounded-xl px-6 py-2.5 text-sm font-medium hover:bg-red-600 transition-colors flex items-center gap-2 mx-auto"
          >
            <Unlock size={16} /> Unlock Arsenal
          </button>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Swords size={20} className="text-red-400" />
          <h1 className="text-xl font-semibold text-white">Arsenal</h1>
          <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded-full">UNLOCKED</span>
        </div>
        <button
          onClick={() => setUnlocked(false)}
          className="text-xs text-slate-400 hover:text-white transition-colors flex items-center gap-1"
        >
          <Lock size={12} /> Lock
        </button>
      </div>

      <p className="text-sm text-slate-400 mb-6">
        Offensive toolkit with 70+ tools organized by PTES methodology.
        Use the API at <code className="text-kahu-accent">/api/arsenal</code> for tool catalog and AI-assisted attack planning.
      </p>

      <div className="grid gap-3 md:grid-cols-2">
        {["Passive Recon", "Active Scanning", "Vulnerability Analysis", "Exploitation", "Post-Exploitation", "Reporting"].map((phase) => (
          <div key={phase} className="bg-kahu-card border border-kahu-border rounded-xl p-4">
            <h3 className="text-sm font-semibold text-white mb-1">{phase}</h3>
            <p className="text-xs text-slate-500">
              Tools available via API
            </p>
          </div>
        ))}
      </div>
    </div>
  );
}
