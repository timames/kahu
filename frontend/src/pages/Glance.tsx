import { useQuery } from "@tanstack/react-query";
import { getBriefing, getGlance, getTriageStatus } from "@/api/client";
import { AlertTriangle, CheckCircle, Shield } from "lucide-react";

export function Glance() {
  const { data: glance } = useQuery({
    queryKey: ["glance"],
    queryFn: getGlance,
    refetchInterval: 10_000,
  });
  const { data: status } = useQuery({
    queryKey: ["triage-status"],
    queryFn: getTriageStatus,
    refetchInterval: 10_000,
  });
  const { data: briefing } = useQuery({ queryKey: ["briefing"], queryFn: getBriefing });

  const count = glance?.count ?? 0;
  const breakdown = glance?.breakdown;
  const orbColor =
    glance?.color === "green"
      ? "from-green-500 to-emerald-600"
      : glance?.color === "yellow"
        ? "from-yellow-500 to-amber-600"
        : "from-red-500 to-rose-600";

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] gap-8">
      {/* Status orb */}
      <div
        className={`relative w-40 h-40 rounded-full bg-gradient-to-br ${orbColor} flex flex-col items-center justify-center shadow-lg shadow-current/20`}
      >
        <span className="text-5xl font-bold text-white">{count}</span>
        <span className="text-sm text-white/80">pending</span>
      </div>

      {/* Headline */}
      {glance?.headline && (
        <p className="text-center text-slate-300 max-w-md font-medium">{glance.headline}</p>
      )}

      {/* Briefing */}
      {briefing && (
        <p className="text-center text-slate-400 max-w-md leading-relaxed text-sm">
          {briefing.briefing}
        </p>
      )}

      {/* Breakdown */}
      {breakdown && (
        <div className="grid grid-cols-5 gap-2 w-full max-w-lg">
          <BreakdownChip label="Critical" value={breakdown.critical} color="text-sev-critical" />
          <BreakdownChip label="High" value={breakdown.high} color="text-sev-high" />
          <BreakdownChip label="Medium" value={breakdown.medium} color="text-sev-medium" />
          <BreakdownChip label="Low" value={breakdown.low} color="text-sev-low" />
          <BreakdownChip label="Info" value={breakdown.info} color="text-sev-info" />
        </div>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-2 gap-3 w-full max-w-lg">
        <StatCard
          icon={<CheckCircle size={18} />}
          label="Pipeline"
          value={status?.pipeline_running ? "Running" : "Stopped"}
          valueClass={status?.pipeline_running ? "text-green-400" : "text-red-400"}
        />
        <StatCard
          icon={<Shield size={18} />}
          label="AI Model"
          value={
            !status?.ollama_healthy
              ? "Offline"
              : status?.ollama_model_loaded
                ? "Online"
                : "Not loaded"
          }
          valueClass={
            status?.ollama_healthy && status?.ollama_model_loaded
              ? "text-green-400"
              : status?.ollama_healthy
                ? "text-amber-400"
                : "text-red-400"
          }
        />
      </div>

      {status?.pipeline_degraded && (
        <div className="flex items-center gap-2 text-amber-400 text-sm bg-amber-400/10 px-4 py-2 rounded-lg">
          <AlertTriangle size={16} />
          AI triage degraded — running deterministic-only mode
        </div>
      )}
    </div>
  );
}

function BreakdownChip({
  label,
  value,
  color,
}: {
  label: string;
  value: number;
  color: string;
}) {
  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-2 text-center">
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-[10px] text-slate-500 uppercase tracking-wide">{label}</div>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  valueClass = "text-white",
}: {
  icon: React.ReactNode;
  label: string;
  value: string | number;
  valueClass?: string;
}) {
  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-3 flex flex-col gap-1">
      <div className="flex items-center gap-2 text-slate-400 text-xs">
        {icon}
        {label}
      </div>
      <div className={`text-lg font-semibold ${valueClass}`}>{value}</div>
    </div>
  );
}
