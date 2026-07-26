import { useQuery } from "@tanstack/react-query";
import { getBriefing, getTriageStatus } from "@/api/client";
import { AlertTriangle, CheckCircle, Clock, Shield } from "lucide-react";

export function Glance() {
  const { data: briefing } = useQuery({ queryKey: ["briefing"], queryFn: getBriefing });
  const { data: status } = useQuery({
    queryKey: ["triage-status"],
    queryFn: getTriageStatus,
    refetchInterval: 10_000,
  });

  const queueDepth = status?.queue_depth ?? 0;
  const orbColor = queueDepth === 0
    ? "from-green-500 to-emerald-600"
    : queueDepth < 10
      ? "from-yellow-500 to-amber-600"
      : "from-red-500 to-rose-600";

  return (
    <div className="flex flex-col items-center justify-center min-h-[70vh] gap-8">
      {/* Status orb */}
      <div className={`relative w-40 h-40 rounded-full bg-gradient-to-br ${orbColor} flex flex-col items-center justify-center shadow-lg shadow-current/20`}>
        <span className="text-5xl font-bold text-white">{queueDepth}</span>
        <span className="text-sm text-white/80">pending</span>
      </div>

      {/* Briefing */}
      {briefing && (
        <p className="text-center text-slate-300 max-w-md leading-relaxed">
          {briefing.briefing}
        </p>
      )}

      {/* Quick stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 w-full max-w-lg">
        <StatCard
          icon={<Shield size={18} />}
          label="Processed"
          value={status?.total_processed ?? 0}
        />
        <StatCard
          icon={<Clock size={18} />}
          label="Queue"
          value={queueDepth}
        />
        <StatCard
          icon={<CheckCircle size={18} />}
          label="Pipeline"
          value={status?.pipeline_running ? "Running" : "Stopped"}
          valueClass={status?.pipeline_running ? "text-green-400" : "text-red-400"}
        />
        <StatCard
          icon={<AlertTriangle size={18} />}
          label="AI Model"
          value={status?.ollama_healthy ? "Online" : "Offline"}
          valueClass={status?.ollama_healthy ? "text-green-400" : "text-red-400"}
        />
      </div>

      {status?.degraded && (
        <div className="flex items-center gap-2 text-amber-400 text-sm bg-amber-400/10 px-4 py-2 rounded-lg">
          <AlertTriangle size={16} />
          AI triage degraded — running deterministic-only mode
        </div>
      )}
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
