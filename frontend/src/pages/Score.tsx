import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPonoScore,
  getPonoHistory,
  getPonoStatus,
  getValidationDrift,
  recalculatePono,
  type PonoComponent,
  type PonoHistoryPoint,
} from "@/api/client";
import {
  Shield,
  Bug,
  SlidersHorizontal,
  KeyRound,
  Clock,
  Users,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
} from "lucide-react";
import { timeAgo } from "@/lib/severity";

const COMPONENT_META: Record<string, { icon: typeof Shield; label: string }> = {
  detection_posture:     { icon: Shield,            label: "Detection" },
  vulnerability_posture: { icon: Bug,               label: "Vulnerability" },
  tuning_hygiene:        { icon: SlidersHorizontal, label: "Tuning" },
  identity_access:       { icon: KeyRound,          label: "Identity" },
  response_readiness:    { icon: Clock,             label: "Response" },
  human_layer:           { icon: Users,             label: "Human" },
};

export function Score() {
  const queryClient = useQueryClient();
  const { data: snapshot, isLoading } = useQuery({
    queryKey: ["pono-current"],
    queryFn: getPonoScore,
    refetchInterval: 60_000,
  });
  const { data: history } = useQuery({
    queryKey: ["pono-history"],
    queryFn: () => getPonoHistory(50),
  });
  const { data: status } = useQuery({
    queryKey: ["pono-status"],
    queryFn: getPonoStatus,
  });
  const { data: drift } = useQuery({
    queryKey: ["validation-drift"],
    queryFn: getValidationDrift,
  });

  const recalc = useMutation({
    mutationFn: recalculatePono,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["pono-current"] });
      queryClient.invalidateQueries({ queryKey: ["pono-history"] });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center min-h-[50vh] text-slate-500">Loading...</div>;
  }

  if (!snapshot) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[50vh] gap-4">
        <p className="text-slate-400">No Pono Score computed yet.</p>
        <button
          onClick={() => recalc.mutate()}
          disabled={recalc.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-kahu-accent text-white rounded-lg text-sm hover:bg-kahu-accent/90 disabled:opacity-50"
        >
          <RefreshCw size={14} className={recalc.isPending ? "animate-spin" : ""} />
          Calculate now
        </button>
      </div>
    );
  }

  const score = snapshot.pono_score;
  const circumference = 2 * Math.PI * 72;
  const offset = circumference - (Math.min(100, Math.max(0, score)) / 100) * circumference;
  const ringColor = score >= 80 ? "stroke-green-400" : score >= 50 ? "stroke-yellow-400" : "stroke-red-400";
  const scoreColor = score >= 80 ? "text-green-400" : score >= 50 ? "text-yellow-400" : "text-red-400";

  const points = (history?.snapshots ?? []).slice().reverse();

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header: Score ring + summary */}
      <div className="flex flex-col md:flex-row items-center gap-6 mb-8">
        {/* Ring */}
        <div className="relative w-44 h-44 shrink-0">
          <svg viewBox="0 0 160 160" className="w-full h-full -rotate-90">
            <circle cx="80" cy="80" r="72" fill="none" strokeWidth="8" className="stroke-kahu-border" />
            <circle
              cx="80" cy="80" r="72" fill="none" strokeWidth="8"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              className={`${ringColor} transition-all duration-1000`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className={`text-4xl font-bold ${scoreColor}`}>{Math.round(score)}</span>
            <span className="text-xs text-slate-500">Pono Score</span>
          </div>
        </div>

        {/* Summary cards */}
        <div className="flex-1 grid grid-cols-2 gap-3 w-full">
          <SummaryCard
            label="Last updated"
            value={timeAgo(snapshot.timestamp)}
            sub={status?.loop_running ? "Auto-refresh active" : "Manual mode"}
            icon={<Clock size={14} />}
          />
          <SummaryCard
            label="Components assessed"
            value={`${snapshot.components.filter((c) => c.assessed).length} / ${snapshot.components.length}`}
            sub={`v${snapshot.schema_version}`}
            icon={<Shield size={14} />}
          />
          {drift?.has_validation && (
            <SummaryCard
              label="Validation"
              value={drift.drift_detected ? "Drift detected" : "Verified"}
              sub={drift.validation_rate != null ? `${(drift.validation_rate * 100).toFixed(0)}% pass rate` : ""}
              icon={drift.drift_detected ? <AlertTriangle size={14} /> : <CheckCircle size={14} />}
              alert={drift.drift_detected ?? false}
            />
          )}
          {snapshot.biggest_gain && (
            <SummaryCard
              label="Biggest gain"
              value={COMPONENT_META[snapshot.biggest_gain.component]?.label ?? snapshot.biggest_gain.component}
              sub={`+${snapshot.biggest_gain.available_gain.toFixed(0)} pts available`}
              icon={<TrendingUp size={14} />}
            />
          )}
        </div>
      </div>

      {/* Drop alert */}
      {snapshot.pono_drop && (
        <div className="flex items-center gap-3 mb-6 p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-sm">
          <TrendingDown size={16} className="text-red-400 shrink-0" />
          <span className="text-red-300">
            Score dropped {snapshot.pono_drop.drop.toFixed(1)} points
            ({snapshot.pono_drop.previous_score.toFixed(0)} → {snapshot.pono_drop.current_score.toFixed(0)})
          </span>
        </div>
      )}

      {/* Component breakdown */}
      <h2 className="text-sm font-medium text-slate-400 mb-3">Components</h2>
      <div className="grid gap-2 mb-8">
        {snapshot.components.map((c) => (
          <ComponentRow key={c.name} component={c} />
        ))}
      </div>

      {/* History sparkline */}
      {points.length > 1 && (
        <div className="mb-8">
          <h2 className="text-sm font-medium text-slate-400 mb-3">History</h2>
          <div className="bg-kahu-card border border-kahu-border rounded-xl p-4">
            <Sparkline points={points} />
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <button
          onClick={() => recalc.mutate()}
          disabled={recalc.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-kahu-card border border-kahu-border text-slate-300 rounded-lg text-sm hover:bg-kahu-elevated disabled:opacity-50"
        >
          <RefreshCw size={14} className={recalc.isPending ? "animate-spin" : ""} />
          Recalculate
        </button>
      </div>
    </div>
  );
}

function ComponentRow({ component: c }: { component: PonoComponent }) {
  const meta = COMPONENT_META[c.name] ?? { icon: Shield, label: c.name };
  const Icon = meta.icon;
  const pct = c.max_points > 0 ? (c.weighted_score / c.max_points) * 100 : 0;
  const barColor = !c.assessed ? "bg-slate-600"
    : pct >= 80 ? "bg-green-500"
    : pct >= 50 ? "bg-yellow-500"
    : "bg-red-500";

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-3">
      <div className="flex items-center gap-3 mb-2">
        <Icon size={16} className={c.assessed ? "text-slate-300" : "text-slate-600"} />
        <span className="text-sm text-white flex-1">{meta.label}</span>
        <span className="text-sm font-semibold text-white">
          {c.weighted_score.toFixed(1)}
          <span className="text-slate-500 font-normal"> / {c.max_points}</span>
        </span>
      </div>
      <div className="flex items-center gap-3">
        <div className="flex-1 h-1.5 bg-kahu-border rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-700 ${barColor}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        {!c.assessed && (
          <span className="text-[10px] text-slate-500 uppercase tracking-wider">not assessed</span>
        )}
        {c.assessed && c.evidence_age_days > 7 && (
          <span className="text-[10px] text-yellow-500">{Math.round(c.evidence_age_days)}d old</span>
        )}
      </div>
    </div>
  );
}

function Sparkline({ points }: { points: PonoHistoryPoint[] }) {
  if (points.length < 2) return null;

  const w = 600;
  const h = 80;
  const pad = 4;
  const min = Math.min(...points.map((p) => p.pono_score)) - 2;
  const max = Math.max(...points.map((p) => p.pono_score)) + 2;
  const range = max - min || 1;

  const coords = points.map((p, i) => ({
    x: pad + (i / (points.length - 1)) * (w - pad * 2),
    y: pad + (1 - (p.pono_score - min) / range) * (h - pad * 2),
  }));

  const pathD = coords.map((c, i) => `${i === 0 ? "M" : "L"} ${c.x} ${c.y}`).join(" ");
  const first = points[0]!;
  const latest = points[points.length - 1]!;
  const lastCoord = coords[coords.length - 1]!;
  const trending = latest.pono_score >= first.pono_score;

  return (
    <div>
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-20" preserveAspectRatio="none">
        <path d={pathD} fill="none" stroke={trending ? "#4ade80" : "#f87171"} strokeWidth="2" />
        <circle cx={lastCoord.x} cy={lastCoord.y} r="3" fill={trending ? "#4ade80" : "#f87171"} />
      </svg>
      <div className="flex justify-between text-[10px] text-slate-600 mt-1 px-1">
        <span>{new Date(first.timestamp).toLocaleDateString()}</span>
        <span>{new Date(latest.timestamp).toLocaleDateString()}</span>
      </div>
    </div>
  );
}

function SummaryCard({
  label, value, sub, icon, alert = false,
}: {
  label: string;
  value: string | number;
  sub?: string;
  icon: React.ReactNode;
  alert?: boolean;
}) {
  return (
    <div className={`bg-kahu-card border rounded-xl p-3 ${alert ? "border-red-500/30" : "border-kahu-border"}`}>
      <div className="flex items-center gap-1.5 text-slate-500 text-xs mb-1">{icon}{label}</div>
      <div className={`text-sm font-semibold ${alert ? "text-red-400" : "text-white"}`}>{value}</div>
      {sub && <div className="text-[10px] text-slate-600 mt-0.5">{sub}</div>}
    </div>
  );
}
