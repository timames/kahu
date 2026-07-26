import { useQuery } from "@tanstack/react-query";
import { getScore, getTickets, type Ticket } from "@/api/client";
import { Trophy, Flame, Zap, Clock, Target } from "lucide-react";
import { severityClass, timeAgo } from "@/lib/severity";

export function Score() {
  const { data: score } = useQuery({ queryKey: ["score"], queryFn: getScore });
  const { data: ticketData } = useQuery({ queryKey: ["tickets"], queryFn: getTickets });

  const s = score ?? {
    pono_score: 0, trend: "steady", xp: 0, streak: 0,
    today_count: 0, avg_response_minutes: 0, badges: [],
  };

  const ringPct = Math.min(100, Math.max(0, s.pono_score));
  const circumference = 2 * Math.PI * 72;
  const offset = circumference - (ringPct / 100) * circumference;

  const ringColor = ringPct >= 80 ? "stroke-green-400"
    : ringPct >= 50 ? "stroke-yellow-400"
    : "stroke-red-400";

  return (
    <div>
      {/* Score ring */}
      <div className="flex flex-col items-center mb-8">
        <div className="relative w-44 h-44">
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
            <span className="text-4xl font-bold text-white">{s.pono_score}</span>
            <span className="text-xs text-slate-500 capitalize">{s.trend}</span>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <StatCard icon={<Zap size={16} />} label="Total XP" value={s.xp.toLocaleString()} />
        <StatCard icon={<Flame size={16} />} label="Streak" value={`${s.streak}d`} />
        <StatCard icon={<Target size={16} />} label="Today" value={s.today_count} />
        <StatCard icon={<Clock size={16} />} label="Avg Response" value={`${s.avg_response_minutes}m`} />
      </div>

      {/* Badges */}
      {s.badges.length > 0 && (
        <div className="mb-6">
          <h2 className="text-sm font-medium text-slate-400 mb-3">Badges</h2>
          <div className="flex flex-wrap gap-2">
            {s.badges.map((badge) => (
              <span key={badge} className="bg-kahu-card border border-kahu-border rounded-full px-3 py-1 text-xs text-slate-300">
                <Trophy size={10} className="inline mr-1 text-yellow-400" />
                {badge}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Open tickets */}
      <h2 className="text-sm font-medium text-slate-400 mb-3">
        Open Tickets
        {ticketData?.tickets && (
          <span className="ml-2 text-xs text-slate-600">({ticketData.tickets.length})</span>
        )}
      </h2>
      <div className="flex flex-col gap-2">
        {(ticketData?.tickets ?? []).length === 0 ? (
          <div className="text-center text-slate-500 text-sm py-6">No open tickets</div>
        ) : (
          (ticketData?.tickets ?? []).map((t: Ticket) => (
            <div key={t.id} className="bg-kahu-card border border-kahu-border rounded-xl p-3 flex items-center gap-3">
              <span className={`severity-chip ${severityClass(t.severity)}`}>{t.severity}</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm text-white truncate">{t.title}</div>
                <div className="text-xs text-slate-500">{timeAgo(t.created_at)}</div>
              </div>
              <span className="text-xs text-slate-500 capitalize">{t.status}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function StatCard({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-3">
      <div className="flex items-center gap-1.5 text-slate-500 text-xs mb-1">{icon}{label}</div>
      <div className="text-lg font-semibold text-white">{value}</div>
    </div>
  );
}
