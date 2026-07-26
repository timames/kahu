import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getQueue, disposeAlert, type Alert } from "@/api/client";
import { severityClass, timeAgo } from "@/lib/severity";
import { CheckCircle, XCircle, ArrowUpCircle, ChevronDown, ChevronUp } from "lucide-react";

export function Feed() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["queue"], queryFn: () => getQueue(50) });

  const dispose = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: string }) =>
      disposeAlert(id, verdict),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["queue"] });
      queryClient.invalidateQueries({ queryKey: ["triage-status"] });
      queryClient.invalidateQueries({ queryKey: ["briefing"] });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-slate-400">Loading alerts...</div>;
  }

  const alerts = data?.alerts ?? [];

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold text-white">Feed</h1>
        <span className="text-sm text-slate-400">{alerts.length} pending</span>
      </div>

      {alerts.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
          <CheckCircle size={32} className="text-green-400" />
          <p>Queue clear — nothing to review.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {alerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onDispose={(verdict) => dispose.mutate({ id: alert.id, verdict })}
              disposing={dispose.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function AlertCard({
  alert,
  onDispose,
  disposing,
}: {
  alert: Alert;
  onDispose: (verdict: string) => void;
  disposing: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const srcIp = (alert.raw_event?.data as Record<string, unknown>)?.srcip as string | undefined;

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`severity-chip ${severityClass(alert.severity)}`}>
              {alert.severity}
            </span>
            <span className="text-xs text-slate-500">Rule {alert.rule_id}</span>
          </div>
          <p className="text-sm text-slate-200 leading-snug">{alert.rule_description}</p>
          <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500">
            {alert.agent_name && <span>{alert.agent_name}</span>}
            {srcIp && <span>src: {srcIp}</span>}
            <span>{timeAgo(alert.created_at)}</span>
          </div>
        </div>
        {expanded ? <ChevronUp size={16} className="text-slate-500 mt-1" /> : <ChevronDown size={16} className="text-slate-500 mt-1" />}
      </button>

      {/* Expanded details */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-kahu-border pt-3">
          {alert.llm_triage?.explanation && (
            <div className="mb-3">
              <div className="text-xs text-slate-500 mb-1 font-medium">AI Analysis</div>
              <p className="text-sm text-slate-300">{alert.llm_triage.explanation}</p>
            </div>
          )}

          {alert.llm_triage?.recommended_actions && alert.llm_triage.recommended_actions.length > 0 && (
            <div className="mb-3">
              <div className="text-xs text-slate-500 mb-1 font-medium">Recommended Actions</div>
              <ul className="text-sm text-slate-300 list-disc list-inside space-y-0.5">
                {alert.llm_triage.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Disposition actions */}
          <div className="flex gap-2 mt-3">
            <button
              onClick={() => onDispose("true_positive")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              <XCircle size={14} /> Confirm
            </button>
            <button
              onClick={() => onDispose("acknowledged")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/10 text-slate-400 hover:bg-slate-500/20 transition-colors disabled:opacity-50"
            >
              <CheckCircle size={14} /> Acknowledge
            </button>
            <button
              onClick={() => onDispose("undetermined")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
            >
              <ArrowUpCircle size={14} /> Escalate
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
