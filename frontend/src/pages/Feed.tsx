import { useState, useRef, useCallback, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getQueue,
  getHistory,
  getWazuhLogs,
  getLogStorage,
  getSwipeFeed,
  getTriageStatus,
  getMutes,
  muteRule,
  unmuteRule,
  disposeAlert,
  swipeAlert,
  type SwipeCard,
  type LogStorage,
  type MutedRule,
} from "@/api/client";
import { severityClass, timeAgo } from "@/lib/severity";
import {
  CheckCircle,
  XCircle,
  ArrowUpCircle,
  ChevronDown,
  ChevronUp,
  Layers,
  CreditCard,
  Search,
  HardDrive,
  AlertTriangle,
  BellOff,
  Server,
  X,
} from "lucide-react";

const SEV_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const VERDICT_LABEL: Record<string, string> = {
  true_positive: "Confirmed",
  false_positive: "False positive",
  acknowledged: "Acknowledged",
  undetermined: "Escalated",
};

const VERDICT_COLOR: Record<string, string> = {
  true_positive: "text-red-400 bg-red-500/10",
  false_positive: "text-slate-400 bg-slate-500/10",
  acknowledged: "text-green-400 bg-green-500/10",
  undetermined: "text-amber-400 bg-amber-500/10",
};

/** Common shape the pending queue, triaged history, and raw Wazuh logs all normalize to. */
interface Row {
  id: string;
  severity: string;
  rule_id: string;
  rule_description: string;
  agent_name: string | null;
  created_at: string;
  llm_explanation: string | null;
  verdict: string | null; // null = still pending / undispositioned
  degraded: boolean;
  muted?: boolean; // persisted under an active rule mute (history view only)
  isLog?: boolean; // raw Wazuh indexer log — read-only, no disposition
  fullLog?: string | null;
  srcIp?: string | null;
  level?: number;
}

/** Warns operators when new alerts are being triaged deterministically because
 *  the local model is unreachable or not resident in memory. */
function DegradedBanner() {
  const { data: status } = useQuery({
    queryKey: ["triage-status"],
    queryFn: getTriageStatus,
    refetchInterval: 15_000,
  });

  if (!status || !status.pipeline_degraded) return null;

  const reason = !status.ollama_healthy
    ? "The local model service is unreachable."
    : "The local model is not loaded (warming up or evicted from memory).";

  return (
    <div className="mb-4 flex items-start gap-2 p-3 rounded-xl border border-amber-500/40 bg-amber-500/10">
      <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-400" />
      <div>
        <p className="text-sm font-medium text-amber-300">
          AI triage unavailable — deterministic assessment only
        </p>
        <p className="mt-0.5 text-xs text-amber-400/80">
          {reason} New alerts get rule-based triage until it returns.
        </p>
      </div>
    </div>
  );
}

export function Feed() {
  const [swipeMode, setSwipeMode] = useState(false);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold text-white">Feed</h1>
        <button
          onClick={() => setSwipeMode(!swipeMode)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            swipeMode
              ? "bg-kahu-accent text-white"
              : "bg-kahu-elevated text-slate-400 hover:text-white"
          }`}
        >
          {swipeMode ? <Layers size={14} /> : <CreditCard size={14} />}
          {swipeMode ? "List View" : "Swipe Mode"}
        </button>
      </div>

      <DegradedBanner />

      {swipeMode ? <SwipeFeed /> : <ListFeed />}
    </div>
  );
}

/* ── List Feed (multi-select, sort, filter, all-logs view) ── */

function ListFeed() {
  const queryClient = useQueryClient();

  const [view, setView] = useState<"pending" | "triaged" | "logs">("pending");
  const [severity, setSeverity] = useState("");
  const [verdict, setVerdict] = useState("");
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<"severity" | "newest" | "oldest">("severity");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [logsOffset, setLogsOffset] = useState(0);
  const [groupByDevice, setGroupByDevice] = useState(false);
  const [muteTarget, setMuteTarget] = useState<{ ruleId: string; description: string } | null>(
    null,
  );
  const [showMutes, setShowMutes] = useState(false);
  const LOGS_PAGE = 100;

  const clearSelection = () => setSelected(new Set());

  const queueQuery = useQuery({
    queryKey: ["queue", severity],
    queryFn: () => getQueue(200, severity || undefined),
    enabled: view === "pending",
  });

  const historyQuery = useQuery({
    queryKey: ["history", severity, verdict, search],
    queryFn: () =>
      getHistory({
        limit: 200,
        severity: severity || undefined,
        verdict: verdict || undefined,
        search: search || undefined,
      }),
    enabled: view === "triaged",
  });

  const logsQuery = useQuery({
    queryKey: ["wazuh-logs", severity, search, logsOffset],
    queryFn: () =>
      getWazuhLogs({
        limit: LOGS_PAGE,
        offset: logsOffset,
        severity: severity || undefined,
        search: search || undefined,
      }),
    enabled: view === "logs",
  });

  const storageQuery = useQuery({
    queryKey: ["log-storage"],
    queryFn: getLogStorage,
    enabled: view === "logs",
    staleTime: 60_000,
  });

  const mutesQuery = useQuery({
    queryKey: ["mutes"],
    queryFn: getMutes,
    staleTime: 30_000,
  });
  const mutes = mutesQuery.data?.mutes ?? [];

  const muteMut = useMutation({
    mutationFn: ({
      ruleId,
      reason,
      duration,
    }: {
      ruleId: string;
      reason?: string;
      duration?: "24h" | "7d" | null;
    }) => muteRule(ruleId, reason, duration),
    onSuccess: () => {
      setMuteTarget(null);
      queryClient.invalidateQueries({ queryKey: ["mutes"] });
      queryClient.invalidateQueries({ queryKey: ["queue"] });
    },
  });

  const unmuteMut = useMutation({
    mutationFn: (muteId: string) => unmuteRule(muteId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["mutes"] });
    },
  });

  const isLoading =
    view === "pending"
      ? queueQuery.isLoading
      : view === "triaged"
        ? historyQuery.isLoading
        : logsQuery.isLoading;

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["queue"] });
    queryClient.invalidateQueries({ queryKey: ["history"] });
    queryClient.invalidateQueries({ queryKey: ["triage-status"] });
    queryClient.invalidateQueries({ queryKey: ["briefing"] });
  };

  const dispose = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: string }) => disposeAlert(id, verdict),
    onSuccess: invalidate,
  });

  const bulkDispose = useMutation({
    mutationFn: ({ ids, verdict }: { ids: string[]; verdict: string }) =>
      Promise.all(ids.map((id) => disposeAlert(id, verdict))),
    onSuccess: () => {
      clearSelection();
      invalidate();
    },
  });

  const rows = useMemo<Row[]>(() => {
    let base: Row[];
    if (view === "pending") {
      base = (queueQuery.data?.alerts ?? []).map((a) => ({
        id: a.id,
        severity: a.severity,
        rule_id: a.rule_id,
        rule_description: a.rule_description,
        agent_name: a.agent_name,
        created_at: a.created_at,
        llm_explanation: a.llm_explanation,
        verdict: null,
        degraded: a.degraded,
      }));
      // The queue endpoint has no server-side search, so filter locally.
      if (search.trim()) {
        const q = search.trim().toLowerCase();
        base = base.filter(
          (r) =>
            r.rule_description.toLowerCase().includes(q) ||
            r.rule_id.toLowerCase().includes(q) ||
            (r.agent_name ?? "").toLowerCase().includes(q),
        );
      }
    } else if (view === "triaged") {
      base = (historyQuery.data?.alerts ?? []).map((h) => ({
        id: h.id,
        severity: h.severity,
        rule_id: h.rule_id,
        rule_description: h.rule_description,
        agent_name: h.agent_name,
        created_at: h.created_at,
        llm_explanation: h.llm_explanation,
        verdict: h.verdict,
        degraded: false,
        muted: h.muted,
      }));
    } else {
      base = (logsQuery.data?.logs ?? []).map((l) => ({
        id: l.id,
        severity: l.severity,
        rule_id: l.rule_id,
        rule_description: l.rule_description,
        agent_name: l.agent_name,
        created_at: l.timestamp ?? "",
        llm_explanation: null,
        verdict: null,
        degraded: false,
        isLog: true,
        fullLog: l.full_log,
        srcIp: l.src_ip,
        level: l.rule_level,
      }));
    }

    const sorted = [...base];
    if (sort === "severity") {
      sorted.sort(
        (a, b) =>
          (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) ||
          +new Date(b.created_at) - +new Date(a.created_at),
      );
    } else if (sort === "newest") {
      sorted.sort((a, b) => +new Date(b.created_at) - +new Date(a.created_at));
    } else {
      sorted.sort((a, b) => +new Date(a.created_at) - +new Date(b.created_at));
    }
    return sorted;
  }, [view, queueQuery.data, historyQuery.data, logsQuery.data, search, sort]);

  // Raw Wazuh logs carry no disposition, so they are never selectable.
  const selectableIds =
    view === "logs" ? [] : rows.filter((r) => r.verdict === null).map((r) => r.id);
  const allSelected = selectableIds.length > 0 && selected.size === selectableIds.length;

  const logsTotal = logsQuery.data?.total ?? 0;
  const hasPrevPage = logsOffset > 0;
  const hasNextPage = logsOffset + LOGS_PAGE < logsTotal;

  const switchView = (v: "pending" | "triaged" | "logs") => {
    setView(v);
    clearSelection();
    setLogsOffset(0);
    if (v !== "triaged") setVerdict("");
  };

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const toggleAll = () =>
    setSelected(allSelected ? new Set() : new Set(selectableIds));

  const applyBulk = (v: string) => bulkDispose.mutate({ ids: [...selected], verdict: v });

  const selectClass =
    "px-2.5 py-1.5 rounded-lg text-xs bg-kahu-elevated border border-kahu-border text-slate-300 focus:outline-none focus:border-kahu-accent";

  return (
    <div>
      {/* View toggle + filters */}
      <div className="flex flex-wrap items-center gap-2 mb-3">
        <div className="flex rounded-lg bg-kahu-elevated border border-kahu-border overflow-hidden text-xs font-medium">
          <button
            onClick={() => switchView("pending")}
            className={`px-3 py-1.5 transition-colors ${
              view === "pending" ? "bg-kahu-accent text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Pending
          </button>
          <button
            onClick={() => switchView("triaged")}
            className={`px-3 py-1.5 transition-colors ${
              view === "triaged" ? "bg-kahu-accent text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            Triaged
          </button>
          <button
            onClick={() => switchView("logs")}
            className={`px-3 py-1.5 transition-colors ${
              view === "logs" ? "bg-kahu-accent text-white" : "text-slate-400 hover:text-white"
            }`}
          >
            All logs
          </button>
        </div>

        <select
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value);
            setLogsOffset(0);
            clearSelection();
          }}
          className={selectClass}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>

        {view === "triaged" && (
          <select
            value={verdict}
            onChange={(e) => setVerdict(e.target.value)}
            className={selectClass}
          >
            <option value="">All verdicts</option>
            <option value="pending">Pending</option>
            <option value="true_positive">Confirmed</option>
            <option value="false_positive">False positive</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="undetermined">Escalated</option>
          </select>
        )}

        <select
          value={sort}
          onChange={(e) => setSort(e.target.value as typeof sort)}
          className={selectClass}
        >
          <option value="severity">Severity</option>
          <option value="newest">Newest</option>
          <option value="oldest">Oldest</option>
        </select>

        <div className="relative flex-1 min-w-[140px]">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            value={search}
            onChange={(e) => {
              setSearch(e.target.value);
              setLogsOffset(0);
            }}
            placeholder="Search rule, agent…"
            className="w-full pl-8 pr-2.5 py-1.5 rounded-lg text-xs bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent"
          />
        </div>

        <button
          onClick={() => setGroupByDevice(!groupByDevice)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            groupByDevice
              ? "bg-kahu-accent text-white"
              : "bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white"
          }`}
        >
          <Server size={14} /> By device
        </button>

        <button
          onClick={() => setShowMutes(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white transition-colors"
        >
          <BellOff size={14} /> Muted rules ({mutes.length})
        </button>
      </div>

      {/* Storage / retention summary (All logs view only) */}
      {view === "logs" && (
        <StoragePanel data={storageQuery.data} loading={storageQuery.isLoading} />
      )}

      {/* Select-all header (pending rows only) */}
      {selectableIds.length > 0 && (
        <div className="flex items-center gap-2 mb-3 text-sm text-slate-400">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={toggleAll}
              className="h-4 w-4 rounded border-kahu-border bg-kahu-elevated accent-kahu-accent"
            />
            <span>
              {selectableIds.length} pending{view === "triaged" ? ` of ${rows.length}` : ""}
            </span>
          </label>
        </div>
      )}

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="flex items-center gap-2 mb-3 p-2 rounded-lg bg-kahu-elevated border border-kahu-border sticky top-0 z-10">
          <span className="text-xs text-slate-300 px-1">{selected.size} selected</span>
          <div className="flex-1" />
          <button
            onClick={() => applyBulk("true_positive")}
            disabled={bulkDispose.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
          >
            <XCircle size={14} /> Confirm
          </button>
          <button
            onClick={() => applyBulk("acknowledged")}
            disabled={bulkDispose.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/10 text-slate-400 hover:bg-slate-500/20 transition-colors disabled:opacity-50"
          >
            <CheckCircle size={14} /> Acknowledge
          </button>
          <button
            onClick={() => applyBulk("undetermined")}
            disabled={bulkDispose.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
          >
            <ArrowUpCircle size={14} /> Escalate
          </button>
          <button
            onClick={clearSelection}
            disabled={bulkDispose.isPending}
            className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-500 hover:text-white transition-colors disabled:opacity-50"
          >
            Clear
          </button>
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center h-64 text-slate-400">Loading alerts...</div>
      ) : rows.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
          <CheckCircle size={32} className="text-green-400" />
          <p>{view === "pending" ? "Queue clear — nothing to review." : "No matching logs."}</p>
        </div>
      ) : (
        <>
          {groupByDevice ? (
            <div className="flex flex-col gap-3">
              {groupRowsByDevice(rows).map(([device, deviceRows]) => (
                <DeviceGroup key={device} device={device} rows={deviceRows}>
                  {deviceRows.map((row) => (
                    <AlertCard
                      key={row.id}
                      row={row}
                      selectable={!row.isLog && row.verdict === null}
                      selected={selected.has(row.id)}
                      onToggleSelect={() => toggle(row.id)}
                      onDispose={(v) => dispose.mutate({ id: row.id, verdict: v })}
                      disposing={dispose.isPending}
                      onMute={(ruleId, description) => setMuteTarget({ ruleId, description })}
                    />
                  ))}
                </DeviceGroup>
              ))}
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              {rows.map((row) => (
                <AlertCard
                  key={row.id}
                  row={row}
                  selectable={!row.isLog && row.verdict === null}
                  selected={selected.has(row.id)}
                  onToggleSelect={() => toggle(row.id)}
                  onDispose={(v) => dispose.mutate({ id: row.id, verdict: v })}
                  disposing={dispose.isPending}
                  onMute={(ruleId, description) => setMuteTarget({ ruleId, description })}
                />
              ))}
            </div>
          )}

          {view === "logs" && (
            <div className="flex items-center justify-between mt-4 text-xs text-slate-400">
              <span>
                {logsTotal > 0
                  ? `${logsOffset + 1}–${logsOffset + rows.length} of ${logsTotal.toLocaleString()}`
                  : `${rows.length} logs`}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setLogsOffset((o) => Math.max(0, o - LOGS_PAGE))}
                  disabled={!hasPrevPage}
                  className="px-3 py-1.5 rounded-lg bg-kahu-elevated border border-kahu-border text-slate-300 hover:text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Previous
                </button>
                <button
                  onClick={() => setLogsOffset((o) => o + LOGS_PAGE)}
                  disabled={!hasNextPage}
                  className="px-3 py-1.5 rounded-lg bg-kahu-elevated border border-kahu-border text-slate-300 hover:text-white transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {muteTarget && (
        <MuteModal
          target={muteTarget}
          onClose={() => setMuteTarget(null)}
          onMute={(reason, duration) =>
            muteMut.mutate({ ruleId: muteTarget.ruleId, reason, duration })
          }
          pending={muteMut.isPending}
          error={muteMut.isError ? String(muteMut.error) : null}
        />
      )}

      {showMutes && (
        <MutedRulesModal
          mutes={mutes}
          onClose={() => setShowMutes(false)}
          onUnmute={(id) => unmuteMut.mutate(id)}
          pending={unmuteMut.isPending}
        />
      )}
    </div>
  );
}

/* ── Device grouping ── */

function groupRowsByDevice(rows: Row[]): [string, Row[]][] {
  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    const key = row.agent_name || "Unknown device";
    const list = groups.get(key);
    if (list) list.push(row);
    else groups.set(key, [row]);
  }
  // Order groups by their worst severity, then by size.
  return [...groups.entries()].sort(([, a], [, b]) => {
    const worst = (rs: Row[]) => Math.min(...rs.map((r) => SEV_RANK[r.severity] ?? 9));
    return worst(a) - worst(b) || b.length - a.length;
  });
}

function DeviceGroup({
  device,
  rows,
  children,
}: {
  device: string;
  rows: Row[];
  children: React.ReactNode;
}) {
  const [expanded, setExpanded] = useState(false);
  const worst = rows.reduce(
    (acc, r) => ((SEV_RANK[r.severity] ?? 9) < (SEV_RANK[acc] ?? 9) ? r.severity : acc),
    rows[0]?.severity ?? "info",
  );

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-white/[0.02] transition-colors"
      >
        <Server size={16} className="text-kahu-accent shrink-0" />
        <span className="flex-1 min-w-0 text-sm font-medium text-white truncate">{device}</span>
        <span className={`severity-chip ${severityClass(worst)}`}>{worst}</span>
        <span className="text-xs text-slate-500">
          {rows.length} alert{rows.length === 1 ? "" : "s"}
        </span>
        {expanded ? (
          <ChevronUp size={16} className="text-slate-500" />
        ) : (
          <ChevronDown size={16} className="text-slate-500" />
        )}
      </button>
      {expanded && (
        <div className="flex flex-col gap-3 px-3 pb-3 border-t border-kahu-border pt-3">
          {children}
        </div>
      )}
    </div>
  );
}

/* ── Mute modals ── */

function FeedModalShell({
  onClose,
  title,
  children,
}: {
  onClose: () => void;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-kahu-card border border-kahu-border rounded-2xl w-full max-w-lg max-h-[85vh] overflow-y-auto p-6 shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">{title}</h2>
          <button onClick={onClose} className="text-slate-500 hover:text-white transition-colors">
            <X size={18} />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function MuteModal({
  target,
  onClose,
  onMute,
  pending,
  error,
}: {
  target: { ruleId: string; description: string };
  onClose: () => void;
  onMute: (reason: string, duration: "24h" | "7d" | null) => void;
  pending: boolean;
  error: string | null;
}) {
  const [duration, setDuration] = useState<"24h" | "7d" | null>("24h");
  const [reason, setReason] = useState("");

  const durationBtn = (value: "24h" | "7d" | null, label: string) => (
    <button
      onClick={() => setDuration(value)}
      className={`flex-1 px-3 py-2 rounded-lg text-xs font-medium transition-colors ${
        duration === value
          ? "bg-kahu-accent text-white"
          : "bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <FeedModalShell onClose={onClose} title={`Mute rule ${target.ruleId}`}>
      <p className="text-sm text-slate-300 mb-1">{target.description}</p>
      <p className="text-xs text-slate-500 mb-4">
        New alerts from this rule are still recorded for audit, but skip AI triage and stay out of
        the pending queue. Alerts already in the queue remain until dispositioned. High and
        critical alerts are never muted.
      </p>

      <div className="text-xs text-slate-500 mb-1 font-medium">Duration</div>
      <div className="flex gap-2 mb-4">
        {durationBtn("24h", "24 hours")}
        {durationBtn("7d", "7 days")}
        {durationBtn(null, "Forever")}
      </div>

      <div className="text-xs text-slate-500 mb-1 font-medium">Reason (optional)</div>
      <input
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Why is this rule noise?"
        className="w-full px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent mb-4"
      />

      {error && <p className="text-xs text-red-400 mb-3">{error}</p>}

      <div className="flex justify-end gap-2">
        <button
          onClick={onClose}
          className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-white transition-colors"
        >
          Cancel
        </button>
        <button
          onClick={() => onMute(reason, duration)}
          disabled={pending}
          className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm font-medium bg-kahu-accent text-white hover:opacity-90 transition-opacity disabled:opacity-50"
        >
          <BellOff size={14} /> Mute rule
        </button>
      </div>
    </FeedModalShell>
  );
}

function muteExpiry(expiresAt: string | null): string {
  if (!expiresAt) return "forever";
  const ms = +new Date(expiresAt) - Date.now();
  if (ms <= 0) return "expired";
  const hours = ms / 3_600_000;
  if (hours < 1) return `${Math.max(1, Math.round(ms / 60_000))}m left`;
  if (hours < 48) return `${Math.round(hours)}h left`;
  return `${Math.round(hours / 24)}d left`;
}

function MutedRulesModal({
  mutes,
  onClose,
  onUnmute,
  pending,
}: {
  mutes: MutedRule[];
  onClose: () => void;
  onUnmute: (muteId: string) => void;
  pending: boolean;
}) {
  // Proactive mute-by-ID form — same endpoint and guardrails as muting from an
  // alert card (critical rules rejected server-side, duplicates 409).
  const queryClient = useQueryClient();
  const [newRuleId, setNewRuleId] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newDuration, setNewDuration] = useState<"24h" | "7d" | null>("24h");
  const addMut = useMutation({
    mutationFn: () => muteRule(newRuleId.trim(), newReason, newDuration),
    onSuccess: () => {
      setNewRuleId("");
      setNewReason("");
      queryClient.invalidateQueries({ queryKey: ["mutes"] });
    },
  });

  const durationBtn = (value: "24h" | "7d" | null, label: string) => (
    <button
      type="button"
      onClick={() => setNewDuration(value)}
      className={`px-2.5 py-1.5 rounded-lg text-[11px] font-medium transition-colors ${
        newDuration === value
          ? "bg-kahu-accent text-white"
          : "bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white"
      }`}
    >
      {label}
    </button>
  );

  return (
    <FeedModalShell onClose={onClose} title={`Muted rules (${mutes.length})`}>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (newRuleId.trim()) addMut.mutate();
        }}
        className="mb-4 p-3 rounded-lg bg-kahu-elevated/50 border border-kahu-border"
      >
        <div className="text-xs text-slate-500 mb-2 font-medium">Mute a rule by ID</div>
        <div className="flex gap-2 mb-2">
          <input
            value={newRuleId}
            onChange={(e) => setNewRuleId(e.target.value.replace(/[^0-9]/g, ""))}
            placeholder="Rule ID"
            inputMode="numeric"
            className="w-28 px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent font-mono"
          />
          <input
            value={newReason}
            onChange={(e) => setNewReason(e.target.value)}
            placeholder="Reason (optional)"
            className="flex-1 min-w-0 px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent"
          />
        </div>
        <div className="flex items-center gap-2">
          {durationBtn("24h", "24 hours")}
          {durationBtn("7d", "7 days")}
          {durationBtn(null, "Forever")}
          <button
            type="submit"
            disabled={addMut.isPending || !newRuleId.trim()}
            className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-kahu-accent text-white hover:opacity-90 transition-opacity disabled:opacity-50"
          >
            <BellOff size={12} /> Mute
          </button>
        </div>
        {addMut.isError && (
          <p className="text-xs text-red-400 mt-2 break-all">{String(addMut.error)}</p>
        )}
        <p className="text-[11px] text-slate-600 mt-2">
          Alerts from the rule are still recorded for audit but skip AI triage and the pending
          queue. Critical rules and high/critical alerts are never muted.
        </p>
      </form>

      {mutes.length === 0 ? (
        <p className="text-sm text-slate-400">No rules are muted.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {mutes.map((m) => (
            <div
              key={m.id}
              className="flex items-start gap-3 p-3 rounded-lg bg-kahu-elevated border border-kahu-border"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white">Rule {m.rule_id}</span>
                  <span className="text-[11px] text-slate-500">{muteExpiry(m.expires_at)}</span>
                </div>
                {m.rule_description && (
                  <p className="text-xs text-slate-400 mt-0.5 truncate">{m.rule_description}</p>
                )}
                {m.reason && <p className="text-xs text-slate-500 mt-0.5">“{m.reason}”</p>}
                <p className="text-[11px] text-slate-600 mt-0.5">
                  by {m.created_by} · {timeAgo(m.created_at)}
                </p>
              </div>
              <button
                onClick={() => onUnmute(m.id)}
                disabled={pending}
                className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/10 text-slate-300 hover:bg-slate-500/20 transition-colors disabled:opacity-50 shrink-0"
              >
                Unmute
              </button>
            </div>
          ))}
        </div>
      )}
    </FeedModalShell>
  );
}

/* ── Storage / retention panel ── */

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatDays(days: number): string {
  if (!days || days <= 0) return "—";
  if (days < 1) return "<1 day";
  if (days < 90) return `${Math.round(days)} days`;
  const months = days / 30.44;
  if (days < 730) return `${months.toFixed(1)} months`;
  return `${(days / 365.25).toFixed(1)} years`;
}

function StoragePanel({ data, loading }: { data?: LogStorage; loading: boolean }) {
  if (loading) {
    return (
      <div className="mb-3 p-4 rounded-xl bg-kahu-card border border-kahu-border text-xs text-slate-500">
        Loading storage telemetry…
      </div>
    );
  }
  if (!data) {
    return (
      <div className="mb-3 p-4 rounded-xl bg-kahu-card border border-kahu-border text-xs text-amber-400">
        Storage telemetry unavailable — Wazuh indexer not reachable.
      </div>
    );
  }

  const usedPct =
    data.disk_total_bytes > 0
      ? Math.min(100, (data.disk_used_bytes / data.disk_total_bytes) * 100)
      : 0;
  const barColor = usedPct >= 90 ? "bg-red-400" : usedPct >= 75 ? "bg-amber-400" : "bg-green-400";
  const hasRate = data.bytes_per_day > 0;

  return (
    <div className="mb-3 p-4 rounded-xl bg-kahu-card border border-kahu-border">
      <div className="flex items-center gap-2 mb-3">
        <HardDrive size={16} className="text-kahu-accent" />
        <h3 className="text-sm font-semibold text-white">Log retention</h3>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-3">
        <Metric
          label="Retention capacity"
          value={hasRate ? formatDays(data.total_capacity_days) : "—"}
          hint="before logs roll off"
          accent
        />
        <Metric
          label="Time to full"
          value={hasRate ? formatDays(data.days_until_full) : "—"}
          hint="free disk at current rate"
        />
        <Metric
          label="Currently stored"
          value={formatDays(data.span_days)}
          hint={`${data.logs_doc_count.toLocaleString()} events`}
        />
        <Metric
          label="Ingest rate"
          value={hasRate ? `${formatBytes(data.bytes_per_day)}/day` : "—"}
          hint={
            data.docs_per_day > 0
              ? `${Math.round(data.docs_per_day).toLocaleString()} events/day`
              : "insufficient history"
          }
        />
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-400">
        <div className="flex-1 h-1.5 rounded-full bg-kahu-elevated overflow-hidden">
          <div className={`h-full ${barColor} transition-all`} style={{ width: `${usedPct}%` }} />
        </div>
        <span className="shrink-0">
          {formatBytes(data.disk_used_bytes)} / {formatBytes(data.disk_total_bytes)} disk (
          {Math.round(usedPct)}%)
        </span>
      </div>
      <div className="mt-1 text-[11px] text-slate-600">
        Logs occupy {formatBytes(data.logs_size_bytes)}. Estimates project the current ingest rate
        against free disk; actual retention depends on index lifecycle policies.
      </div>
    </div>
  );
}

function Metric({
  label,
  value,
  hint,
  accent,
}: {
  label: string;
  value: string;
  hint?: string;
  accent?: boolean;
}) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-lg font-semibold ${accent ? "text-kahu-accent" : "text-white"}`}>
        {value}
      </div>
      {hint && <div className="text-[11px] text-slate-600">{hint}</div>}
    </div>
  );
}

function AlertCard({
  row,
  selectable,
  selected,
  onToggleSelect,
  onDispose,
  disposing,
  onMute,
}: {
  row: Row;
  selectable: boolean;
  selected: boolean;
  onToggleSelect: () => void;
  onDispose: (verdict: string) => void;
  disposing: boolean;
  onMute?: (ruleId: string, description: string) => void;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className={`bg-kahu-card border rounded-xl overflow-hidden ${
        selected ? "border-kahu-accent" : "border-kahu-border"
      }`}
    >
      <div className="flex items-start">
        {selectable && (
          <label className="flex items-center pl-4 pt-4 cursor-pointer">
            <input
              type="checkbox"
              checked={selected}
              onChange={onToggleSelect}
              className="h-4 w-4 rounded border-kahu-border bg-kahu-elevated accent-kahu-accent"
            />
          </label>
        )}
        <button
          onClick={() => setExpanded(!expanded)}
          className="flex-1 min-w-0 flex items-start gap-3 p-4 text-left hover:bg-white/[0.02] transition-colors"
        >
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className={`severity-chip ${severityClass(row.severity)}`}>{row.severity}</span>
              <span className="text-xs text-slate-500">Rule {row.rule_id}</span>
              {row.verdict && (
                <span
                  className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide ${
                    VERDICT_COLOR[row.verdict] ?? "text-slate-400 bg-slate-500/10"
                  }`}
                >
                  {VERDICT_LABEL[row.verdict] ?? row.verdict}
                </span>
              )}
              {row.muted && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wide text-slate-400 bg-slate-500/10">
                  <BellOff size={10} /> Muted
                </span>
              )}
            </div>
            <p className="text-sm text-slate-200 leading-snug">{row.rule_description}</p>
            <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500">
              {row.agent_name && <span>{row.agent_name}</span>}
              <span>{timeAgo(row.created_at)}</span>
            </div>
          </div>
          {expanded ? (
            <ChevronUp size={16} className="text-slate-500 mt-1" />
          ) : (
            <ChevronDown size={16} className="text-slate-500 mt-1" />
          )}
        </button>
      </div>

      {expanded && (
        <div className="px-4 pb-4 border-t border-kahu-border pt-3">
          {row.isLog && (
            <div className="mb-3 flex flex-col gap-2">
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
                {typeof row.level === "number" && <span>Rule level {row.level}</span>}
                {row.srcIp && <span>src: {row.srcIp}</span>}
              </div>
              {row.fullLog && (
                <div>
                  <div className="text-xs text-slate-500 mb-1 font-medium">Raw log</div>
                  <pre className="text-xs text-slate-300 bg-kahu-elevated border border-kahu-border rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-words">
                    {row.fullLog}
                  </pre>
                </div>
              )}
            </div>
          )}

          {row.llm_explanation && (
            <div className="mb-3">
              <div className="text-xs text-slate-500 mb-1 font-medium">AI Analysis</div>
              <p className="text-sm text-slate-300">{row.llm_explanation}</p>
            </div>
          )}

          {row.degraded && (
            <div className="mb-3 text-xs text-amber-400">
              LLM unavailable — deterministic triage only
            </div>
          )}

          {row.isLog ? (
            <div className="text-xs text-slate-500">
              Raw Wazuh event — indexed {row.created_at ? timeAgo(row.created_at) : "recently"}
            </div>
          ) : selectable ? (
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
              {onMute && (
                <button
                  onClick={() => onMute(row.rule_id, row.rule_description)}
                  disabled={disposing}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/10 text-slate-400 hover:bg-slate-500/20 transition-colors disabled:opacity-50"
                >
                  <BellOff size={14} /> Mute rule
                </button>
              )}
            </div>
          ) : (
            <div className="text-xs text-slate-500">
              Dispositioned {timeAgo(row.created_at)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Swipe Feed ── */

function SwipeFeed() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["swipe-feed"],
    queryFn: () => getSwipeFeed(10),
  });

  const [currentIndex, setCurrentIndex] = useState(0);
  const [exitDirection, setExitDirection] = useState<string | null>(null);
  const [swipeResult, setSwipeResult] = useState<string | null>(null);

  const swipeMut = useMutation({
    mutationFn: ({ id, direction }: { id: string; direction: string }) => swipeAlert(id, direction),
    onSuccess: (result) => {
      setSwipeResult(result.message);
      setTimeout(() => {
        setSwipeResult(null);
        setCurrentIndex((i) => i + 1);
        setExitDirection(null);
      }, 600);
      queryClient.invalidateQueries({ queryKey: ["queue"] });
      queryClient.invalidateQueries({ queryKey: ["triage-status"] });
    },
    onError: () => {
      setExitDirection(null);
    },
  });

  const handleSwipe = useCallback(
    (direction: string) => {
      const cards = data?.cards ?? [];
      const card = cards[currentIndex];
      if (!card || swipeMut.isPending) return;
      setExitDirection(direction);
      swipeMut.mutate({ id: card.id, direction });
    },
    [data, currentIndex, swipeMut],
  );

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-slate-400">Loading...</div>;
  }

  const cards = data?.cards ?? [];

  if (currentIndex >= cards.length) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
        <CheckCircle size={32} className="text-green-400" />
        <p>All caught up! No more alerts to review.</p>
        <p className="text-xs text-slate-600">{data?.remaining ?? 0} remaining in queue</p>
      </div>
    );
  }

  const card = cards[currentIndex]!;

  return (
    <div className="flex flex-col items-center">
      {/* Progress */}
      <div className="flex items-center gap-2 mb-4 text-xs text-slate-500">
        <span>
          {currentIndex + 1} / {cards.length}
        </span>
        <span>&middot;</span>
        <span>{data?.remaining ?? 0} more in queue</span>
      </div>

      {/* Swipe legend */}
      <div className="flex items-center gap-6 mb-4 text-xs">
        <span className="text-green-400 flex items-center gap-1">
          <CheckCircle size={12} /> Swipe left = Acknowledge
        </span>
        <span className="text-amber-400 flex items-center gap-1">
          <ArrowUpCircle size={12} /> Swipe up = Escalate
        </span>
        <span className="text-red-400 flex items-center gap-1">
          <XCircle size={12} /> Swipe right = Confirm TP
        </span>
      </div>

      {/* Card — keyed so each incoming card mounts fresh and animates in
          from the top instead of sliding back from the previous exit. */}
      <SwipeCardUI
        key={card.id}
        card={card}
        exitDirection={exitDirection}
        onSwipe={handleSwipe}
      />

      {/* Result toast */}
      {swipeResult && (
        <div className="mt-4 px-4 py-2 bg-kahu-elevated border border-kahu-border rounded-lg text-sm text-slate-300 animate-pulse">
          {swipeResult}
        </div>
      )}

      {/* Button fallbacks */}
      <div className="flex gap-3 mt-6">
        <button
          onClick={() => handleSwipe("left")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-green-500/10 text-green-400 hover:bg-green-500/20 transition-colors disabled:opacity-50"
        >
          <CheckCircle size={16} /> Acknowledge
        </button>
        <button
          onClick={() => handleSwipe("up")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
        >
          <ArrowUpCircle size={16} /> Escalate
        </button>
        <button
          onClick={() => handleSwipe("right")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
        >
          <XCircle size={16} /> Confirm
        </button>
      </div>
    </div>
  );
}

/* ── Swipe Card with touch/drag ── */

function SwipeCardUI({
  card,
  exitDirection,
  onSwipe,
}: {
  card: SwipeCard;
  exitDirection: string | null;
  onSwipe: (direction: string) => void;
}) {
  const cardRef = useRef<HTMLDivElement>(null);
  const dragStart = useRef<{ x: number; y: number } | null>(null);
  const [drag, setDrag] = useState({ x: 0, y: 0 });
  const THRESHOLD = 80;

  const onPointerDown = (e: React.PointerEvent) => {
    dragStart.current = { x: e.clientX, y: e.clientY };
    cardRef.current?.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    if (!dragStart.current) return;
    setDrag({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y,
    });
  };

  const onPointerUp = () => {
    if (!dragStart.current) return;
    if (Math.abs(drag.x) > THRESHOLD && Math.abs(drag.x) > Math.abs(drag.y)) {
      onSwipe(drag.x > 0 ? "right" : "left");
    } else if (drag.y < -THRESHOLD && Math.abs(drag.y) > Math.abs(drag.x)) {
      onSwipe("up");
    }
    dragStart.current = null;
    setDrag({ x: 0, y: 0 });
  };

  // Determine tint from drag direction
  let tint = "";
  if (Math.abs(drag.x) > 30 || Math.abs(drag.y) > 30) {
    if (Math.abs(drag.x) > Math.abs(drag.y)) {
      tint = drag.x > 0 ? "border-red-500/50" : "border-green-500/50";
    } else if (drag.y < -30) {
      tint = "border-amber-500/50";
    }
  }

  // Exit animation
  const exitTransform = exitDirection
    ? exitDirection === "right"
      ? "translate(120%, 0) rotate(20deg)"
      : exitDirection === "left"
        ? "translate(-120%, 0) rotate(-20deg)"
        : "translate(0, -120%)"
    : undefined;

  const style: React.CSSProperties = exitDirection
    ? { transform: exitTransform, opacity: 0, transition: "transform 0.4s ease, opacity 0.3s ease" }
    : {
        transform: `translate(${drag.x}px, ${drag.y}px) rotate(${drag.x * 0.05}deg)`,
        transition: dragStart.current ? "none" : "transform 0.3s ease",
      };

  const confidencePct = Math.round(card.ai_confidence * 100);
  const verdictColors: Record<string, string> = {
    true_positive: "text-red-400",
    acknowledged: "text-green-400",
    escalate: "text-amber-400",
  };

  return (
    <div
      ref={cardRef}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      style={style}
      className={`card-enter w-full max-w-md bg-kahu-card border-2 ${tint || "border-kahu-border"} rounded-2xl p-5
                  cursor-grab active:cursor-grabbing select-none touch-none`}
    >
      {/* Severity + agent */}
      <div className="flex items-center justify-between mb-3">
        <span className={`severity-chip ${severityClass(card.severity)}`}>{card.severity}</span>
        <span className="text-xs text-slate-500">{card.agent ?? "unknown"}</span>
      </div>

      {/* Title */}
      <h3 className="text-base font-medium text-white mb-2 leading-snug">{card.title}</h3>

      {/* AI explanation */}
      <p className="text-sm text-slate-300 mb-3 leading-relaxed">{card.explanation}</p>

      {/* AI verdict hint */}
      {card.ai_verdict && (
        <div className="flex items-center gap-2 mb-3 text-xs">
          <span className="text-slate-500">AI suggests:</span>
          <span className={`font-medium ${verdictColors[card.ai_verdict] ?? "text-slate-400"}`}>
            {card.ai_verdict.replace("_", " ")}
          </span>
          <span className="text-slate-600">({confidencePct}% confidence)</span>
        </div>
      )}

      {/* Recommended actions */}
      {card.recommended_actions.length > 0 && (
        <div className="mb-3">
          <div className="text-xs text-slate-500 mb-1">Recommended</div>
          <ul className="text-xs text-slate-400 space-y-0.5">
            {card.recommended_actions.slice(0, 3).map((action, i) => (
              <li key={i} className="flex items-start gap-1.5">
                <span className="text-slate-600 mt-0.5">-</span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Meta */}
      <div className="flex items-center gap-3 text-xs text-slate-600 pt-2 border-t border-kahu-border">
        {card.source_ip && <span>src: {card.source_ip}</span>}
        <span>{timeAgo(card.timestamp)}</span>
      </div>
    </div>
  );
}
