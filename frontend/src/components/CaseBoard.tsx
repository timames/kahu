import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getCaseTickets,
  getTicketDetail,
  promoteTicket,
  closeCaseTicket,
  updateCaseTicket,
  generateIncidentReport,
  type CaseTicket,
  type Report,
} from "@/api/client";
import { severityClass, timeAgo } from "@/lib/severity";
import { Markdown } from "@/components/Markdown";
import {
  ArrowUpCircle,
  CheckCircle,
  FileText,
  FolderSearch,
  Siren,
  User,
  X,
} from "lucide-react";

type CaseKind = "investigation" | "incident";

const STATUS_LABEL: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  closed: "Closed",
};

const STATUS_COLOR: Record<string, string> = {
  open: "text-amber-400 bg-amber-500/10",
  in_progress: "text-blue-400 bg-blue-500/10",
  closed: "text-green-400 bg-green-500/10",
};

const CLOSE_VERDICTS: { value: string; label: string; desc: string }[] = [
  { value: "true_positive", label: "True positive", desc: "Confirmed malicious activity" },
  { value: "false_positive", label: "False positive", desc: "Detection fired incorrectly" },
  { value: "acknowledged", label: "Acknowledged", desc: "Reviewed — benign or accepted" },
];

export function CaseBoard({ kind }: { kind: CaseKind }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<"open" | "closed">("open");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const listQuery = useQuery({
    queryKey: ["cases", kind, status],
    queryFn: () => getCaseTickets({ ticket_type: kind, status, limit: 100 }),
    refetchInterval: 30_000,
  });

  const tickets = listQuery.data?.tickets ?? [];
  const isIncident = kind === "incident";

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold text-white flex items-center gap-2">
          {isIncident ? <Siren size={20} /> : <FolderSearch size={20} />}
          {isIncident ? "Incidents" : "Investigations"}
        </h1>
        <div className="flex rounded-lg bg-kahu-elevated border border-kahu-border overflow-hidden text-xs font-medium">
          {(["open", "closed"] as const).map((s) => (
            <button
              key={s}
              onClick={() => setStatus(s)}
              className={`px-3 py-1.5 transition-colors ${
                status === s ? "bg-kahu-accent text-white" : "text-slate-400 hover:text-white"
              }`}
            >
              {s === "open" ? "Open" : "Closed"}
            </button>
          ))}
        </div>
      </div>

      <p className="text-xs text-slate-500 mb-4">
        {isIncident
          ? "Confirmed true positives that need response and remediation."
          : "Escalated alerts that need deeper analysis before a verdict."}
      </p>

      {listQuery.isLoading ? (
        <div className="flex items-center justify-center h-64 text-slate-400">Loading cases...</div>
      ) : tickets.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
          <CheckCircle size={32} className="text-green-400" />
          <p>
            {status === "open"
              ? `No open ${isIncident ? "incidents" : "investigations"}.`
              : "No closed cases yet."}
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {tickets.map((t) => (
            <CaseCard key={t.id} ticket={t} onOpen={() => setSelectedId(t.id)} />
          ))}
        </div>
      )}

      {selectedId && (
        <CaseDetailModal
          ticketId={selectedId}
          kind={kind}
          onClose={() => setSelectedId(null)}
          onChanged={() => {
            queryClient.invalidateQueries({ queryKey: ["cases"] });
            queryClient.invalidateQueries({ queryKey: ["ticket-counts"] });
            queryClient.invalidateQueries({ queryKey: ["history"] });
          }}
        />
      )}
    </div>
  );
}

function CaseCard({ ticket, onOpen }: { ticket: CaseTicket; onOpen: () => void }) {
  return (
    <button
      onClick={onOpen}
      className="bg-kahu-card border border-kahu-border rounded-xl p-4 text-left hover:border-kahu-accent/30 transition-colors"
    >
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`severity-chip ${severityClass(ticket.severity)}`}>{ticket.severity}</span>
        <span className="flex-1 min-w-0 text-sm font-medium text-white truncate">
          {ticket.title}
        </span>
        <span
          className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLOR[ticket.status] ?? ""}`}
        >
          {STATUS_LABEL[ticket.status] ?? ticket.status}
        </span>
      </div>
      <div className="flex items-center gap-3 mt-2 text-xs text-slate-500 flex-wrap">
        {ticket.alert_agent_name && <span>{ticket.alert_agent_name}</span>}
        <span>{timeAgo(ticket.created_at)}</span>
        <span className="flex items-center gap-1">
          <User size={11} /> {ticket.assigned_to}
        </span>
        {ticket.promoted_by && (
          <span className="text-amber-400/80">promoted by {ticket.promoted_by}</span>
        )}
        {ticket.closed_by && <span>closed by {ticket.closed_by}</span>}
      </div>
    </button>
  );
}

function ModalShell({
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
      <div className="relative bg-kahu-card border border-kahu-border rounded-2xl w-full max-w-2xl max-h-[85vh] overflow-y-auto p-6 shadow-xl">
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

function CaseDetailModal({
  ticketId,
  kind,
  onClose,
  onChanged,
}: {
  ticketId: string;
  kind: CaseKind;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [showClose, setShowClose] = useState(false);
  const [assignee, setAssignee] = useState("");
  const [report, setReport] = useState<Report | null>(null);

  const detailQuery = useQuery({
    queryKey: ["case-detail", ticketId],
    queryFn: () => getTicketDetail(ticketId),
  });
  const t = detailQuery.data;

  const promoteMut = useMutation({
    mutationFn: () => promoteTicket(ticketId),
    onSuccess: () => {
      onChanged();
      onClose();
    },
  });

  const closeMut = useMutation({
    mutationFn: ({ verdict, notes }: { verdict: string; notes: string }) =>
      closeCaseTicket(ticketId, verdict, notes),
    onSuccess: () => {
      onChanged();
      onClose();
    },
  });

  const updateMut = useMutation({
    mutationFn: (body: { status?: string; assigned_to?: string }) =>
      updateCaseTicket(ticketId, body),
    onSuccess: () => {
      onChanged();
      detailQuery.refetch();
      setAssignee("");
    },
  });

  const reportMut = useMutation({
    mutationFn: () => generateIncidentReport([t!.alert_id], t!.title),
    onSuccess: (r) => setReport(r),
  });

  const isClosed = t?.status === "closed";
  const isInvestigation = (t?.ticket_type ?? kind) === "investigation";

  const assetContext = t?.alert_enrichment?.asset_context ?? null;
  const relatedEvents = t?.alert_enrichment?.related_events ?? [];

  return (
    <ModalShell
      onClose={onClose}
      title={isInvestigation ? "Investigation" : "Incident"}
    >
      {!t ? (
        <p className="text-sm text-slate-400">Loading...</p>
      ) : showClose ? (
        <CloseForm
          pending={closeMut.isPending}
          error={closeMut.isError ? String(closeMut.error) : null}
          onCancel={() => setShowClose(false)}
          onSubmit={(verdict, notes) => closeMut.mutate({ verdict, notes })}
        />
      ) : (
        <>
          <div className="flex items-center gap-2 mb-3 flex-wrap">
            <span className={`severity-chip ${severityClass(t.severity)}`}>{t.severity}</span>
            <span
              className={`px-2 py-0.5 rounded-full text-[10px] font-medium ${STATUS_COLOR[t.status] ?? ""}`}
            >
              {STATUS_LABEL[t.status] ?? t.status}
            </span>
          </div>
          <p className="text-sm font-medium text-white mb-3">{t.title}</p>

          <div className="text-xs text-slate-400 space-y-1 mb-4">
            {t.alert_rule_id && <div>Rule {t.alert_rule_id}</div>}
            {t.alert_agent_name && <div>Device: {t.alert_agent_name}</div>}
            {t.alert_created_at && <div>Alert raised {timeAgo(t.alert_created_at)}</div>}
            <div>
              Assigned to <span className="text-slate-300">{t.assigned_to}</span>
            </div>
            {t.promoted_by && (
              <div className="text-amber-400/80">
                Promoted to incident by {t.promoted_by}
                {t.promoted_at ? ` ${timeAgo(t.promoted_at)}` : ""}
              </div>
            )}
            {t.closed_by && (
              <div>
                Closed by {t.closed_by}
                {t.resolution_notes ? ` — ${t.resolution_notes}` : ""}
              </div>
            )}
          </div>

          {(t.alert_rule_description || t.alert_source_ip || t.alert_dest_ip || assetContext) && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">Alert details</div>
              <div className="text-xs text-slate-300 bg-kahu-elevated border border-kahu-border rounded-lg p-3 space-y-1">
                {t.alert_rule_description && <div>{t.alert_rule_description}</div>}
                {t.alert_source_ip && (
                  <div>
                    <span className="text-slate-500">Source IP:</span> {t.alert_source_ip}
                  </div>
                )}
                {t.alert_dest_ip && (
                  <div>
                    <span className="text-slate-500">Destination IP:</span> {t.alert_dest_ip}
                  </div>
                )}
                {assetContext?.hostname && (
                  <div>
                    <span className="text-slate-500">Host:</span> {assetContext.hostname}
                    {assetContext.ip ? ` (${assetContext.ip})` : ""}
                  </div>
                )}
                {assetContext?.os && (
                  <div>
                    <span className="text-slate-500">OS:</span> {assetContext.os}
                    {assetContext.os_version ? ` ${assetContext.os_version}` : ""}
                  </div>
                )}
              </div>
            </div>
          )}

          {t.alert_llm_explanation && !t.alert_degraded && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">AI analysis</div>
              <p className="text-sm text-slate-300 bg-kahu-elevated border border-kahu-border rounded-lg p-3">
                {t.alert_llm_explanation}
              </p>
            </div>
          )}

          {t.alert_recommended_actions.length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">Recommended actions</div>
              <ul className="text-sm text-slate-300 list-disc list-inside space-y-0.5">
                {t.alert_recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          )}

          {relatedEvents.length > 0 && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">
                Related events on this device ({relatedEvents.length})
              </div>
              <div className="flex flex-col gap-1 max-h-56 overflow-y-auto">
                {relatedEvents.map((e, i) => (
                  <div
                    key={i}
                    className="text-xs bg-kahu-elevated border border-kahu-border rounded-lg px-2.5 py-1.5"
                  >
                    <div className="flex items-center gap-2 text-slate-500">
                      {e.timestamp && <span>{new Date(e.timestamp).toLocaleString()}</span>}
                      {e.rule?.level != null && <span>L{e.rule.level}</span>}
                    </div>
                    <div className="text-slate-300">{e.rule?.description ?? "—"}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {t.alert_full_log && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">Raw log</div>
              <pre className="text-[11px] font-mono text-slate-300 bg-kahu-elevated border border-kahu-border rounded-lg p-3 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                {t.alert_full_log}
              </pre>
            </div>
          )}

          {report && (
            <div className="mb-4">
              <div className="text-xs text-slate-500 font-medium mb-1">Incident report</div>
              <div className="bg-kahu-elevated border border-kahu-border rounded-lg p-3">
                <Markdown>{report.narrative}</Markdown>
              </div>
            </div>
          )}

          {!isClosed && (
            <>
              <div className="flex items-center gap-2 mb-3">
                <input
                  value={assignee}
                  onChange={(e) => setAssignee(e.target.value)}
                  placeholder="Reassign to…"
                  className="flex-1 px-3 py-1.5 rounded-lg text-xs bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent"
                />
                <button
                  onClick={() => assignee.trim() && updateMut.mutate({ assigned_to: assignee.trim() })}
                  disabled={!assignee.trim() || updateMut.isPending}
                  className="px-3 py-1.5 rounded-lg text-xs font-medium bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white transition-colors disabled:opacity-40"
                >
                  Assign
                </button>
              </div>

              <div className="flex flex-wrap justify-end gap-2">
                {!isInvestigation && (
                  <>
                    <button
                      onClick={() =>
                        updateMut.mutate({
                          status: t.status === "open" ? "in_progress" : "open",
                        })
                      }
                      disabled={updateMut.isPending}
                      className="px-3 py-2 rounded-lg text-xs font-medium bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white transition-colors disabled:opacity-50"
                    >
                      {t.status === "open" ? "Start work" : "Mark open"}
                    </button>
                    <button
                      onClick={() => reportMut.mutate()}
                      disabled={reportMut.isPending}
                      className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-kahu-elevated border border-kahu-border text-slate-400 hover:text-white transition-colors disabled:opacity-50"
                    >
                      <FileText size={14} />
                      {reportMut.isPending ? "Generating…" : "Generate incident report"}
                    </button>
                  </>
                )}
                {isInvestigation && (
                  <button
                    onClick={() => {
                      if (window.confirm("Promote to incident? This confirms the alert as a true positive.")) {
                        promoteMut.mutate();
                      }
                    }}
                    disabled={promoteMut.isPending}
                    className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
                  >
                    <ArrowUpCircle size={14} /> Promote to incident
                  </button>
                )}
                <button
                  onClick={() => setShowClose(true)}
                  className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium bg-green-500/10 text-green-400 hover:bg-green-500/20 transition-colors"
                >
                  <CheckCircle size={14} /> Close
                </button>
              </div>
            </>
          )}
        </>
      )}
    </ModalShell>
  );
}

function CloseForm({
  onSubmit,
  onCancel,
  pending,
  error,
}: {
  onSubmit: (verdict: string, notes: string) => void;
  onCancel: () => void;
  pending: boolean;
  error: string | null;
}) {
  const [verdict, setVerdict] = useState("true_positive");
  const [notes, setNotes] = useState("");

  return (
    <div>
      <p className="text-xs text-slate-500 mb-3">
        Closing records your verdict on the underlying alert with full attribution in the evidence
        chain.
      </p>

      <div className="text-xs text-slate-500 mb-1 font-medium">Verdict</div>
      <div className="flex flex-col gap-2 mb-4">
        {CLOSE_VERDICTS.map((v) => (
          <label
            key={v.value}
            className={`flex items-start gap-2 p-2.5 rounded-lg border cursor-pointer transition-colors ${
              verdict === v.value
                ? "border-kahu-accent bg-kahu-accent/5"
                : "border-kahu-border bg-kahu-elevated hover:border-slate-600"
            }`}
          >
            <input
              type="radio"
              name="verdict"
              value={v.value}
              checked={verdict === v.value}
              onChange={() => setVerdict(v.value)}
              className="mt-0.5 accent-kahu-accent"
            />
            <span>
              <span className="block text-sm text-white">{v.label}</span>
              <span className="block text-xs text-slate-500">{v.desc}</span>
            </span>
          </label>
        ))}
      </div>

      <div className="text-xs text-slate-500 mb-1 font-medium">Resolution notes (required)</div>
      <textarea
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        rows={3}
        placeholder="What was found, and what was done about it?"
        className="w-full px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent mb-3"
      />

      {error && <p className="text-xs text-red-400 mb-3">{error}</p>}

      <div className="flex justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-4 py-2 rounded-lg text-sm text-slate-400 hover:text-white transition-colors"
        >
          Back
        </button>
        <button
          onClick={() => onSubmit(verdict, notes.trim())}
          disabled={!notes.trim() || pending}
          className="px-4 py-2 rounded-lg text-sm font-medium bg-kahu-accent text-white hover:bg-blue-600 transition-colors disabled:opacity-40"
        >
          {pending ? "Closing…" : "Close case"}
        </button>
      </div>
    </div>
  );
}
