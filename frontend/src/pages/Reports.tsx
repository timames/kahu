import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { getExecutiveReport, getEvidencePackage, type Report } from "@/api/client";
import { Markdown } from "@/components/Markdown";
import { FileText, Shield, AlertTriangle, Loader2 } from "lucide-react";

type ReportTab = "executive" | "evidence";

export function Reports() {
  const [tab, setTab] = useState<ReportTab>("executive");
  const [days, setDays] = useState(7);
  const [report, setReport] = useState<Report | null>(null);

  const generate = useMutation({
    mutationFn: () =>
      tab === "executive" ? getExecutiveReport(days) : getEvidencePackage(days),
    onSuccess: (data) => setReport(data),
  });

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Reports</h1>

      {/* Tab bar */}
      <div className="flex gap-1 bg-kahu-card border border-kahu-border rounded-xl p-1 mb-4">
        <TabButton active={tab === "executive"} onClick={() => { setTab("executive"); setReport(null); }}>
          <FileText size={14} /> Executive
        </TabButton>
        <TabButton active={tab === "evidence"} onClick={() => { setTab("evidence"); setReport(null); }}>
          <Shield size={14} /> Evidence
        </TabButton>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-3 mb-4">
        <label className="text-sm text-slate-400">Period:</label>
        <select
          value={days}
          onChange={(e) => setDays(Number(e.target.value))}
          className="bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-kahu-accent"
        >
          <option value={1}>Last 24 hours</option>
          <option value={7}>Last 7 days</option>
          <option value={14}>Last 14 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
        </select>
        <button
          onClick={() => generate.mutate()}
          disabled={generate.isPending}
          className="bg-kahu-accent text-white rounded-lg px-4 py-1.5 text-sm font-medium hover:bg-blue-600 transition-colors disabled:opacity-50 flex items-center gap-2"
        >
          {generate.isPending ? <Loader2 size={14} className="animate-spin" /> : null}
          Generate
        </button>
      </div>

      {generate.isError && (
        <div className="flex items-center gap-2 text-red-400 text-xs mb-4 bg-red-400/10 px-3 py-2 rounded-lg">
          <AlertTriangle size={12} />
          Report generation failed — {generate.error instanceof Error ? generate.error.message : "unknown error"}
        </div>
      )}

      {/* Report output */}
      {report && (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-5">
          {report.degraded && (
            <div className="flex items-center gap-2 text-amber-400 text-xs mb-3 bg-amber-400/10 px-3 py-1.5 rounded-lg">
              <AlertTriangle size={12} />
              AI model offline — showing deterministic summary
            </div>
          )}

          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-white capitalize">
              {report.report_type.replace("_", " ")} Report
            </h2>
            <span className="text-xs text-slate-500">
              {new Date(report.generated_at).toLocaleString()}
            </span>
          </div>

          {report.period && (
            <div className="text-xs text-slate-500 mb-3">
              {new Date(report.period.since).toLocaleDateString()} — {new Date(report.period.until).toLocaleDateString()}
            </div>
          )}

          <Markdown>{report.narrative}</Markdown>

          {/* Data summary for executive reports */}
          {report.report_type === "executive" && report.data && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4 pt-4 border-t border-kahu-border">
              <MiniStat label="Total Alerts" value={report.data.total_alerts as number} />
              <MiniStat label="Disposition Rate" value={`${report.data.disposition_rate}%`} />
              <MiniStat label="Pending" value={report.data.pending as number} />
              <MiniStat label="Disposed" value={report.data.disposed as number} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function TabButton({
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
      className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors flex-1 justify-center ${
        active
          ? "bg-kahu-accent text-white"
          : "text-slate-400 hover:text-white hover:bg-white/5"
      }`}
    >
      {children}
    </button>
  );
}

function MiniStat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="text-center">
      <div className="text-lg font-semibold text-white">{value}</div>
      <div className="text-xs text-slate-500">{label}</div>
    </div>
  );
}
