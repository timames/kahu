import { useState } from "react";
import { NavLink } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  getProfiles,
  getCoverage,
  type Profile,
  type ControlCoverage,
} from "@/api/client";
import {
  ChevronDown,
  ChevronUp,
  ClipboardCheck,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Target,
} from "lucide-react";

function coverageColor(pct: number): string {
  if (pct >= 80) return "text-green-400";
  if (pct >= 50) return "text-amber-400";
  return "text-red-400";
}

function barColor(pct: number): string {
  if (pct >= 80) return "bg-green-400";
  if (pct >= 50) return "bg-amber-400";
  return "bg-red-400";
}

export function GRC() {
  const { data: profiles, isLoading } = useQuery({
    queryKey: ["profiles"],
    queryFn: getProfiles,
  });

  if (isLoading) {
    return <div className="text-slate-400 text-center py-16">Loading…</div>;
  }

  const active = profiles ?? [];

  if (active.length === 0) {
    return (
      <div>
        <h1 className="text-xl font-semibold text-white mb-4">GRC</h1>
        <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-3">
          <ClipboardCheck size={32} className="text-slate-600" />
          <p>No frameworks selected yet.</p>
          <NavLink
            to="/compliance"
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-kahu-accent text-white hover:bg-kahu-accent/90 transition-colors"
          >
            Select frameworks
          </NavLink>
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-1">GRC</h1>
      <p className="text-sm text-slate-400 mb-6">
        Governance, Risk &amp; Compliance — live control coverage for your selected frameworks.
      </p>

      <div className="flex flex-col gap-4">
        {active.map((profile) => (
          <FrameworkCard key={profile.framework_id} profile={profile} />
        ))}
      </div>
    </div>
  );
}

function FrameworkCard({ profile }: { profile: Profile }) {
  const [expanded, setExpanded] = useState(false);

  const { data: coverage, isLoading } = useQuery({
    queryKey: ["coverage", profile.framework_id],
    queryFn: () => getCoverage(profile.framework_id),
  });

  const pct = coverage?.coverage_pct ?? 0;
  const gapCount = coverage
    ? coverage.total_controls - coverage.covered_controls - coverage.ready_controls
    : 0;

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-4 p-4 text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="w-10 h-10 rounded-lg bg-kahu-accent/10 flex items-center justify-center shrink-0">
          <ClipboardCheck size={20} className="text-kahu-accent" />
        </div>
        <div className="flex-1 min-w-0">
          <h3 className="text-sm font-semibold text-white truncate">{profile.framework_name}</h3>
          <div className="text-xs text-slate-500 mt-0.5">{profile.organization_name}</div>
          <div className="flex items-start gap-1.5 mt-1.5 text-xs text-slate-400">
            <Target size={13} className="text-slate-500 shrink-0 mt-0.5" />
            <span className="min-w-0">
              <span className="text-slate-500">Scope: </span>
              {profile.scope}
            </span>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <div className="flex-1 h-1.5 rounded-full bg-kahu-elevated overflow-hidden max-w-xs">
              <div
                className={`h-full ${barColor(pct)} transition-all`}
                style={{ width: `${pct}%` }}
              />
            </div>
            <span className={`text-xs font-semibold ${coverageColor(pct)}`}>
              {isLoading ? "…" : `${Math.round(pct)}%`}
            </span>
          </div>
          {coverage && (
            <div className="flex flex-wrap items-center gap-x-3 gap-y-0.5 text-xs mt-1">
              <span className="text-green-400">{coverage.covered_controls} met</span>
              <span className="text-sky-400">{coverage.ready_controls} ready</span>
              <span className="text-amber-400">{gapCount} gaps</span>
              <span className="text-slate-600">of {coverage.total_controls}</span>
            </div>
          )}
        </div>
        {expanded ? (
          <ChevronUp size={16} className="text-slate-500 shrink-0" />
        ) : (
          <ChevronDown size={16} className="text-slate-500 shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-kahu-border p-4">
          {isLoading ? (
            <div className="text-sm text-slate-500">Loading coverage…</div>
          ) : (
            <div className="flex flex-col gap-4">
              {(coverage?.families ?? []).map((fam) => (
                <div key={fam.family_id}>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wide">
                      {fam.family_id} · {fam.family_name}
                    </h4>
                    <span className={`text-xs font-medium ${coverageColor(fam.coverage_pct)}`}>
                      {Math.round(fam.coverage_pct)}%
                    </span>
                  </div>
                  <div className="flex flex-col gap-1">
                    {fam.controls.map((c) => (
                      <ControlRow key={c.id} control={c} />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ControlRow({ control }: { control: ControlCoverage }) {
  return (
    <div className="flex items-start gap-2 py-1.5 px-2 rounded-lg hover:bg-white/[0.02]">
      {control.covered ? (
        <CheckCircle2 size={15} className="text-green-400 shrink-0 mt-0.5" />
      ) : control.ready ? (
        <Clock size={15} className="text-sky-400 shrink-0 mt-0.5" />
      ) : (
        <AlertTriangle size={15} className="text-amber-400 shrink-0 mt-0.5" />
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-400 shrink-0">{control.id}</span>
          <span className="text-xs text-slate-300 truncate">{control.title}</span>
        </div>
        <div className="text-[10px] text-slate-600 mt-0.5">
          {control.covered && control.coverage_source ? (
            <>
              {control.coverage_source}
              {control.evidence_count > 0 && ` · ${control.evidence_count} evidence`}
              {control.stale && <span className="text-amber-500"> · stale</span>}
            </>
          ) : control.ready ? (
            <span className="text-sky-500">Kahu-capable — no evidence collected yet</span>
          ) : (
            <span className="text-amber-500">Gap — needs a manual or policy control</span>
          )}
        </div>
      </div>
    </div>
  );
}
