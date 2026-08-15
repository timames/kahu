import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getFrameworks,
  getProfiles,
  activateProfile,
  deactivateProfile,
  type Framework,
} from "@/api/client";
import { ShieldCheck, CheckCircle, Circle, X } from "lucide-react";

export function Compliance() {
  const queryClient = useQueryClient();

  const { data: frameworks, isLoading } = useQuery({
    queryKey: ["frameworks"],
    queryFn: getFrameworks,
  });
  const { data: profiles } = useQuery({
    queryKey: ["profiles"],
    queryFn: getProfiles,
  });

  const activeIds = new Set(profiles?.map((p) => p.framework_id) ?? []);
  // Reuse the org name from an existing profile so the operator only types it once.
  const knownOrg = profiles?.[0]?.organization_name ?? "";

  const [pendingFw, setPendingFw] = useState<Framework | null>(null);

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["profiles"] });
  };

  const activate = useMutation({
    mutationFn: ({ id, org, scope }: { id: string; org: string; scope: string }) =>
      activateProfile(id, org, scope),
    onSuccess: () => {
      setPendingFw(null);
      invalidate();
    },
  });
  const deactivate = useMutation({
    mutationFn: (frameworkId: string) => deactivateProfile(frameworkId),
    onSuccess: invalidate,
  });

  const busy = activate.isPending || deactivate.isPending;

  const onCardClick = (fw: Framework) => {
    if (busy) return;
    if (activeIds.has(fw.id)) deactivate.mutate(fw.id);
    else setPendingFw(fw);
  };

  if (isLoading) {
    return <div className="text-slate-400 text-center py-16">Loading frameworks...</div>;
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Compliance</h1>
      <p className="text-sm text-slate-400 mb-6">
        Select frameworks to assess. Each requires a defined assessment scope, then appears in the
        GRC tab with live control coverage mapped from your evidence.
      </p>

      <div className="grid gap-3 md:grid-cols-2">
        {(frameworks ?? []).map((fw: Framework) => {
          const active = activeIds.has(fw.id);
          return (
            <button
              key={fw.id}
              onClick={() => onCardClick(fw)}
              disabled={busy}
              className={`text-left bg-kahu-card border rounded-xl p-4 flex items-start gap-3 transition-colors disabled:opacity-60 ${
                active
                  ? "border-kahu-accent/60 hover:border-kahu-accent"
                  : "border-kahu-border hover:border-kahu-accent/30"
              }`}
            >
              <div className="w-10 h-10 rounded-lg bg-kahu-accent/10 flex items-center justify-center shrink-0">
                <ShieldCheck size={20} className="text-kahu-accent" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-semibold text-white truncate">{fw.name}</h3>
                  {active ? (
                    <CheckCircle size={14} className="text-green-400 shrink-0" />
                  ) : (
                    <Circle size={14} className="text-slate-600 shrink-0" />
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-0.5">{fw.description}</p>
                <div className="flex items-center gap-2 mt-1 text-xs text-slate-600">
                  <span>v{fw.version}</span>
                  <span>&middot;</span>
                  <span>{fw.control_count} controls</span>
                  {active && <span className="text-green-400">&middot; Assessing</span>}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {pendingFw && (
        <ScopeModal
          framework={pendingFw}
          defaultOrg={knownOrg}
          submitting={activate.isPending}
          onCancel={() => setPendingFw(null)}
          onConfirm={(org, scope) => activate.mutate({ id: pendingFw.id, org, scope })}
        />
      )}
    </div>
  );
}

function ScopeModal({
  framework,
  defaultOrg,
  submitting,
  onCancel,
  onConfirm,
}: {
  framework: Framework;
  defaultOrg: string;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: (org: string, scope: string) => void;
}) {
  const [org, setOrg] = useState(defaultOrg);
  const [scope, setScope] = useState("");

  const canSubmit = org.trim().length > 0 && scope.trim().length > 0 && !submitting;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onCancel}
    >
      <div
        className="w-full max-w-md bg-kahu-card border border-kahu-border rounded-xl p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between mb-1">
          <h2 className="text-sm font-semibold text-white">Define assessment scope</h2>
          <button onClick={onCancel} className="text-slate-500 hover:text-white transition-colors">
            <X size={16} />
          </button>
        </div>
        <p className="text-xs text-slate-500 mb-4">
          {framework.name} coverage will be assessed against this scope.
        </p>

        <label className="block text-xs text-slate-400 mb-1">Organization</label>
        <input
          value={org}
          onChange={(e) => setOrg(e.target.value)}
          placeholder="Acme Corp"
          className="w-full mb-3 px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent"
        />

        <label className="block text-xs text-slate-400 mb-1">Assessment scope</label>
        <textarea
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="e.g. Production CUI enclave — 42 endpoints, 3 servers, corporate domain"
          rows={3}
          className="w-full mb-1 px-3 py-2 rounded-lg text-sm bg-kahu-elevated border border-kahu-border text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-kahu-accent resize-none"
        />
        <p className="text-[11px] text-slate-600 mb-4">
          Describe the systems, boundary, and data this assessment covers.
        </p>

        <div className="flex justify-end gap-2">
          <button
            onClick={onCancel}
            className="px-3 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={() => onConfirm(org.trim(), scope.trim())}
            disabled={!canSubmit}
            className="px-3 py-1.5 rounded-lg text-xs font-medium bg-kahu-accent text-white hover:bg-kahu-accent/90 transition-colors disabled:opacity-50"
          >
            {submitting ? "Starting…" : "Start assessment"}
          </button>
        </div>
      </div>
    </div>
  );
}
