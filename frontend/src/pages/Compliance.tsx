import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getFrameworks,
  getProfiles,
  activateProfile,
  deactivateProfile,
  type Framework,
} from "@/api/client";
import { ShieldCheck, CheckCircle, Circle } from "lucide-react";

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

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ["profiles"] });
  };

  const activate = useMutation({
    mutationFn: (frameworkId: string) => activateProfile(frameworkId),
    onSuccess: invalidate,
  });
  const deactivate = useMutation({
    mutationFn: (frameworkId: string) => deactivateProfile(frameworkId),
    onSuccess: invalidate,
  });

  const pending = activate.isPending || deactivate.isPending;

  const toggle = (frameworkId: string) => {
    if (pending) return;
    if (activeIds.has(frameworkId)) deactivate.mutate(frameworkId);
    else activate.mutate(frameworkId);
  };

  if (isLoading) {
    return <div className="text-slate-400 text-center py-16">Loading frameworks...</div>;
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Compliance</h1>
      <p className="text-sm text-slate-400 mb-6">
        Select frameworks to track. Each selected framework appears in the GRC tab with live control
        coverage mapped from your detection rules and evidence.
      </p>

      <div className="grid gap-3 md:grid-cols-2">
        {(frameworks ?? []).map((fw: Framework) => {
          const active = activeIds.has(fw.id);
          return (
            <button
              key={fw.id}
              onClick={() => toggle(fw.id)}
              disabled={pending}
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
                  {active && <span className="text-green-400">&middot; Selected</span>}
                </div>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
