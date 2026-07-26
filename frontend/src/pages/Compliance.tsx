import { useQuery } from "@tanstack/react-query";
import { getFrameworks, getProfiles, type Framework } from "@/api/client";
import { ShieldCheck, CheckCircle, Circle } from "lucide-react";

export function Compliance() {
  const { data: frameworks, isLoading } = useQuery({
    queryKey: ["frameworks"],
    queryFn: getFrameworks,
  });
  const { data: profiles } = useQuery({
    queryKey: ["profiles"],
    queryFn: getProfiles,
  });

  const activeIds = new Set(profiles?.map((p) => p.framework_id) ?? []);

  if (isLoading) {
    return <div className="text-slate-400 text-center py-16">Loading frameworks...</div>;
  }

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Compliance</h1>
      <p className="text-sm text-slate-400 mb-6">
        Activate frameworks to track coverage. Kahu maps your detection rules and evidence to controls automatically.
      </p>

      <div className="grid gap-3 md:grid-cols-2">
        {(frameworks ?? []).map((fw: Framework) => (
          <div
            key={fw.id}
            className="bg-kahu-card border border-kahu-border rounded-xl p-4 flex items-start gap-3"
          >
            <div className="w-10 h-10 rounded-lg bg-kahu-accent/10 flex items-center justify-center shrink-0">
              <ShieldCheck size={20} className="text-kahu-accent" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <h3 className="text-sm font-semibold text-white truncate">{fw.name}</h3>
                {activeIds.has(fw.id) ? (
                  <CheckCircle size={14} className="text-green-400 shrink-0" />
                ) : (
                  <Circle size={14} className="text-slate-600 shrink-0" />
                )}
              </div>
              <p className="text-xs text-slate-500 mt-0.5">{fw.description}</p>
              <span className="text-xs text-slate-600">v{fw.version}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
