import { useQuery } from "@tanstack/react-query";
import { getConnectorCatalog, getConnectorSources, type ConnectorSource } from "@/api/client";
import { Cable, CheckCircle, XCircle, Clock } from "lucide-react";
import { timeAgo } from "@/lib/severity";

export function Connectors() {
  const { data: sources, isLoading } = useQuery({
    queryKey: ["connector-sources"],
    queryFn: getConnectorSources,
  });

  const { data: catalog } = useQuery({
    queryKey: ["connector-catalog"],
    queryFn: getConnectorCatalog,
  });

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold text-white">Connectors</h1>
        <span className="text-sm text-slate-400">
          {catalog?.length ?? 0} available
        </span>
      </div>

      {/* Active sources */}
      <h2 className="text-sm font-medium text-slate-400 mb-3">Active Sources</h2>
      {isLoading ? (
        <div className="text-slate-400 text-center py-8">Loading...</div>
      ) : (sources ?? []).length === 0 ? (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-6 text-center text-slate-500 mb-6">
          <Cable size={24} className="mx-auto mb-2 text-slate-600" />
          <p className="text-sm">No sources connected yet.</p>
        </div>
      ) : (
        <div className="grid gap-3 mb-6">
          {(sources ?? []).map((src: ConnectorSource) => (
            <div
              key={src.id}
              className="bg-kahu-card border border-kahu-border rounded-xl p-4 flex items-center gap-3"
            >
              <StatusIcon status={src.status} />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white truncate">{src.name}</div>
                <div className="text-xs text-slate-500">{src.connector_type}</div>
              </div>
              <div className="text-right shrink-0">
                <div className="text-sm font-medium text-white">{src.event_count.toLocaleString()}</div>
                <div className="text-xs text-slate-500">
                  {src.last_event_at ? timeAgo(src.last_event_at) : "never"}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Catalog */}
      <h2 className="text-sm font-medium text-slate-400 mb-3">Available Connectors</h2>
      <div className="grid gap-2 md:grid-cols-2 lg:grid-cols-3">
        {(catalog ?? []).map((ct) => (
          <div
            key={ct.id}
            className="bg-kahu-card border border-kahu-border rounded-xl p-3 flex items-center gap-3 hover:border-kahu-accent/30 transition-colors cursor-pointer"
          >
            <div className="w-8 h-8 rounded-lg bg-kahu-elevated flex items-center justify-center text-xs text-slate-400 shrink-0">
              {ct.icon || ct.name.slice(0, 2).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="text-sm text-white truncate">{ct.name}</div>
              <div className="text-xs text-slate-500 capitalize">{ct.category}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "active":
      return <CheckCircle size={16} className="text-green-400 shrink-0" />;
    case "error":
      return <XCircle size={16} className="text-red-400 shrink-0" />;
    default:
      return <Clock size={16} className="text-slate-500 shrink-0" />;
  }
}
