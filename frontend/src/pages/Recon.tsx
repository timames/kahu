import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { dnsLookup, portScan, getVulnSummary } from "@/api/client";
import { Radar, Shield, Loader2 } from "lucide-react";

type ReconTab = "discovery" | "vulns";

export function Recon() {
  const [tab, setTab] = useState<ReconTab>("discovery");

  return (
    <div>
      <h1 className="text-xl font-semibold text-white mb-4">Recon</h1>

      <div className="flex gap-1 bg-kahu-card border border-kahu-border rounded-xl p-1 mb-4">
        <TabBtn active={tab === "discovery"} onClick={() => setTab("discovery")}>
          <Radar size={14} /> Discovery
        </TabBtn>
        <TabBtn active={tab === "vulns"} onClick={() => setTab("vulns")}>
          <Shield size={14} /> Vulnerabilities
        </TabBtn>
      </div>

      {tab === "discovery" ? <DiscoveryPanel /> : <VulnPanel />}
    </div>
  );
}

function DiscoveryPanel() {
  const [target, setTarget] = useState("");
  const [tool, setTool] = useState<"dns" | "port">("dns");

  const dns = useMutation({ mutationFn: (t: string) => dnsLookup(t) as Promise<Record<string, unknown>> });
  const ports = useMutation({ mutationFn: (t: string) => portScan(t) as Promise<Record<string, unknown>> });

  const isPending = dns.isPending || ports.isPending;
  const result = tool === "dns" ? dns.data : ports.data;

  function handleRun() {
    if (!target.trim()) return;
    if (tool === "dns") dns.mutate(target.trim());
    else ports.mutate(target.trim());
  }

  return (
    <div>
      <div className="flex flex-col sm:flex-row gap-2 mb-4">
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleRun()}
          placeholder="Target (hostname or IP)"
          className="flex-1 bg-kahu-elevated border border-kahu-border rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-kahu-accent"
        />
        <div className="flex gap-2">
          <select
            value={tool}
            onChange={(e) => setTool(e.target.value as "dns" | "port")}
            className="bg-kahu-elevated border border-kahu-border rounded-xl px-3 py-2.5 text-sm text-white focus:outline-none"
          >
            <option value="dns">DNS Lookup</option>
            <option value="port">Port Scan</option>
          </select>
          <button
            onClick={handleRun}
            disabled={isPending || !target.trim()}
            className="bg-kahu-accent text-white rounded-xl px-4 py-2.5 text-sm font-medium hover:bg-blue-600 transition-colors disabled:opacity-40 flex items-center gap-2"
          >
            {isPending ? <Loader2 size={14} className="animate-spin" /> : <Radar size={14} />}
            Run
          </button>
        </div>
      </div>

      {result && (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-4">
          <pre className="text-xs text-slate-300 whitespace-pre-wrap overflow-x-auto">
            {JSON.stringify(result as Record<string, unknown>, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}

function VulnPanel() {
  const { data, isLoading } = useQuery({
    queryKey: ["vuln-summary"],
    queryFn: getVulnSummary,
  });

  if (isLoading) {
    return <div className="text-slate-400 text-center py-8">Loading vulnerability data...</div>;
  }

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-4">
      {data ? (
        <pre className="text-xs text-slate-300 whitespace-pre-wrap overflow-x-auto">
          {JSON.stringify(data, null, 2)}
        </pre>
      ) : (
        <div className="text-center text-slate-500 py-8">
          <Shield size={24} className="mx-auto mb-2 text-slate-600" />
          <p className="text-sm">No vulnerability data available. Configure a Greenbone scan first.</p>
        </div>
      )}
    </div>
  );
}

function TabBtn({
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
        active ? "bg-kahu-accent text-white" : "text-slate-400 hover:text-white hover:bg-white/5"
      }`}
    >
      {children}
    </button>
  );
}
