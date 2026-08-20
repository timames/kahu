import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  getDevices,
  getDeviceSca,
  getDeviceScaChecks,
  getWazuhLogs,
  type Device,
  type ScaPolicy,
  type ScaCheck,
} from "@/api/client";
import {
  CheckCircle,
  XCircle,
  Clock,
  ChevronDown,
  ChevronRight,
  Download,
  Loader2,
  Monitor,
  Server,
  ShieldCheck,
  Activity,
} from "lucide-react";
import { timeAgo } from "@/lib/severity";

export function DevicesTab() {
  const [expanded, setExpanded] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["devices"],
    queryFn: getDevices,
    refetchInterval: 30_000,
  });

  const devices = data?.devices ?? [];

  return (
    <div>
      {/* Deploy agent */}
      <div className="bg-kahu-card border border-kahu-border rounded-xl p-4 mb-6 flex flex-col md:flex-row md:items-center gap-3">
        <div className="flex-1">
          <h2 className="text-sm font-medium text-white mb-0.5">Deploy Wazuh Agent</h2>
          <p className="text-xs text-slate-500">
            Download and run the installer on a host to enroll it with this appliance.
          </p>
        </div>
        <div className="flex gap-2">
          <a
            href="/api/agents/install.ps1"
            download
            className="flex items-center gap-1.5 px-3 py-2 bg-kahu-elevated border border-kahu-border
                       rounded-lg text-sm text-white hover:border-kahu-accent/40 transition-colors"
          >
            <Download size={14} />
            Windows
          </a>
          <a
            href="/api/agents/install.sh"
            download
            className="flex items-center gap-1.5 px-3 py-2 bg-kahu-elevated border border-kahu-border
                       rounded-lg text-sm text-white hover:border-kahu-accent/40 transition-colors"
          >
            <Download size={14} />
            Linux / macOS
          </a>
        </div>
      </div>

      <h2 className="text-sm font-medium text-slate-400 mb-3">
        Enrolled Devices {devices.length > 0 && `(${devices.length})`}
      </h2>

      {data?.error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400 mb-4">
          {data.error}
        </div>
      )}

      {isLoading ? (
        <div className="text-slate-400 text-center py-8">Loading...</div>
      ) : devices.length === 0 ? (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-6 text-center text-slate-500">
          <Monitor size={24} className="mx-auto mb-2 text-slate-600" />
          <p className="text-sm">No devices enrolled. Deploy an agent to get started.</p>
        </div>
      ) : (
        <div className="grid gap-2">
          {devices.map((d) => (
            <DeviceRow
              key={d.agent_id}
              device={d}
              expanded={expanded === d.agent_id}
              onToggle={() => setExpanded(expanded === d.agent_id ? null : d.agent_id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function DeviceRow({
  device,
  expanded,
  onToggle,
}: {
  device: Device;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl overflow-hidden">
      <button
        onClick={onToggle}
        className="p-4 flex items-center gap-3 hover:bg-kahu-elevated/40 transition-colors text-left w-full"
      >
        <DeviceStatusIcon status={device.status} />
        <div className="w-8 h-8 rounded-lg bg-kahu-elevated flex items-center justify-center shrink-0 text-slate-400">
          {device.is_manager ? <Server size={16} /> : <Monitor size={16} />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-medium text-white truncate">
            {device.name}
            {device.is_manager && (
              <span className="ml-2 text-[10px] bg-kahu-accent/20 text-kahu-accent px-1.5 py-0.5 rounded-full">
                manager
              </span>
            )}
          </div>
          <div className="text-xs text-slate-500 truncate">
            {device.os_name || device.os_platform || "unknown OS"}
            {device.ip && <> &middot; {device.ip}</>} &middot; id {device.agent_id}
          </div>
        </div>
        <div className="text-right shrink-0">
          <div className="text-sm font-medium text-white">
            {device.events_today.toLocaleString()}
            <span className="text-slate-500 font-normal"> today</span>
          </div>
          <div className="text-xs text-slate-500">
            {device.events_total.toLocaleString()} total &middot;{" "}
            {device.last_keepalive ? timeAgo(device.last_keepalive) : "never seen"}
          </div>
        </div>
        {expanded ? (
          <ChevronDown size={14} className="text-slate-600 shrink-0" />
        ) : (
          <ChevronRight size={14} className="text-slate-600 shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-kahu-border p-4 space-y-5">
          <DeviceSca agentId={device.agent_id} />
          <DeviceEvents agentName={device.name} />
        </div>
      )}
    </div>
  );
}

/* ── SCA section ── */

function DeviceSca({ agentId }: { agentId: string }) {
  const [openPolicy, setOpenPolicy] = useState<string | null>(null);

  const { data: policies, isLoading } = useQuery({
    queryKey: ["device-sca", agentId],
    queryFn: () => getDeviceSca(agentId),
  });

  return (
    <div>
      <h3 className="text-xs font-medium text-slate-400 mb-2 flex items-center gap-1.5">
        <ShieldCheck size={13} />
        Configuration Assessment (SCA)
      </h3>
      {isLoading ? (
        <div className="text-xs text-slate-500 flex items-center gap-2 py-2">
          <Loader2 size={12} className="animate-spin" /> Loading assessments...
        </div>
      ) : !policies || policies.length === 0 ? (
        <p className="text-xs text-slate-500 italic">No SCA scans for this device.</p>
      ) : (
        <div className="space-y-2">
          {policies.map((p) => (
            <ScaPolicyRow
              key={p.policy_id}
              agentId={agentId}
              policy={p}
              open={openPolicy === p.policy_id}
              onToggle={() =>
                setOpenPolicy(openPolicy === p.policy_id ? null : p.policy_id)
              }
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ScaPolicyRow({
  agentId,
  policy,
  open,
  onToggle,
}: {
  agentId: string;
  policy: ScaPolicy;
  open: boolean;
  onToggle: () => void;
}) {
  const scoreColor =
    policy.score >= 80 ? "bg-green-500" : policy.score >= 50 ? "bg-yellow-500" : "bg-red-500";

  return (
    <div className="bg-kahu-elevated rounded-lg overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full p-3 text-left hover:bg-kahu-border/30 transition-colors"
      >
        <div className="flex items-center justify-between gap-3 mb-1.5">
          <span className="text-xs font-medium text-white truncate">{policy.name}</span>
          <span className="text-xs text-slate-400 shrink-0">{policy.score}%</span>
        </div>
        <div className="h-1.5 bg-kahu-border rounded-full overflow-hidden mb-1.5">
          <div className={`h-full ${scoreColor}`} style={{ width: `${policy.score}%` }} />
        </div>
        <div className="flex items-center gap-3 text-[11px] text-slate-500">
          <span className="text-green-400">{policy.pass_count} pass</span>
          <span className="text-red-400">{policy.fail_count} fail</span>
          <span>{policy.total_checks} checks</span>
          {policy.end_scan && <span className="ml-auto">scanned {timeAgo(policy.end_scan)}</span>}
        </div>
      </button>
      {open && <ScaChecks agentId={agentId} policyId={policy.policy_id} />}
    </div>
  );
}

function ScaChecks({ agentId, policyId }: { agentId: string; policyId: string }) {
  const [filter, setFilter] = useState<"failed" | "passed" | "">("failed");
  const [openCheck, setOpenCheck] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["device-sca-checks", agentId, policyId, filter],
    queryFn: () =>
      getDeviceScaChecks(agentId, policyId, {
        result: filter || undefined,
        limit: 50,
      }),
  });

  return (
    <div className="border-t border-kahu-border p-3">
      <div className="flex gap-1.5 mb-2">
        {([
          ["failed", "Failed"],
          ["passed", "Passed"],
          ["", "All"],
        ] as const).map(([val, label]) => (
          <button
            key={val}
            onClick={() => setFilter(val)}
            className={`px-2 py-0.5 rounded-full text-[11px] font-medium transition-colors ${
              filter === val
                ? "bg-kahu-accent text-white"
                : "bg-kahu-card text-slate-400 hover:text-white"
            }`}
          >
            {label}
          </button>
        ))}
        {data && <span className="ml-auto text-[11px] text-slate-500">{data.total} checks</span>}
      </div>
      {isLoading ? (
        <div className="text-xs text-slate-500 flex items-center gap-2 py-2">
          <Loader2 size={12} className="animate-spin" /> Loading checks...
        </div>
      ) : !data || data.checks.length === 0 ? (
        <p className="text-xs text-slate-500 italic py-1">No checks match.</p>
      ) : (
        <div className="space-y-1">
          {data.checks.map((c) => (
            <ScaCheckRow
              key={c.check_id}
              check={c}
              open={openCheck === c.check_id}
              onToggle={() => setOpenCheck(openCheck === c.check_id ? null : c.check_id)}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ScaCheckRow({
  check,
  open,
  onToggle,
}: {
  check: ScaCheck;
  open: boolean;
  onToggle: () => void;
}) {
  const resultColor =
    check.result === "passed"
      ? "text-green-400"
      : check.result === "failed"
        ? "text-red-400"
        : "text-slate-400";

  return (
    <div className="bg-kahu-card rounded-lg">
      <button
        onClick={onToggle}
        className="w-full px-2.5 py-2 flex items-start gap-2 text-left hover:bg-kahu-elevated/40 rounded-lg transition-colors"
      >
        <span className={`text-[10px] font-semibold uppercase mt-0.5 shrink-0 w-12 ${resultColor}`}>
          {check.result}
        </span>
        <span className="text-xs text-slate-300 flex-1">{check.title}</span>
        {open ? (
          <ChevronDown size={12} className="text-slate-600 mt-0.5 shrink-0" />
        ) : (
          <ChevronRight size={12} className="text-slate-600 mt-0.5 shrink-0" />
        )}
      </button>
      {open && (
        <div className="px-2.5 pb-2.5 space-y-2">
          {check.description && (
            <div>
              <div className="text-[10px] uppercase text-slate-500 mb-0.5">Description</div>
              <p className="text-xs text-slate-400">{check.description}</p>
            </div>
          )}
          {check.rationale && (
            <div>
              <div className="text-[10px] uppercase text-slate-500 mb-0.5">Rationale</div>
              <p className="text-xs text-slate-400">{check.rationale}</p>
            </div>
          )}
          {check.remediation && (
            <div>
              <div className="text-[10px] uppercase text-slate-500 mb-0.5">Remediation</div>
              <p className="text-xs text-slate-400">{check.remediation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ── Per-device events ── */

const EVENTS_PAGE = 25;

function DeviceEvents({ agentName }: { agentName: string }) {
  const [limit, setLimit] = useState(EVENTS_PAGE);

  const { data, isLoading, isFetching } = useQuery({
    queryKey: ["device-events", agentName, limit],
    queryFn: () => getWazuhLogs({ agent: agentName, limit }),
    placeholderData: (prev) => prev,
  });

  return (
    <div>
      <h3 className="text-xs font-medium text-slate-400 mb-2 flex items-center gap-1.5">
        <Activity size={13} />
        Recent Events
      </h3>
      {isLoading ? (
        <div className="text-xs text-slate-500 flex items-center gap-2 py-2">
          <Loader2 size={12} className="animate-spin" /> Loading events...
        </div>
      ) : !data || data.logs.length === 0 ? (
        <p className="text-xs text-slate-500 italic">No indexed events for this device.</p>
      ) : (
        <>
          <div className="space-y-1 mb-2">
            {data.logs.map((log) => (
              <div
                key={log.id}
                className="bg-kahu-elevated rounded-lg px-2.5 py-1.5 flex items-center gap-2"
              >
                <SeverityChip severity={log.severity} />
                <span className="text-xs text-slate-300 flex-1 truncate">
                  {log.rule_description}
                </span>
                <span className="text-[11px] text-slate-500 shrink-0">
                  {log.timestamp ? timeAgo(log.timestamp) : ""}
                </span>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-3">
            {data.total > data.logs.length && (
              <button
                onClick={() => setLimit((l) => Math.min(l + EVENTS_PAGE, 200))}
                disabled={isFetching || limit >= 200}
                className="text-xs text-kahu-accent hover:underline disabled:opacity-50"
              >
                {isFetching ? "Loading..." : "Load more"}
              </button>
            )}
            <span className="text-[11px] text-slate-500">
              {data.logs.length} of {data.total.toLocaleString()}
            </span>
          </div>
        </>
      )}
    </div>
  );
}

export function SeverityChip({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600/20 text-red-400",
    high: "bg-orange-500/20 text-orange-400",
    medium: "bg-yellow-500/20 text-yellow-400",
    low: "bg-blue-500/20 text-blue-400",
    info: "bg-slate-500/20 text-slate-400",
  };
  return (
    <span
      className={`text-[10px] font-medium px-1.5 py-0.5 rounded-full shrink-0 ${
        colors[severity] ?? colors.info
      }`}
    >
      {severity}
    </span>
  );
}

function DeviceStatusIcon({ status }: { status: string }) {
  switch (status) {
    case "active":
      return <CheckCircle size={16} className="text-green-400 shrink-0" />;
    case "disconnected":
      return <XCircle size={16} className="text-red-400 shrink-0" />;
    default:
      return <Clock size={16} className="text-slate-500 shrink-0" />;
  }
}
