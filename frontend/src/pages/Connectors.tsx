import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getConnectorCatalog,
  getConnectorSources,
  getConnectorOverview,
  addConnectorSource,
  testConnectorSource,
  deleteConnectorSource,
  toggleConnectorSource,
  type ConnectorType,
  type ConnectorSource,
  type ConnectorField,
} from "@/api/client";
import {
  Cable,
  CheckCircle,
  XCircle,
  Clock,
  Trash2,
  Zap,
  Power,
  PowerOff,
  ExternalLink,
  ChevronRight,
  X,
  Loader2,
  Activity,
  AlertTriangle,
  Download,
} from "lucide-react";
import { timeAgo } from "@/lib/severity";

type ModalState =
  | { kind: "closed" }
  | { kind: "add"; connector: ConnectorType }
  | { kind: "detail"; source: ConnectorSource };

export function Connectors() {
  const qc = useQueryClient();
  const [modal, setModal] = useState<ModalState>({ kind: "closed" });
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  const { data: catalog } = useQuery({
    queryKey: ["connector-catalog"],
    queryFn: getConnectorCatalog,
  });
  const { data: sources, isLoading } = useQuery({
    queryKey: ["connector-sources"],
    queryFn: getConnectorSources,
    refetchInterval: 30_000,
  });
  const { data: overview } = useQuery({
    queryKey: ["connector-overview"],
    queryFn: getConnectorOverview,
    refetchInterval: 30_000,
  });

  const categories = catalog?.categories ?? [];
  const connectors = catalog?.connectors ?? [];
  const filtered = categoryFilter
    ? connectors.filter((c) => c.category === categoryFilter)
    : connectors;

  // Count configured sources (exclude wazuh_agent live sources)
  const configuredIds = new Set((sources ?? []).filter((s) => s.connector_type !== "wazuh_agent").map((s) => s.connector_type));

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <h1 className="text-xl font-semibold text-white">Connectors</h1>
        <span className="text-sm text-slate-400">
          {overview?.total_sources ?? 0} sources &middot;{" "}
          {overview?.active_sources ?? 0} active
        </span>
      </div>

      {/* Overview stats */}
      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
          <StatCard label="Total Sources" value={overview.total_sources} icon={<Cable size={16} />} />
          <StatCard
            label="Active"
            value={overview.active_sources}
            icon={<CheckCircle size={16} className="text-green-400" />}
          />
          <StatCard
            label="Errors"
            value={overview.error_sources}
            icon={overview.error_sources > 0
              ? <AlertTriangle size={16} className="text-red-400" />
              : <CheckCircle size={16} className="text-slate-500" />}
          />
          <StatCard
            label="Events Today"
            value={overview.events_today.toLocaleString()}
            icon={<Activity size={16} className="text-kahu-accent" />}
          />
        </div>
      )}

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

      {/* Active sources */}
      <h2 className="text-sm font-medium text-slate-400 mb-3">Active Sources</h2>
      {isLoading ? (
        <div className="text-slate-400 text-center py-8">Loading...</div>
      ) : (sources ?? []).length === 0 ? (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-6 text-center text-slate-500 mb-6">
          <Cable size={24} className="mx-auto mb-2 text-slate-600" />
          <p className="text-sm">No sources connected yet. Add one from the catalog below.</p>
        </div>
      ) : (
        <div className="grid gap-2 mb-6">
          {(sources ?? []).map((src) => (
            <SourceRow
              key={src.id}
              source={src}
              onDetail={() => setModal({ kind: "detail", source: src })}
            />
          ))}
        </div>
      )}

      {/* Catalog */}
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-medium text-slate-400">Connector Catalog</h2>
      </div>

      {/* Category filter pills */}
      <div className="flex flex-wrap gap-2 mb-4">
        <button
          onClick={() => setCategoryFilter(null)}
          className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
            categoryFilter === null
              ? "bg-kahu-accent text-white"
              : "bg-kahu-elevated text-slate-400 hover:text-white"
          }`}
        >
          All ({connectors.length})
        </button>
        {categories.map((cat) => (
          <button
            key={cat.id}
            onClick={() => setCategoryFilter(cat.id === categoryFilter ? null : cat.id)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              categoryFilter === cat.id
                ? "bg-kahu-accent text-white"
                : "bg-kahu-elevated text-slate-400 hover:text-white"
            }`}
          >
            {cat.name} ({cat.count})
          </button>
        ))}
      </div>

      {/* Catalog grid */}
      <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
        {filtered.map((ct) => {
          const configured = configuredIds.has(ct.id);
          return (
            <button
              key={ct.id}
              onClick={() => setModal({ kind: "add", connector: ct })}
              className="bg-kahu-card border border-kahu-border rounded-xl p-4 flex items-start gap-3
                         hover:border-kahu-accent/40 transition-colors text-left group"
            >
              <div className="w-10 h-10 rounded-lg bg-kahu-elevated flex items-center justify-center text-lg shrink-0">
                {ct.icon}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white truncate">{ct.name}</span>
                  {configured && (
                    <span className="text-[10px] bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded-full">
                      connected
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{ct.description}</p>
                <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-600">
                  <span>{ct.events_per_day} eps</span>
                  <span className="capitalize">{ct.auth_method.replace("_", " ")}</span>
                </div>
              </div>
              <ChevronRight
                size={14}
                className="text-slate-600 group-hover:text-kahu-accent mt-1 shrink-0 transition-colors"
              />
            </button>
          );
        })}
      </div>

      {/* Modals */}
      {modal.kind === "add" && (
        <AddSourceModal
          connector={modal.connector}
          onClose={() => setModal({ kind: "closed" })}
          onAdded={() => {
            qc.invalidateQueries({ queryKey: ["connector-sources"] });
            qc.invalidateQueries({ queryKey: ["connector-overview"] });
            setModal({ kind: "closed" });
          }}
        />
      )}
      {modal.kind === "detail" && (
        <SourceDetailModal
          source={modal.source}
          onClose={() => setModal({ kind: "closed" })}
          onChanged={() => {
            qc.invalidateQueries({ queryKey: ["connector-sources"] });
            qc.invalidateQueries({ queryKey: ["connector-overview"] });
          }}
          onDeleted={() => {
            qc.invalidateQueries({ queryKey: ["connector-sources"] });
            qc.invalidateQueries({ queryKey: ["connector-overview"] });
            setModal({ kind: "closed" });
          }}
        />
      )}
    </div>
  );
}

/* ── Stat Card ── */

function StatCard({ label, value, icon }: { label: string; value: number | string; icon: React.ReactNode }) {
  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl p-3">
      <div className="flex items-center gap-2 mb-1 text-slate-400">{icon}<span className="text-xs">{label}</span></div>
      <div className="text-lg font-semibold text-white">{value}</div>
    </div>
  );
}

/* ── Source Row ── */

function SourceRow({ source, onDetail }: { source: ConnectorSource; onDetail: () => void }) {
  return (
    <button
      onClick={onDetail}
      className="bg-kahu-card border border-kahu-border rounded-xl p-4 flex items-center gap-3
                 hover:border-kahu-accent/30 transition-colors text-left w-full"
    >
      <StatusIcon status={source.status} />
      <div className="w-8 h-8 rounded-lg bg-kahu-elevated flex items-center justify-center text-sm shrink-0">
        {source.type_icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium text-white truncate">{source.name}</div>
        <div className="text-xs text-slate-500">{source.type_name}</div>
        {source.error_message && (
          <div className="text-xs text-red-400 mt-0.5 truncate">{source.error_message}</div>
        )}
      </div>
      <div className="text-right shrink-0">
        <div className="text-sm font-medium text-white">
          {source.events_today.toLocaleString()}
          <span className="text-slate-500 font-normal"> today</span>
        </div>
        <div className="text-xs text-slate-500">
          {source.events_total.toLocaleString()} total &middot;{" "}
          {source.last_event_at ? timeAgo(source.last_event_at) : "no events"}
        </div>
      </div>
      <ChevronRight size={14} className="text-slate-600 shrink-0" />
    </button>
  );
}

/* ── Add Source Modal ── */

function AddSourceModal({
  connector,
  onClose,
  onAdded,
}: {
  connector: ConnectorType;
  onClose: () => void;
  onAdded: () => void;
}) {
  const [name, setName] = useState(connector.name);
  const [fieldValues, setFieldValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);

  const mutation = useMutation({
    mutationFn: addConnectorSource,
    onSuccess: onAdded,
    onError: (err: Error) => setError(err.message),
  });

  const setField = (fieldName: string, value: string) =>
    setFieldValues((prev) => ({ ...prev, [fieldName]: value }));

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    // Split into config vs credentials based on field type
    const config: Record<string, string> = {};
    const credentials: Record<string, string> = {};
    for (const field of connector.fields) {
      const val = fieldValues[field.name] ?? "";
      if (field.type === "password") {
        credentials[field.name] = val;
      } else {
        config[field.name] = val;
      }
    }

    mutation.mutate({
      connector_type: connector.id,
      name,
      config,
      credentials,
    });
  };

  return (
    <ModalShell onClose={onClose} title={`Add ${connector.name}`}>
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Description */}
        <p className="text-sm text-slate-400">{connector.description}</p>

        {connector.setup_guide_url && (
          <a
            href={connector.setup_guide_url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-kahu-accent hover:underline"
          >
            Setup guide <ExternalLink size={11} />
          </a>
        )}

        {/* Source name */}
        <div>
          <label className="block text-xs text-slate-400 mb-1">Source Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
            className="w-full bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2
                       text-sm text-white placeholder-slate-600 focus:outline-none focus:border-kahu-accent"
          />
        </div>

        {/* Dynamic fields */}
        {connector.fields.map((field) => (
          <FieldInput
            key={field.name}
            field={field}
            value={fieldValues[field.name] ?? ""}
            onChange={(v) => setField(field.name, v)}
          />
        ))}

        {error && <p className="text-sm text-red-400">{error}</p>}

        <div className="flex gap-2 pt-2">
          <button
            type="submit"
            disabled={mutation.isPending}
            className="flex-1 bg-kahu-accent hover:bg-kahu-accent/80 text-white rounded-lg px-4 py-2
                       text-sm font-medium disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            {mutation.isPending && <Loader2 size={14} className="animate-spin" />}
            Add Source
          </button>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-2 text-sm text-slate-400 hover:text-white transition-colors"
          >
            Cancel
          </button>
        </div>
      </form>
    </ModalShell>
  );
}

/* ── Source Detail Modal ── */

function SourceDetailModal({
  source,
  onClose,
  onChanged,
  onDeleted,
}: {
  source: ConnectorSource;
  onClose: () => void;
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const [testResult, setTestResult] = useState<{ success: boolean; message: string } | null>(null);
  const isWazuh = source.connector_type === "wazuh_agent";

  const testMut = useMutation({
    mutationFn: () => testConnectorSource(source.id),
    onSuccess: (r) => {
      setTestResult(r);
      onChanged();
    },
    onError: (err: Error) => setTestResult({ success: false, message: err.message }),
  });

  const toggleMut = useMutation({
    mutationFn: () => toggleConnectorSource(source.id),
    onSuccess: onChanged,
  });

  const deleteMut = useMutation({
    mutationFn: () => deleteConnectorSource(source.id),
    onSuccess: onDeleted,
  });

  const [confirmDelete, setConfirmDelete] = useState(false);

  return (
    <ModalShell onClose={onClose} title={source.name}>
      <div className="space-y-4">
        {/* Status header */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-kahu-elevated flex items-center justify-center text-lg">
            {source.type_icon}
          </div>
          <div>
            <div className="text-sm text-white font-medium">{source.type_name}</div>
            <div className="flex items-center gap-2 mt-0.5">
              <StatusBadge status={source.status} />
              <span className="text-xs text-slate-500 capitalize">{source.category}</span>
            </div>
          </div>
        </div>

        {source.error_message && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400">
            {source.error_message}
          </div>
        )}

        {/* Stats */}
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-kahu-elevated rounded-lg p-3 text-center">
            <div className="text-lg font-semibold text-white">{source.events_today.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500">Today</div>
          </div>
          <div className="bg-kahu-elevated rounded-lg p-3 text-center">
            <div className="text-lg font-semibold text-white">{source.events_total.toLocaleString()}</div>
            <div className="text-[11px] text-slate-500">Total</div>
          </div>
          <div className="bg-kahu-elevated rounded-lg p-3 text-center">
            <div className="text-sm font-medium text-white">
              {source.last_event_at ? timeAgo(source.last_event_at) : "never"}
            </div>
            <div className="text-[11px] text-slate-500">Last event</div>
          </div>
        </div>

        {/* Test result */}
        {testResult && (
          <div
            className={`rounded-lg p-3 text-sm ${
              testResult.success
                ? "bg-green-500/10 border border-green-500/20 text-green-400"
                : "bg-red-500/10 border border-red-500/20 text-red-400"
            }`}
          >
            {testResult.message}
          </div>
        )}

        {/* Actions */}
        {!isWazuh && (
          <div className="flex flex-wrap gap-2 pt-2">
            <button
              onClick={() => testMut.mutate()}
              disabled={testMut.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-kahu-elevated border border-kahu-border
                         rounded-lg text-sm text-white hover:border-kahu-accent/40 transition-colors disabled:opacity-50"
            >
              {testMut.isPending ? <Loader2 size={14} className="animate-spin" /> : <Zap size={14} />}
              Test
            </button>
            <button
              onClick={() => toggleMut.mutate()}
              disabled={toggleMut.isPending}
              className="flex items-center gap-1.5 px-3 py-2 bg-kahu-elevated border border-kahu-border
                         rounded-lg text-sm text-white hover:border-kahu-accent/40 transition-colors disabled:opacity-50"
            >
              {source.status === "disabled" ? <Power size={14} /> : <PowerOff size={14} />}
              {source.status === "disabled" ? "Enable" : "Disable"}
            </button>
            {!confirmDelete ? (
              <button
                onClick={() => setConfirmDelete(true)}
                className="flex items-center gap-1.5 px-3 py-2 bg-kahu-elevated border border-kahu-border
                           rounded-lg text-sm text-red-400 hover:border-red-500/40 transition-colors ml-auto"
              >
                <Trash2 size={14} />
                Delete
              </button>
            ) : (
              <div className="flex items-center gap-2 ml-auto">
                <span className="text-xs text-red-400">Confirm?</span>
                <button
                  onClick={() => deleteMut.mutate()}
                  disabled={deleteMut.isPending}
                  className="px-3 py-2 bg-red-600 hover:bg-red-700 rounded-lg text-sm text-white transition-colors disabled:opacity-50"
                >
                  {deleteMut.isPending ? <Loader2 size={14} className="animate-spin" /> : "Yes, delete"}
                </button>
                <button
                  onClick={() => setConfirmDelete(false)}
                  className="px-3 py-2 text-sm text-slate-400 hover:text-white transition-colors"
                >
                  No
                </button>
              </div>
            )}
          </div>
        )}

        {isWazuh && (
          <p className="text-xs text-slate-500 italic">
            Wazuh agents are managed through the Wazuh Manager. Use the agent deployment guide to add or remove agents.
          </p>
        )}
      </div>
    </ModalShell>
  );
}

/* ── Shared components ── */

function FieldInput({
  field,
  value,
  onChange,
}: {
  field: ConnectorField;
  value: string;
  onChange: (v: string) => void;
}) {
  const base =
    "w-full bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2 text-sm text-white placeholder-slate-600 focus:outline-none focus:border-kahu-accent";

  return (
    <div>
      <label className="block text-xs text-slate-400 mb-1">
        {field.label}
        {field.required && <span className="text-red-400 ml-0.5">*</span>}
      </label>
      {field.type === "textarea" ? (
        <textarea
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={field.required}
          placeholder={field.placeholder}
          rows={4}
          className={base + " resize-y"}
        />
      ) : field.type === "select" ? (
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={field.required}
          className={base}
        >
          <option value="">Select...</option>
          {field.placeholder.split(",").map((opt) => (
            <option key={opt} value={opt.trim()}>
              {opt.trim()}
            </option>
          ))}
        </select>
      ) : (
        <input
          type={field.type === "password" ? "password" : "text"}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={field.required}
          placeholder={field.placeholder}
          className={base}
        />
      )}
      {field.help_text && <p className="text-[11px] text-slate-600 mt-1">{field.help_text}</p>}
    </div>
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
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      {/* Panel */}
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

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "active":
      return <CheckCircle size={16} className="text-green-400 shrink-0" />;
    case "error":
      return <XCircle size={16} className="text-red-400 shrink-0" />;
    case "disabled":
      return <PowerOff size={16} className="text-slate-600 shrink-0" />;
    case "testing":
      return <Loader2 size={16} className="text-yellow-400 shrink-0 animate-spin" />;
    default:
      return <Clock size={16} className="text-slate-500 shrink-0" />;
  }
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    active: "bg-green-500/20 text-green-400",
    error: "bg-red-500/20 text-red-400",
    disabled: "bg-slate-500/20 text-slate-400",
    testing: "bg-yellow-500/20 text-yellow-400",
    pending: "bg-slate-500/20 text-slate-400",
  };
  return (
    <span className={`text-[11px] px-1.5 py-0.5 rounded-full ${colors[status] ?? colors.pending}`}>
      {status}
    </span>
  );
}
