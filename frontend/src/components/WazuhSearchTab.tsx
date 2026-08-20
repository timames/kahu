import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { opensearchQuery, suggestLucene, type OpenSearchResult } from "@/api/client";
import { ChevronDown, ChevronRight, Loader2, Search, Sparkles } from "lucide-react";
import { SeverityChip } from "@/components/DevicesTab";

const PAGE_SIZE = 50;

const TIME_RANGES: { value: string; label: string; from: string | null }[] = [
  { value: "15m", label: "Last 15 minutes", from: "now-15m" },
  { value: "1h", label: "Last hour", from: "now-1h" },
  { value: "24h", label: "Last 24 hours", from: "now-24h" },
  { value: "7d", label: "Last 7 days", from: "now-7d" },
  { value: "30d", label: "Last 30 days", from: "now-30d" },
  { value: "all", label: "All time", from: null },
];

function levelToSeverity(level: number): string {
  if (level >= 13) return "critical";
  if (level >= 10) return "high";
  if (level >= 7) return "medium";
  if (level >= 4) return "low";
  return "info";
}

function get(source: Record<string, unknown>, path: string): unknown {
  let cur: unknown = source;
  for (const key of path.split(".")) {
    if (cur && typeof cur === "object" && key in (cur as Record<string, unknown>)) {
      cur = (cur as Record<string, unknown>)[key];
    } else {
      return undefined;
    }
  }
  return cur;
}

export function WazuhSearchTab() {
  const [indexPattern, setIndexPattern] = useState("wazuh-alerts-*");
  const [query, setQuery] = useState("*");
  const [timeRange, setTimeRange] = useState("24h");
  const [offset, setOffset] = useState(0);
  const [result, setResult] = useState<OpenSearchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openHit, setOpenHit] = useState<string | null>(null);
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiError, setAiError] = useState<string | null>(null);

  const aiMutation = useMutation({
    mutationFn: (prompt: string) => suggestLucene(prompt),
    onSuccess: (r) => {
      setQuery(r.query);
      setAiError(null);
    },
    onError: (err: Error) => setAiError(err.message),
  });

  const mutation = useMutation({
    mutationFn: (opts: { offset: number }) => {
      const range = TIME_RANGES.find((r) => r.value === timeRange);
      return opensearchQuery({
        index_pattern: indexPattern.trim(),
        query: query.trim() || "*",
        time_from: range?.from ?? undefined,
        size: PAGE_SIZE,
        offset: opts.offset,
      });
    },
    onSuccess: (r, vars) => {
      setResult(r);
      setOffset(vars.offset);
      setError(null);
      setOpenHit(null);
    },
    onError: (err: Error) => {
      // Backend 4xx detail arrives as `${status}: ${json body}` — surface it raw.
      setError(err.message);
      setResult(null);
    },
  });

  const runSearch = (newOffset = 0) => mutation.mutate({ offset: newOffset });

  return (
    <div>
      {/* Controls */}
      <div className="bg-kahu-card border border-kahu-border rounded-xl p-4 mb-4">
        <form
          onSubmit={(e) => {
            e.preventDefault();
            runSearch(0);
          }}
          className="flex flex-col md:flex-row gap-2"
        >
          <input
            type="text"
            value={indexPattern}
            onChange={(e) => setIndexPattern(e.target.value)}
            placeholder="wazuh-alerts-*"
            className="md:w-48 bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2
                       text-sm text-white placeholder-slate-600 focus:outline-none focus:border-kahu-accent font-mono"
          />
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder='Lucene query, e.g. rule.level:>=10 AND agent.name:"dc01"'
            className="flex-1 bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2
                       text-sm text-white placeholder-slate-600 focus:outline-none focus:border-kahu-accent font-mono"
          />
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2 text-sm text-white
                       focus:outline-none focus:border-kahu-accent"
          >
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
          <button
            type="submit"
            disabled={mutation.isPending}
            className="flex items-center justify-center gap-1.5 px-4 py-2 bg-kahu-accent hover:bg-kahu-accent/80
                       text-white rounded-lg text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {mutation.isPending ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Search size={14} />
            )}
            Search
          </button>
        </form>
        {/* AI Lucene helper */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (aiPrompt.trim()) aiMutation.mutate(aiPrompt.trim());
          }}
          className="flex gap-2 mt-2"
        >
          <input
            type="text"
            value={aiPrompt}
            onChange={(e) => setAiPrompt(e.target.value)}
            placeholder='Describe what to find, e.g. "failed windows logons for administrator"'
            maxLength={500}
            className="flex-1 bg-kahu-elevated border border-kahu-border rounded-lg px-3 py-2
                       text-sm text-white placeholder-slate-600 focus:outline-none focus:border-kahu-accent"
          />
          <button
            type="submit"
            disabled={aiMutation.isPending || !aiPrompt.trim()}
            title="Generate a Lucene query with the local AI model"
            className="flex items-center justify-center gap-1.5 px-4 py-2 bg-kahu-elevated border border-kahu-border
                       hover:border-kahu-accent/40 text-white rounded-lg text-sm font-medium disabled:opacity-50 transition-colors"
          >
            {aiMutation.isPending ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <Sparkles size={14} className="text-kahu-accent" />
            )}
            Ask AI
          </button>
        </form>
        {aiError && (
          <p className="text-[11px] text-red-400 mt-1.5 break-all">{aiError}</p>
        )}
        <p className="text-[11px] text-slate-600 mt-2">
          Queries run against the local Wazuh indexer. Index pattern must start with{" "}
          <code className="text-slate-500">wazuh-</code>. Ask AI drafts a Lucene query into the
          box above — review it, then hit Search.
        </p>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 text-sm text-red-400 mb-4 break-all">
          {error}
        </div>
      )}

      {result && (
        <>
          <div className="flex items-center justify-between mb-2 text-xs text-slate-500">
            <span>
              {result.total.toLocaleString()} results &middot; {result.took_ms} ms
            </span>
            {result.total > PAGE_SIZE && (
              <span>
                {offset + 1}&ndash;{Math.min(offset + result.hits.length, result.total)}
              </span>
            )}
          </div>

          {result.hits.length === 0 ? (
            <div className="bg-kahu-card border border-kahu-border rounded-xl p-6 text-center text-slate-500 text-sm">
              No matching documents.
            </div>
          ) : (
            <div className="grid gap-1.5">
              {result.hits.map((hit) => {
                const ts = get(hit.source, "timestamp") ?? get(hit.source, "@timestamp");
                const agent = get(hit.source, "agent.name");
                const level = Number(get(hit.source, "rule.level") ?? 0);
                const desc = get(hit.source, "rule.description");
                const open = openHit === hit.id;
                return (
                  <div key={hit.id} className="bg-kahu-card border border-kahu-border rounded-lg">
                    <button
                      onClick={() => setOpenHit(open ? null : hit.id)}
                      className="w-full px-3 py-2 flex items-center gap-2 text-left hover:bg-kahu-elevated/40 rounded-lg transition-colors"
                    >
                      <span className="text-[11px] text-slate-500 shrink-0 font-mono w-36 truncate">
                        {typeof ts === "string" ? ts.replace("T", " ").slice(0, 19) : "—"}
                      </span>
                      {level > 0 && <SeverityChip severity={levelToSeverity(level)} />}
                      <span className="text-xs text-slate-400 shrink-0 w-28 truncate">
                        {typeof agent === "string" ? agent : ""}
                      </span>
                      <span className="text-xs text-slate-300 flex-1 truncate">
                        {typeof desc === "string" ? desc : hit.index}
                      </span>
                      {open ? (
                        <ChevronDown size={12} className="text-slate-600 shrink-0" />
                      ) : (
                        <ChevronRight size={12} className="text-slate-600 shrink-0" />
                      )}
                    </button>
                    {open && (
                      <pre className="text-[11px] text-slate-400 bg-kahu-elevated m-2 mt-0 p-3 rounded-lg overflow-x-auto whitespace-pre-wrap break-all">
                        {JSON.stringify(hit.source, null, 2)}
                      </pre>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Pagination */}
          {result.total > PAGE_SIZE && (
            <div className="flex items-center gap-2 mt-3">
              <button
                onClick={() => runSearch(Math.max(0, offset - PAGE_SIZE))}
                disabled={offset === 0 || mutation.isPending}
                className="px-3 py-1.5 bg-kahu-elevated border border-kahu-border rounded-lg text-xs
                           text-white disabled:opacity-40 hover:border-kahu-accent/40 transition-colors"
              >
                Previous
              </button>
              <button
                onClick={() => runSearch(offset + PAGE_SIZE)}
                disabled={
                  offset + PAGE_SIZE >= result.total ||
                  offset + PAGE_SIZE > 9000 ||
                  mutation.isPending
                }
                className="px-3 py-1.5 bg-kahu-elevated border border-kahu-border rounded-lg text-xs
                           text-white disabled:opacity-40 hover:border-kahu-accent/40 transition-colors"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}

      {!result && !error && !mutation.isPending && (
        <div className="bg-kahu-card border border-kahu-border rounded-xl p-8 text-center text-slate-500">
          <Search size={24} className="mx-auto mb-2 text-slate-600" />
          <p className="text-sm">
            Search raw events in the Wazuh indexer with Lucene syntax.
          </p>
          <p className="text-xs text-slate-600 mt-1">
            Examples: <code>rule.level:&gt;=10</code> &middot;{" "}
            <code>data.srcip:192.168.1.*</code> &middot;{" "}
            <code>rule.description:malware</code>
          </p>
        </div>
      )}
    </div>
  );
}
