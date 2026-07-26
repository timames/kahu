import { useState, useRef, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { investigate, type InvestigationResponse } from "@/api/client";
import { Send, Bot, User, AlertTriangle } from "lucide-react";

interface Message {
  role: "analyst" | "kahu";
  content: string;
  context_used?: number;
  degraded?: boolean;
}

export function Investigate() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [sessionId, setSessionId] = useState<string>();
  const bottomRef = useRef<HTMLDivElement>(null);

  const query = useMutation({
    mutationFn: (message: string) => investigate(message, sessionId),
    onSuccess: (data: InvestigationResponse) => {
      setSessionId(data.session_id);
      setMessages((prev) => [
        ...prev,
        {
          role: "kahu",
          content: data.response,
          context_used: data.context_used,
          degraded: data.degraded,
        },
      ]);
    },
  });

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const msg = input.trim();
    if (!msg || query.isPending) return;
    setMessages((prev) => [...prev, { role: "analyst", content: msg }]);
    setInput("");
    query.mutate(msg);
  }

  return (
    <div className="flex flex-col h-full -m-4 md:-m-6">
      {/* Header */}
      <div className="px-4 md:px-6 py-3 border-b border-kahu-border">
        <h1 className="text-lg font-semibold text-white">Investigation</h1>
        <p className="text-xs text-slate-500">
          Ask about alerts, hosts, IPs, or threat patterns. Searches both triaged alerts and raw Wazuh logs.
        </p>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto px-4 md:px-6 py-4 space-y-4">
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center h-full text-slate-500 gap-3">
            <Bot size={32} />
            <p className="text-sm text-center max-w-sm">
              Try: "What happened on server-02 in the last 6 hours?" or "Show me all critical alerts this week"
            </p>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex gap-3 ${msg.role === "analyst" ? "justify-end" : ""}`}>
            {msg.role === "kahu" && (
              <div className="w-7 h-7 rounded-lg bg-kahu-accent/20 flex items-center justify-center shrink-0 mt-0.5">
                <Bot size={14} className="text-kahu-accent" />
              </div>
            )}
            <div
              className={`max-w-[80%] rounded-xl px-4 py-3 text-sm leading-relaxed ${
                msg.role === "analyst"
                  ? "bg-kahu-accent text-white"
                  : "bg-kahu-card border border-kahu-border text-slate-200"
              }`}
            >
              <p className="whitespace-pre-wrap">{msg.content}</p>
              {msg.role === "kahu" && (
                <div className="flex items-center gap-3 mt-2 text-xs text-slate-500">
                  {msg.context_used !== undefined && (
                    <span>{msg.context_used} events referenced</span>
                  )}
                  {msg.degraded && (
                    <span className="flex items-center gap-1 text-amber-400">
                      <AlertTriangle size={10} /> degraded
                    </span>
                  )}
                </div>
              )}
            </div>
            {msg.role === "analyst" && (
              <div className="w-7 h-7 rounded-lg bg-slate-700 flex items-center justify-center shrink-0 mt-0.5">
                <User size={14} className="text-slate-300" />
              </div>
            )}
          </div>
        ))}

        {query.isPending && (
          <div className="flex gap-3">
            <div className="w-7 h-7 rounded-lg bg-kahu-accent/20 flex items-center justify-center shrink-0">
              <Bot size={14} className="text-kahu-accent animate-pulse" />
            </div>
            <div className="bg-kahu-card border border-kahu-border rounded-xl px-4 py-3">
              <div className="flex gap-1">
                <span className="w-1.5 h-1.5 bg-slate-500 rounded-full animate-bounce" />
                <span className="w-1.5 h-1.5 bg-slate-500 rounded-full animate-bounce [animation-delay:0.15s]" />
                <span className="w-1.5 h-1.5 bg-slate-500 rounded-full animate-bounce [animation-delay:0.3s]" />
              </div>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="px-4 md:px-6 py-3 border-t border-kahu-border">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about your environment..."
            className="flex-1 bg-kahu-elevated border border-kahu-border rounded-xl px-4 py-2.5 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-kahu-accent transition-colors"
          />
          <button
            type="submit"
            disabled={!input.trim() || query.isPending}
            className="bg-kahu-accent text-white rounded-xl px-4 py-2.5 hover:bg-blue-600 transition-colors disabled:opacity-40 disabled:hover:bg-kahu-accent"
          >
            <Send size={16} />
          </button>
        </div>
      </form>
    </div>
  );
}
