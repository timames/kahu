import { useState, useRef, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getQueue,
  getSwipeFeed,
  disposeAlert,
  swipeAlert,
  type Alert,
  type SwipeCard,
} from "@/api/client";
import { severityClass, timeAgo } from "@/lib/severity";
import {
  CheckCircle,
  XCircle,
  ArrowUpCircle,
  ChevronDown,
  ChevronUp,
  Layers,
  CreditCard,
} from "lucide-react";

export function Feed() {
  const [swipeMode, setSwipeMode] = useState(false);

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-xl font-semibold text-white">Feed</h1>
        <button
          onClick={() => setSwipeMode(!swipeMode)}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
            swipeMode
              ? "bg-kahu-accent text-white"
              : "bg-kahu-elevated text-slate-400 hover:text-white"
          }`}
        >
          {swipeMode ? <Layers size={14} /> : <CreditCard size={14} />}
          {swipeMode ? "List View" : "Swipe Mode"}
        </button>
      </div>

      {swipeMode ? <SwipeFeed /> : <ListFeed />}
    </div>
  );
}

/* ── List Feed (original) ── */

function ListFeed() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["queue"], queryFn: () => getQueue(50) });

  const dispose = useMutation({
    mutationFn: ({ id, verdict }: { id: string; verdict: string }) => disposeAlert(id, verdict),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["queue"] });
      queryClient.invalidateQueries({ queryKey: ["triage-status"] });
      queryClient.invalidateQueries({ queryKey: ["briefing"] });
    },
  });

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-slate-400">Loading alerts...</div>;
  }

  const alerts = data?.alerts ?? [];

  if (alerts.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
        <CheckCircle size={32} className="text-green-400" />
        <p>Queue clear — nothing to review.</p>
      </div>
    );
  }

  return (
    <div>
      <div className="text-sm text-slate-400 mb-3">{alerts.length} pending</div>
      <div className="flex flex-col gap-3">
        {alerts.map((alert) => (
          <AlertCard
            key={alert.id}
            alert={alert}
            onDispose={(verdict) => dispose.mutate({ id: alert.id, verdict })}
            disposing={dispose.isPending}
          />
        ))}
      </div>
    </div>
  );
}

function AlertCard({
  alert,
  onDispose,
  disposing,
}: {
  alert: Alert;
  onDispose: (verdict: string) => void;
  disposing: boolean;
}) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-kahu-card border border-kahu-border rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-3 p-4 text-left hover:bg-white/[0.02] transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`severity-chip ${severityClass(alert.severity)}`}>{alert.severity}</span>
            <span className="text-xs text-slate-500">Rule {alert.rule_id}</span>
          </div>
          <p className="text-sm text-slate-200 leading-snug">{alert.rule_description}</p>
          <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-500">
            {alert.agent_name && <span>{alert.agent_name}</span>}
            <span>{timeAgo(alert.created_at)}</span>
          </div>
        </div>
        {expanded ? (
          <ChevronUp size={16} className="text-slate-500 mt-1" />
        ) : (
          <ChevronDown size={16} className="text-slate-500 mt-1" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-kahu-border pt-3">
          {alert.llm_explanation && (
            <div className="mb-3">
              <div className="text-xs text-slate-500 mb-1 font-medium">AI Analysis</div>
              <p className="text-sm text-slate-300">{alert.llm_explanation}</p>
            </div>
          )}

          {alert.degraded && (
            <div className="mb-3 text-xs text-amber-400">
              LLM unavailable — deterministic triage only
            </div>
          )}

          <div className="flex gap-2 mt-3">
            <button
              onClick={() => onDispose("true_positive")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              <XCircle size={14} /> Confirm
            </button>
            <button
              onClick={() => onDispose("acknowledged")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-500/10 text-slate-400 hover:bg-slate-500/20 transition-colors disabled:opacity-50"
            >
              <CheckCircle size={14} /> Acknowledge
            </button>
            <button
              onClick={() => onDispose("undetermined")}
              disabled={disposing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
            >
              <ArrowUpCircle size={14} /> Escalate
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Swipe Feed ── */

function SwipeFeed() {
  const queryClient = useQueryClient();
  const { data, isLoading } = useQuery({
    queryKey: ["swipe-feed"],
    queryFn: () => getSwipeFeed(10),
  });

  const [currentIndex, setCurrentIndex] = useState(0);
  const [exitDirection, setExitDirection] = useState<string | null>(null);
  const [swipeResult, setSwipeResult] = useState<string | null>(null);

  const swipeMut = useMutation({
    mutationFn: ({ id, direction }: { id: string; direction: string }) => swipeAlert(id, direction),
    onSuccess: (result) => {
      setSwipeResult(result.message);
      setTimeout(() => {
        setSwipeResult(null);
        setCurrentIndex((i) => i + 1);
        setExitDirection(null);
      }, 600);
      queryClient.invalidateQueries({ queryKey: ["queue"] });
      queryClient.invalidateQueries({ queryKey: ["triage-status"] });
    },
    onError: () => {
      setExitDirection(null);
    },
  });

  const handleSwipe = useCallback(
    (direction: string) => {
      const cards = data?.cards ?? [];
      const card = cards[currentIndex];
      if (!card || swipeMut.isPending) return;
      setExitDirection(direction);
      swipeMut.mutate({ id: card.id, direction });
    },
    [data, currentIndex, swipeMut],
  );

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-slate-400">Loading...</div>;
  }

  const cards = data?.cards ?? [];

  if (currentIndex >= cards.length) {
    return (
      <div className="flex flex-col items-center justify-center h-64 text-slate-400 gap-2">
        <CheckCircle size={32} className="text-green-400" />
        <p>All caught up! No more alerts to review.</p>
        <p className="text-xs text-slate-600">{data?.remaining ?? 0} remaining in queue</p>
      </div>
    );
  }

  const card = cards[currentIndex]!;

  return (
    <div className="flex flex-col items-center">
      {/* Progress */}
      <div className="flex items-center gap-2 mb-4 text-xs text-slate-500">
        <span>
          {currentIndex + 1} / {cards.length}
        </span>
        <span>&middot;</span>
        <span>{data?.remaining ?? 0} more in queue</span>
      </div>

      {/* Swipe legend */}
      <div className="flex items-center gap-6 mb-4 text-xs">
        <span className="text-green-400 flex items-center gap-1">
          <CheckCircle size={12} /> Swipe left = Acknowledge
        </span>
        <span className="text-amber-400 flex items-center gap-1">
          <ArrowUpCircle size={12} /> Swipe up = Escalate
        </span>
        <span className="text-red-400 flex items-center gap-1">
          <XCircle size={12} /> Swipe right = Confirm TP
        </span>
      </div>

      {/* Card */}
      <SwipeCardUI
        card={card}
        exitDirection={exitDirection}
        onSwipe={handleSwipe}
      />

      {/* Result toast */}
      {swipeResult && (
        <div className="mt-4 px-4 py-2 bg-kahu-elevated border border-kahu-border rounded-lg text-sm text-slate-300 animate-pulse">
          {swipeResult}
        </div>
      )}

      {/* Button fallbacks */}
      <div className="flex gap-3 mt-6">
        <button
          onClick={() => handleSwipe("left")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-green-500/10 text-green-400 hover:bg-green-500/20 transition-colors disabled:opacity-50"
        >
          <CheckCircle size={16} /> Acknowledge
        </button>
        <button
          onClick={() => handleSwipe("up")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-amber-500/10 text-amber-400 hover:bg-amber-500/20 transition-colors disabled:opacity-50"
        >
          <ArrowUpCircle size={16} /> Escalate
        </button>
        <button
          onClick={() => handleSwipe("right")}
          disabled={swipeMut.isPending}
          className="flex items-center gap-1.5 px-5 py-2.5 rounded-xl text-sm font-medium
                     bg-red-500/10 text-red-400 hover:bg-red-500/20 transition-colors disabled:opacity-50"
        >
          <XCircle size={16} /> Confirm
        </button>
      </div>
    </div>
  );
}

/* ── Swipe Card with touch/drag ── */

function SwipeCardUI({
  card,
  exitDirection,
  onSwipe,
}: {
  card: SwipeCard;
  exitDirection: string | null;
  onSwipe: (direction: string) => void;
}) {
  const cardRef = useRef<HTMLDivElement>(null);
  const dragStart = useRef<{ x: number; y: number } | null>(null);
  const [drag, setDrag] = useState({ x: 0, y: 0 });
  const THRESHOLD = 80;

  const onPointerDown = (e: React.PointerEvent) => {
    dragStart.current = { x: e.clientX, y: e.clientY };
    cardRef.current?.setPointerCapture(e.pointerId);
  };

  const onPointerMove = (e: React.PointerEvent) => {
    if (!dragStart.current) return;
    setDrag({
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y,
    });
  };

  const onPointerUp = () => {
    if (!dragStart.current) return;
    if (Math.abs(drag.x) > THRESHOLD && Math.abs(drag.x) > Math.abs(drag.y)) {
      onSwipe(drag.x > 0 ? "right" : "left");
    } else if (drag.y < -THRESHOLD && Math.abs(drag.y) > Math.abs(drag.x)) {
      onSwipe("up");
    }
    dragStart.current = null;
    setDrag({ x: 0, y: 0 });
  };

  // Determine tint from drag direction
  let tint = "";
  if (Math.abs(drag.x) > 30 || Math.abs(drag.y) > 30) {
    if (Math.abs(drag.x) > Math.abs(drag.y)) {
      tint = drag.x > 0 ? "border-red-500/50" : "border-green-500/50";
    } else if (drag.y < -30) {
      tint = "border-amber-500/50";
    }
  }

  // Exit animation
  const exitTransform = exitDirection
    ? exitDirection === "right"
      ? "translate(120%, 0) rotate(20deg)"
      : exitDirection === "left"
        ? "translate(-120%, 0) rotate(-20deg)"
        : "translate(0, -120%)"
    : undefined;

  const style: React.CSSProperties = exitDirection
    ? { transform: exitTransform, opacity: 0, transition: "transform 0.4s ease, opacity 0.3s ease" }
    : {
        transform: `translate(${drag.x}px, ${drag.y}px) rotate(${drag.x * 0.05}deg)`,
        transition: dragStart.current ? "none" : "transform 0.3s ease",
      };

  const confidencePct = Math.round(card.ai_confidence * 100);
  const verdictColors: Record<string, string> = {
    true_positive: "text-red-400",
    acknowledged: "text-green-400",
    escalate: "text-amber-400",
  };

  return (
    <div
      ref={cardRef}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      style={style}
      className={`w-full max-w-md bg-kahu-card border-2 ${tint || "border-kahu-border"} rounded-2xl p-5
                  cursor-grab active:cursor-grabbing select-none touch-none`}
    >
      {/* Severity + agent */}
      <div className="flex items-center justify-between mb-3">
        <span className={`severity-chip ${severityClass(card.severity)}`}>{card.severity}</span>
        <span className="text-xs text-slate-500">{card.agent ?? "unknown"}</span>
      </div>

      {/* Title */}
      <h3 className="text-base font-medium text-white mb-2 leading-snug">{card.title}</h3>

      {/* AI explanation */}
      <p className="text-sm text-slate-300 mb-3 leading-relaxed">{card.explanation}</p>

      {/* AI verdict hint */}
      {card.ai_verdict && (
        <div className="flex items-center gap-2 mb-3 text-xs">
          <span className="text-slate-500">AI suggests:</span>
          <span className={`font-medium ${verdictColors[card.ai_verdict] ?? "text-slate-400"}`}>
            {card.ai_verdict.replace("_", " ")}
          </span>
          <span className="text-slate-600">({confidencePct}% confidence)</span>
        </div>
      )}

      {/* Recommended actions */}
      {card.recommended_actions.length > 0 && (
        <div className="mb-3">
          <div className="text-xs text-slate-500 mb-1">Recommended</div>
          <ul className="text-xs text-slate-400 space-y-0.5">
            {card.recommended_actions.slice(0, 3).map((action, i) => (
              <li key={i} className="flex items-start gap-1.5">
                <span className="text-slate-600 mt-0.5">-</span>
                {action}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Meta */}
      <div className="flex items-center gap-3 text-xs text-slate-600 pt-2 border-t border-kahu-border">
        {card.source_ip && <span>src: {card.source_ip}</span>}
        <span>{timeAgo(card.timestamp)}</span>
      </div>
    </div>
  );
}
