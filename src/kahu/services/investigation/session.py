"""Investigation session — maintains conversation history for multi-turn queries."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

# In-memory session store. For v1 this is fine — sessions are ephemeral
# and tied to a single analyst's browser tab. Persistence can move to
# Redis later if needed.
_sessions: dict[str, "InvestigationSession"] = {}

SESSION_TTL = 3600  # 1 hour
MAX_HISTORY = 20  # max turns to keep


@dataclass
class Turn:
    role: str  # "analyst" or "kahu"
    content: str
    context_count: int = 0
    timestamp: float = field(default_factory=time.time)


@dataclass
class InvestigationSession:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    history: list[Turn] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_active: float = field(default_factory=time.time)

    def add_analyst_turn(self, message: str) -> None:
        self.history.append(Turn(role="analyst", content=message))
        self._trim()
        self.last_active = time.time()

    def add_kahu_turn(self, response: str, context_count: int = 0) -> None:
        self.history.append(
            Turn(role="kahu", content=response, context_count=context_count)
        )
        self._trim()
        self.last_active = time.time()

    def format_history(self) -> str:
        """Format conversation history for LLM context."""
        if not self.history:
            return ""
        lines = []
        for turn in self.history:
            prefix = "Analyst" if turn.role == "analyst" else "Kahu"
            lines.append(f"{prefix}: {turn.content}")
        return "\n".join(lines)

    def _trim(self) -> None:
        if len(self.history) > MAX_HISTORY:
            self.history = self.history[-MAX_HISTORY:]


def get_or_create_session(session_id: str | None) -> InvestigationSession:
    """Get an existing session or create a new one."""
    _evict_stale()

    if session_id and session_id in _sessions:
        session = _sessions[session_id]
        session.last_active = time.time()
        return session

    session = InvestigationSession()
    _sessions[session.id] = session
    return session


def _evict_stale() -> None:
    """Remove sessions older than TTL."""
    now = time.time()
    stale = [
        sid for sid, s in _sessions.items() if now - s.last_active > SESSION_TTL
    ]
    for sid in stale:
        del _sessions[sid]
