"""Auto-disposition — AI handles obvious alerts, humans review the rest.

Runs after Stage 4 (persist). Based on AI confidence and exposure tolerance,
auto-disposes alerts that meet thresholds. Creates tickets for auto-confirmed
true positives. Records all auto-dispositions with analyst="kahu-ai" so the
evidence trail is clear.

Tolerance thresholds:
  Conservative (1): auto-dismiss at 95%+, never auto-confirm
  Balanced (2):     auto-dismiss at 80%+, auto-confirm at 90%+
  Aggressive (3):   auto-dismiss at 60%+, auto-confirm at 75%+
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.models.tickets import Ticket, TicketStatus
from kahu.models.xp import XpEvent
from kahu.services.triage.disposition import record_disposition

logger = logging.getLogger(__name__)

AI_ANALYST = "kahu-ai"

# Thresholds: (dismiss_confidence, confirm_confidence)
# None means never auto-act
TOLERANCE_THRESHOLDS: dict[int, tuple[float, float | None]] = {
    1: (0.95, None),       # Conservative: very high bar to dismiss, never auto-confirm
    2: (0.80, 0.90),       # Balanced
    3: (0.60, 0.75),       # Aggressive
}

# Runtime tolerance — set via API, defaults to balanced
_current_tolerance: int = 2


def get_tolerance() -> int:
    return _current_tolerance


def set_tolerance(level: int) -> None:
    global _current_tolerance
    _current_tolerance = max(1, min(3, level))


@dataclass
class AutoDispositionResult:
    auto_handled: bool = False
    verdict: str | None = None
    confidence: float = 0.0
    ticket_created: bool = False


async def maybe_auto_dispose(
    alert: Alert,
    llm_output: dict | None,
    session: AsyncSession,
) -> AutoDispositionResult:
    """Check if an alert can be auto-dispositioned based on AI confidence.

    Returns whether it was handled. Alerts that aren't auto-handled stay in
    the feed for human review.
    """
    if not llm_output or llm_output.get("degraded"):
        return AutoDispositionResult()

    confidence = llm_output.get("confidence", 0.0)
    ai_verdict = llm_output.get("recommended_verdict")
    benign = llm_output.get("benign_explanations", [])
    severity = alert.severity.value if isinstance(alert.severity, Severity) else alert.severity
    llm_severity = llm_output.get("severity", "medium")

    tolerance = get_tolerance()
    dismiss_threshold, confirm_threshold = TOLERANCE_THRESHOLDS.get(tolerance, (0.80, 0.90))

    # Never auto-dispose critical alerts in conservative mode
    if tolerance == 1 and severity == "critical":
        return AutoDispositionResult()

    # Infer verdict from data when no explicit recommendation
    if not ai_verdict:
        ai_verdict = _infer_verdict(confidence, benign, severity, llm_severity)

    # Check for auto-dismiss (false positive)
    if ai_verdict == "false_positive":
        # For inferred verdicts, use (1 - confidence) as dismiss confidence
        # since low confidence = likely benign
        dismiss_conf = confidence if llm_output.get("recommended_verdict") == "false_positive" else max(1 - confidence, len(benign) * 0.3)
        if dismiss_conf >= dismiss_threshold:
            await record_disposition(
                alert_id=alert.id,
                verdict=DispositionVerdict.FALSE_POSITIVE,
                analyst=AI_ANALYST,
                notes=f"Auto-dismissed by AI (confidence: {dismiss_conf:.0%}, tolerance: {tolerance})",
                session=session,
            )
            logger.info("Auto-dismissed alert %s (confidence=%.2f)", alert.id, dismiss_conf)
            return AutoDispositionResult(
                auto_handled=True,
                verdict="false_positive",
                confidence=dismiss_conf,
            )

    # Check for auto-confirm (true positive)
    if confirm_threshold is not None and ai_verdict == "true_positive" and confidence >= confirm_threshold:
        await record_disposition(
            alert_id=alert.id,
            verdict=DispositionVerdict.TRUE_POSITIVE,
            analyst=AI_ANALYST,
            notes=f"Auto-confirmed by AI (confidence: {confidence:.0%}, tolerance: {tolerance})",
            session=session,
        )

        # Create ticket
        ticket = Ticket(
            alert_id=alert.id,
            title=alert.rule_description or f"Rule {alert.rule_id}",
            severity=severity,
            status=TicketStatus.OPEN,
            assigned_to=AI_ANALYST,
        )
        session.add(ticket)

        await session.commit()
        logger.info("Auto-confirmed alert %s → ticket created (confidence=%.2f)", alert.id, confidence)
        return AutoDispositionResult(
            auto_handled=True,
            verdict="true_positive",
            confidence=confidence,
            ticket_created=True,
        )

    return AutoDispositionResult()


def _infer_verdict(confidence: float, benign: list, severity: str, llm_severity: str | None) -> str | None:
    """Infer verdict from LLM data when no explicit recommendation exists.

    Logic:
    - Low confidence + multiple benign explanations → false positive
    - Low severity + low confidence → false positive
    - High confidence + no benign + high severity → true positive
    - Everything else → escalate (stays in human queue)
    """
    # Strong false positive signals
    if len(benign) >= 2 and confidence <= 0.5:
        return "false_positive"
    if confidence <= 0.3 and severity in ("low", "info"):
        return "false_positive"
    if llm_severity in ("low", "info") and confidence <= 0.4:
        return "false_positive"

    # Strong true positive signals
    if confidence >= 0.8 and not benign and severity in ("critical", "high"):
        return "true_positive"
    if confidence >= 0.9 and not benign:
        return "true_positive"

    # Medium confidence with info/low severity — likely noise
    if confidence <= 0.5 and severity in ("low", "info") and len(benign) >= 1:
        return "false_positive"

    return None  # Uncertain — human reviews
