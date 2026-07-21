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

from sqlalchemy import func, select
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

    # Query rule disposition history for statistical signal
    rule_fp_rate = await _get_rule_fp_rate(alert.rule_id, session)

    # Infer verdict from data when no explicit recommendation
    if not ai_verdict:
        ai_verdict = _infer_verdict(confidence, benign, severity, llm_severity, rule_fp_rate)

    # Check for auto-dismiss (false positive)
    if ai_verdict == "false_positive":
        # Compute dismiss confidence by combining available signals
        if llm_output.get("recommended_verdict") == "false_positive":
            dismiss_conf = confidence
        else:
            # LLM-derived FP confidence (inverted — low threat = high FP)
            llm_fp_conf = max(1 - confidence, len(benign) * 0.3)
            if rule_fp_rate is not None and rule_fp_rate >= 0.5:
                # Both history and LLM agree it's likely FP — combine signals.
                # Use "noisy-OR": P(FP) = 1 - (1-history)(1-llm)
                dismiss_conf = 1 - (1 - rule_fp_rate) * (1 - llm_fp_conf)
            else:
                dismiss_conf = llm_fp_conf
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


def _infer_verdict(
    confidence: float,
    benign: list,
    severity: str,
    llm_severity: str | None,
    rule_fp_rate: float | None = None,
) -> str | None:
    """Infer verdict from LLM data and disposition history.

    History is the strongest signal — if a rule is consistently FP, new
    instances of the same rule are almost certainly FP too.
    """
    # Disposition history — strongest signal
    if rule_fp_rate is not None and rule_fp_rate >= 0.6:
        # 60%+ FP rate: dismiss unless LLM is highly confident it's real
        if confidence < 0.85 or len(benign) >= 1:
            return "false_positive"
    if rule_fp_rate is not None and rule_fp_rate >= 0.5:
        # 50%+ FP rate with any benign explanation or moderate confidence
        if len(benign) >= 1 or confidence <= 0.7:
            return "false_positive"

    # Strong false positive signals (original logic)
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


async def _get_rule_fp_rate(rule_id: str, session: AsyncSession) -> float | None:
    """Get false-positive rate for a rule from disposition history.

    Returns None if no history exists (< 5 dispositions).
    """
    if not rule_id:
        return None

    try:
        total_stmt = (
            select(func.count())
            .select_from(Alert)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.rule_id == rule_id)
        )
        total = await session.scalar(total_stmt) or 0

        if total < 5:
            return None

        fp_stmt = (
            select(func.count())
            .select_from(Alert)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.rule_id == rule_id)
            .where(AlertDisposition.verdict == DispositionVerdict.FALSE_POSITIVE)
        )
        fp_count = await session.scalar(fp_stmt) or 0

        return round(fp_count / total, 2)
    except Exception:
        logger.warning("Failed to query rule FP rate", exc_info=True)
        return None
