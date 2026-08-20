"""Auto-disposition — AI handles obvious alerts, humans review the rest.

Runs after Stage 4 (persist). Based on AI confidence and exposure tolerance,
auto-disposes alerts that meet thresholds. Creates tickets for auto-confirmed
true positives. Records all auto-dispositions with analyst="kahu-ai" so the
evidence trail is clear.

Tolerance thresholds:
  Conservative (1): auto-acknowledge at 95%+, never auto-confirm
  Balanced (2):     auto-acknowledge at 80%+, auto-confirm at 90%+
  Aggressive (3):   auto-acknowledge at 60%+, auto-confirm at 75%+
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from kahu.models.alerts import Alert, AlertDisposition, DispositionVerdict, Severity
from kahu.services.compliance.evidence import record_evidence
from kahu.services.triage.disposition import AI_ANALYST, record_disposition
from kahu.services.triage.llm_triage import canonical_verdict

logger = logging.getLogger(__name__)

# Thresholds: (dismiss_confidence, confirm_confidence)
# None means never auto-act
TOLERANCE_THRESHOLDS: dict[int, tuple[float, float | None]] = {
    1: (0.95, None),  # Conservative: very high bar to dismiss, never auto-confirm
    2: (0.80, 0.90),  # Balanced
    3: (0.60, 0.75),  # Aggressive
}

TOLERANCE_LABELS: dict[int, str] = {1: "Conservative", 2: "Balanced", 3: "Aggressive"}

# A tolerance change moves the global auto-dismiss posture for the whole
# appliance, so it is change-management evidence, not just a setting.
TOLERANCE_CHANGE_CONTROLS = [
    "800-171:3.4.1",  # Baseline configuration
    "800-171:3.4.2",  # Change control for configuration settings
    "800-171:3.3.1",  # Create and retain audit records
    "CIS:4.2",  # Establish and maintain a secure configuration process
    "SOC2:CC8.1",  # Change management
]

# --- Deterministic floor on auto-dismissal ---------------------------------
# The model advises; the ruleset governs. pipeline._bound_severity enforces
# that for the *displayed* severity, but auto-acknowledgement is a separate
# action that silently closes an alert, and it did not re-apply the floor. The
# model reads attacker-controllable log content (inside <ALERT_DATA>), so it
# must never be able to drive a high/critical DETERMINISTIC finding — or any
# CRITICAL_RULE_IDS hit — to auto-dismissed. Going quiet on those is a human's
# call. Auto-confirm/escalate is deliberately unaffected: erring toward
# visibility is safe; erring toward silence is the failure this pipeline
# exists to prevent. This mirrors the filter stage's "never suppress" guarantee
# and the nociceptive-receptor rule in the design docs: the dangerous class is
# exempt from every suppression path, regardless of tolerance or history.
NON_DISMISSIBLE_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})


def auto_dismiss_forbidden(
    deterministic_severity: str | None,
    critical_rule: bool = False,
) -> bool:
    """Return True if the deterministic floor forbids auto-acknowledging.

    ``deterministic_severity`` is the severity assigned by the filter stage
    (``filters.FilterResult.severity``), NOT the model-bounded severity — the
    whole point is to bypass any one-band laundering the model may have done.
    ``critical_rule`` is ``filters.FilterResult.critical_rule`` (a
    ``CRITICAL_RULE_IDS`` match), which is forbidden even if its mapped severity
    is somehow lower.
    """
    if critical_rule:
        return True
    return (deterministic_severity or "").strip().lower() in NON_DISMISSIBLE_SEVERITIES


# Runtime tolerance — set via API, defaults to balanced
_current_tolerance: int = 2


def get_tolerance() -> int:
    return _current_tolerance


def set_tolerance(level: int) -> None:
    global _current_tolerance
    _current_tolerance = max(1, min(3, level))


async def set_tolerance_audited(
    level: int,
    session: AsyncSession,
    actor: str,
) -> int:
    """Set the global auto-dispose tolerance and record the change as evidence.

    The tolerance is a global suppression-posture dial: aggressive mode lowers
    the auto-dismiss bar for the whole appliance. A change to it is a security-
    relevant configuration event, so it is appended to the hash-chained evidence
    store (change-management control) with the actor who made it, making the
    change attributable and tamper-evident. Returns the effective (clamped)
    level. The caller owns the request; this commits the evidence record.
    """
    old_level = get_tolerance()
    set_tolerance(level)
    new_level = get_tolerance()

    dismiss, confirm = TOLERANCE_THRESHOLDS.get(new_level, (None, None))
    await record_evidence(
        session,
        event_type="auto_disposition_tolerance_changed",
        control_tags=TOLERANCE_CHANGE_CONTROLS,
        payload={
            "old_level": old_level,
            "new_level": new_level,
            "old_label": TOLERANCE_LABELS.get(old_level),
            "new_label": TOLERANCE_LABELS.get(new_level),
            "changed": old_level != new_level,
            "auto_dismiss_threshold": dismiss,
            "auto_confirm_threshold": confirm,
        },
        actor=actor,
    )
    await session.commit()
    logger.info(
        "Auto-dispose tolerance set to %s (%s) by %s [was %s]",
        new_level,
        TOLERANCE_LABELS.get(new_level),
        actor,
        old_level,
    )
    return new_level


@dataclass
class AutoDispositionResult:
    auto_handled: bool = False
    verdict: str | None = None
    confidence: float = 0.0
    ticket_created: bool = False
    # True when a would-be auto-dismiss was refused by the deterministic floor
    # (high/critical deterministic severity or a critical-rule hit). Surfaced so
    # the pipeline can stamp provenance and the refusal is auditable.
    floor_blocked_dismiss: bool = False


async def maybe_auto_dispose(
    alert: Alert,
    llm_output: dict | None,
    session: AsyncSession,
    *,
    deterministic_severity: str | None = None,
    critical_rule: bool = False,
) -> AutoDispositionResult:
    """Check if an alert can be auto-dispositioned based on AI confidence.

    Returns whether it was handled. Alerts that aren't auto-handled stay in
    the feed for human review.

    ``deterministic_severity`` and ``critical_rule`` come from the filter stage
    (``FilterResult.severity`` / ``FilterResult.critical_rule``) and enforce the
    deterministic floor on auto-dismissal — see ``auto_dismiss_forbidden``. They
    are keyword-only with safe defaults so callers that cannot supply them keep
    working; the production pipeline always supplies them.
    """
    if not llm_output or llm_output.get("degraded"):
        return AutoDispositionResult()

    # The ruleset governs. A high/critical deterministic finding (or a
    # critical-rule hit) can never be auto-acknowledged, regardless of tolerance,
    # model confidence, or rule-FP history. It goes to a human.
    dismiss_blocked = auto_dismiss_forbidden(deterministic_severity, critical_rule)

    confidence = llm_output.get("confidence", 0.0)
    # Canonical spelling ("acknowledged"), folding the legacy "acknowledge" and
    # "false_positive" variants that older stored payloads still carry. This is
    # normalised at the parse boundary too; doing it again here means a caller
    # that hand-builds llm_output cannot silently disable the comparisons below.
    explicit_verdict = canonical_verdict(llm_output.get("recommended_verdict"))
    ai_verdict = explicit_verdict
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

    # Check for auto-acknowledge (false positive)
    if ai_verdict == "acknowledged":
        if dismiss_blocked:
            # A would-be dismissal on a high/critical deterministic finding.
            # Refuse it and route to a human — this is the injection / numb-key
            # failure mode the floor exists to stop.
            logger.info(
                "Auto-dismiss refused by deterministic floor for alert %s "
                "(deterministic_severity=%s critical_rule=%s)",
                alert.id,
                deterministic_severity,
                critical_rule,
            )
            return AutoDispositionResult(floor_blocked_dismiss=True)
        # Compute dismiss confidence by combining available signals
        if explicit_verdict == "acknowledged":
            # The model recommended dismissal outright, so its stated confidence
            # IS its confidence in dismissing. Still bounded by the floor above.
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
                verdict=DispositionVerdict.ACKNOWLEDGED,
                analyst=AI_ANALYST,
                notes=(
                    f"Auto-acknowledged by AI"
                    f" (confidence: {dismiss_conf:.0%}, tolerance: {tolerance})"
                ),
                session=session,
            )
            logger.info("Auto-acknowledged alert %s (confidence=%.2f)", alert.id, dismiss_conf)
            return AutoDispositionResult(
                auto_handled=True,
                verdict="acknowledged",
                confidence=dismiss_conf,
            )

    # Check for auto-confirm (true positive)
    if (
        confirm_threshold is not None
        and ai_verdict == "true_positive"
        and confidence >= confirm_threshold
    ):
        await record_disposition(
            alert_id=alert.id,
            verdict=DispositionVerdict.TRUE_POSITIVE,
            analyst=AI_ANALYST,
            notes=f"Auto-confirmed by AI (confidence: {confidence:.0%}, tolerance: {tolerance})",
            session=session,
        )

        # Open the incident ticket (idempotent — shared helper with the web
        # and mobile confirm paths). Imported lazily: kahu.services.tickets
        # imports from this package, so a module-level import here closes a
        # cycle through kahu.services.triage.__init__ → pipeline → here.
        from kahu.services.tickets import ensure_ticket_for_verdict

        await ensure_ticket_for_verdict(
            session, alert, DispositionVerdict.TRUE_POSITIVE, AI_ANALYST
        )

        await session.commit()
        logger.info(
            "Auto-confirmed alert %s → ticket created (confidence=%.2f)", alert.id, confidence
        )
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
    """Infer a *recommended* verdict from LLM data and disposition history.

    History is the strongest signal — if a rule is consistently FP, new
    instances of the same rule are almost certainly FP too.

    This is a recommender, not an enforcer. It can and does return
    "acknowledged" on a poisoned rule-FP history even for a serious finding;
    the deterministic floor that refuses to ACT on that recommendation lives at
    the single decision point in ``maybe_auto_dispose`` (``dismiss_blocked``),
    so the block is observable and cannot be bypassed by a caller that forgets
    to re-apply it here.
    """
    # Disposition history — strongest signal
    if rule_fp_rate is not None and rule_fp_rate >= 0.6 and (confidence < 0.85 or len(benign) >= 1):
        # 60%+ FP rate: dismiss unless LLM is highly confident it's real
        return "acknowledged"
    if rule_fp_rate is not None and rule_fp_rate >= 0.5 and (len(benign) >= 1 or confidence <= 0.7):
        # 50%+ FP rate with any benign explanation or moderate confidence
        return "acknowledged"

    # Strong false positive signals (original logic)
    if len(benign) >= 2 and confidence <= 0.5:
        return "acknowledged"
    if confidence <= 0.3 and severity in ("low", "info"):
        return "acknowledged"
    if llm_severity in ("low", "info") and confidence <= 0.4:
        return "acknowledged"

    # Strong true positive signals
    if confidence >= 0.8 and not benign and severity in ("critical", "high"):
        return "true_positive"
    if confidence >= 0.9 and not benign:
        return "true_positive"

    # Medium confidence with info/low severity — likely noise
    if confidence <= 0.5 and severity in ("low", "info") and len(benign) >= 1:
        return "acknowledged"

    return None  # Uncertain — human reviews


async def _get_rule_fp_rate(rule_id: str, session: AsyncSession) -> float | None:
    """Get false-positive rate for a rule from HUMAN disposition history.

    Returns None if no history exists (< 5 dispositions).

    kahu-ai's own dispositions are excluded: this rate feeds the noisy-OR
    dismiss confidence, so counting the AI's past auto-acknowledgements would
    let each auto-dismiss raise the odds of the next one — a self-reinforcing
    slide toward silence, which is exactly the failure this pipeline exists to
    prevent. Only human verdicts are signal.
    """
    if not rule_id:
        return None

    try:
        total_stmt = (
            select(func.count())
            .select_from(Alert)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.rule_id == rule_id)
            .where(AlertDisposition.analyst != AI_ANALYST)
        )
        total = await session.scalar(total_stmt) or 0

        if total < 5:
            return None

        fp_stmt = (
            select(func.count())
            .select_from(Alert)
            .join(AlertDisposition, AlertDisposition.alert_id == Alert.id)
            .where(Alert.rule_id == rule_id)
            .where(AlertDisposition.analyst != AI_ANALYST)
            .where(
                AlertDisposition.verdict.in_(
                    [
                        DispositionVerdict.ACKNOWLEDGED,
                        DispositionVerdict.FALSE_POSITIVE,
                    ]
                )
            )
        )
        fp_count = await session.scalar(fp_stmt) or 0

        return round(fp_count / total, 2)
    except Exception:
        logger.warning("Failed to query rule FP rate", exc_info=True)
        return None
