"""Stage 3 — LLM-based triage via Ollama."""

from kuahene.services.triage.enrichment import EnrichedAlert


async def run_llm_triage(enriched: EnrichedAlert) -> dict:
    """Send enriched alert to Ollama for structured triage assessment.

    Returns structured JSON with: severity, explanation, benign_explanations,
    recommended_actions, confidence.

    Output is treated as untrusted draft content — it populates recommendations
    but never directly triggers an action.
    """
    # TODO: implement Ollama API call with structured prompt
    # - Redact secrets before prompt assembly
    # - Delimit log-derived text as data
    # - Parse response as structured JSON
    # - Handle inference failures gracefully (pipeline continues without LLM)
    return {
        "severity": None,
        "explanation": "",
        "benign_explanations": [],
        "recommended_actions": [],
        "confidence": 0.0,
    }
