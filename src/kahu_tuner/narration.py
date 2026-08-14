"""Mind narration -- LLM summary of proposal evidence (strictly out of decision path).

The narration is generated AFTER the proposal is signed. It uses only the
evidence block as input. The narration is appended to the proposal but is
NOT covered by the signature, enforcing that it cannot alter the decision.
"""

from __future__ import annotations

import httpx


async def narrate_proposal(
    evidence: dict,
    ollama_url: str = "http://localhost:11434",
    model: str = "mistral:7b-instruct-v0.3-q4_K_M",
) -> str | None:
    """Generate a two-sentence human summary of a proposal's evidence.

    The narration is generated from the evidence JSON only.
    If Ollama is unavailable, returns None (proposals proceed without narration).
    No LLM output may alter action, action_params, thresholds, or approval state.

    Returns:
        Two-sentence summary string, or None if unavailable.
    """
    prompt = _build_narration_prompt(evidence)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{ollama_url}/api/generate",
                json={
                    "model": model,
                    "prompt": prompt,
                    "system": (
                        "You are a concise security analyst narrator. "
                        "Summarize the statistical evidence in exactly two sentences. "
                        "Use plain language. Do not suggest actions or make recommendations. "
                        "Focus on what the data shows about the alert rate behavior."
                    ),
                    "stream": False,
                },
            )
            resp.raise_for_status()
            return resp.json().get("response", "").strip()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError):
        return None


def _build_narration_prompt(evidence: dict) -> str:
    """Build a narration prompt from the evidence block only."""
    parts = [
        "Alert rate evidence summary:",
        f"- Events observed in 90 days: {evidence.get('n_90d', 0)}",
        f"- Effective exposure: {evidence.get('t_star_hours', 0):.1f} hours",
        f"- Posterior mean rate: {evidence.get('posterior_mean', 0):.4f} events/hour",
        f"- Posterior CV (uncertainty): {evidence.get('posterior_cv', 0):.4f}",
        f"- Log Bayes factor (benign vs elevated): {evidence.get('log_bf01', 0):.4f}",
        f"- Posterior odds of benign: {evidence.get('posterior_odds', 0):.4f}",
        f"- Risk multiplier applied: {evidence.get('risk_multiplier', 1):.1f}",
        f"- Threshold for suppression: {evidence.get('threshold_applied', 20):.1f}",
        f"- KL divergence vs golden baseline: {evidence.get('kl_vs_golden', 0):.4f}",
        f"- Windows consistent: {evidence.get('windows_consistent', True)}",
    ]
    return "\n".join(parts)
