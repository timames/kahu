"""Thin Ollama API client — model-agnostic by design."""

import httpx

from kahu.config import settings

# Keep the model pinned in VRAM. On GPU appliances a cold reload of a 7B model
# can take 60-100s; without this every idle-then-triage cycle re-pays that cost
# and blows past the request timeout, forcing the whole pipeline into degraded
# mode. -1 = never unload. Mirrors OLLAMA_KEEP_ALIVE on the server as a
# self-healing default in case that env var is missing.
_KEEP_ALIVE = -1

# A cold model load must fit inside this. Warm generations are single-digit
# seconds; the headroom is for the first request after an Ollama restart.
_GENERATE_TIMEOUT = 300.0

# Cap output length. Ollama serves one generation at a time, so a single
# degenerate/looping prompt with no bound can emit thousands of tokens and
# monopolize the GPU for minutes, starving all other triage (observed in
# production: one prompt ran to ~13k tokens / ~350s, tripping the request
# timeout and pushing every queued alert into degraded mode). A triage response
# is small JSON; callers that legitimately need long output (reports) raise it.
_DEFAULT_NUM_PREDICT = 1024


class OllamaClient:
    def __init__(self) -> None:
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model

    async def generate(
        self, prompt: str, system: str = "", num_predict: int = _DEFAULT_NUM_PREDICT
    ) -> str:
        async with httpx.AsyncClient(timeout=_GENERATE_TIMEOUT) as client:
            response = await client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": system,
                    "stream": False,
                    "keep_alive": _KEEP_ALIVE,
                    "options": {"num_predict": num_predict},
                },
            )
            response.raise_for_status()
            return response.json()["response"]

    async def health(self) -> bool:
        """Reachability only — the API answers even with no model loaded."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/tags")
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    async def model_loaded(self) -> bool:
        """True only when the configured model is resident in memory.

        `health()` reports reachability, which stays green during a cold load
        or after an eviction. This checks `/api/ps` (running models) so the UI
        can warn operators that triage is falling back to deterministic-only.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.base_url}/api/ps")
                resp.raise_for_status()
                running = resp.json().get("models", [])
                return any(
                    m.get("model") == self.model or m.get("name") == self.model
                    for m in running
                )
        except httpx.HTTPError:
            return False

    async def preload(self) -> bool:
        """Warm the model into memory and pin it.

        Called at startup so the first real triage doesn't pay the cold-load
        penalty. An empty-prompt generate loads the model without producing
        tokens.
        """
        try:
            async with httpx.AsyncClient(timeout=_GENERATE_TIMEOUT) as client:
                resp = await client.post(
                    f"{self.base_url}/api/generate",
                    json={"model": self.model, "keep_alive": _KEEP_ALIVE},
                )
                resp.raise_for_status()
                return True
        except httpx.HTTPError:
            return False
