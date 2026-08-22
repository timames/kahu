# Kahu Roadmap

Small, user-visible improvements queued behind current work.

- (empty — mute-by-rule-ID shipped)

## Agent architecture ideas (from nsx discussion, 2026-08-21)

1. **Efference copy for self-habituation** — when an agent (or scanner/poller) generates
   its own traffic, tag outbound actions and suppress the predicted sensory consequence so
   the agent's own probes don't register as the most salient "novelty" in the environment.
   The residual — prediction error on your *own* action's effect — is the interesting
   signal: it's how you notice a host responding differently than it used to.

2. **Case-level memory across shifts** — persistent case memory must survive restarts
   (same lesson as the in-memory poller cursor) and must carry provenance on whether each
   assessment was model-derived or human-confirmed, or model conclusions compound into a
   self-reinforcing echo (same failure as the AI disposition loop, commit 1523cd0).

3. **Naive-LLM baseline ablation row** — any eval of the triage architecture needs a
   bare-model baseline row; without it you can't claim the architecture matters rather
   than the model.

4. **Model as an ablation axis** — run the same eval across model sizes to learn whether
   the scaffolding does the work or just rides model capability. The mistral→qwen switch
   was exactly this: the architecture was fine, the model was the ceiling.
