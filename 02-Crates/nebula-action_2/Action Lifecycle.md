---
title: Action Lifecycle
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# Action Lifecycle

All actions follow a predictable lifecycle:

1) **Registration** — action metadata & parameter schema exposed to registry.
2) **Initialization** — dependencies wired (resources/credentials), metrics registered.
3) **Execution Loop** — run handler (`execute`, `poll`, `handle`, etc.).
4) **Result Handling** — [[Action Result System]] determines next step (continue/branch/wait/stop/retry).
5) **State Persistence** (stateful only) — commit state, migrate if needed.
6) **Cleanup** — release resources; for triggers/streaming, call `stop/close`.

### Threading & Cancellation
- Actions run in async executors. Respect `ctx.cancellation_token()` and timeouts.
- Offload CPU-bound work via `spawn_blocking` and backpressure signals for streaming.
