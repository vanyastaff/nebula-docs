---
title: Action Result System
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# Action Result System

The result type drives control flow. Common variants:

- `Success(data)` — produced output; proceed to next node.
- `Route(route_key, data)` — choose a branch (IF/Switch).
- `Wait(mode)` — suspend with a resume token/cursor (e.g., backoff until ready).
- `Retry(reason, delay)` — transient failure; engine will retry with policy.
- `Stop` — gracefully stop workflow (successfully).
- `Done` — no further outputs; mark node as completed.
- `Break { reason, output }` — break from loop with optional result.
- `Stream(Open|Chunk|Closed)` — for streaming actions.
- `Enqueue(QueueItemId)` — delegated to queue; resume on ack.
- `Error(ActionError)` — typed error; see Error Model.

Your real Rust enum can be richer (e.g., include progress, ETA, metrics marks). Keep variants serializable.
