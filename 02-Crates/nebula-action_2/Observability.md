---
title: Observability (Logs, Metrics, Tracing)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Observability (Logs, Metrics, Tracing)

Minimum useful metrics per action:
- `duration_ms`, `attempts`, `errors_total{kind}`, `throughput{items/sec}`
- Polling: `items_polled`, `backoff_ms`
- Webhooks: `validated`, `replayed`, `invalid_signature`
- Streaming: `chunks_emitted`, `backpressure_events`
Attach labels: `action_id`, `workflow_id`, `node_id`, `tenant`.
