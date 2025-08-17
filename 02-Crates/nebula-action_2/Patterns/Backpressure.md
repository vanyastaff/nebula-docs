---
title: Streaming & Backpressure
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Streaming & Backpressure

For `StreamingAction`, treat the stream as a bounded channel:
- Emit `StreamChunk` only when downstream is ready.
- Use watermark metrics: `inflight_chunks`, `dropped_chunks`.
- Provide checkpoints (byte offset, message ID) at intervals for resume.
