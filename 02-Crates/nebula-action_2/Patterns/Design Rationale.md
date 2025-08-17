---
title: Design Rationale
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Design Rationale

Why so many action types? To get **strong guarantees** at compile time and a simpler runtime:
- The engine can schedule/scale differently based on type (e.g., long-poll vs CPU-bound).
- UI can render correct forms and hints (webhook secrets, cursors for polling, etc.).
- Observability becomes uniform (we know which metrics to expect).

Alternatives ("fat" universal nodes) lead to implicit contracts, runtime surprises, and harder testing.
