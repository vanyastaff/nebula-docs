---
title: Sequence Patterns
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Sequence Patterns

## Trigger → Transform → DB (Detailed)
```
External Source ──► [TriggerAction] ──► Engine
                        start()            enqueue events
                                     ┌───────────┐
                                     │ Scheduler │
                                     └────┬──────┘
                                          ▼
                                 [ProcessAction] execute()
                                          │ Success(data)
                                          ▼
                                      [DB Action]
```
- Offsets persisted after successful downstream commit.
