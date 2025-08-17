---
title: Security & Privacy
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Security & Privacy

- Do not log secrets; use structured logs with redaction.
- Prefer credential handles over raw tokens; rotate via `nebula-credential`.
- Webhooks: verify signatures; replay-protect with nonce+timestamp.
- PII: tag fields with `sensitive` metadata; encrypt at rest in state.
