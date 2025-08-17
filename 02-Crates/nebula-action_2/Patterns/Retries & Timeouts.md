---
title: Retries & Timeouts
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Retries & Timeouts

- **Network**: timeout per request + overall deadline from `ctx`.
- **Retry policy**: exponential backoff with jitter; cap max attempts.
- Mark errors **retryable** (`ExternalServiceError`, `ResourceUnavailable`) vs **final** (`InvalidInput`).
- Emit structured events with attempt number and next backoff.
