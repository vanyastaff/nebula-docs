---
title: Error Model
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# Error Model

Use precise, typed errors to simplify retries and observability.

Suggested variants (flatten to your `ActionError`):
- `InvalidInput { field, reason }`
- `PreconditionFailed { reason }`
- `Timeout { at, duration }`
- `Cancelled`
- `ExternalServiceError { service, error }`
- `ResourceUnavailable { resource, reason }`
- `Conflict { key, detail }` (for idempotency)
- `Serialization { detail }`
- `Unknown { detail }`

Retryable vs non-retryable should be encoded (trait or enum flag) and reflected in metrics.
