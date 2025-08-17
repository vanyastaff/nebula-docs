---
title: Idempotency
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Idempotency

Idempotency ensures repeat invocations produce the same observable result.

## Key derivation
```
key = hash(action_id, version, normalize(input))
```
- Normalize: drop non-semantic fields, stable order for maps, trim strings, lower-case where relevant.

## Stores
- **Short TTL** (5–60 min) for external requests (HTTP/DB writes).
- **Long TTL** for webhook delivery IDs and polling offsets.

## Engine behavior
- On duplicate `key`, engine returns cached `ActionResult` or short-circuits the call.
- Conflicts should map to `ActionError::Conflict { key, .. }`.
