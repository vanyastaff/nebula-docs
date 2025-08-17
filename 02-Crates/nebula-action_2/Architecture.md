---
title: Architecture
tags: [nebula, nebula-action, crate]
status: draft
created: 2025-08-17
---

# Architecture

High‑level architecture of **nebula-action** with its role inside the Nebula engine.

## Components
- **Core Traits** — `Action`, metadata, lifecycle, validation.
- **Action Types** — Process/Stateful/Trigger/Supply (+ streaming/interactive/transactional).
- **ActionResult System** — success/skip/retry/continue/break/branch/async/wait/route/etc.
- **Execution Context** — logging, metrics, variables, resources/clients, credentials, cancellation, temp files, events.
- **Testing Utilities** — test context, mocks, assertions.
- **Idempotency** — automatic deduplication and replay handling.
- **Composition** — sequential/parallel composition helpers.

## Data Flow
1. Registration -> 2. Initialization -> 3. Execution -> 4. (State) Persist/Migrate -> 5. (Supply) Create/Health/Destroy -> 6. (Trigger) Start/Publish/Stop -> 7. Shutdown.

## Performance & Security Checklists
- Avoid blocking in async; pool and reuse expensive resources.
- Cache when appropriate (with TTL) and keep state compact.
- Validate inputs; never log secrets; enforce timeouts and quotas.
