---
title: nebula-action — Overview
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# nebula-action — Overview

**nebula-action** defines how units of work (actions) are implemented and run in Nebula.

Use this crate when you:
- Create new action types (stateless/stateful/streaming/etc.)
- Build triggers (polling/webhook/event) that start workflows
- Provide resources (clients/pools) to other actions
- Implement transactional steps with undo/compensation
- Expose interactive steps that await human/system input

## When to choose nebula-action
- You need deterministic, typed execution with clear inputs/outputs
- You want reusability across workflows and stable versioning
- You need observability (logs, metrics, tracing) and safe error handling

## Quick start
1. Pick an action type from [[Action Catalog]].
2. Implement the trait for your type (see the corresponding "How-to").
3. Register the action in your crate's registry and export its metadata.
4. Use it in a node; configure parameters via `nebula-parameter`.

See also: [[Action Lifecycle]], [[Action Result System]], [[Development Approaches]], [[Custom Actions]], [[Examples]].
