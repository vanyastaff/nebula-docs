---
title: Example: Composition (sequential/parallel)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Example: Composition (sequential/parallel)

Patterns for composing actions:

- **Sequential**: A -> B -> C; propagate `ActionResult::Route` to branch.
- **Parallel**: fan-out to multiple ProcessActions, then aggregate with a Reduce action.
- **Loop**: StatefulAction accumulating results with `Continue{progress}` until `Break`.

Provide per-pattern error handling and retry strategies.
