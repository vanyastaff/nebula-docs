---
title: First Application
tags: [nebula, nebula-memory, docs]
status: draft
created: 2025-08-19
---

# First Application

Мини-сервис HTTP с request-scoped ареной и отчётом утечек при `scope.close()`.

```rust
async fn handle(req: Request) -> Response {
    let mm = req.extensions().get::<MemoryManager>().unwrap();
    let scope = mm.open_scope(ScopeConfig{ kind: ScopeKind::Request, name: "http",
        budget: MemoryBudget{ hard_limit: 16<<20, soft_limit: 12<<20 }, leak_report: true });
    let mut arena = scope.bump_arena(2<<20);
    // ... work ...
    let leaks = scope.close();
    if leaks.leaked_bytes > 0 { tracing::warn!(?leaks, "leaks"); }
    Response::ok()
}
```
