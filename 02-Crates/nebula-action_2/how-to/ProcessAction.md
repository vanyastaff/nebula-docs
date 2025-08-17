---
title: How to: ProcessAction
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# How to: ProcessAction

**Purpose.** Pure, stateless transformation or external request with no persistent state.

## Trait Signature
```rust
#[async_trait]
pub trait ProcessAction: Action {
    type Input: DeserializeOwned + Send + Sync;
    type Output: Serialize + Send + Sync;
    async fn execute(&self, input: Self::Input, ctx: &ExecutionContext)
        -> Result<ActionResult<Self::Output>, ActionError>;
}
```

## Implementation Steps

1. Define `Input` and `Output`. Keep them small and serializable.
2. Use `ctx` for logging/metrics/credentials.
3. Return `Success`, `Retry`, or `Route` based on logic.
4. Avoid blocking calls; await network IO; use timeouts.


## Minimal Example
```rust
#[derive(Default)]
pub struct Slugify;

#[derive(Deserialize)]
pub struct In { pub title: String }

#[derive(Serialize)]
pub struct Out { pub slug: String }

#[async_trait]
impl ProcessAction for Slugify {
    type Input = In;
    type Output = Out;
    async fn execute(&self, input: In, ctx: &ExecutionContext) -> Result<ActionResult<Out>, ActionError> {
        ctx.log_debug("slugifying");
        let slug = input.title.to_lowercase().replace(' ', "-");
        Ok(ActionResult::Success(Out { slug }))
    }
}
```
