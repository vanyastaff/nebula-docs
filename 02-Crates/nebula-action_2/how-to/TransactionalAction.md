---
title: How to: TransactionalAction (Saga, Deep)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# How to: TransactionalAction (Saga, Deep)

**Purpose.** Coordinate distributed operations with compensation.

## Saga log
- Record steps: `try -> confirm` or `try -> compensate`
- Correlate by `saga_id` (e.g., workflow execution id + node id).

## Payment example
```rust
#[derive(Deserialize)] struct In { order_id: String, amount: u64 }
#[derive(Serialize)] struct Out { auth_id: String }

pub struct PaymentSaga;
#[async_trait]
impl TransactionalAction for PaymentSaga {
    type Input = In; type Output = Out;
    async fn try_phase(&self, input: In, ctx: &ExecutionContext) -> Result<ActionResult<Out>, ActionError> {
        ctx.log_info(&format!("auth order {}", input.order_id));
        Ok(ActionResult::Success(Out { auth_id: "auth-xyz".into() }))
    }
    async fn confirm(&self, _ctx: &ExecutionContext) -> Result<(), ActionError> { Ok(()) }
    async fn compensate(&self, _ctx: &ExecutionContext) -> Result<(), ActionError> { Ok(()) }
}
```
