---
title: How to: StatefulAction
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# How to: StatefulAction

**Purpose.** Maintain durable state across executions, with migrations.

## Trait Signature
```rust
#[async_trait]
pub trait StatefulAction: Action {
    type State: Serialize + DeserializeOwned + Send + Sync;
    type Input: DeserializeOwned + Send + Sync;
    type Output: Serialize + Send + Sync;
    async fn execute_with_state(&self, input: Self::Input, state: &mut Self::State, ctx: &ExecutionContext)
        -> Result<ActionResult<Self::Output>, ActionError>;
    async fn migrate_state(&self, old: serde_json::Value, from: semver::Version)
        -> Result<Self::State, ActionError>;
}
```

## Implementation Steps

1. Design a compact `State` with a clear version.
2. Implement `migrate_state` for upgrades.
3. Mutate `state` in `execute_with_state`; keep I/O bounded.
4. Use `Break/Continue/Done` to control loops when applicable.


## Minimal Example
```rust
#[derive(Default, Serialize, Deserialize)]
pub struct AccState { total: u64 }

#[derive(Deserialize)]
pub struct In { value: u64 }

#[derive(Serialize)]
pub struct Out { total: u64 }

pub struct Accumulator;

#[async_trait]
impl StatefulAction for Accumulator {
    type State = AccState;
    type Input = In;
    type Output = Out;
    async fn execute_with_state(&self, input: In, state: &mut AccState, _ctx: &ExecutionContext)
        -> Result<ActionResult<Out>, ActionError> {
        state.total += input.value;
        Ok(ActionResult::Success(Out { total: state.total }))
    }
    async fn migrate_state(&self, old: serde_json::Value, _from: semver::Version)
        -> Result<AccState, ActionError> {
        // parse and convert
        Ok(serde_json::from_value(old).unwrap_or_default())
    }
}
```
