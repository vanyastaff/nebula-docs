---
title: How to: TriggerAction
tags: [nebula, nebula-action, crate, docs]
status: draft
created: 2025-08-17
---

# How to: TriggerAction

**Purpose.** Start workflows by emitting events from external systems.

## Trait Signature
```rust
#[async_trait]
pub trait TriggerAction: Action {
    type Config: DeserializeOwned + Send + Sync;
    type Event: Serialize + Clone + Send + Sync;
    async fn start(&self, config: Self::Config, tctx: &TriggerContext)
        -> Result<TriggerEventStream<Self::Event>, ActionError>;
    async fn stop(&self) -> Result<(), ActionError>;
}
```

## Implementation Steps

1. Define `Config` with credentials/topics/filters.
2. In `start`, subscribe to source and return an async event stream.
3. Emit typed `Event`s; include offsets for exactly-once or at-least-once.
4. Implement `stop` to close connections and flush offsets.


## Minimal Example
```rust
pub struct KafkaTrigger;
#[derive(Deserialize)] pub struct Cfg { pub topic: String }
#[derive(Serialize, Clone)] pub struct Event { pub key: String, pub payload: serde_json::Value, pub offset: i64 }

#[async_trait]
impl TriggerAction for KafkaTrigger {
    type Config = Cfg;
    type Event = Event;
    async fn start(&self, cfg: Cfg, tctx: &TriggerContext) -> Result<TriggerEventStream<Event>, ActionError> {
        let (tx, stream) = tctx.stream::<Event>();
        // spawn consumer task pushing into tx...
        Ok(stream)
    }
    async fn stop(&self) -> Result<(), ActionError> { Ok(()) }
}
```
