---
title: Example: Kafka Trigger (TriggerAction)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Example: Kafka Trigger (TriggerAction)

Emit events from Kafka with offsets.

```rust
// Pseudocode (use rdkafka)
#[derive(Deserialize)] struct Cfg { brokers: Vec<String>, topic: String, group_id: String }
#[derive(Serialize, Clone)] struct Event { key: Option<String>, payload: serde_json::Value, offset: i64, partition: i32 }

pub struct KafkaTrigger;

#[async_trait]
impl TriggerAction for KafkaTrigger {
    type Config = Cfg; type Event = Event;
    async fn start(&self, _cfg: Cfg, tctx: &TriggerContext) -> Result<TriggerEventStream<Event>, ActionError> {
        let (_tx, stream) = tctx.stream::<Event>();
        // spawn consumer task that sends Event{...} into tx
        Ok(stream)
    }
    async fn stop(&self) -> Result<(), ActionError> { Ok(()) }
}
```
