---
title: Action Traits Reference
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Action Traits Reference

This is a **complete reference** for the core traits and types used by actions.
The code below is intended as an *interface specification* for implementors. It may differ slightly from your actual crate,
but captures the semantics we rely on across the docs.

## Base traits & identifiers
```rust
use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};
use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionId(pub Cow<'static, str>);

#[derive(Debug, Clone)]
pub struct ActionVersion(pub u32);

#[derive(Debug, Clone)]
pub struct ActionMetadata {
    pub id: ActionId,
    pub name: Cow<'static, str>,
    pub version: ActionVersion,
    pub description: Cow<'static, str>,
    pub parameters: serde_json::Value, // produced by nebula-parameter
    pub outputs: serde_json::Value,    // JSON schema of output when relevant
    pub kind: ActionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Process,
    Stateful,
    Trigger,
    Polling,
    Webhook,
    Streaming,
    Interactive,
    Transactional,
    Queue,
    Schedule,
    Supply,
}

#[async_trait]
pub trait Action: Send + Sync {
    fn metadata(&self) -> &ActionMetadata;
}
```

## Execution contexts
```rust
#[derive(Clone)]
pub struct ExecutionContext {
    // Logging
    pub fn log_debug(&self, msg: &str) {}
    pub fn log_info(&self, msg: &str) {}
    pub fn log_warn(&self, msg: &str) {}
    pub fn log_error(&self, msg: &str) {}

    // Metrics
    pub fn increment_counter(&self, name: &str, labels: &[(&str, &str)]) {}
    pub fn record_metric(&self, name: &str, value: f64, labels: &[(&str, &str)]) {}
    pub fn start_timer(&self, name: &str) -> Timer { Timer }
    pub fn span<F: FnOnce() -> T, T>(&self, name: &str, f: F) -> T { f() }

    // Variables / KV
    pub fn get_variable(&self, key: &str) -> Option<serde_json::Value> { None }
    pub fn set_variable(&self, key: &str, value: serde_json::Value) {}

    // Clients / Credentials / Resources
    pub fn get_credential(&self, kind: &str) -> Option<serde_json::Value> { None }
    pub fn get_client<T: 'static + Send + Sync>(&self, kind: &str) -> Option<T> { None }
    pub fn get_resource<T: 'static + Send + Sync>(&self) -> Option<T> { None }

    // Cancellation
    pub fn is_cancelled(&self) -> bool { false }
    pub fn cancellation_token(&self) -> CancellationToken { CancellationToken }
}

pub struct CancellationToken;
pub struct Timer;
impl Timer { pub fn stop_and_record(self) {} }
```

### Specialized contexts
```rust
pub struct TriggerContext;
impl TriggerContext {
    pub fn stream<E: Serialize + Clone + Send + Sync + 'static>(&self) -> (Sender<E>, TriggerEventStream<E>) {
        unimplemented!()
    }
}

pub struct WebhookContext;
pub struct Lease; // Remaining time/ops budget for polling
impl Lease { pub fn remaining_ms(&self) -> u64 { 0 } }
```

## Results and flow control
```rust
#[derive(Debug, Clone)]
pub enum WaitMode {
    Until(std::time::SystemTime),
    BackoffMs(u64),
    PendingToken(String), // for interactive resume
}

#[derive(Debug, Clone)]
pub struct LoopProgress {
    pub current_iteration: usize,
    pub total_items: Option<usize>,
    pub processed_items: usize,
    pub percentage: Option<f32>,
    pub status_message: Option<String>,
}

#[derive(Debug, Clone)]
pub enum ActionResult<T> {
    Success(T),
    Route { key: String, data: T },
    Continue { output: T, progress: LoopProgress, delay: Option<u64> },
    Break { output: T, reason: BreakReason },
    Wait(WaitMode),
    Retry { reason: String, delay_ms: Option<u64> },
    Done,  // no output
    Stop,  // gracefully stop workflow
    StreamOpen(StreamHandle),
    StreamChunk(T),
    StreamClosed,
    Enqueue(String), // queue item id
}

#[derive(Debug, Clone, Copy)]
pub enum BreakReason { Completed, Cancelled, LimitReached }

pub struct StreamHandle;
```

## Polling
```rust
#[derive(Debug, Clone)]
pub struct PollResult<Item, Cursor> {
    pub items: Vec<Item>,
    pub cursor: Cursor,
    pub backoff_ms: Option<u64>,
}
impl<Item, Cursor> PollResult<Item, Cursor> {
    pub fn items(items: Vec<Item>, cursor: Cursor) -> Self { Self { items, cursor, backoff_ms: None } }
    pub fn with_backoff_ms(mut self, ms: u64) -> Self { self.backoff_ms = Some(ms); self }
}
```

## Errors
```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ActionError {
    #[error("invalid input: {field} - {reason}")]
    InvalidInput { field: String, reason: String },
    #[error("precondition failed: {0}")]
    PreconditionFailed(String),
    #[error("timeout after {0}")]
    Timeout(String),
    #[error("cancelled")]
    Cancelled,
    #[error("external service {service}: {error}")]
    ExternalServiceError { service: String, error: String },
    #[error("resource {resource} unavailable: {reason}")]
    ResourceUnavailable { resource: String, reason: String },
    #[error("conflict {key}: {detail}")]
    Conflict { key: String, detail: String },
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("unknown: {0}")]
    Unknown(String),
}
```
