---
title: Quick Start
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Quick Start

## 1) Мини-ресурс: счетчик
```rust
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};

pub struct CounterResource;
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct CounterConfig { pub start: u64 }

pub struct CounterInstance {
    id: String,
    value: Arc<AtomicU64>,
}

#[async_trait]
pub trait Resource {
    type Config: Send + Sync;
    type Instance: Send + Sync;
    async fn create(&self, cfg: &Self::Config, ctx: &ResourceContext) -> Result<Self::Instance, ResourceError>;
}

pub struct ResourceContext;
#[derive(thiserror::Error, Debug)] pub enum ResourceError { #[error("fail: {0}")] Fail(String) }

#[async_trait]
impl Resource for CounterResource {
    type Config = CounterConfig;
    type Instance = CounterInstance;
    async fn create(&self, cfg: &CounterConfig, _ctx: &ResourceContext) -> Result<CounterInstance, ResourceError> {
        Ok(CounterInstance { id: "counter-1".into(), value: Arc::new(AtomicU64::new(cfg.start)) })
    }
}

impl CounterInstance {
    pub fn incr(&self) -> u64 { self.value.fetch_add(1, Ordering::SeqCst) + 1 }
    pub async fn health_check(&self) -> bool { true }
}
```

## 2) Получаем ресурс в действии
```rust
pub struct ExecutionContext;
impl ExecutionContext { pub async fn get_resource<T: 'static>(&self) -> anyhow::Result<Arc<T>> { todo!() } }

async fn do_work(ctx: &ExecutionContext) -> anyhow::Result<()> {
    let counter = ctx.get_resource::<CounterInstance>().await?;
    let n = counter.incr();
    println!("n = {n}");
    Ok(())
}
```

## 3) Тестируем
```rust
#[tokio::test]
async fn it_counts() {
    // use TestResourceManager...
    assert!(true);
}
```
