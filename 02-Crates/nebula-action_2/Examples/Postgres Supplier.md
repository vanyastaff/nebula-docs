---
title: Example: Postgres Supplier (SupplyAction)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Example: Postgres Supplier (SupplyAction)

Provide a pooled Postgres client with health check.

```rust
use async_trait::async_trait;
use serde::Deserialize;
use deadpool_postgres::{Manager, Pool};
use tokio_postgres::NoTls;

pub struct PgSupply {
    pool: Pool,
}

#[derive(Deserialize)]
pub struct PgConfig {
    pub dsn: String,
    pub max_connections: Option<usize>,
}

#[async_trait]
impl SupplyAction for PgSupply {
    type Config = PgConfig;
    type Resource = Pool;

    async fn create(&self, cfg: Self::Config, _ctx: &ExecutionContext) -> Result<Self::Resource, ActionError> {
        let mgr = Manager::new(cfg.dsn.parse().unwrap(), NoTls);
        let pool = Pool::builder(mgr)
            .max_size(cfg.max_connections.unwrap_or(10))
            .build().unwrap();
        Ok(pool)
    }

    async fn destroy(&self, _resource: Self::Resource) -> Result<(), ActionError> { Ok(()) }

    async fn health_check(&self, pool: &Self::Resource) -> Result<HealthStatus, ActionError> {
        let client = pool.get().await.map_err(|e| ActionError::ResourceUnavailable { resource: "pg_pool".into(), reason: e.to_string() })?;
        let stmt = client.prepare("SELECT 1").await.map_err(|e| ActionError::ExternalServiceError { service: "postgres".into(), error: e.to_string() })?;
        let _ = client.query(&stmt, &[]).await;
        Ok(HealthStatus::Healthy)
    }
}
```
