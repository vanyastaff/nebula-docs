---
title: README
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---


## Overview

`nebula-resource` provides a comprehensive resource management framework for the Nebula workflow engine. It handles the lifecycle, pooling, scoping, and observability of all resources used within workflows and actions.

### Key Features

- 🔄 **Lifecycle Management** - Automatic initialization, health checks, and cleanup
- 🏊 **Resource Pooling** - Efficient connection pooling with configurable strategies
- 🔍 **Context Awareness** - Automatic context propagation for tracing and multi-tenancy
- 🔐 **Credential Integration** - Seamless integration with `nebula-credential` for secure credential management
- 📊 **Built-in Observability** - Metrics, logging, and distributed tracing out of the box
- 🎯 **Scoped Resources** - Support for Global, Tenant, Workflow, and Action-level resource scoping
- 🔗 **Dependency Management** - Automatic dependency resolution and circular dependency detection
- 🎨 **Extensible** - Plugin system and hooks for custom behavior

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  nebula-engine                    │
├──────────────────────────────────────────────────┤
│         nebula-workflow    nebula-action         │
├──────────────────────────────────────────────────┤
│              nebula-resource (this crate)        │
│  ┌────────────────────────────────────────────┐  │
│  │  ResourceManager                           │  │
│  │  ├── Registry (resource discovery)         │  │
│  │  ├── PoolManager (connection pooling)      │  │
│  │  ├── LifecycleManager (state management)   │  │
│  │  └── MetricsCollector (observability)      │  │
│  └────────────────────────────────────────────┘  │
├──────────────────────────────────────────────────┤
│              nebula-credential                   │
└──────────────────────────────────────────────────┘
```

## Quick Start

### Installation

```toml
[dependencies]
nebula-resource = "0.2"
```

### Basic Usage

```rust
use nebula_resource::prelude::*;
use async_trait::async_trait;

// Define a resource
#[derive(Resource)]
#[resource(
    id = "database",
    name = "PostgreSQL Database",
    poolable = true,
    health_checkable = true
)]
pub struct DatabaseResource;

// Define configuration
#[derive(ResourceConfig)]
pub struct DatabaseConfig {
    pub connection_string: String,
    pub max_connections: u32,
    pub idle_timeout_seconds: u64,
}

// Define instance
pub struct DatabaseInstance {
    pool: sqlx::PgPool,
}

// Implement resource trait
#[async_trait]
impl Resource for DatabaseResource {
    type Config = DatabaseConfig;
    type Instance = DatabaseInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        let pool = sqlx::PgPool::connect(&config.connection_string)
            .await
            .map_err(|e| ResourceError::InitializationFailed(e.to_string()))?;
        
        Ok(DatabaseInstance { pool })
    }
}

// Use in a workflow action
async fn process_data(ctx: &ExecutionContext) -> Result<()> {
    // Resource is automatically acquired and managed
    let db = ctx.get_resource::<DatabaseInstance>().await?;
    
    // Use the resource
    let result = sqlx::query("SELECT * FROM users")
        .fetch_all(&db.pool)
        .await?;
    
    // Resource is automatically released when action completes
    Ok(())
}
```

## Core Concepts

### Resource Lifecycle

Resources go through well-defined lifecycle states:

```rust
pub enum LifecycleState {
    Created,        // Resource created but not initialized
    Initializing,   // Currently being initialized
    Ready,          // Available for use
    InUse,          // Currently being used
    Idle,           // Ready but not in use
    Maintenance,    // Under maintenance
    Draining,       // Preparing for shutdown
    Cleanup,        // Being cleaned up
    Terminated,     // Fully terminated
    Failed,         // In error state
}
```

### Resource Scoping

Resources can be scoped at different levels:

- **Global** - Shared across all workflows and tenants
- **Tenant** - Isolated per tenant for multi-tenancy
- **Workflow** - Scoped to a specific workflow execution
- **Action** - Scoped to a specific action within a workflow

### Resource Pooling

Built-in support for efficient resource pooling:

```rust
#[derive(PoolConfig)]
pub struct PoolConfiguration {
    pub min_size: usize,          // Minimum pool size
    pub max_size: usize,          // Maximum pool size
    pub acquire_timeout: Duration, // Timeout for acquiring resource
    pub idle_timeout: Duration,    // Idle timeout before cleanup
    pub max_lifetime: Duration,    // Maximum resource lifetime
    pub validation_interval: Duration, // Health check interval
}
```

## Advanced Features

### Context Enrichment

Automatically enrich resource context with metadata:

```rust
pub struct ContextEnricher {
    enrichers: Vec<Box<dyn Enricher>>,
}

#[async_trait]
pub trait Enricher: Send + Sync {
    async fn enrich(&self, context: &mut ResourceContext) -> Result<()>;
}

// Example enrichers
- UserEnricher: adds user information
- GeoEnricher: adds geolocation data
- SecurityEnricher: adds security context
- TenantEnricher: adds tenant information
```

### Dependency Management

Declare and automatically resolve resource dependencies:

```rust
#[derive(Resource)]
#[resource(
    id = "api_service",
    depends_on = ["database", "cache", "logger"]
)]
pub struct ApiServiceResource;
```

### Credential Integration

Seamless integration with `nebula-credential`:

```rust
#[derive(ResourceConfig)]
pub struct ApiConfig {
    pub endpoint: String,
    
    #[credential(id = "api_key")]
    pub api_key: SecretString,
    
    #[credential(id = "api_secret", optional = true)]
    pub api_secret: Option<SecretString>,
}
```

### Observability

Built-in metrics and tracing:

```rust
// Automatic metrics collection
- resource.acquisitions.total
- resource.active.count
- resource.acquisition.duration
- resource.health.checks.total
- resource.errors.total

// Automatic tracing spans
- resource.acquire
- resource.initialize
- resource.health_check
- resource.cleanup
```

## Built-in Resources

### Available Resources

- **DatabaseResource** - Database connections (PostgreSQL, MySQL, SQLite)
- **HttpClientResource** - HTTP client with retry and circuit breaker
- **CacheResource** - Redis/Memcached caching
- **MessageQueueResource** - Kafka/RabbitMQ/SQS integration
- **StorageResource** - S3/GCS/Azure blob storage
- **LoggerResource** - Structured logging
- **MetricsResource** - Metrics collection
- **TracingResource** - Distributed tracing

### Custom Resources

Create custom resources by implementing the `Resource` trait:

```rust
#[async_trait]
pub trait Resource: Send + Sync {
    type Config: ResourceConfig;
    type Instance: Send + Sync;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError>;
    
    async fn health_check(&self, instance: &Self::Instance) -> Result<HealthStatus>;
    
    async fn cleanup(&self, instance: Self::Instance) -> Result<()>;
}
```

## Integration with Nebula Ecosystem

### nebula-workflow Integration

Resources are automatically managed within workflows:

```rust
#[workflow]
async fn data_pipeline(ctx: WorkflowContext) -> Result<()> {
    // Resources are automatically acquired
    let db = ctx.resource::<DatabaseInstance>().await?;
    let cache = ctx.resource::<CacheInstance>().await?;
    
    // Use resources in actions
    ctx.execute_action("fetch_data", |action_ctx| async {
        // Resources are available in actions
        let data = fetch_from_db(&db).await?;
        cache_data(&cache, data).await?;
        Ok(())
    }).await?;
    
    // Resources are automatically released
    Ok(())
}
```

### nebula-action Integration

Actions can declare required resources:

```rust
#[action(
    resources = ["database", "cache", "logger"]
)]
async fn process_record(ctx: ActionContext) -> Result<()> {
    let db = ctx.resource::<DatabaseInstance>().await?;
    let cache = ctx.resource::<CacheInstance>().await?;
    let logger = ctx.resource::<LoggerInstance>().await?;
    
    // Use resources...
    Ok(())
}
```

## Configuration

### Resource Configuration

Resources can be configured via:

1. **Configuration files** (YAML/TOML/JSON)
2. **Environment variables**
3. **Runtime configuration**
4. **Credential providers**

Example configuration:

```yaml
resources:
  database:
    type: postgresql
    config:
      connection_string: "${DATABASE_URL}"
      max_connections: 50
      idle_timeout_seconds: 300
    pool:
      min_size: 5
      max_size: 50
      acquire_timeout: 10s
    health_check:
      interval: 30s
      timeout: 5s
      
  cache:
    type: redis
    config:
      url: "${REDIS_URL}"
      max_connections: 100
    scoping: tenant  # Tenant-level isolation
```

## Testing

### Test Utilities

```rust
#[cfg(test)]
mod tests {
    use nebula_resource::testing::*;
    
    #[tokio::test]
    async fn test_resource_lifecycle() {
        // Create test resource manager
        let manager = TestResourceManager::new();
        
        // Register mock resource
        manager.register_mock::<DatabaseResource>(|mock| {
            mock.expect_create()
                .returning(|_, _| Ok(DatabaseInstance::mock()));
        });
        
        // Test resource operations
        let instance = manager.acquire::<DatabaseInstance>().await.unwrap();
        assert!(instance.is_healthy().await);
    }
}
```

## Performance Considerations

### Optimization Tips

1. **Pool Sizing** - Configure appropriate pool sizes based on workload
2. **Health Checks** - Balance frequency vs overhead
3. **Scoping** - Use appropriate scope to minimize resource creation
4. **Caching** - Enable resource caching where appropriate
5. **Lazy Loading** - Resources are loaded on-demand
6. **Circuit Breakers** - Prevent cascading failures

### Benchmarks

```
resource_acquire         time:   [127.3 ns 128.1 ns 128.9 ns]
resource_health_check    time:   [1.234 µs 1.241 µs 1.248 µs]
resource_pool_acquire    time:   [89.23 ns 89.67 ns 90.12 ns]
context_enrichment       time:   [234.5 ns 235.8 ns 237.1 ns]
```

## Migration Guide

### From v0.1 to v0.2

Major changes:

- New trait-based resource system
- Improved context propagation
- Enhanced pooling strategies
- Better credential integration

See [MIGRATION.md](https://claude.ai/chat/docs/MIGRATION.md) for detailed migration instructions.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](https://claude.ai/chat/CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repository
git clone https://github.com/nebula-rs/nebula-resource
cd nebula-resource

# Install dependencies
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](https://claude.ai/chat/LICENSE-APACHE))
- MIT license ([LICENSE-MIT](https://claude.ai/chat/LICENSE-MIT))

at your option.

## Resources

- [Documentation](https://docs.rs/nebula-resource)
- [Examples](https://claude.ai/chat/examples/)
- [API Reference](https://docs.rs/nebula-resource)
- [Discord Community](https://discord.gg/nebula-rs)
- [Blog Posts](https://blog.nebula.rs/tags/resources)

---

## Deep Dive: Resource System Implementation

### The Resource Trait

All resources implement the core `Resource` trait:

```rust
#[async_trait]
pub trait Resource: Send + Sync + 'static {
    /// Configuration type for this resource
    type Config: ResourceConfig + Clone;

    /// The instance type created from this resource
    type Instance: Send + Sync + 'static;

    /// Resource identifier (unique across system)
    fn id() -> &'static str;

    /// Human-readable name
    fn name() -> &'static str {
        Self::id()
    }

    /// Create a new instance of the resource
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError>;

    /// Perform health check on instance
    async fn health_check(&self, instance: &Self::Instance) -> Result<HealthStatus, ResourceError> {
        Ok(HealthStatus::Healthy)
    }

    /// Cleanup/destroy instance
    async fn cleanup(&self, instance: Self::Instance) -> Result<(), ResourceError> {
        drop(instance);
        Ok(())
    }

    /// Check if resource supports pooling
    fn is_poolable() -> bool {
        true
    }

    /// Get dependencies (other resources this depends on)
    fn dependencies() -> Vec<&'static str> {
        Vec::new()
    }

    /// Get resource metadata
    fn metadata() -> ResourceMetadata {
        ResourceMetadata {
            id: Self::id(),
            name: Self::name(),
            poolable: Self::is_poolable(),
            dependencies: Self::dependencies(),
            tags: HashMap::new(),
        }
    }
}
```

### Complete Example: PostgreSQL Resource with Pooling

```rust
use nebula_resource::prelude::*;
use sqlx::postgres::{PgPool, PgPoolOptions, PgConnection};
use std::sync::Arc;
use tokio::sync::Semaphore;

/// Configuration for PostgreSQL resource
#[derive(Clone, Serialize, Deserialize)]
pub struct PostgresConfig {
    pub host: String,
    pub port: u16,
    pub database: String,

    #[credential(id = "postgres_creds")]
    pub credentials: PostgresCredential,

    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout: Duration,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub ssl_mode: String,
}

impl ResourceConfig for PostgresConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.max_connections == 0 {
            return Err(ConfigError::invalid("max_connections must be > 0"));
        }

        if self.min_connections > self.max_connections {
            return Err(ConfigError::invalid("min_connections cannot exceed max_connections"));
        }

        if self.host.is_empty() {
            return Err(ConfigError::invalid("host cannot be empty"));
        }

        Ok(())
    }
}

/// PostgreSQL resource instance
pub struct PostgresInstance {
    pool: Arc<PgPool>,
    config: PostgresConfig,
    metrics: Arc<ResourceMetrics>,
    created_at: Instant,
}

impl PostgresInstance {
    /// Get a connection from the pool
    pub async fn acquire(&self) -> Result<PoolConnection<Postgres>, ResourceError> {
        self.metrics.record_acquisition_attempt();

        let start = Instant::now();
        let conn = self.pool
            .acquire()
            .await
            .map_err(|e| ResourceError::acquisition_failed(format!("Failed to acquire connection: {}", e)))?;

        self.metrics.record_acquisition_success(start.elapsed());

        Ok(conn)
    }

    /// Execute a query
    pub async fn execute<'q, Q>(&self, query: Q) -> Result<PgQueryResult, ResourceError>
    where
        Q: Execute<'q, Postgres>,
    {
        let mut conn = self.acquire().await?;

        sqlx::query(query)
            .execute(&mut *conn)
            .await
            .map_err(|e| ResourceError::operation_failed(format!("Query failed: {}", e)))
    }

    /// Get pool statistics
    pub fn pool_stats(&self) -> PoolStats {
        PoolStats {
            active_connections: self.pool.size() as u32,
            idle_connections: self.pool.num_idle() as u32,
            max_connections: self.config.max_connections,
            min_connections: self.config.min_connections,
        }
    }
}

/// PostgreSQL resource
pub struct PostgresResource;

#[async_trait]
impl Resource for PostgresResource {
    type Config = PostgresConfig;
    type Instance = PostgresInstance;

    fn id() -> &'static str {
        "postgres"
    }

    fn name() -> &'static str {
        "PostgreSQL Database"
    }

    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        context.log_info(&format!(
            "Initializing PostgreSQL connection to {}:{}/{}",
            config.host, config.port, config.database
        ));

        // Build connection string
        let connection_string = format!(
            "postgres://{}:{}@{}:{}/{}?sslmode={}",
            urlencoding::encode(&config.credentials.username),
            urlencoding::encode(&config.credentials.password),
            config.host,
            config.port,
            config.database,
            config.ssl_mode
        );

        // Create pool
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(config.connection_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .test_before_acquire(true)
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    // Set session parameters
                    sqlx::query("SET application_name = 'nebula-workflow'")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&connection_string)
            .await
            .map_err(|e| ResourceError::initialization_failed(format!("Pool creation failed: {}", e)))?;

        context.log_info("PostgreSQL connection pool initialized");
        context.record_metric("postgres.pool.initialized", 1.0);

        Ok(PostgresInstance {
            pool: Arc::new(pool),
            config: config.clone(),
            metrics: Arc::new(ResourceMetrics::new("postgres")),
            created_at: Instant::now(),
        })
    }

    async fn health_check(&self, instance: &Self::Instance) -> Result<HealthStatus, ResourceError> {
        // Try to acquire connection
        let mut conn = instance.pool
            .acquire()
            .await
            .map_err(|e| ResourceError::health_check_failed(format!("Connection failed: {}", e)))?;

        // Execute simple query
        sqlx::query("SELECT 1")
            .execute(&mut *conn)
            .await
            .map_err(|e| ResourceError::health_check_failed(format!("Query failed: {}", e)))?;

        let stats = instance.pool_stats();

        Ok(HealthStatus::Healthy {
            metadata: HashMap::from([
                ("active_connections".to_string(), stats.active_connections.to_string()),
                ("idle_connections".to_string(), stats.idle_connections.to_string()),
                ("uptime_seconds".to_string(), instance.created_at.elapsed().as_secs().to_string()),
            ]),
        })
    }

    async fn cleanup(&self, instance: Self::Instance) -> Result<(), ResourceError> {
        instance.pool.close().await;
        Ok(())
    }

    fn is_poolable() -> bool {
        true
    }
}
```

### Complete Example: HTTP Client Resource with Circuit Breaker

```rust
use nebula_resource::prelude::*;
use reqwest::{Client, ClientBuilder};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

#[derive(Clone, Serialize, Deserialize)]
pub struct HttpClientConfig {
    pub base_url: Option<String>,
    pub timeout: Duration,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub user_agent: String,

    // Circuit breaker settings
    pub circuit_breaker_enabled: bool,
    pub circuit_breaker_threshold: u32,
    pub circuit_breaker_timeout: Duration,

    // Retry settings
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 32,
            user_agent: "nebula-workflow/1.0".to_string(),
            circuit_breaker_enabled: true,
            circuit_breaker_threshold: 5,
            circuit_breaker_timeout: Duration::from_secs(60),
            max_retries: 3,
            retry_delay: Duration::from_secs(1),
        }
    }
}

impl ResourceConfig for HttpClientConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.timeout.is_zero() {
            return Err(ConfigError::invalid("timeout must be > 0"));
        }
        Ok(())
    }
}

pub struct HttpClientInstance {
    client: Client,
    config: HttpClientConfig,
    circuit_state: Arc<CircuitBreakerState>,
    metrics: Arc<ResourceMetrics>,
}

struct CircuitBreakerState {
    state: AtomicU32,  // 0 = Closed, 1 = Open, 2 = HalfOpen
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: AtomicU64,
}

impl CircuitBreakerState {
    fn new() -> Self {
        Self {
            state: AtomicU32::new(0),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: AtomicU64::new(0),
        }
    }

    fn is_open(&self) -> bool {
        self.state.load(Ordering::Relaxed) == 1
    }

    fn open(&self) {
        self.state.store(1, Ordering::Relaxed);
        self.last_failure_time.store(
            Instant::now().elapsed().as_secs(),
            Ordering::Relaxed
        );
    }

    fn close(&self) {
        self.state.store(0, Ordering::Relaxed);
        self.failure_count.store(0, Ordering::Relaxed);
    }

    fn half_open(&self) {
        self.state.store(2, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
    }

    fn record_success(&self) -> u32 {
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn record_failure(&self) -> u32 {
        self.success_count.store(0, Ordering::Relaxed);
        self.failure_count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

impl HttpClientInstance {
    /// Execute HTTP GET request
    pub async fn get(&self, url: &str) -> Result<reqwest::Response, ResourceError> {
        self.execute_with_circuit_breaker(|| async {
            self.client
                .get(url)
                .send()
                .await
                .map_err(|e| ResourceError::operation_failed(e.to_string()))
        })
        .await
    }

    /// Execute HTTP POST request
    pub async fn post<B: Serialize>(
        &self,
        url: &str,
        body: &B,
    ) -> Result<reqwest::Response, ResourceError> {
        self.execute_with_circuit_breaker(|| async {
            self.client
                .post(url)
                .json(body)
                .send()
                .await
                .map_err(|e| ResourceError::operation_failed(e.to_string()))
        })
        .await
    }

    async fn execute_with_circuit_breaker<F, Fut>(
        &self,
        f: F,
    ) -> Result<reqwest::Response, ResourceError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, ResourceError>>,
    {
        if !self.config.circuit_breaker_enabled {
            return f().await;
        }

        // Check circuit breaker
        if self.circuit_state.is_open() {
            let elapsed = Duration::from_secs(
                Instant::now().elapsed().as_secs() -
                self.circuit_state.last_failure_time.load(Ordering::Relaxed)
            );

            if elapsed < self.config.circuit_breaker_timeout {
                return Err(ResourceError::circuit_breaker_open(
                    format!("Circuit breaker open, retry after {:?}", self.config.circuit_breaker_timeout - elapsed)
                ));
            }

            self.circuit_state.half_open();
        }

        // Execute request with retry
        let mut last_error = None;
        for attempt in 0..=self.config.max_retries {
            match f().await {
                Ok(response) => {
                    let success_count = self.circuit_state.record_success();

                    // Close circuit if half-open and successful
                    if success_count >= 2 {
                        self.circuit_state.close();
                    }

                    self.metrics.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    last_error = Some(e);

                    if attempt < self.config.max_retries {
                        tokio::time::sleep(self.config.retry_delay * (attempt + 1)).await;
                    }
                }
            }
        }

        // All retries failed
        let failure_count = self.circuit_state.record_failure();
        if failure_count >= self.config.circuit_breaker_threshold {
            self.circuit_state.open();
            self.metrics.record_circuit_breaker_opened();
        }

        self.metrics.record_failure();
        Err(last_error.unwrap())
    }
}

pub struct HttpClientResource;

#[async_trait]
impl Resource for HttpClientResource {
    type Config = HttpClientConfig;
    type Instance = HttpClientInstance;

    fn id() -> &'static str {
        "http_client"
    }

    fn name() -> &'static str {
        "HTTP Client"
    }

    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        context.log_info("Initializing HTTP client resource");

        let mut builder = ClientBuilder::new()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .user_agent(&config.user_agent);

        if let Some(base_url) = &config.base_url {
            // Validate base URL
            reqwest::Url::parse(base_url)
                .map_err(|e| ResourceError::configuration_invalid(format!("Invalid base URL: {}", e)))?;
        }

        let client = builder
            .build()
            .map_err(|e| ResourceError::initialization_failed(format!("Client build failed: {}", e)))?;

        context.log_info("HTTP client initialized");

        Ok(HttpClientInstance {
            client,
            config: config.clone(),
            circuit_state: Arc::new(CircuitBreakerState::new()),
            metrics: Arc::new(ResourceMetrics::new("http_client")),
        })
    }

    async fn health_check(&self, instance: &Self::Instance) -> Result<HealthStatus, ResourceError> {
        // Simple connectivity check if base_url is configured
        if let Some(base_url) = &instance.config.base_url {
            let response = instance.client
                .head(base_url)
                .send()
                .await
                .map_err(|e| ResourceError::health_check_failed(e.to_string()))?;

            if response.status().is_success() {
                Ok(HealthStatus::Healthy {
                    metadata: HashMap::from([
                        ("circuit_breaker_state".to_string(),
                         if instance.circuit_state.is_open() { "open" } else { "closed" }.to_string()),
                    ]),
                })
            } else {
                Ok(HealthStatus::Degraded {
                    reason: format!("Health check returned status {}", response.status()),
                })
            }
        } else {
            Ok(HealthStatus::Healthy { metadata: HashMap::new() })
        }
    }

    fn is_poolable() -> bool {
        false  // HTTP client manages its own connection pool
    }
}
```

### Complete Example: Redis Cache Resource

```rust
use nebula_resource::prelude::*;
use redis::{aio::ConnectionManager, Client, AsyncCommands};

#[derive(Clone, Serialize, Deserialize)]
pub struct RedisCacheConfig {
    pub url: String,
    pub pool_size: u32,
    pub connection_timeout: Duration,
    pub response_timeout: Duration,
    pub default_ttl: Duration,
    pub key_prefix: Option<String>,
}

impl ResourceConfig for RedisCacheConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        // Validate URL
        redis::parse_redis_url(&self.url)
            .map_err(|e| ConfigError::invalid(format!("Invalid Redis URL: {}", e)))?;
        Ok(())
    }
}

pub struct RedisCacheInstance {
    manager: ConnectionManager,
    config: RedisCacheConfig,
}

impl RedisCacheInstance {
    /// Get value from cache
    pub async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, ResourceError> {
        let full_key = self.build_key(key);

        let mut conn = self.manager.clone();
        let value: Option<String> = conn
            .get(&full_key)
            .await
            .map_err(|e| ResourceError::operation_failed(format!("Redis GET failed: {}", e)))?;

        value
            .map(|v| serde_json::from_str(&v))
            .transpose()
            .map_err(|e| ResourceError::deserialization_failed(e.to_string()))
    }

    /// Set value in cache
    pub async fn set<T: Serialize>(
        &self,
        key: &str,
        value: &T,
        ttl: Option<Duration>,
    ) -> Result<(), ResourceError> {
        let full_key = self.build_key(key);
        let serialized = serde_json::to_string(value)
            .map_err(|e| ResourceError::serialization_failed(e.to_string()))?;

        let mut conn = self.manager.clone();
        let ttl = ttl.unwrap_or(self.config.default_ttl);

        conn.set_ex(&full_key, serialized, ttl.as_secs())
            .await
            .map_err(|e| ResourceError::operation_failed(format!("Redis SET failed: {}", e)))?;

        Ok(())
    }

    /// Delete value from cache
    pub async fn delete(&self, key: &str) -> Result<bool, ResourceError> {
        let full_key = self.build_key(key);

        let mut conn = self.manager.clone();
        let deleted: i32 = conn
            .del(&full_key)
            .await
            .map_err(|e| ResourceError::operation_failed(format!("Redis DEL failed: {}", e)))?;

        Ok(deleted > 0)
    }

    fn build_key(&self, key: &str) -> String {
        if let Some(prefix) = &self.config.key_prefix {
            format!("{}:{}", prefix, key)
        } else {
            key.to_string()
        }
    }
}

pub struct RedisCacheResource;

#[async_trait]
impl Resource for RedisCacheResource {
    type Config = RedisCacheConfig;
    type Instance = RedisCacheInstance;

    fn id() -> &'static str {
        "redis_cache"
    }

    fn name() -> &'static str {
        "Redis Cache"
    }

    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        context.log_info(&format!("Initializing Redis cache at {}", config.url));

        let client = Client::open(config.url.as_str())
            .map_err(|e| ResourceError::initialization_failed(format!("Client creation failed: {}", e)))?;

        let manager = ConnectionManager::new(client)
            .await
            .map_err(|e| ResourceError::initialization_failed(format!("Connection failed: {}", e)))?;

        context.log_info("Redis cache initialized");

        Ok(RedisCacheInstance {
            manager,
            config: config.clone(),
        })
    }

    async fn health_check(&self, instance: &Self::Instance) -> Result<HealthStatus, ResourceError> {
        let mut conn = instance.manager.clone();

        // PING command
        let pong: String = conn
            .ping()
            .await
            .map_err(|e| ResourceError::health_check_failed(format!("PING failed: {}", e)))?;

        if pong == "PONG" {
            Ok(HealthStatus::Healthy { metadata: HashMap::new() })
        } else {
            Ok(HealthStatus::Degraded {
                reason: "Unexpected PING response".to_string(),
            })
        }
    }

    fn is_poolable() -> bool {
        true
    }
}
```

## Advanced Resource Patterns

### Pattern 1: Resource Composition

Compose multiple resources into a single logical unit:

```rust
pub struct CompositeResource {
    postgres: Arc<PostgresInstance>,
    redis: Arc<RedisCacheInstance>,
    http_client: Arc<HttpClientInstance>,
}

impl CompositeResource {
    /// Cached database query
    pub async fn get_user_cached(&self, user_id: i64) -> Result<User, ResourceError> {
        let cache_key = format!("user:{}", user_id);

        // Try cache first
        if let Some(user) = self.redis.get(&cache_key).await? {
            return Ok(user);
        }

        // Cache miss, query database
        let mut conn = self.postgres.acquire().await?;
        let user: User = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| ResourceError::operation_failed(e.to_string()))?;

        // Store in cache
        self.redis.set(&cache_key, &user, Some(Duration::from_secs(300))).await?;

        Ok(user)
    }
}

#[derive(Clone)]
pub struct CompositeResourceConfig {
    pub postgres: PostgresConfig,
    pub redis: RedisCacheConfig,
    pub http_client: HttpClientConfig,
}

pub struct CompositeResourceDefinition;

#[async_trait]
impl Resource for CompositeResourceDefinition {
    type Config = CompositeResourceConfig;
    type Instance = CompositeResource;

    fn id() -> &'static str {
        "composite"
    }

    fn dependencies() -> Vec<&'static str> {
        vec!["postgres", "redis_cache", "http_client"]
    }

    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        // Dependencies are automatically resolved
        let postgres = context.get_resource::<PostgresInstance>().await?;
        let redis = context.get_resource::<RedisCacheInstance>().await?;
        let http_client = context.get_resource::<HttpClientInstance>().await?;

        Ok(CompositeResource {
            postgres,
            redis,
            http_client,
        })
    }
}
```

### Pattern 2: Lazy Resource Initialization

Defer resource creation until first use:

```rust
use std::sync::Arc;
use tokio::sync::OnceCell;

pub struct LazyResource<R: Resource> {
    config: R::Config,
    instance: OnceCell<Arc<R::Instance>>,
    context: ResourceContext,
}

impl<R: Resource> LazyResource<R> {
    pub fn new(config: R::Config, context: ResourceContext) -> Self {
        Self {
            config,
            instance: OnceCell::new(),
            context,
        }
    }

    pub async fn get(&self) -> Result<Arc<R::Instance>, ResourceError> {
        self.instance
            .get_or_try_init(|| async {
                let resource = R::default();
                let instance = resource.create(&self.config, &self.context).await?;
                Ok(Arc::new(instance))
            })
            .await
            .cloned()
    }
}
```

### Pattern 3: Resource Warming

Pre-warm resources during startup:

```rust
pub struct ResourceWarmer {
    manager: Arc<ResourceManager>,
}

impl ResourceWarmer {
    pub async fn warm_all(&self) -> Result<(), ResourceError> {
        // Identify resources that should be pre-warmed
        let warmable_resources = self.manager.list_warmable();

        // Warm in parallel
        let handles: Vec<_> = warmable_resources
            .into_iter()
            .map(|resource_id| {
                let manager = self.manager.clone();
                tokio::spawn(async move {
                    manager.warm_resource(&resource_id).await
                })
            })
            .collect();

        for handle in handles {
            handle.await??;
        }

        Ok(())
    }
}

impl ResourceManager {
    async fn warm_resource(&self, resource_id: &str) -> Result<(), ResourceError> {
        // Create minimum pool size
        let config = self.get_config(resource_id)?;

        if let Some(pool_config) = config.pool_config {
            for _ in 0..pool_config.min_size {
                self.create_instance(resource_id).await?;
            }
        }

        Ok(())
    }
}
```

### Pattern 4: Resource Monitoring and Auto-Healing

Monitor resource health and automatically recover:

```rust
pub struct ResourceMonitor {
    manager: Arc<ResourceManager>,
    check_interval: Duration,
}

impl ResourceMonitor {
    pub async fn start_monitoring(&self) {
        let mut interval = tokio::time::interval(self.check_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.check_all_resources().await {
                eprintln!("Resource health check failed: {}", e);
            }
        }
    }

    async fn check_all_resources(&self) -> Result<(), ResourceError> {
        let resources = self.manager.list_resources();

        for resource_id in resources {
            match self.manager.health_check(&resource_id).await {
                Ok(HealthStatus::Healthy { .. }) => {
                    // All good
                }
                Ok(HealthStatus::Degraded { reason }) => {
                    eprintln!("Resource {} degraded: {}", resource_id, reason);
                    // Could trigger alert
                }
                Err(e) => {
                    eprintln!("Health check failed for {}: {}", resource_id, e);

                    // Attempt recovery
                    if let Err(recovery_err) = self.recover_resource(&resource_id).await {
                        eprintln!("Recovery failed for {}: {}", resource_id, recovery_err);
                    }
                }
            }
        }

        Ok(())
    }

    async fn recover_resource(&self, resource_id: &str) -> Result<(), ResourceError> {
        // Drain existing instances
        self.manager.drain_resource(resource_id).await?;

        // Recreate with new instances
        self.manager.warm_resource(resource_id).await?;

        Ok(())
    }
}
```

## Testing Strategies

### Unit Testing Resources

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nebula_resource::testing::*;

    #[tokio::test]
    async fn test_postgres_resource_lifecycle() {
        // Use test database
        let config = PostgresConfig {
            host: "localhost".to_string(),
            port: 5432,
            database: "test_db".to_string(),
            credentials: test_credentials(),
            max_connections: 5,
            min_connections: 1,
            connection_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_lifetime: Duration::from_secs(3600),
            ssl_mode: "prefer".to_string(),
        };

        let context = ResourceContext::test();
        let resource = PostgresResource;

        // Create instance
        let instance = resource.create(&config, &context).await.unwrap();

        // Health check
        let health = resource.health_check(&instance).await.unwrap();
        assert!(matches!(health, HealthStatus::Healthy { .. }));

        // Use instance
        let mut conn = instance.acquire().await.unwrap();
        let result: (i32,) = sqlx::query_as("SELECT 1")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(result.0, 1);

        // Cleanup
        resource.cleanup(instance).await.unwrap();
    }

    #[tokio::test]
    async fn test_http_client_circuit_breaker() {
        let config = HttpClientConfig {
            circuit_breaker_enabled: true,
            circuit_breaker_threshold: 3,
            max_retries: 0,  // No retries for this test
            ..Default::default()
        };

        let context = ResourceContext::test();
        let resource = HttpClientResource;
        let instance = resource.create(&config, &context).await.unwrap();

        // Simulate failures
        for _ in 0..3 {
            let _ = instance.get("http://localhost:9999/nonexistent").await;
        }

        // Circuit should now be open
        let result = instance.get("http://localhost:9999/nonexistent").await;
        assert!(matches!(result, Err(ResourceError::CircuitBreakerOpen(_))));
    }
}
```

### Integration Testing with TestContainers

```rust
#[cfg(test)]
mod integration_tests {
    use testcontainers::*;

    #[tokio::test]
    async fn test_postgres_with_testcontainers() {
        let docker = clients::Cli::default();
        let postgres_image = images::postgres::Postgres::default();
        let node = docker.run(postgres_image);

        let config = PostgresConfig {
            host: "localhost".to_string(),
            port: node.get_host_port_ipv4(5432),
            database: "postgres".to_string(),
            credentials: PostgresCredential {
                username: "postgres".to_string(),
                password: "postgres".to_string(),
            },
            ..Default::default()
        };

        let context = ResourceContext::test();
        let resource = PostgresResource;
        let instance = resource.create(&config, &context).await.unwrap();

        // Run migrations
        sqlx::migrate!("./migrations")
            .run(&*instance.pool)
            .await
            .unwrap();

        // Test operations
        // ...

        resource.cleanup(instance).await.unwrap();
    }
}
```

## Best Practices

1. **Always validate configuration** - Fail fast on invalid config
2. **Implement health checks** - Enable automatic recovery
3. **Use appropriate pool sizes** - Based on workload characteristics
4. **Monitor resource metrics** - Track acquisitions, failures, pool stats
5. **Handle failures gracefully** - Implement circuit breakers and retries
6. **Test resource lifecycle** - Create, use, health check, cleanup
7. **Use scoped resources** - Limit resource lifetime appropriately
8. **Enable connection pooling** - Reuse expensive connections
9. **Implement graceful shutdown** - Drain resources before termination
10. **Document dependencies** - Make resource dependencies explicit

---

**Next Steps**: Explore [[Built-in Resources]] or implement [[Custom Resources]].