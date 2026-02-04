---
title: Built-in Resources
tags: [nebula, nebula-resource, docs]
status: complete
created: 2025-08-17
updated: 2025-11-09
---

# Built-in Resources

**Built-in resources** are production-ready resource implementations provided by `nebula-resource`. These resources handle common infrastructure needs like database connections, HTTP clients, message queues, caching, logging, and metrics collection with built-in pooling, health checks, and observability.

## Overview

```mermaid
graph TD
    A[Built-in Resources] --> B[Data Layer]
    A --> C[Network Layer]
    A --> D[Messaging]
    A --> E[Observability]
    A --> F[Caching]
    A --> G[System]

    B --> B1[PostgreSQL Pool]
    B --> B2[Redis Pool]
    B --> B3[MongoDB Pool]
    B --> B4[SQLite Pool]

    C --> C1[HTTP Client]
    C --> C2[gRPC Client]
    C --> C3[WebSocket Client]

    D --> D1[Kafka Client]
    D --> D2[RabbitMQ Client]
    D --> D3[NATS Client]

    E --> E1[Logger]
    E --> E2[Metrics Collector]
    E --> E3[Tracer]

    F --> F1[In-Memory Cache]
    F --> F2[Distributed Cache]

    G --> G1[Thread Pool]
    G --> G2[File System]
```

## Data Layer Resources

### PostgreSQL Pool

High-performance PostgreSQL connection pool with automatic failover and read replica support.

```rust
use nebula_resource::builtin::PostgresPool;
use nebula_resource::{Resource, ResourceContext};

#[derive(Debug, Serialize, Deserialize)]
pub struct PostgresPoolConfig {
    /// Connection string
    pub connection_string: String,
    /// Minimum connections in pool
    pub min_connections: u32,
    /// Maximum connections in pool
    pub max_connections: u32,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Idle timeout
    pub idle_timeout: Duration,
    /// Enable TLS
    pub tls_enabled: bool,
    /// Read replicas for read-only queries
    pub read_replicas: Vec<String>,
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            connection_string: String::new(),
            min_connections: 2,
            max_connections: 20,
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_mins(10),
            tls_enabled: true,
            read_replicas: Vec::new(),
        }
    }
}

pub struct PostgresPool {
    pool: Arc<deadpool_postgres::Pool>,
    read_pools: Vec<Arc<deadpool_postgres::Pool>>,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for PostgresPool {
    type Config = PostgresPoolConfig;
    type Instance = PostgresConnection;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        // Create main pool
        let pool_config = deadpool_postgres::Config {
            host: Some(extract_host(&config.connection_string)?),
            port: Some(extract_port(&config.connection_string)?),
            dbname: Some(extract_dbname(&config.connection_string)?),
            manager: Some(ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            }),
            ..Default::default()
        };

        let pool = pool_config
            .create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)?;

        // Create read replica pools
        let mut read_pools = Vec::new();
        for replica_url in &config.read_replicas {
            let replica_config = deadpool_postgres::Config {
                host: Some(extract_host(replica_url)?),
                // ... similar config
            };
            let replica_pool = replica_config.create_pool(Some(Runtime::Tokio1), tokio_postgres::NoTls)?;
            read_pools.push(Arc::new(replica_pool));
        }

        Ok(Self {
            pool: Arc::new(pool),
            read_pools,
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        match self.pool.get().await {
            Ok(conn) => {
                match conn.query_one("SELECT 1", &[]).await {
                    Ok(_) => HealthStatus::Healthy,
                    Err(e) => HealthStatus::Unhealthy(e.to_string()),
                }
            }
            Err(e) => HealthStatus::Unhealthy(format!("Failed to acquire connection: {}", e)),
        }
    }
}

impl PostgresPool {
    /// Get connection for read/write operations
    pub async fn get(&self) -> Result<PostgresConnection, ResourceError> {
        let start = Instant::now();
        let conn = self.pool.get().await?;
        self.metrics.record_acquisition(start.elapsed());
        Ok(PostgresConnection { conn, read_only: false })
    }

    /// Get connection for read-only operations (uses read replica if available)
    pub async fn get_read(&self) -> Result<PostgresConnection, ResourceError> {
        if self.read_pools.is_empty() {
            return self.get().await;
        }

        // Round-robin selection of read replicas
        let pool_idx = rand::thread_rng().gen_range(0..self.read_pools.len());
        let conn = self.read_pools[pool_idx].get().await?;
        Ok(PostgresConnection { conn, read_only: true })
    }
}

// Usage example
async fn example_postgres_usage(manager: &ResourceManager) -> Result<()> {
    let postgres_pool = manager.acquire::<PostgresPool>().await?;

    // Write operation
    let mut conn = postgres_pool.get().await?;
    conn.execute("INSERT INTO users (name) VALUES ($1)", &[&"Alice"]).await?;

    // Read operation (uses read replica if configured)
    let mut read_conn = postgres_pool.get_read().await?;
    let rows = read_conn.query("SELECT * FROM users", &[]).await?;

    Ok(())
}
```

### Redis Pool

Redis connection pool with clustering and sentinel support.

```rust
use redis::aio::ConnectionManager;

#[derive(Debug, Serialize, Deserialize)]
pub struct RedisPoolConfig {
    /// Connection URLs
    pub nodes: Vec<String>,
    /// Pool size
    pub pool_size: usize,
    /// Connection timeout
    pub timeout: Duration,
    /// Enable cluster mode
    pub cluster_mode: bool,
    /// Enable TLS
    pub tls_enabled: bool,
    /// Password
    pub password: Option<SecretString>,
}

pub struct RedisPool {
    pool: Arc<deadpool_redis::Pool>,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for RedisPool {
    type Config = RedisPoolConfig;
    type Instance = RedisConnection;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        let redis_config = if config.cluster_mode {
            redis::cluster::ClusterClientBuilder::new(config.nodes.clone())
                .password(config.password.as_ref().map(|p| p.expose_secret().to_string()))
                .build()?
        } else {
            redis::Client::open(config.nodes[0].as_str())?
        };

        let pool = deadpool_redis::Pool::builder(redis_config)
            .max_size(config.pool_size)
            .build()?;

        Ok(Self {
            pool: Arc::new(pool),
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        match self.pool.get().await {
            Ok(mut conn) => {
                match redis::cmd("PING").query_async(&mut conn).await {
                    Ok(redis::Value::Status(ref s)) if s == "PONG" => HealthStatus::Healthy,
                    _ => HealthStatus::Unhealthy("Invalid PING response".to_string()),
                }
            }
            Err(e) => HealthStatus::Unhealthy(e.to_string()),
        }
    }
}

// Usage example
async fn example_redis_usage(manager: &ResourceManager) -> Result<()> {
    let redis_pool = manager.acquire::<RedisPool>().await?;
    let mut conn = redis_pool.get().await?;

    // Set value
    redis::cmd("SET")
        .arg("key")
        .arg("value")
        .query_async(&mut conn)
        .await?;

    // Get value
    let value: String = redis::cmd("GET")
        .arg("key")
        .query_async(&mut conn)
        .await?;

    Ok(())
}
```

### MongoDB Pool

MongoDB connection pool with change stream support.

```rust
use mongodb::{Client, options::ClientOptions};

#[derive(Debug, Serialize, Deserialize)]
pub struct MongoPoolConfig {
    pub connection_string: String,
    pub database: String,
    pub min_pool_size: u32,
    pub max_pool_size: u32,
    pub server_selection_timeout: Duration,
}

pub struct MongoPool {
    client: Client,
    database_name: String,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for MongoPool {
    type Config = MongoPoolConfig;
    type Instance = mongodb::Database;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        let mut client_options = ClientOptions::parse(&config.connection_string).await?;
        client_options.min_pool_size = Some(config.min_pool_size);
        client_options.max_pool_size = Some(config.max_pool_size);
        client_options.server_selection_timeout = Some(config.server_selection_timeout);

        let client = Client::with_options(client_options)?;

        Ok(Self {
            client,
            database_name: config.database.clone(),
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        match self.client.list_database_names(None, None).await {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Unhealthy(e.to_string()),
        }
    }
}

impl MongoPool {
    pub fn database(&self) -> mongodb::Database {
        self.client.database(&self.database_name)
    }
}
```

## Network Layer Resources

### HTTP Client

Production-ready HTTP client with connection pooling, retries, and circuit breaker.

```rust
use reqwest::{Client, ClientBuilder};

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpClientConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Connection pool size
    pub pool_max_idle_per_host: usize,
    /// Retry attempts
    pub max_retries: u32,
    /// Circuit breaker threshold
    pub circuit_breaker_threshold: u32,
    /// User agent
    pub user_agent: String,
    /// Enable compression
    pub gzip: bool,
    /// Enable TLS verification
    pub tls_verify: bool,
}

pub struct HttpClient {
    client: Client,
    retry_policy: RetryPolicy,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for HttpClient {
    type Config = HttpClientConfig;
    type Instance = HttpClient;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        let client = ClientBuilder::new()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .user_agent(&config.user_agent)
            .gzip(config.gzip)
            .danger_accept_invalid_certs(!config.tls_verify)
            .build()?;

        let retry_policy = RetryPolicy::new(config.max_retries);
        let circuit_breaker = CircuitBreaker::new(config.circuit_breaker_threshold);

        Ok(Self {
            client,
            retry_policy,
            circuit_breaker,
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        // HTTP client is always healthy if constructed
        HealthStatus::Healthy
    }
}

impl HttpClient {
    /// Execute GET request with retries
    pub async fn get(&self, url: &str) -> Result<reqwest::Response, ResourceError> {
        self.execute_with_retry(|| async {
            self.client.get(url).send().await
        }).await
    }

    /// Execute POST request with retries
    pub async fn post(&self, url: &str, body: impl Into<reqwest::Body>)
        -> Result<reqwest::Response, ResourceError> {
        self.execute_with_retry(|| async {
            self.client.post(url).body(body).send().await
        }).await
    }

    async fn execute_with_retry<F, Fut>(&self, f: F) -> Result<reqwest::Response, ResourceError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        if !self.circuit_breaker.allow_request() {
            return Err(ResourceError::CircuitBreakerOpen);
        }

        let mut attempts = 0;
        loop {
            match f().await {
                Ok(resp) => {
                    self.circuit_breaker.record_success();
                    return Ok(resp);
                }
                Err(e) if attempts < self.retry_policy.max_attempts => {
                    attempts += 1;
                    let backoff = self.retry_policy.backoff_duration(attempts);
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => {
                    self.circuit_breaker.record_failure();
                    return Err(ResourceError::from(e));
                }
            }
        }
    }
}

// Usage example
async fn example_http_usage(manager: &ResourceManager) -> Result<()> {
    let http_client = manager.acquire::<HttpClient>().await?;

    let response = http_client.get("https://api.example.com/data").await?;
    let body = response.json::<serde_json::Value>().await?;

    Ok(())
}
```

## Messaging Resources

### Kafka Client

Apache Kafka producer and consumer with exactly-once semantics.

```rust
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::consumer::{StreamConsumer, Consumer};

#[derive(Debug, Serialize, Deserialize)]
pub struct KafkaConfig {
    pub brokers: Vec<String>,
    pub client_id: String,
    pub security_protocol: SecurityProtocol,
    pub producer_config: ProducerConfig,
    pub consumer_config: Option<ConsumerConfig>,
}

pub struct KafkaClient {
    producer: FutureProducer,
    consumer: Option<StreamConsumer>,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for KafkaClient {
    type Config = KafkaConfig;
    type Instance = KafkaClient;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        let mut producer_config = rdkafka::config::ClientConfig::new();
        producer_config
            .set("bootstrap.servers", config.brokers.join(","))
            .set("client.id", &config.client_id)
            .set("message.timeout.ms", "30000");

        let producer: FutureProducer = producer_config.create()?;

        let consumer = if let Some(consumer_cfg) = &config.consumer_config {
            let mut consumer_config = rdkafka::config::ClientConfig::new();
            consumer_config
                .set("bootstrap.servers", config.brokers.join(","))
                .set("group.id", &consumer_cfg.group_id)
                .set("enable.auto.commit", "false");

            let consumer: StreamConsumer = consumer_config.create()?;
            Some(consumer)
        } else {
            None
        };

        Ok(Self {
            producer,
            consumer,
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        // Check broker connectivity
        match self.producer.client().fetch_metadata(None, Duration::from_secs(5)) {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Unhealthy(e.to_string()),
        }
    }
}

impl KafkaClient {
    pub async fn send(&self, topic: &str, key: &str, payload: &[u8])
        -> Result<(), ResourceError> {
        let record = FutureRecord::to(topic)
            .key(key)
            .payload(payload);

        self.producer.send(record, Duration::from_secs(0)).await
            .map_err(|(e, _)| ResourceError::from(e))?;

        Ok(())
    }
}
```

## Observability Resources

### Logger

Structured logging with context propagation and log aggregation.

```rust
use tracing::{Level, Subscriber};
use tracing_subscriber::{Layer, Registry};

#[derive(Debug, Serialize, Deserialize)]
pub struct LoggerConfig {
    pub level: LogLevel,
    pub format: LogFormat,
    pub output: LogOutput,
    pub structured: bool,
}

pub struct Logger {
    subscriber: Arc<dyn Subscriber + Send + Sync>,
}

#[async_trait]
impl Resource for Logger {
    type Config = LoggerConfig;
    type Instance = Logger;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        let level = match config.level {
            LogLevel::Trace => Level::TRACE,
            LogLevel::Debug => Level::DEBUG,
            LogLevel::Info => Level::INFO,
            LogLevel::Warn => Level::WARN,
            LogLevel::Error => Level::ERROR,
        };

        let subscriber = tracing_subscriber::fmt()
            .with_max_level(level)
            .json()
            .finish();

        Ok(Self {
            subscriber: Arc::new(subscriber),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}
```

### Metrics Collector

Prometheus-compatible metrics collection.

```rust
use prometheus::{Registry, Counter, Histogram, Gauge};

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub namespace: String,
    pub subsystem: String,
    pub push_gateway: Option<String>,
    pub push_interval: Duration,
}

pub struct MetricsCollector {
    registry: Registry,
    counters: DashMap<String, Counter>,
    histograms: DashMap<String, Histogram>,
    gauges: DashMap<String, Gauge>,
}

impl MetricsCollector {
    pub fn increment_counter(&self, name: &str, labels: &[(&str, String)]) {
        let key = format!("{}_{}", name, labels.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(","));

        let counter = self.counters.entry(key.clone()).or_insert_with(|| {
            let opts = prometheus::Opts::new(name, "Counter metric")
                .const_labels(labels.iter().cloned().collect());
            let counter = Counter::with_opts(opts).unwrap();
            self.registry.register(Box::new(counter.clone())).unwrap();
            counter
        });

        counter.inc();
    }

    pub fn record_histogram(&self, name: &str, value: f64, labels: &[(&str, String)]) {
        // Similar implementation
    }

    pub fn set_gauge(&self, name: &str, value: f64, labels: &[(&str, String)]) {
        // Similar implementation
    }
}
```

## Configuration Examples

### Complete Resource Configuration

```toml
[resources.postgres]
type = "PostgresPool"
connection_string = "postgresql://user:pass@localhost/db"
min_connections = 2
max_connections = 20
connect_timeout = "5s"
idle_timeout = "10m"
tls_enabled = true
read_replicas = [
    "postgresql://user:pass@replica1/db",
    "postgresql://user:pass@replica2/db"
]

[resources.redis]
type = "RedisPool"
nodes = ["redis://localhost:6379"]
pool_size = 10
timeout = "5s"
cluster_mode = false

[resources.http_client]
type = "HttpClient"
connect_timeout = "5s"
request_timeout = "30s"
pool_max_idle_per_host = 10
max_retries = 3
circuit_breaker_threshold = 5
user_agent = "Nebula/1.0"
gzip = true

[resources.kafka]
type = "KafkaClient"
brokers = ["localhost:9092"]
client_id = "nebula-producer"
security_protocol = "PLAINTEXT"

[resources.logger]
type = "Logger"
level = "info"
format = "json"
structured = true

[resources.metrics]
type = "MetricsCollector"
namespace = "nebula"
subsystem = "workflow"
push_gateway = "http://localhost:9091"
push_interval = "15s"
```

## Best Practices

### 1. Connection Pool Sizing

```rust
// Calculate optimal pool size
fn calculate_pool_size(cpu_cores: usize, io_bound: bool) -> usize {
    if io_bound {
        // IO-bound: more connections needed
        cpu_cores * 2 + 1
    } else {
        // CPU-bound: fewer connections
        cpu_cores + 1
    }
}
```

### 2. Health Check Configuration

```rust
// Configure health checks appropriately
let health_check_config = HealthCheckConfig {
    interval: Duration::from_secs(30),
    timeout: Duration::from_secs(5),
    unhealthy_threshold: 3,
    healthy_threshold: 2,
};
```

### 3. Resource Lifecycle Management

```rust
// Proper resource initialization and cleanup
async fn initialize_resources(manager: &ResourceManager) -> Result<()> {
    // Register resources in dependency order
    manager.register::<Logger>().await?;
    manager.register::<MetricsCollector>().await?;
    manager.register::<PostgresPool>().await?;
    manager.register::<RedisPool>().await?;
    manager.register::<HttpClient>().await?;
    manager.register::<KafkaClient>().await?;

    // Warm up pools
    manager.warmup_all().await?;

    Ok(())
}
```

## Links

- [[02-Crates/nebula-resource/Architecture|Resource Architecture]]
- [[02-Crates/nebula-resource/Examples|Usage Examples]]
- [[02-Crates/nebula-resource/Resource Lifecycle|Resource Lifecycle]]
- [[04-Development/Resource Development]]
