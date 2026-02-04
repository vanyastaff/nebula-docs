---
title: Resource Examples
tags: [nebula, nebula-resource, docs, examples]
status: complete
created: 2025-08-17
updated: 2025-11-09
---

# Resource Examples

This guide provides comprehensive examples for using `nebula-resource` in real-world scenarios, from simple resource acquisition to advanced patterns like dependency injection, custom resources, and distributed resource management.

## Basic Usage

### Simple Resource Acquisition

```rust
use nebula_resource::{ResourceManager, Resource};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize resource manager
    let manager = ResourceManager::builder()
        .build();

    // Register PostgreSQL pool
    manager.register::<PostgresPool>().await?;

    // Acquire resource
    let postgres = manager.acquire::<PostgresPool>().await?;

    // Use resource
    let result = postgres.query("SELECT * FROM users", &[]).await?;

    // Resource is automatically returned to pool on drop
    Ok(())
}
```

### Resource with Configuration

```rust
use nebula_resource::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct HttpClientConfig {
    base_url: String,
    timeout: Duration,
    max_retries: u32,
}

async fn example_with_config() -> Result<()> {
    let manager = ResourceManager::builder()
        .with_config_file("resources.toml")
        .build();

    // Register with custom configuration
    let config = HttpClientConfig {
        base_url: "https://api.example.com".to_string(),
        timeout: Duration::from_secs(30),
        max_retries: 3,
    };

    manager.register_with_config::<HttpClient>(config).await?;

    let client = manager.acquire::<HttpClient>().await?;
    let response = client.get("/endpoint").send().await?;

    Ok(())
}
```

## Database Connection Pooling

### PostgreSQL with Read Replicas

```rust
use nebula_resource::builtin::PostgresPool;

async fn postgres_example(manager: &ResourceManager) -> Result<()> {
    // Configure pool with read replicas
    let config = PostgresPoolConfig {
        connection_string: "postgresql://localhost/mydb".to_string(),
        min_connections: 2,
        max_connections: 20,
        read_replicas: vec![
            "postgresql://replica1/mydb".to_string(),
            "postgresql://replica2/mydb".to_string(),
        ],
        ..Default::default()
    };

    manager.register_with_config::<PostgresPool>(config).await?;

    // Write operation (uses primary)
    let pool = manager.acquire::<PostgresPool>().await?;
    let mut conn = pool.get().await?;
    conn.execute(
        "INSERT INTO users (name, email) VALUES ($1, $2)",
        &[&"Alice", &"alice@example.com"]
    ).await?;

    // Read operation (uses replica)
    let mut read_conn = pool.get_read().await?;
    let rows = read_conn.query(
        "SELECT * FROM users WHERE email = $1",
        &[&"alice@example.com"]
    ).await?;

    for row in rows {
        let name: String = row.get("name");
        let email: String = row.get("email");
        println!("{}: {}", name, email);
    }

    Ok(())
}
```

### Redis Caching with TTL

```rust
use nebula_resource::builtin::RedisPool;
use redis::AsyncCommands;

async fn redis_caching_example(manager: &ResourceManager) -> Result<()> {
    let redis = manager.acquire::<RedisPool>().await?;
    let mut conn = redis.get().await?;

    // Set value with TTL
    conn.set_ex("user:123", "Alice", 3600).await?;

    // Get value
    let value: Option<String> = conn.get("user:123").await?;
    println!("Cached value: {:?}", value);

    // Atomic increment
    let counter: i64 = conn.incr("page:views", 1).await?;
    println!("Page views: {}", counter);

    // Use pipeline for batching
    let results: Vec<String> = redis::pipe()
        .set("key1", "value1")
        .set("key2", "value2")
        .get("key1")
        .get("key2")
        .query_async(&mut conn)
        .await?;

    Ok(())
}
```

### MongoDB with Change Streams

```rust
use nebula_resource::builtin::MongoPool;
use mongodb::bson::{doc, Document};
use futures::stream::StreamExt;

async fn mongodb_change_stream_example(manager: &ResourceManager) -> Result<()> {
    let mongo = manager.acquire::<MongoPool>().await?;
    let db = mongo.database();
    let collection = db.collection::<Document>("users");

    // Insert document
    collection.insert_one(doc! {
        "name": "Alice",
        "age": 30,
        "email": "alice@example.com"
    }, None).await?;

    // Watch for changes
    let mut change_stream = collection.watch(None, None).await?;

    tokio::spawn(async move {
        while let Some(event) = change_stream.next().await {
            match event {
                Ok(change) => {
                    println!("Change detected: {:?}", change);
                }
                Err(e) => {
                    eprintln!("Change stream error: {}", e);
                }
            }
        }
    });

    Ok(())
}
```

## HTTP Client Patterns

### REST API Client with Retries

```rust
use nebula_resource::builtin::HttpClient;
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct ApiResponse {
    data: Vec<User>,
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: u64,
    name: String,
    email: String,
}

async fn rest_api_example(manager: &ResourceManager) -> Result<()> {
    let client = manager.acquire::<HttpClient>().await?;

    // GET request with automatic retries
    let response = client
        .get("https://api.example.com/users")
        .send()
        .await?;

    let api_response: ApiResponse = response.json().await?;
    println!("Found {} users", api_response.data.len());

    // POST request with JSON body
    let new_user = User {
        id: 0,
        name: "Bob".to_string(),
        email: "bob@example.com".to_string(),
    };

    let response = client
        .post("https://api.example.com/users")
        .json(&new_user)
        .send()
        .await?;

    let created_user: User = response.json().await?;
    println!("Created user: {:?}", created_user);

    Ok(())
}
```

### GraphQL Client

```rust
use serde_json::json;

async fn graphql_example(manager: &ResourceManager) -> Result<()> {
    let client = manager.acquire::<HttpClient>().await?;

    let query = json!({
        "query": r#"
            query GetUser($id: ID!) {
                user(id: $id) {
                    id
                    name
                    email
                }
            }
        "#,
        "variables": {
            "id": "123"
        }
    });

    let response = client
        .post("https://api.example.com/graphql")
        .json(&query)
        .send()
        .await?;

    let result: serde_json::Value = response.json().await?;
    println!("GraphQL result: {}", result);

    Ok(())
}
```

## Message Queue Integration

### Kafka Producer/Consumer

```rust
use nebula_resource::builtin::KafkaClient;
use rdkafka::message::OwnedMessage;
use futures::stream::StreamExt;

async fn kafka_example(manager: &ResourceManager) -> Result<()> {
    let kafka = manager.acquire::<KafkaClient>().await?;

    // Produce messages
    let topic = "user-events";
    for i in 0..10 {
        let payload = format!("Event {}", i);
        kafka.send(topic, &format!("key-{}", i), payload.as_bytes()).await?;
        println!("Sent: {}", payload);
    }

    // Consume messages
    if let Some(consumer) = kafka.consumer() {
        consumer.subscribe(&[topic])?;

        let mut message_stream = consumer.stream();
        while let Some(message) = message_stream.next().await {
            match message {
                Ok(msg) => {
                    let payload = msg.payload_view::<str>()
                        .unwrap()
                        .unwrap();
                    println!("Received: {}", payload);

                    // Manual commit
                    consumer.commit_message(&msg, rdkafka::consumer::CommitMode::Async)?;
                }
                Err(e) => {
                    eprintln!("Error consuming message: {}", e);
                }
            }
        }
    }

    Ok(())
}
```

### RabbitMQ with Work Queues

```rust
use nebula_resource::builtin::RabbitMQClient;
use lapin::{
    options::*, types::FieldTable, BasicProperties, Connection, ConnectionProperties
};

async fn rabbitmq_example(manager: &ResourceManager) -> Result<()> {
    let rabbit = manager.acquire::<RabbitMQClient>().await?;
    let channel = rabbit.create_channel().await?;

    // Declare queue
    let queue_name = "tasks";
    channel.queue_declare(
        queue_name,
        QueueDeclareOptions::default(),
        FieldTable::default(),
    ).await?;

    // Publish messages
    for i in 0..10 {
        let payload = format!("Task {}", i);
        channel.basic_publish(
            "",
            queue_name,
            BasicPublishOptions::default(),
            payload.as_bytes(),
            BasicProperties::default(),
        ).await?;
        println!("Published: {}", payload);
    }

    // Consume messages
    let consumer = channel
        .basic_consume(
            queue_name,
            "worker",
            BasicConsumeOptions::default(),
            FieldTable::default(),
        )
        .await?;

    consumer.for_each(|delivery| async {
        if let Ok((channel, delivery)) = delivery {
            let payload = String::from_utf8_lossy(&delivery.data);
            println!("Processing: {}", payload);

            // Simulate work
            tokio::time::sleep(Duration::from_secs(1)).await;

            // Acknowledge
            channel.basic_ack(delivery.delivery_tag, BasicAckOptions::default())
                .await
                .expect("Failed to ack");
        }
    }).await;

    Ok(())
}
```

## Custom Resource Implementation

### Custom Database Connection

```rust
use nebula_resource::{Resource, ResourceConfig, ResourceContext, ResourceError};
use async_trait::async_trait;

// Custom configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDbConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub max_connections: usize,
}

impl ResourceConfig for CustomDbConfig {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.host.is_empty() {
            return Err(ValidationError::new("host cannot be empty"));
        }
        if self.port == 0 {
            return Err(ValidationError::new("port must be > 0"));
        }
        Ok(())
    }
}

// Custom resource
pub struct CustomDbPool {
    pool: Arc<InternalPool>,
    config: CustomDbConfig,
    metrics: Arc<MetricsCollector>,
}

#[async_trait]
impl Resource for CustomDbPool {
    type Config = CustomDbConfig;
    type Instance = CustomDbConnection;

    async fn create(config: &Self::Config, context: &ResourceContext)
        -> Result<Self, ResourceError> {
        config.validate()?;

        let pool = InternalPool::new(
            &config.host,
            config.port,
            &config.database,
            config.max_connections,
        ).await?;

        Ok(Self {
            pool: Arc::new(pool),
            config: config.clone(),
            metrics: context.metrics().clone(),
        })
    }

    async fn health_check(&self) -> HealthStatus {
        match self.pool.ping().await {
            Ok(_) => HealthStatus::Healthy,
            Err(e) => HealthStatus::Unhealthy(e.to_string()),
        }
    }

    async fn on_acquire(&self, context: &ResourceContext) -> Result<(), ResourceError> {
        self.metrics.increment_counter("resource.acquired", &[
            ("resource_type", "CustomDbPool".to_string()),
        ]);
        Ok(())
    }

    async fn on_release(&self, context: &ResourceContext) -> Result<(), ResourceError> {
        self.metrics.increment_counter("resource.released", &[
            ("resource_type", "CustomDbPool".to_string()),
        ]);
        Ok(())
    }
}

// Usage
async fn custom_resource_example() -> Result<()> {
    let manager = ResourceManager::builder().build();

    let config = CustomDbConfig {
        host: "localhost".to_string(),
        port: 5432,
        database: "mydb".to_string(),
        max_connections: 10,
    };

    manager.register_with_config::<CustomDbPool>(config).await?;

    let db = manager.acquire::<CustomDbPool>().await?;
    // Use custom database...

    Ok(())
}
```

## Resource Scoping

### Workflow-Scoped Resources

```rust
use nebula_resource::scope::{Scope, ScopedResourceManager};

async fn workflow_scoped_example() -> Result<()> {
    let manager = ScopedResourceManager::new();

    // Create workflow scope
    let workflow_id = "workflow-123";
    let workflow_scope = Scope::Workflow(workflow_id.to_string());

    // Register resources in workflow scope
    manager.register_scoped::<PostgresPool>(workflow_scope.clone()).await?;
    manager.register_scoped::<RedisPool>(workflow_scope.clone()).await?;

    // Acquire resources (scoped to workflow)
    let postgres = manager.acquire_scoped::<PostgresPool>(&workflow_scope).await?;
    let redis = manager.acquire_scoped::<RedisPool>(&workflow_scope).await?;

    // Use resources...
    postgres.query("SELECT * FROM tasks WHERE workflow_id = $1", &[&workflow_id]).await?;

    // Resources are automatically cleaned up when workflow scope is dropped
    manager.cleanup_scope(&workflow_scope).await?;

    Ok(())
}
```

### Tenant-Isolated Resources

```rust
async fn tenant_isolation_example() -> Result<()> {
    let manager = ScopedResourceManager::new();

    // Create tenant-specific scopes
    let tenant_a_scope = Scope::Tenant("tenant-a".to_string());
    let tenant_b_scope = Scope::Tenant("tenant-b".to_string());

    // Register separate database pools per tenant
    let tenant_a_config = PostgresPoolConfig {
        connection_string: "postgresql://tenant-a-db/data".to_string(),
        ..Default::default()
    };

    let tenant_b_config = PostgresPoolConfig {
        connection_string: "postgresql://tenant-b-db/data".to_string(),
        ..Default::default()
    };

    manager.register_scoped_with_config::<PostgresPool>(
        tenant_a_scope.clone(),
        tenant_a_config,
    ).await?;

    manager.register_scoped_with_config::<PostgresPool>(
        tenant_b_scope.clone(),
        tenant_b_config,
    ).await?;

    // Each tenant gets isolated resources
    let tenant_a_db = manager.acquire_scoped::<PostgresPool>(&tenant_a_scope).await?;
    let tenant_b_db = manager.acquire_scoped::<PostgresPool>(&tenant_b_scope).await?;

    // Tenants cannot access each other's resources
    Ok(())
}
```

## Advanced Patterns

### Resource Dependency Chain

```rust
use nebula_resource::dependency::{DependencyGraph, DependsOn};

#[derive(DependsOn)]
#[depends_on(Logger, MetricsCollector)]
struct PostgresPool {
    // ... PostgresPool automatically waits for Logger and MetricsCollector
}

async fn dependency_chain_example() -> Result<()> {
    let manager = ResourceManager::builder()
        .with_dependency_resolution()
        .build();

    // Resources registered in any order
    manager.register::<PostgresPool>().await?;  // Depends on Logger + Metrics
    manager.register::<Logger>().await?;
    manager.register::<MetricsCollector>().await?;

    // Manager ensures correct initialization order:
    // 1. Logger
    // 2. MetricsCollector
    // 3. PostgresPool

    let postgres = manager.acquire::<PostgresPool>().await?;

    Ok(())
}
```

### Circuit Breaker Pattern

```rust
use nebula_resource::patterns::CircuitBreaker;

async fn circuit_breaker_example(manager: &ResourceManager) -> Result<()> {
    let http_client = manager.acquire::<HttpClient>().await?;

    let circuit_breaker = CircuitBreaker::builder()
        .failure_threshold(5)
        .timeout(Duration::from_secs(60))
        .build();

    for _ in 0..10 {
        match circuit_breaker.call(|| async {
            http_client.get("https://flaky-api.example.com/data").send().await
        }).await {
            Ok(response) => {
                println!("Request succeeded: {:?}", response.status());
            }
            Err(e) => {
                eprintln!("Request failed: {}", e);
            }
        }
    }

    Ok(())
}
```

### Resource Pooling with Warming

```rust
async fn pool_warming_example() -> Result<()> {
    let manager = ResourceManager::builder()
        .with_pool_warming(true)
        .with_min_pool_size(5)
        .build();

    manager.register::<PostgresPool>().await?;

    // Warm up pool (create min_pool_size connections)
    manager.warmup::<PostgresPool>().await?;

    // Connections are immediately available
    let postgres = manager.acquire::<PostgresPool>().await?;
    // No initialization delay!

    Ok(())
}
```

## Testing Examples

### Mock Resources for Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nebula_resource::testing::{MockResourceManager, MockResource};

    #[tokio::test]
    async fn test_with_mock_resources() {
        let manager = MockResourceManager::new();

        // Register mock
        let mock_db = MockPostgresPool::new();
        mock_db.expect_query()
            .with(eq("SELECT * FROM users"))
            .returning(|_| Ok(vec![/* mock rows */]));

        manager.register_mock(mock_db).await.unwrap();

        // Test code that uses resources
        let result = my_function_that_uses_db(&manager).await;
        assert!(result.is_ok());
    }
}
```

## Performance Monitoring

### Resource Metrics Collection

```rust
async fn metrics_example(manager: &ResourceManager) -> Result<()> {
    let metrics = manager.metrics();

    // Resource acquisition metrics
    let acquisition_duration = metrics.histogram("resource.acquisition.duration");
    let acquisition_count = metrics.counter("resource.acquisitions.total");

    // Pool utilization
    let pool_size = metrics.gauge("resource.pool.size");
    let pool_utilization = metrics.gauge("resource.pool.utilization");

    // Health check metrics
    let health_check_failures = metrics.counter("resource.health_checks.failed");

    // Export metrics to Prometheus
    let prometheus_exporter = metrics.prometheus_exporter();
    let metrics_text = prometheus_exporter.encode_to_string()?;

    Ok(())
}
```

## Complete Application Example

```rust
use nebula_resource::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize resource manager
    let manager = ResourceManager::builder()
        .with_config_file("resources.toml")
        .with_dependency_resolution()
        .with_health_checks(Duration::from_secs(30))
        .with_metrics_enabled(true)
        .build();

    // Register all resources
    manager.register::<Logger>().await?;
    manager.register::<MetricsCollector>().await?;
    manager.register::<PostgresPool>().await?;
    manager.register::<RedisPool>().await?;
    manager.register::<HttpClient>().await?;
    manager.register::<KafkaClient>().await?;

    // Warm up pools
    manager.warmup_all().await?;

    // Start health check monitor
    tokio::spawn(manager.clone().start_health_monitor());

    // Application logic
    let app_state = AppState { manager };
    let app = create_app(app_state);

    // Run application
    axum::Server::bind(&"0.0.0.0:3000".parse()?)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

struct AppState {
    manager: Arc<ResourceManager>,
}

async fn handle_request(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Response>, StatusCode> {
    // Acquire resources
    let postgres = state.manager.acquire::<PostgresPool>().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let redis = state.manager.acquire::<RedisPool>().await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    // Use resources...
    let users = fetch_users(&postgres).await?;
    cache_users(&redis, &users).await?;

    Ok(Json(Response { users }))
}
```

## Links

- [[02-Crates/nebula-resource/Architecture|Resource Architecture]]
- [[02-Crates/nebula-resource/Built-in Resources|Built-in Resources]]
- [[02-Crates/nebula-resource/Resource Lifecycle|Resource Lifecycle]]
- [[02-Crates/nebula-resource/Scoped Resources|Scoped Resources]]
- [[04-Development/Testing Resources]]
