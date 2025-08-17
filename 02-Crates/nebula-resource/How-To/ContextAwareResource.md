---

title: Context-Aware Resource
tags: [nebula-resource, how-to, context, observability]
status: stable
created: 2025-08-17

---

# Context-Aware Resource

Guide to creating resources that automatically capture and propagate execution context for enhanced observability and debugging.

## Overview

Context-aware resources automatically:

- Capture execution context (workflow ID, user, tenant, etc.)
- Propagate context through distributed systems
- Add context to logs, metrics, and traces
- Support multi-tenancy
- Enable request correlation

## Basic Context Awareness

### Step 1: Define Context-Aware Resource

```rust
use nebula_resource::prelude::*;
use nebula_resource::context::*;

#[derive(Resource)]
#[resource(
    id = "context_logger",
    name = "Context-Aware Logger",
    context_aware = true,  // Enable context awareness
)]
pub struct ContextLoggerResource;

pub struct ContextLoggerInstance {
    id: ResourceInstanceId,
    writer: Arc<dyn LogWriter>,
    context: Arc<RwLock<ExecutionContext>>,
    correlation_id: String,
}

/// Execution context that flows through the system
#[derive(Clone, Debug)]
pub struct ExecutionContext {
    pub execution_id: String,
    pub workflow_id: String,
    pub action_id: String,
    pub user_id: Option<String>,
    pub tenant_id: Option<String>,
    pub account_id: Option<String>,
    pub correlation_id: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub baggage: HashMap<String, String>,
    pub start_time: DateTime<Utc>,
}

impl ExecutionContext {
    /// Create child context for nested operations
    pub fn child(&self, action_id: &str) -> Self {
        Self {
            action_id: action_id.to_string(),
            parent_span_id: self.span_id.clone(),
            span_id: Some(generate_span_id()),
            start_time: Utc::now(),
            ..self.clone()
        }
    }
    
    /// Add custom baggage that propagates
    pub fn with_baggage(mut self, key: String, value: String) -> Self {
        self.baggage.insert(key, value);
        self
    }
}
```

### Step 2: Automatic Context Injection

```rust
#[async_trait]
impl ContextAwareResource for ContextLoggerResource {
    type Context = ExecutionContext;
    
    /// Create instance with context
    async fn create_with_context(
        &self,
        config: &Self::Config,
        context: ExecutionContext,
        resource_context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        let correlation_id = context.correlation_id.clone();
        
        resource_context.log_info(&format!(
            "Creating context-aware logger for workflow: {}, correlation: {}",
            context.workflow_id, correlation_id
        ));
        
        Ok(ContextLoggerInstance {
            id: ResourceInstanceId::new(),
            writer: Arc::new(JsonLogWriter::new()),
            context: Arc::new(RwLock::new(context)),
            correlation_id,
        })
    }
    
    /// Update context when it changes
    async fn update_context(
        &self,
        instance: &mut Self::Instance,
        new_context: ExecutionContext,
    ) -> Result<(), ResourceError> {
        *instance.context.write().await = new_context;
        Ok(())
    }
}

impl ContextLoggerInstance {
    /// Log with automatic context
    pub async fn log(&self, level: LogLevel, message: &str) {
        let context = self.context.read().await;
        
        let log_entry = ContextualLogEntry {
            timestamp: Utc::now(),
            level,
            message: message.to_string(),
            
            // Automatic context fields
            execution_id: context.execution_id.clone(),
            workflow_id: context.workflow_id.clone(),
            action_id: context.action_id.clone(),
            correlation_id: self.correlation_id.clone(),
            
            // Optional context fields
            user_id: context.user_id.clone(),
            tenant_id: context.tenant_id.clone(),
            account_id: context.account_id.clone(),
            
            // Tracing context
            trace_id: context.trace_id.clone(),
            span_id: context.span_id.clone(),
            parent_span_id: context.parent_span_id.clone(),
            
            // Duration
            duration_ms: Utc::now()
                .signed_duration_since(context.start_time)
                .num_milliseconds(),
            
            // Custom fields from baggage
            custom_fields: context.baggage.clone(),
            
            // System info
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            thread_id: format!("{:?}", std::thread::current().id()),
        };
        
        self.writer.write(log_entry).await;
    }
    
    /// Create structured log builder
    pub fn info(&self, message: &str) -> LogBuilder {
        LogBuilder::new(self, LogLevel::Info, message)
    }
    
    pub fn error(&self, message: &str) -> LogBuilder {
        LogBuilder::new(self, LogLevel::Error, message)
    }
}

/// Fluent log builder with context
pub struct LogBuilder<'a> {
    logger: &'a ContextLoggerInstance,
    level: LogLevel,
    message: String,
    fields: HashMap<String, serde_json::Value>,
}

impl<'a> LogBuilder<'a> {
    pub fn field(mut self, key: &str, value: impl Serialize) -> Self {
        self.fields.insert(
            key.to_string(),
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
        );
        self
    }
    
    pub async fn send(self) {
        let mut log_message = self.message;
        
        if !self.fields.is_empty() {
            log_message.push_str(" | ");
            log_message.push_str(&serde_json::to_string(&self.fields).unwrap());
        }
        
        self.logger.log(self.level, &log_message).await;
    }
}
```

## Advanced: Multi-Tenant Context

### Tenant-Aware Resources

```rust
/// Multi-tenant aware resource
#[derive(Resource)]
#[resource(
    id = "tenant_database",
    context_aware = true,
    multi_tenant = true,
)]
pub struct TenantDatabaseResource;

pub struct TenantDatabaseInstance {
    pools: Arc<DashMap<String, PgPool>>,  // Pool per tenant
    context: Arc<RwLock<TenantContext>>,
    config: TenantDatabaseConfig,
}

#[derive(Clone)]
pub struct TenantContext {
    pub tenant_id: String,
    pub tenant_tier: TenantTier,
    pub data_residency: DataResidency,
    pub isolation_level: IsolationLevel,
    pub resource_limits: ResourceLimits,
}

#[derive(Clone)]
pub enum TenantTier {
    Free,
    Standard,
    Premium,
    Enterprise,
}

#[derive(Clone)]
pub enum DataResidency {
    US,
    EU,
    APAC,
    // Specific regions for compliance
    Germany,  // GDPR strict
    Switzerland,  // Banking regulations
}

#[derive(Clone)]
pub enum IsolationLevel {
    /// Shared database, schema separation
    Schema,
    /// Dedicated database
    Database,
    /// Dedicated server
    Server,
}

impl TenantDatabaseInstance {
    /// Get connection for current tenant
    pub async fn get_connection(&self) -> Result<PooledConnection, DatabaseError> {
        let context = self.context.read().await;
        let tenant_id = &context.tenant_id;
        
        // Get or create pool for tenant
        let pool = if let Some(pool) = self.pools.get(tenant_id) {
            pool.clone()
        } else {
            self.create_tenant_pool(tenant_id, &context).await?
        };
        
        // Apply resource limits based on tier
        let conn = match context.tenant_tier {
            TenantTier::Free => {
                // Strict limits for free tier
                timeout(Duration::from_secs(5), pool.acquire()).await??
            }
            TenantTier::Enterprise => {
                // Relaxed limits for enterprise
                timeout(Duration::from_secs(30), pool.acquire()).await??
            }
            _ => {
                timeout(Duration::from_secs(10), pool.acquire()).await??
            }
        };
        
        Ok(conn)
    }
    
    async fn create_tenant_pool(
        &self,
        tenant_id: &str,
        context: &TenantContext,
    ) -> Result<PgPool, DatabaseError> {
        // Determine connection string based on isolation level
        let connection_string = match context.isolation_level {
            IsolationLevel::Schema => {
                // Shared database, tenant-specific schema
                format!("{}/{}?schema={}", 
                    self.config.shared_database_url,
                    self.config.shared_database_name,
                    tenant_id
                )
            }
            IsolationLevel::Database => {
                // Dedicated database
                format!("{}/tenant_{}", 
                    self.config.cluster_url,
                    tenant_id
                )
            }
            IsolationLevel::Server => {
                // Dedicated server based on data residency
                let server = self.get_server_for_residency(&context.data_residency);
                format!("{}/tenant_{}", server, tenant_id)
            }
        };
        
        // Create pool with tier-specific settings
        let pool_config = self.get_pool_config_for_tier(&context.tenant_tier);
        
        let pool = PgPoolOptions::new()
            .min_connections(pool_config.min_connections)
            .max_connections(pool_config.max_connections)
            .max_lifetime(pool_config.max_lifetime)
            .idle_timeout(pool_config.idle_timeout)
            .connect(&connection_string)
            .await?;
        
        self.pools.insert(tenant_id.to_string(), pool.clone());
        
        Ok(pool)
    }
    
    /// Execute query with tenant context
    pub async fn query<T>(&self, sql: &str) -> Result<Vec<T>, DatabaseError> 
    where
        T: for<'r> sqlx::FromRow<'r, PgRow>,
    {
        let context = self.context.read().await;
        let mut conn = self.get_connection().await?;
        
        // Add tenant context to query
        let contextualized_sql = format!(
            "-- tenant_id: {}, tier: {:?}, correlation_id: {}\n{}",
            context.tenant_id,
            context.tenant_tier,
            self.correlation_id,
            sql
        );
        
        // Track metrics per tenant
        let start = Instant::now();
        let result = sqlx::query_as::<_, T>(&contextualized_sql)
            .fetch_all(&mut conn)
            .await?;
        
        self.record_tenant_metrics(
            &context.tenant_id,
            "query",
            start.elapsed(),
            result.len()
        ).await;
        
        Ok(result)
    }
}
```

## Context Propagation

### HTTP Context Propagation

```rust
/// HTTP client that propagates context
pub struct ContextAwareHttpClient {
    client: reqwest::Client,
    context: Arc<RwLock<ExecutionContext>>,
}

impl ContextAwareHttpClient {
    /// Make request with context propagation
    pub async fn request(&self, method: Method, url: &str) -> RequestBuilder {
        let context = self.context.read().await;
        
        self.client
            .request(method, url)
            // W3C Trace Context
            .header("traceparent", format!(
                "00-{}-{}-01",
                context.trace_id.as_ref().unwrap_or(&"0".repeat(32)),
                context.span_id.as_ref().unwrap_or(&"0".repeat(16))
            ))
            // Correlation ID
            .header("X-Correlation-ID", &context.correlation_id)
            // Tenant context
            .header("X-Tenant-ID", context.tenant_id.as_ref().unwrap_or(&"".to_string()))
            // User context
            .header("X-User-ID", context.user_id.as_ref().unwrap_or(&"".to_string()))
            // Custom baggage
            .header("baggage", self.serialize_baggage(&context.baggage))
    }
    
    fn serialize_baggage(&self, baggage: &HashMap<String, String>) -> String {
        baggage.iter()
            .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join(",")
    }
}
```

### Message Queue Context Propagation

```rust
/// Kafka producer with context
pub struct ContextAwareKafkaProducer {
    producer: FutureProducer,
    context: Arc<RwLock<ExecutionContext>>,
}

impl ContextAwareKafkaProducer {
    pub async fn send(&self, topic: &str, key: &str, value: &[u8]) -> Result<(), KafkaError> {
        let context = self.context.read().await;
        
        let record = FutureRecord::to(topic)
            .key(key)
            .payload(value)
            // Add context as headers
            .headers(OwnedHeaders::new()
                .add("correlation-id", &context.correlation_id)
                .add("execution-id", &context.execution_id)
                .add("workflow-id", &context.workflow_id)
                .add("tenant-id", context.tenant_id.as_ref().unwrap_or(&"".to_string()))
                .add("trace-id", context.trace_id.as_ref().unwrap_or(&"".to_string()))
            );
        
        self.producer.send(record, Duration::from_secs(10)).await?;
        Ok(())
    }
}
```

## Observability Integration

### Metrics with Context

```rust
pub struct ContextAwareMetrics {
    registry: Arc<Registry>,
    context: Arc<RwLock<ExecutionContext>>,
}

impl ContextAwareMetrics {
    pub async fn record(&self, metric: &str, value: f64) {
        let context = self.context.read().await;
        
        // Add context as labels
        let labels = vec![
            ("workflow_id", context.workflow_id.as_str()),
            ("action_id", context.action_id.as_str()),
            ("tenant_id", context.tenant_id.as_deref().unwrap_or("unknown")),
            ("user_id", context.user_id.as_deref().unwrap_or("unknown")),
        ];
        
        self.registry
            .get_metric(metric)
            .unwrap()
            .with_label_values(&labels)
            .observe(value);
    }
    
    pub async fn increment(&self, counter: &str) {
        let context = self.context.read().await;
        
        let labels = self.context_labels(&context);
        
        self.registry
            .get_counter(counter)
            .unwrap()
            .with_label_values(&labels)
            .inc();
    }
}
```

### Distributed Tracing

```rust
use opentelemetry::trace::{Tracer, SpanKind};

pub struct ContextAwareTracer {
    tracer: Box<dyn Tracer>,
    context: Arc<RwLock<ExecutionContext>>,
}

impl ContextAwareTracer {
    pub async fn span<F, Fut, T>(&self, name: &str, f: F) -> Result<T, TracingError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, TracingError>>,
    {
        let context = self.context.read().await;
        
        let span = self.tracer
            .span_builder(name)
            .with_kind(SpanKind::Internal)
            .with_attributes(vec![
                KeyValue::new("workflow.id", context.workflow_id.clone()),
                KeyValue::new("action.id", context.action_id.clone()),
                KeyValue::new("correlation.id", context.correlation_id.clone()),
                KeyValue::new("tenant.id", context.tenant_id.clone().unwrap_or_default()),
            ])
            .start(&self.tracer);
        
        let _guard = span.enter();
        
        f().await
    }
}
```

## Testing Context-Aware Resources

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_context_propagation() {
        let context = ExecutionContext {
            execution_id: "exec-123".into(),
            workflow_id: "workflow-456".into(),
            action_id: "action-789".into(),
            user_id: Some("user-abc".into()),
            tenant_id: Some("tenant-xyz".into()),
            correlation_id: "corr-111".into(),
            trace_id: Some("trace-222".into()),
            span_id: Some("span-333".into()),
            parent_span_id: None,
            baggage: hashmap! {
                "custom_field".into() => "custom_value".into(),
            },
            start_time: Utc::now(),
        };
        
        let logger = create_context_logger(context.clone()).await;
        
        // Log should include all context
        logger.info("Test message")
            .field("extra", "data")
            .send()
            .await;
        
        // Verify log contains context
        let logs = get_test_logs().await;
        let log = &logs[0];
        
        assert_eq!(log.execution_id, "exec-123");
        assert_eq!(log.workflow_id, "workflow-456");
        assert_eq!(log.correlation_id, "corr-111");
        assert_eq!(log.tenant_id, Some("tenant-xyz".into()));
    }
    
    #[tokio::test]
    async fn test_child_context() {
        let parent = ExecutionContext::new("exec-1", "workflow-1", "action-1");
        let child = parent.child("action-2");
        
        assert_eq!(child.execution_id, parent.execution_id);
        assert_eq!(child.workflow_id, parent.workflow_id);
        assert_eq!(child.action_id, "action-2");
        assert_eq!(child.parent_span_id, parent.span_id);
        assert_ne!(child.span_id, parent.span_id);
    }
}
```

## Best Practices

1. **Always propagate context** - Through all service boundaries
2. **Use correlation IDs** - For request tracing
3. **Include tenant context** - For multi-tenancy
4. **Add to logs/metrics** - For observability
5. **Keep context lightweight** - Don't add large data
6. **Use standard headers** - W3C Trace Context
7. **Test context flow** - Ensure propagation works
8. **Handle missing context** - Graceful defaults
9. **Secure sensitive context** - Don't log PII
10. **Version context schema** - For compatibility