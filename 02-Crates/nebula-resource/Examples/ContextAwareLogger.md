---
title:  ContextAwareLogger
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Example: ContextAwareLogger

> Логгер, автоматически обогащающий логи контекстом выполнения workflow

## Overview

`ContextAwareLogger` автоматически добавляет в каждое лог-сообщение информацию о текущем workflow, execution, action, user и trace, обеспечивая полную observability без явного указания контекста.

## Implementation

```rust
use nebula_resource::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug, span, Level};

/// Context-aware logger resource
#[derive(Resource)]
#[resource(
    id = "context_logger",
    name = "Context-Aware Logger",
    context_aware = true
)]
pub struct ContextAwareLoggerResource;

/// Logger configuration
#[derive(ResourceConfig, Serialize, Deserialize, Clone)]
pub struct LoggerConfig {
    /// Log level
    #[serde(default = "default_level")]
    pub level: LogLevel,
    
    /// Output format
    #[serde(default = "default_format")]
    pub format: LogFormat,
    
    /// Include execution context
    #[serde(default = "default_true")]
    pub include_context: bool,
    
    /// Include trace information
    #[serde(default = "default_true")]
    pub include_trace: bool,
    
    /// Custom fields to always include
    #[serde(default)]
    pub custom_fields: HashMap<String, String>,
    
    /// Log targets (stdout, file, remote)
    #[serde(default = "default_targets")]
    pub targets: Vec<LogTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogTarget {
    Stdout,
    File { path: String, rotation: RotationPolicy },
    Remote { endpoint: String, batch_size: usize },
}

/// Logger instance with context
pub struct ContextAwareLoggerInstance {
    config: LoggerConfig,
    context: Arc<RwLock<Option<ExecutionContext>>>,
    span: Option<tracing::Span>,
    buffer: Arc<RwLock<Vec<LogEntry>>>,
}

#[derive(Serialize, Clone)]
struct LogEntry {
    timestamp: chrono::DateTime<chrono::Utc>,
    level: String,
    message: String,
    fields: HashMap<String, serde_json::Value>,
    context: Option<LogContext>,
}

#[derive(Serialize, Clone)]
struct LogContext {
    workflow_id: String,
    workflow_name: String,
    execution_id: String,
    action_id: Option<String>,
    action_name: Option<String>,
    user_id: Option<String>,
    tenant_id: Option<String>,
    trace_id: Option<String>,
    span_id: Option<String>,
}

/// Resource implementation
#[async_trait]
impl Resource for ContextAwareLoggerResource {
    type Config = LoggerConfig;
    type Instance = ContextAwareLoggerInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        // Create tracing span for this logger
        let span = span!(
            Level::INFO,
            "resource",
            resource.id = %self.id(),
            resource.type = "logger",
            workflow.id = %context.workflow_id,
            execution.id = %context.execution_id,
        );
        
        // Initialize logger instance
        let instance = ContextAwareLoggerInstance {
            config: config.clone(),
            context: Arc::new(RwLock::new(None)),
            span: Some(span),
            buffer: Arc::new(RwLock::new(Vec::new())),
        };
        
        // Setup log targets
        for target in &config.targets {
            instance.setup_target(target).await?;
        }
        
        Ok(instance)
    }
}

impl ContextAwareLoggerInstance {
    /// Inject execution context
    pub async fn inject_context(&self, context: ExecutionContext) {
        let mut ctx = self.context.write().await;
        *ctx = Some(context);
    }
    
    /// Log with automatic context
    pub async fn log(&self, level: LogLevel, message: impl Into<String>) {
        self.log_with_fields(level, message, HashMap::new()).await;
    }
    
    /// Log with additional fields
    pub async fn log_with_fields(
        &self,
        level: LogLevel,
        message: impl Into<String>,
        mut fields: HashMap<String, serde_json::Value>,
    ) {
        let message = message.into();
        
        // Add context if available
        let log_context = if self.config.include_context {
            let ctx = self.context.read().await;
            ctx.as_ref().map(|c| LogContext {
                workflow_id: c.workflow_id.clone(),
                workflow_name: c.workflow_name.clone(),
                execution_id: c.execution_id.clone(),
                action_id: c.action_id.clone(),
                action_name: c.action_name.clone(),
                user_id: c.user_id.clone(),
                tenant_id: c.tenant_id.clone(),
                trace_id: if self.config.include_trace { c.trace_id.clone() } else { None },
                span_id: if self.config.include_trace { c.span_id.clone() } else { None },
            })
        } else {
            None
        };
        
        // Add custom fields
        for (key, value) in &self.config.custom_fields {
            fields.insert(key.clone(), serde_json::Value::String(value.clone()));
        }
        
        // Create log entry
        let entry = LogEntry {
            timestamp: chrono::Utc::now(),
            level: format!("{:?}", level),
            message: message.clone(),
            fields,
            context: log_context,
        };
        
        // Output based on format
        match self.config.format {
            LogFormat::Json => {
                let json = serde_json::to_string(&entry).unwrap();
                println!("{}", json);
            }
            LogFormat::Pretty => {
                let ctx_str = if let Some(ctx) = &entry.context {
                    format!("[{}:{}]", ctx.workflow_id, ctx.execution_id)
                } else {
                    String::new()
                };
                println!("{} {} {} {}", 
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    entry.level,
                    ctx_str,
                    entry.message
                );
            }
            LogFormat::Compact => {
                println!("[{}] {}", entry.level, entry.message);
            }
        }
        
        // Buffer for batch sending
        if self.should_buffer() {
            let mut buffer = self.buffer.write().await;
            buffer.push(entry);
            
            if buffer.len() >= 100 {
                self.flush_buffer().await;
            }
        }
    }
    
    // Convenience methods
    pub async fn debug(&self, message: impl Into<String>) {
        self.log(LogLevel::Debug, message).await;
    }
    
    pub async fn info(&self, message: impl Into<String>) {
        self.log(LogLevel::Info, message).await;
    }
    
    pub async fn warn(&self, message: impl Into<String>) {
        self.log(LogLevel::Warn, message).await;
    }
    
    pub async fn error(&self, message: impl Into<String>) {
        self.log(LogLevel::Error, message).await;
    }
    
    /// Structured logging with data
    pub async fn info_with_data(&self, message: impl Into<String>, data: serde_json::Value) {
        let mut fields = HashMap::new();
        fields.insert("data".to_string(), data);
        self.log_with_fields(LogLevel::Info, message, fields).await;
    }
    
    async fn setup_target(&self, target: &LogTarget) -> Result<(), ResourceError> {
        match target {
            LogTarget::Stdout => {
                // Already handled in log method
                Ok(())
            }
            LogTarget::File { path, rotation } => {
                // Setup file logging with rotation
                // Implementation depends on your file logging library
                Ok(())
            }
            LogTarget::Remote { endpoint, .. } => {
                // Setup remote logging
                // Could use HTTP, gRPC, or other protocols
                Ok(())
            }
        }
    }
    
    async fn flush_buffer(&self) {
        let mut buffer = self.buffer.write().await;
        if buffer.is_empty() {
            return;
        }
        
        // Send buffered logs to remote targets
        for target in &self.config.targets {
            if let LogTarget::Remote { endpoint, .. } = target {
                // Send batch to remote endpoint
                // Implementation depends on your remote logging service
            }
        }
        
        buffer.clear();
    }
    
    fn should_buffer(&self) -> bool {
        self.config.targets.iter().any(|t| matches!(t, LogTarget::Remote { .. }))
    }
}

// Default implementations
fn default_level() -> LogLevel { LogLevel::Info }
fn default_format() -> LogFormat { LogFormat::Json }
fn default_true() -> bool { true }
fn default_targets() -> Vec<LogTarget> { vec![LogTarget::Stdout] }
```

## Usage Examples

### Basic Usage

```rust
async fn example_action(ctx: &ExecutionContext) -> Result<()> {
    // Get logger - it automatically has context
    let logger = ctx.get_resource::<ContextAwareLoggerInstance>().await?;
    
    // Simple logging - context is automatically included
    logger.info("Starting data processing").await;
    
    // Log with additional fields
    logger.info_with_data(
        "Processing batch",
        json!({
            "batch_id": "batch_123",
            "record_count": 1000,
            "source": "s3://bucket/data.csv"
        })
    ).await;
    
    // Error logging with context
    match process_data().await {
        Ok(result) => {
            logger.info(&format!("Processed {} records", result.count)).await;
        }
        Err(e) => {
            logger.error(&format!("Processing failed: {}", e)).await;
        }
    }
    
    Ok(())
}
```

### Configuration Example

```yaml
# logger.yaml
type: context_logger
config:
  level: Info
  format: Json
  include_context: true
  include_trace: true
  custom_fields:
    service: "data-processor"
    environment: "production"
    version: "1.2.3"
  targets:
    - type: Stdout
    - type: File
      path: "/var/log/nebula/workflow.log"
      rotation:
        max_size: "100MB"
        max_age: "7d"
        max_backups: 5
    - type: Remote
      endpoint: "https://logs.example.com/ingest"
      batch_size: 100
```

### Output Examples

#### JSON Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "Info",
  "message": "Processing batch",
  "fields": {
    "data": {
      "batch_id": "batch_123",
      "record_count": 1000,
      "source": "s3://bucket/data.csv"
    },
    "service": "data-processor",
    "environment": "production",
    "version": "1.2.3"
  },
  "context": {
    "workflow_id": "wf_abc123",
    "workflow_name": "DataPipeline",
    "execution_id": "exec_xyz789",
    "action_id": "act_456",
    "action_name": "ProcessBatch",
    "user_id": "user_123",
    "tenant_id": "tenant_456",
    "trace_id": "trace_abc",
    "span_id": "span_123"
  }
}
```

#### Pretty Format

```
2024-01-15 10:30:45 Info [wf_abc123:exec_xyz789] Processing batch
```

## Advanced Features

### Dynamic Context Updates

```rust
impl ContextAwareLoggerInstance {
    /// Add temporary context for a scope
    pub async fn with_context<F, Fut, R>(
        &self,
        additional: HashMap<String, String>,
        f: F,
    ) -> R
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = R>,
    {
        // Temporarily add context
        let mut ctx = self.context.write().await;
        // Add additional context...
        drop(ctx);
        
        let result = f().await;
        
        // Restore original context
        let mut ctx = self.context.write().await;
        // Restore...
        
        result
    }
}
```

### Performance Metrics

```rust
impl ContextAwareLoggerInstance {
    /// Get logger metrics
    pub async fn metrics(&self) -> LoggerMetrics {
        LoggerMetrics {
            total_logs: self.total_count.load(Ordering::Relaxed),
            error_count: self.error_count.load(Ordering::Relaxed),
            buffer_size: self.buffer.read().await.len(),
            last_flush: self.last_flush.load(Ordering::Relaxed),
        }
    }
}
```

## Benefits

1. **Automatic Context** - Не нужно вручную добавлять workflow/execution IDs
2. **Structured Logging** - JSON формат для легкого парсинга
3. **Tracing Integration** - Автоматическая интеграция с distributed tracing
4. **Buffering** - Эффективная отправка логов батчами
5. **Multi-target** - Поддержка множественных destinations
6. **Performance** - Минимальный overhead благодаря async

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nebula_resource::testing::*;
    
    #[tokio::test]
    async fn test_context_injection() {
        let config = LoggerConfig::default();
        let logger = ContextAwareLoggerResource
            .create(&config, &mock_context())
            .await
            .unwrap();
        
        // Inject context
        logger.inject_context(ExecutionContext {
            workflow_id: "test_wf".into(),
            execution_id: "test_exec".into(),
            // ...
        }).await;
        
        // Log should include context
        logger.info("Test message").await;
        
        // Verify buffer contains context
        let buffer = logger.buffer.read().await;
        assert!(!buffer.is_empty());
        assert_eq!(buffer[0].context.as_ref().unwrap().workflow_id, "test_wf");
    }
}
```
