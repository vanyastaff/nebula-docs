---
title:  Logger
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Example: Logger

> Структурированный логгер с поддержкой multiple targets и форматов

## Overview

Пример полнофункционального логгера для nebula-resource с поддержкой структурированного логирования, множественных targets (stdout, file, remote), ротации файлов и интеграцией с distributed tracing.

## Implementation

```rust
use nebula_resource::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use chrono::{DateTime, Utc};

/// Logger resource
#[derive(Resource)]
#[resource(
    id = "logger",
    name = "Structured Logger",
    singleton = true  // One logger instance per scope
)]
pub struct LoggerResource;

/// Logger configuration
#[derive(ResourceConfig, Serialize, Deserialize, Clone)]
pub struct LoggerConfig {
    /// Minimum log level
    #[serde(default = "default_level")]
    pub level: LogLevel,
    
    /// Output format
    #[serde(default = "default_format")]
    pub format: LogFormat,
    
    /// Log targets
    #[serde(default = "default_targets")]
    pub targets: Vec<LogTarget>,
    
    /// Buffer size for async logging
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,
    
    /// Flush interval
    #[serde(default = "default_flush_interval")]
    pub flush_interval: Duration,
    
    /// Include caller information
    #[serde(default)]
    pub include_caller: bool,
    
    /// Include thread info
    #[serde(default)]
    pub include_thread: bool,
    
    /// Custom fields to include in every log
    #[serde(default)]
    pub global_fields: HashMap<String, String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Fatal = 5,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// Human-readable format
    Text,
    /// JSON Lines format
    Json,
    /// Compact single-line format
    Compact,
    /// Logfmt format
    Logfmt,
    /// Custom format with template
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogTarget {
    /// Write to stdout/stderr
    Console {
        #[serde(default)]
        use_stderr_for_errors: bool,
    },
    
    /// Write to file with rotation
    File {
        path: PathBuf,
        #[serde(default = "default_rotation")]
        rotation: FileRotation,
        #[serde(default)]
        compress: bool,
    },
    
    /// Send to remote endpoint
    Remote {
        endpoint: String,
        #[serde(default = "default_batch_size")]
        batch_size: usize,
        #[serde(default = "default_timeout")]
        timeout: Duration,
        #[serde(default)]
        retry_attempts: u32,
    },
    
    /// Send to syslog
    Syslog {
        host: String,
        port: u16,
        facility: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRotation {
    /// Maximum file size before rotation
    pub max_size: usize,
    /// Maximum number of backup files
    pub max_backups: usize,
    /// Maximum age of log files in days
    pub max_age: u32,
    /// Compress rotated files
    pub compress: bool,
}

/// Logger instance
pub struct LoggerInstance {
    config: LoggerConfig,
    targets: Vec<Box<dyn LogWriter>>,
    buffer: Arc<RwLock<Vec<LogEntry>>>,
    metrics: Arc<LoggerMetrics>,
    shutdown: Arc<RwLock<bool>>,
}

/// Log entry structure
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub fields: HashMap<String, serde_json::Value>,
    pub caller: Option<Caller>,
    pub thread: Option<String>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Caller {
    pub file: String,
    pub line: u32,
    pub function: String,
}

/// Trait for log writers
#[async_trait]
trait LogWriter: Send + Sync {
    async fn write(&mut self, entry: &LogEntry) -> Result<(), std::io::Error>;
    async fn flush(&mut self) -> Result<(), std::io::Error>;
    async fn close(&mut self) -> Result<(), std::io::Error>;
}

/// Console writer
struct ConsoleWriter {
    format: LogFormat,
    use_stderr_for_errors: bool,
}

#[async_trait]
impl LogWriter for ConsoleWriter {
    async fn write(&mut self, entry: &LogEntry) -> Result<(), std::io::Error> {
        let formatted = self.format_entry(entry);
        
        if entry.level >= LogLevel::Error && self.use_stderr_for_errors {
            eprintln!("{}", formatted);
        } else {
            println!("{}", formatted);
        }
        
        Ok(())
    }
    
    async fn flush(&mut self) -> Result<(), std::io::Error> {
        // Console is auto-flushed
        Ok(())
    }
    
    async fn close(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl ConsoleWriter {
    fn format_entry(&self, entry: &LogEntry) -> String {
        match &self.format {
            LogFormat::Text => {
                let level_str = format!("{:5}", format!("{:?}", entry.level));
                let caller_str = if let Some(caller) = &entry.caller {
                    format!(" [{}:{}]", caller.file, caller.line)
                } else {
                    String::new()
                };
                
                format!(
                    "{} [{}]{} - {}",
                    entry.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
                    level_str,
                    caller_str,
                    entry.message
                )
            }
            LogFormat::Json => {
                serde_json::to_string(entry).unwrap()
            }
            LogFormat::Compact => {
                format!(
                    "{} {} {}",
                    entry.timestamp.format("%H:%M:%S"),
                    entry.level as u8,
                    entry.message
                )
            }
            LogFormat::Logfmt => {
                let mut parts = vec![
                    format!("ts={}", entry.timestamp.to_rfc3339()),
                    format!("level={:?}", entry.level),
                    format!("msg=\"{}\"", entry.message),
                ];
                
                for (key, value) in &entry.fields {
                    parts.push(format!("{}={}", key, value));
                }
                
                parts.join(" ")
            }
            LogFormat::Custom(template) => {
                // Simple template replacement
                template
                    .replace("{timestamp}", &entry.timestamp.to_rfc3339())
                    .replace("{level}", &format!("{:?}", entry.level))
                    .replace("{message}", &entry.message)
            }
        }
    }
}

/// File writer with rotation
struct FileWriter {
    path: PathBuf,
    file: Option<tokio::fs::File>,
    rotation: FileRotation,
    format: LogFormat,
    current_size: usize,
    created_at: DateTime<Utc>,
}

#[async_trait]
impl LogWriter for FileWriter {
    async fn write(&mut self, entry: &LogEntry) -> Result<(), std::io::Error> {
        // Check if rotation is needed
        if self.should_rotate() {
            self.rotate().await?;
        }
        
        // Ensure file is open
        if self.file.is_none() {
            self.open_file().await?;
        }
        
        let formatted = self.format_entry(entry);
        let bytes = formatted.as_bytes();
        
        if let Some(file) = &mut self.file {
            file.write_all(bytes).await?;
            file.write_all(b"\n").await?;
            self.current_size += bytes.len() + 1;
        }
        
        Ok(())
    }
    
    async fn flush(&mut self) -> Result<(), std::io::Error> {
        if let Some(file) = &mut self.file {
            file.flush().await?;
        }
        Ok(())
    }
    
    async fn close(&mut self) -> Result<(), std::io::Error> {
        if let Some(mut file) = self.file.take() {
            file.flush().await?;
            file.shutdown().await?;
        }
        Ok(())
    }
}

impl FileWriter {
    async fn open_file(&mut self) -> Result<(), std::io::Error> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        
        self.file = Some(file);
        self.created_at = Utc::now();
        
        // Get current file size
        let metadata = tokio::fs::metadata(&self.path).await?;
        self.current_size = metadata.len() as usize;
        
        Ok(())
    }
    
    fn should_rotate(&self) -> bool {
        // Check size limit
        if self.current_size >= self.rotation.max_size {
            return true;
        }
        
        // Check age limit
        let age_days = (Utc::now() - self.created_at).num_days();
        if age_days >= self.rotation.max_age as i64 {
            return true;
        }
        
        false
    }
    
    async fn rotate(&mut self) -> Result<(), std::io::Error> {
        // Close current file
        self.close().await?;
        
        // Generate rotation filename
        let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
        let rotation_path = self.path.with_file_name(
            format!(
                "{}.{}.log",
                self.path.file_stem().unwrap().to_string_lossy(),
                timestamp
            )
        );
        
        // Rename current file
        tokio::fs::rename(&self.path, &rotation_path).await?;
        
        // Compress if needed
        if self.rotation.compress {
            self.compress_file(&rotation_path).await?;
        }
        
        // Clean up old backups
        self.cleanup_old_backups().await?;
        
        // Open new file
        self.open_file().await?;
        
        Ok(())
    }
    
    async fn compress_file(&self, path: &PathBuf) -> Result<(), std::io::Error> {
        // Implementation would use async compression library
        // For example, using async-compression crate
        Ok(())
    }
    
    async fn cleanup_old_backups(&self) -> Result<(), std::io::Error> {
        // List all backup files
        let dir = self.path.parent().unwrap();
        let prefix = self.path.file_stem().unwrap().to_string_lossy();
        
        let mut entries = tokio::fs::read_dir(dir).await?;
        let mut backups = Vec::new();
        
        while let Some(entry) = entries.next_entry().await? {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            
            if name_str.starts_with(&*prefix) && name_str != self.path.file_name().unwrap().to_string_lossy() {
                let metadata = entry.metadata().await?;
                backups.push((entry.path(), metadata.modified()?));
            }
        }
        
        // Sort by modification time
        backups.sort_by_key(|&(_, time)| time);
        backups.reverse();
        
        // Remove old backups
        while backups.len() > self.rotation.max_backups {
            if let Some((path, _)) = backups.pop() {
                tokio::fs::remove_file(path).await?;
            }
        }
        
        Ok(())
    }
    
    fn format_entry(&self, entry: &LogEntry) -> String {
        // Reuse ConsoleWriter's formatting logic
        let console_writer = ConsoleWriter {
            format: self.format.clone(),
            use_stderr_for_errors: false,
        };
        console_writer.format_entry(entry)
    }
}

/// Resource implementation
#[async_trait]
impl Resource for LoggerResource {
    type Config = LoggerConfig;
    type Instance = LoggerInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        let mut targets: Vec<Box<dyn LogWriter>> = Vec::new();
        
        // Create writers for each target
        for target in &config.targets {
            let writer: Box<dyn LogWriter> = match target {
                LogTarget::Console { use_stderr_for_errors } => {
                    Box::new(ConsoleWriter {
                        format: config.format.clone(),
                        use_stderr_for_errors: *use_stderr_for_errors,
                    })
                }
                LogTarget::File { path, rotation, .. } => {
                    Box::new(FileWriter {
                        path: path.clone(),
                        file: None,
                        rotation: rotation.clone(),
                        format: config.format.clone(),
                        current_size: 0,
                        created_at: Utc::now(),
                    })
                }
                LogTarget::Remote { .. } => {
                    // Implementation would create RemoteWriter
                    continue;
                }
                LogTarget::Syslog { .. } => {
                    // Implementation would create SyslogWriter
                    continue;
                }
            };
            targets.push(writer);
        }
        
        let instance = LoggerInstance {
            config: config.clone(),
            targets,
            buffer: Arc::new(RwLock::new(Vec::with_capacity(config.buffer_size))),
            metrics: Arc::new(LoggerMetrics::new()),
            shutdown: Arc::new(RwLock::new(false)),
        };
        
        // Start background flusher
        instance.start_flusher();
        
        Ok(instance)
    }
}

impl LoggerInstance {
    /// Log a message at specified level
    pub async fn log(&self, level: LogLevel, message: impl Into<String>) {
        if level < self.config.level {
            return;
        }
        
        let entry = LogEntry {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            fields: self.config.global_fields.iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
                .collect(),
            caller: self.get_caller(),
            thread: self.get_thread_info(),
            trace_id: self.get_trace_id(),
            span_id: self.get_span_id(),
        };
        
        // Add to buffer
        {
            let mut buffer = self.buffer.write().await;
            buffer.push(entry.clone());
            
            // Flush if buffer is full
            if buffer.len() >= self.config.buffer_size {
                self.flush_buffer(&mut buffer).await;
            }
        }
        
        // Update metrics
        self.metrics.increment_level_count(level);
    }
    
    /// Convenience methods for different log levels
    pub async fn trace(&self, message: impl Into<String>) {
        self.log(LogLevel::Trace, message).await;
    }
    
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
    
    pub async fn fatal(&self, message: impl Into<String>) {
        self.log(LogLevel::Fatal, message).await;
    }
    
    /// Log with additional fields
    pub async fn log_with_fields(
        &self,
        level: LogLevel,
        message: impl Into<String>,
        fields: HashMap<String, serde_json::Value>,
    ) {
        if level < self.config.level {
            return;
        }
        
        let mut entry = LogEntry {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            fields,
            caller: self.get_caller(),
            thread: self.get_thread_info(),
            trace_id: self.get_trace_id(),
            span_id: self.get_span_id(),
        };
        
        // Add global fields
        for (key, value) in &self.config.global_fields {
            entry.fields.entry(key.clone())
                .or_insert_with(|| serde_json::Value::String(value.clone()));
        }
        
        // Write to targets
        for target in &self.targets {
            let _ = target.write(&entry).await;
        }
        
        self.metrics.increment_level_count(level);
    }
    
    /// Start background flusher
    fn start_flusher(&self) {
        let buffer = self.buffer.clone();
        let interval = self.config.flush_interval;
        let shutdown = self.shutdown.clone();
        let targets = self.targets.clone(); // Would need Arc<Mutex<>> in real impl
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Check shutdown
                if *shutdown.read().await {
                    break;
                }
                
                // Flush buffer
                let mut buffer_guard = buffer.write().await;
                if !buffer_guard.is_empty() {
                    // Write entries to targets
                    for entry in buffer_guard.drain(..) {
                        for target in &targets {
                            let _ = target.write(&entry).await;
                        }
                    }
                }
            }
        });
    }
    
    async fn flush_buffer(&self, buffer: &mut Vec<LogEntry>) {
        for entry in buffer.drain(..) {
            for target in &self.targets {
                let _ = target.write(&entry).await;
            }
        }
    }
    
    fn get_caller(&self) -> Option<Caller> {
        if !self.config.include_caller {
            return None;
        }
        
        // Would use backtrace crate in real implementation
        None
    }
    
    fn get_thread_info(&self) -> Option<String> {
        if !self.config.include_thread {
            return None;
        }
        
        std::thread::current()
            .name()
            .map(|s| s.to_string())
    }
    
    fn get_trace_id(&self) -> Option<String> {
        // Would get from tracing context
        None
    }
    
    fn get_span_id(&self) -> Option<String> {
        // Would get from tracing context
        None
    }
}

/// Logger metrics
struct LoggerMetrics {
    total_logs: AtomicU64,
    trace_count: AtomicU64,
    debug_count: AtomicU64,
    info_count: AtomicU64,
    warn_count: AtomicU64,
    error_count: AtomicU64,
    fatal_count: AtomicU64,
    bytes_written: AtomicU64,
}

impl LoggerMetrics {
    fn new() -> Self {
        Self {
            total_logs: AtomicU64::new(0),
            trace_count: AtomicU64::new(0),
            debug_count: AtomicU64::new(0),
            info_count: AtomicU64::new(0),
            warn_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            fatal_count: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
        }
    }
    
    fn increment_level_count(&self, level: LogLevel) {
        self.total_logs.fetch_add(1, Ordering::Relaxed);
        
        match level {
            LogLevel::Trace => self.trace_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Debug => self.debug_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Info => self.info_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Warn => self.warn_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Error => self.error_count.fetch_add(1, Ordering::Relaxed),
            LogLevel::Fatal => self.fatal_count.fetch_add(1, Ordering::Relaxed),
        };
    }
}

// Default implementations
fn default_level() -> LogLevel { LogLevel::Info }
fn default_format() -> LogFormat { LogFormat::Text }
fn default_targets() -> Vec<LogTarget> {
    vec![LogTarget::Console { use_stderr_for_errors: true }]
}
fn default_buffer_size() -> usize { 1000 }
fn default_flush_interval() -> Duration { Duration::from_secs(5) }
fn default_rotation() -> FileRotation {
    FileRotation {
        max_size: 100 * 1024 * 1024, // 100MB
        max_backups: 10,
        max_age: 30,
        compress: false,
    }
}
fn default_batch_size() -> usize { 100 }
fn default_timeout() -> Duration { Duration::from_secs(30) }
```

## Usage Examples

### Basic Usage

```rust
async fn example_usage(ctx: &ExecutionContext) -> Result<()> {
    let logger = ctx.get_resource::<LoggerInstance>().await?;
    
    // Simple logging
    logger.info("Application started").await;
    logger.debug("Debug information").await;
    logger.warn("Warning message").await;
    logger.error("Error occurred").await;
    
    // Logging with fields
    logger.log_with_fields(
        LogLevel::Info,
        "User action",
        hashmap! {
            "user_id" => json!("user_123"),
            "action" => json!("login"),
            "ip_address" => json!("192.168.1.1"),
            "success" => json!(true),
        }
    ).await;
    
    Ok(())
}
```

### Configuration Examples

```yaml
# logger.yaml
type: logger
config:
  level: Debug
  format: Json
  include_caller: true
  include_thread: true
  buffer_size: 1000
  flush_interval: 5s
  global_fields:
    service: "my-service"
    environment: "production"
    version: "1.0.0"
  targets:
    # Console output
    - type: Console
      use_stderr_for_errors: true
    
    # File with rotation
    - type: File
      path: /var/log/nebula/app.log
      rotation:
        max_size: 104857600  # 100MB
        max_backups: 10
        max_age: 30
        compress: true
    
    # Remote logging
    - type: Remote
      endpoint: https://logs.example.com/ingest
      batch_size: 100
      timeout: 30s
      retry_attempts: 3
```

## Output Examples

### Text Format

```
2024-01-15 10:30:45.123 [INFO ] [src/main.rs:42] - Application started
2024-01-15 10:30:45.234 [ERROR] [src/handler.rs:123] - Database connection failed
```

### JSON Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "Info",
  "message": "User action",
  "fields": {
    "user_id": "user_123",
    "action": "login",
    "ip_address": "192.168.1.1",
    "success": true,
    "service": "my-service",
    "environment": "production"
  },
  "caller": {
    "file": "src/handler.rs",
    "line": 42,
    "function": "handle_login"
  },
  "thread": "tokio-runtime-worker",
  "trace_id": "abc123",
  "span_id": "def456"
}
```

### Logfmt Format

```
ts=2024-01-15T10:30:45Z level=Info msg="User action" user_id=user_123 action=login success=true
```

## Benefits

1. **Multiple Targets** - Одновременная запись в консоль, файл и remote
2. **File Rotation** - Автоматическая ротация с compression
3. **Structured Logging** - JSON формат для легкого парсинга
4. **Buffered Writing** - Эффективная запись батчами
5. **Flexible Formatting** - Различные форматы вывода
6. **Performance** - Async I/O и буферизация
