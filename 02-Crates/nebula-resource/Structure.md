# nebula-resource Complete Crate Structure

```
nebula-resource/
├── Cargo.toml
├── README.md
├── LICENSE
├── examples/
│   ├── basic_usage.rs
│   ├── custom_resource.rs
│   ├── with_resilience.rs
│   ├── context_aware.rs
│   ├── credential_rotation.rs
│   ├── dependency_graph.rs
│   ├── resource_scoping.rs
│   ├── plugin_example.rs
│   └── health_pipeline.rs
│
├── src/
│   ├── lib.rs                    # Public API и re-exports
│   │
│   ├── prelude.rs               # Common imports
│   │
│   ├── core/                    # Core traits и types
│   │   ├── mod.rs
│   │   ├── traits/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs          # Resource trait
│   │   │   ├── instance.rs          # ResourceInstance trait
│   │   │   ├── cloneable.rs         # CloneableResource
│   │   │   ├── configurable.rs      # ConfigurableResource
│   │   │   ├── stateful.rs          # StatefulResource
│   │   │   ├── refreshable.rs       # RefreshableResource
│   │   │   ├── observable.rs        # ObservableResource
│   │   │   ├── poolable.rs          # PoolableResource
│   │   │   ├── health_checkable.rs  # HealthCheckable
│   │   │   ├── context_aware.rs     # ContextAware
│   │   │   ├── credential_aware.rs  # CredentialAware
│   │   │   ├── managed.rs           # ManagedResource
│   │   │   ├── dynamic.rs           # DynamicResource (for plugins)
│   │   │   └── retryable.rs         # RetryableError trait
│   │   ├── context/
│   │   │   ├── mod.rs
│   │   │   ├── resource_context.rs  # ResourceContext
│   │   │   ├── execution_context.rs # ExecutionContext
│   │   │   ├── enricher.rs          # Enricher trait
│   │   │   └── baggage.rs           # Context baggage
│   │   ├── types/
│   │   │   ├── mod.rs
│   │   │   ├── error.rs             # ResourceError types
│   │   │   ├── metadata.rs          # ResourceMetadata
│   │   │   ├── handle.rs            # ResourceHandle
│   │   │   ├── guard.rs             # ResourceGuard (RAII)
│   │   │   ├── health.rs            # HealthStatus
│   │   │   ├── lifecycle.rs         # LifecycleState
│   │   │   ├── capabilities.rs      # ResourceCapabilities
│   │   │   ├── version.rs           # Version management
│   │   │   ├── scope.rs             # ResourceScope enum
│   │   │   └── credentials.rs       # Credential types
│   │
│   ├── config/                  # Переиспользуемые конфигурации
│   │   ├── mod.rs
│   │   ├── retry.rs             # RetryConfig with presets
│   │   ├── circuit_breaker.rs   # CircuitBreakerConfig with presets
│   │   ├── rate_limiter.rs      # RateLimiterConfig with presets
│   │   ├── timeout.rs           # TimeoutConfig with presets
│   │   ├── cache.rs             # CacheConfig with presets
│   │   ├── pool.rs              # PoolConfig with strategies
│   │   ├── bulkhead.rs          # BulkheadConfig
│   │   └── fallback.rs          # FallbackConfig
│   │
│   ├── resilience/              # Resilience components implementation
│   │   ├── mod.rs
│   │   ├── manager.rs           # ResilienceManager (combines all)
│   │   ├── retry/
│   │   │   ├── mod.rs
│   │   │   ├── executor.rs      # RetryExecutor
│   │   │   ├── strategy.rs      # RetryStrategy (Fixed, Linear, Exponential, Fibonacci)
│   │   │   ├── jitter.rs        # Jitter implementations
│   │   │   └── backoff.rs       # Backoff algorithms
│   │   ├── circuit_breaker/
│   │   │   ├── mod.rs
│   │   │   ├── breaker.rs       # CircuitBreaker
│   │   │   ├── state.rs         # CircuitState (Closed, Open, HalfOpen)
│   │   │   ├── stats.rs         # CircuitStats
│   │   │   └── metrics.rs       # Circuit metrics
│   │   ├── rate_limiter/
│   │   │   ├── mod.rs
│   │   │   ├── token_bucket.rs  # TokenBucket algorithm
│   │   │   ├── leaky_bucket.rs  # LeakyBucket algorithm
│   │   │   ├── sliding_window.rs # SlidingWindow algorithm
│   │   │   ├── adaptive.rs      # Adaptive rate limiting
│   │   │   └── limiter.rs       # RateLimiter trait
│   │   ├── bulkhead/
│   │   │   ├── mod.rs
│   │   │   ├── semaphore.rs     # Semaphore-based bulkhead
│   │   │   └── thread_pool.rs   # ThreadPool bulkhead
│   │   ├── timeout/
│   │   │   ├── mod.rs
│   │   │   └── manager.rs       # TimeoutManager
│   │   └── fallback/
│   │       ├── mod.rs
│   │       └── handler.rs       # FallbackHandler
│   │
│   ├── manager/                 # Resource management
│   │   ├── mod.rs
│   │   ├── resource_manager.rs # Main ResourceManager
│   │   ├── registry/
│   │   │   ├── mod.rs
│   │   │   ├── registry.rs     # ResourceRegistry
│   │   │   ├── factory.rs      # ResourceFactory
│   │   │   └── discovery.rs    # Resource discovery
│   │   ├── lifecycle/
│   │   │   ├── mod.rs
│   │   │   ├── manager.rs      # LifecycleManager
│   │   │   ├── hooks.rs        # LifecycleHook trait & impls
│   │   │   ├── state.rs        # State transitions
│   │   │   ├── history.rs      # State history tracking
│   │   │   └── auto.rs         # AutoLifecycleManager
│   │   ├── dependency/
│   │   │   ├── mod.rs
│   │   │   ├── graph.rs        # DependencyGraph
│   │   │   ├── resolver.rs     # Dependency resolution
│   │   │   ├── container.rs    # ResourceContainer (DI)
│   │   │   ├── validation.rs   # Circular dependency detection
│   │   │   └── topological.rs  # Topological sorting
│   │   ├── scope/
│   │   │   ├── mod.rs
│   │   │   ├── manager.rs      # ScopeManager
│   │   │   ├── tree.rs         # ScopeTree
│   │   │   ├── isolation.rs    # Resource isolation
│   │   │   ├── sharing.rs      # SharingPolicy
│   │   │   └── migration.rs    # Resource migration between scopes
│   │   ├── enrichment/
│   │   │   ├── mod.rs
│   │   │   ├── enricher.rs     # Enricher trait
│   │   │   ├── pipeline.rs     # EnrichmentPipeline
│   │   │   ├── enrichers/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── user.rs     # UserEnricher
│   │   │   │   ├── geo.rs      # GeoEnricher
│   │   │   │   ├── security.rs # SecurityEnricher
│   │   │   │   ├── tenant.rs   # TenantEnricher
│   │   │   │   └── analytics.rs # AnalyticsEnricher
│   │   ├── events/
│   │   │   ├── mod.rs
│   │   │   ├── emitter.rs      # EventEmitter
│   │   │   ├── handler.rs      # EventHandler trait
│   │   │   ├── processor.rs    # EventProcessor
│   │   │   └── types.rs        # ResourceEvent types
│   │   ├── transfer/
│   │   │   ├── mod.rs
│   │   │   ├── manager.rs      # TransferManager
│   │   │   ├── progress.rs     # TransferProgress
│   │   │   └── state.rs        # TransferState
│   │   └── builder.rs          # ResourceManagerBuilder
│   │
│   ├── pool/                    # Resource pooling
│   │   ├── mod.rs
│   │   ├── pool.rs             # Generic Pool<T>
│   │   ├── strategy/
│   │   │   ├── mod.rs
│   │   │   ├── fifo.rs         # FIFO strategy
│   │   │   ├── lifo.rs         # LIFO strategy
│   │   │   ├── lru.rs          # LRU strategy
│   │   │   ├── weighted.rs     # Weighted round-robin
│   │   │   └── adaptive.rs     # Adaptive strategy
│   │   ├── guard.rs            # PoolGuard (RAII)
│   │   ├── manager.rs          # PoolManager
│   │   ├── hooks.rs            # PoolHook trait
│   │   └── metrics.rs          # Pool metrics
│   │
│   ├── resources/              # Core built-in resources
│   │   ├── mod.rs
│   │   ├── logger/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # LoggerResource
│   │   │   ├── config.rs       # LoggerConfig
│   │   │   ├── instance.rs     # LoggerInstance
│   │   │   ├── targets/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── console.rs  # ConsoleWriter
│   │   │   │   ├── file.rs     # FileWriter with rotation
│   │   │   │   ├── remote.rs   # RemoteWriter
│   │   │   │   └── syslog.rs   # SyslogWriter
│   │   │   ├── context_aware.rs # ContextAwareLogger
│   │   │   ├── formats.rs      # LogFormat (JSON, Text, Logfmt, Custom)
│   │   │   ├── rotation.rs     # File rotation logic
│   │   │   └── buffer.rs       # Log buffering
│   │   ├── metrics/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # MetricsResource
│   │   │   ├── config.rs       # MetricsConfig
│   │   │   ├── collector.rs    # MetricsCollector
│   │   │   ├── exporters/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── prometheus.rs
│   │   │   │   ├── statsd.rs
│   │   │   │   ├── otlp.rs
│   │   │   │   └── json.rs
│   │   │   ├── types/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── counter.rs
│   │   │   │   ├── gauge.rs
│   │   │   │   ├── histogram.rs
│   │   │   │   └── summary.rs
│   │   │   └── aggregation.rs  # Metric aggregation
│   │   ├── http/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # HttpResource
│   │   │   ├── config.rs       # HttpConfig (includes resilience configs)
│   │   │   ├── client.rs       # HttpClient with retry/circuit breaker
│   │   │   ├── request.rs      # Request builder
│   │   │   ├── response.rs     # Response handling
│   │   │   ├── interceptors.rs # Request/Response interceptors
│   │   │   ├── auth.rs         # Authentication (Bearer, Basic, OAuth2)
│   │   │   └── compression.rs  # Request/Response compression
│   │   ├── cache/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # CacheResource
│   │   │   ├── config.rs       # CacheConfig
│   │   │   ├── backends/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── redis.rs    # RedisCache
│   │   │   │   ├── memory.rs   # InMemoryCache
│   │   │   │   ├── memcached.rs # MemcachedCache
│   │   │   │   └── hybrid.rs   # Multi-tier cache
│   │   │   ├── strategies/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── lru.rs      # LRU eviction
│   │   │   │   ├── lfu.rs      # LFU eviction
│   │   │   │   ├── fifo.rs     # FIFO eviction
│   │   │   │   └── arc.rs      # ARC algorithm
│   │   │   ├── serialization.rs # Cache serialization
│   │   │   └── invalidation.rs # Cache invalidation
│   │   ├── database/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # DatabaseResource
│   │   │   ├── config.rs       # DatabaseConfig
│   │   │   ├── pool.rs         # Connection pooling
│   │   │   ├── backends/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── postgres.rs # PostgreSQL with PgPool
│   │   │   │   ├── mysql.rs    # MySQL
│   │   │   │   ├── sqlite.rs   # SQLite
│   │   │   │   └── mongodb.rs  # MongoDB
│   │   │   ├── transaction.rs  # Transaction management
│   │   │   ├── migration.rs    # Database migrations
│   │   │   └── query_cache.rs  # Query result caching
│   │   ├── storage/            # Object storage (S3-compatible)
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs     # S3StorageResource
│   │   │   ├── config.rs       # S3StorageConfig
│   │   │   ├── client.rs       # S3Client wrapper
│   │   │   ├── multipart.rs    # Multipart upload
│   │   │   ├── presigned.rs    # Presigned URLs
│   │   │   ├── encryption.rs   # Client/Server-side encryption
│   │   │   └── lifecycle.rs    # Object lifecycle policies
│   │   ├── message_queue/      # Message queue resources
│   │   │   ├── mod.rs
│   │   │   ├── kafka/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── resource.rs
│   │   │   │   ├── producer.rs
│   │   │   │   └── consumer.rs
│   │   │   ├── rabbitmq/
│   │   │   │   ├── mod.rs
│   │   │   │   └── resource.rs
│   │   │   └── sqs/
│   │   │       ├── mod.rs
│   │   │       └── resource.rs
│   │   └── custom/             # Examples of custom resources
│   │       ├── mod.rs
│   │       ├── telegram_bot.rs
│   │       ├── openai.rs
│   │       └── elasticsearch.rs
│   │
│   ├── plugin/                 # Plugin system
│   │   ├── mod.rs
│   │   ├── loader.rs          # PluginLoader
│   │   ├── registry.rs        # PluginRegistry
│   │   ├── api.rs             # Plugin API/ABI
│   │   ├── descriptor.rs      # PluginDescriptor
│   │   ├── dependency.rs      # Plugin dependencies
│   │   ├── sandbox/
│   │   │   ├── mod.rs
│   │   │   ├── process.rs     # Process isolation
│   │   │   ├── wasm.rs        # WASM sandbox
│   │   │   └── container.rs   # Container isolation
│   │   ├── hot_reload.rs      # Hot reload support
│   │   ├── discovery/
│   │   │   ├── mod.rs
│   │   │   ├── filesystem.rs  # File system discovery
│   │   │   ├── manifest.rs    # Manifest-based discovery
│   │   │   └── registry.rs    # Registry discovery
│   │   └── security.rs        # Plugin security & signatures
│   │
│   ├── observability/          # Observability
│   │   ├── mod.rs
│   │   ├── tracing/
│   │   │   ├── mod.rs
│   │   │   ├── provider.rs    # TraceProvider
│   │   │   ├── span.rs        # Span management
│   │   │   └── propagation.rs # Context propagation
│   │   ├── logging/
│   │   │   ├── mod.rs
│   │   │   └── structured.rs  # Structured logging
│   │   ├── metrics/
│   │   │   ├── mod.rs
│   │   │   └── collector.rs   # Metrics collection
│   │   ├── health/
│   │   │   ├── mod.rs
│   │   │   ├── checker.rs     # HealthChecker
│   │   │   ├── pipeline.rs    # HealthPipeline
│   │   │   └── aggregator.rs  # Health aggregation
│   │   └── dashboard.rs       # Metrics dashboard
│   │
│   ├── credential/             # Credential integration
│   │   ├── mod.rs
│   │   ├── provider.rs        # CredentialProvider trait
│   │   ├── rotation/
│   │   │   ├── mod.rs
│   │   │   ├── rotator.rs     # CredentialRotator
│   │   │   ├── strategy.rs    # Rotation strategies
│   │   │   └── scheduler.rs   # Rotation scheduler
│   │   ├── vault/
│   │   │   ├── mod.rs
│   │   │   ├── hashicorp.rs   # HashiCorp Vault
│   │   │   ├── aws.rs         # AWS Secrets Manager
│   │   │   └── azure.rs       # Azure Key Vault
│   │   └── integration.rs     # nebula-credential integration
│   │
│   ├── state/                  # State management
│   │   ├── mod.rs
│   │   ├── container.rs       # StateContainer
│   │   ├── persistence/
│   │   │   ├── mod.rs
│   │   │   ├── backend.rs     # StatePersistence trait
│   │   │   ├── file.rs        # File persistence
│   │   │   └── database.rs    # Database persistence
│   │   ├── versioning.rs      # State versioning
│   │   ├── migration.rs       # State migration
│   │   └── snapshot.rs        # State snapshots
│   │
│   ├── testing/               # Testing utilities
│   │   ├── mod.rs
│   │   ├── mocks/
│   │   │   ├── mod.rs
│   │   │   ├── resource.rs    # MockResource
│   │   │   ├── manager.rs     # TestResourceManager
│   │   │   └── context.rs     # MockContext
│   │   ├── fixtures.rs       # Test fixtures
│   │   ├── helpers.rs        # Test helpers
│   │   └── harness.rs        # Test harness
│   │
│   └── macros/               # Procedural macros
│       ├── mod.rs
│       ├── derive/
│       │   ├── mod.rs
│       │   ├── resource.rs   # #[derive(Resource)]
│       │   ├── config.rs     # #[derive(ResourceConfig)]
│       │   └── enricher.rs   # #[derive(Enricher)]
│       └── attribute/
│           ├── mod.rs
│           ├── resource.rs   # #[resource(...)]
│           ├── credential.rs # #[credential(...)]
│           └── health.rs     # #[health_check(...)]
│
├── tests/
│   ├── integration/
│   │   ├── basic_resources.rs
│   │   ├── resilience.rs
│   │   ├── pooling.rs
│   │   ├── context_awareness.rs
│   │   ├── credential_rotation.rs
│   │   ├── dependency_graph.rs
│   │   ├── resource_scoping.rs
│   │   ├── plugins.rs
│   │   └── health_checks.rs
│   └── common/
│       ├── mod.rs
│       └── utils.rs
│
├── benches/
│   ├── pool_performance.rs
│   ├── resilience.rs
│   ├── resource_acquisition.rs
│   ├── context_enrichment.rs
│   └── plugin_loading.rs
│
└── docs/
    ├── architecture.md
    ├── getting-started/
    │   ├── installation.md
    │   ├── quick-start.md
    │   └── basic-concepts.md
    ├── how-to/
    │   ├── create-resource.md
    │   ├── context-aware.md
    │   ├── credential-integration.md
    │   ├── dependency-graph.md
    │   ├── resource-scoping.md
    │   └── health-pipeline.md
    ├── reference/
    │   ├── api.md
    │   ├── traits.md
    │   ├── types.md
    │   ├── events.md
    │   └── hooks.md
    └── examples/
        ├── http-client.md
        ├── database-pool.md
        ├── cache-strategy.md
        └── s3-storage.md
```

## Cargo.toml

```toml
[package]
name = "nebula-resource"
version = "0.2.0"
edition = "2021"
authors = ["Your Name"]
description = "Unified resource management for Nebula workflow engine"
license = "MIT OR Apache-2.0"
repository = "https://github.com/yourusername/nebula-resource"
keywords = ["resource", "pool", "resilience", "workflow", "nebula"]
categories = ["asynchronous", "web-programming", "database"]

[dependencies]
# Core
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
futures = "0.3"

# Serialization
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0.9"
toml = "0.8"

# Error handling
thiserror = "1"
anyhow = "1"

# Logging & Tracing
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
slog = "2"
log = "0.4"

# Metrics
prometheus = { version = "0.13", optional = true }
opentelemetry = { version = "0.21", optional = true }
opentelemetry-prometheus = { version = "0.14", optional = true }

# HTTP
reqwest = { version = "0.11", features = ["json", "stream"], optional = true }
hyper = { version = "0.14", optional = true }

# Database
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres", "mysql", "sqlite"], optional = true }
mongodb = { version = "2.7", optional = true }

# Cache
redis = { version = "0.23", features = ["aio", "tokio-comp"], optional = true }
memcache = { version = "0.17", optional = true }

# Storage
aws-sdk-s3 = { version = "1.0", optional = true }
aws-config = { version = "1.0", optional = true }
aws-smithy-types = { version = "1.0", optional = true }

# Message Queue
rdkafka = { version = "0.34", features = ["tokio"], optional = true }
lapin = { version = "2.3", optional = true }

# Plugin support
libloading = { version = "0.8", optional = true }
wasmtime = { version = "15", optional = true }
notify = { version = "6.1", optional = true }

# Utilities
parking_lot = "0.12"
dashmap = "5"
lru = "0.12"
crossbeam = "0.8"
rand = "0.8"
uuid = { version = "1", features = ["v4", "serde"] }
chrono = { version = "0.4", features = ["serde"] }
humantime-serde = "1"
base64 = "0.21"
arc-swap = "1"
bytes = "1"
pin-project = "1"
once_cell = "1"
indexmap = "2"
smallvec = "1"
semver = { version = "1", features = ["serde"] }

# Resilience
governor = { version = "0.6", optional = true }
backoff = { version = "0.4", optional = true }
circuit-breaker = { version = "0.1", optional = true }

# Crypto
ring = { version = "0.17", optional = true }
rustls = { version = "0.21", optional = true }

# Async utilities
async-stream = "0.3"
async-recursion = "1"

# Testing
mockall = { version = "0.11", optional = true }
proptest = { version = "1", optional = true }
fake = { version = "2.9", optional = true }

# Macro support
nebula-resource-macros = { version = "0.2", path = "../nebula-resource-macros", optional = true }

[dev-dependencies]
tokio-test = "0.4"
criterion = { version = "0.5", features = ["async_tokio"] }
tempfile = "3"
wiremock = "0.5"
pretty_assertions = "1"
test-case = "3"
serial_test = "3"

[features]
default = ["core", "builtin-resources", "resilience", "macros"]

# Core functionality
core = []

# Macros
macros = ["nebula-resource-macros"]

# Built-in resources
builtin-resources = ["logger", "metrics", "http", "cache", "database"]
logger = []
metrics = ["prometheus", "opentelemetry", "opentelemetry-prometheus"]
http = ["reqwest", "hyper"]
cache = ["redis", "memcache"]
database = ["sqlx", "mongodb"]
storage = ["aws-sdk-s3", "aws-config", "aws-smithy-types"]
message-queue = ["rdkafka", "lapin"]

# Resilience patterns
resilience = ["governor", "backoff", "circuit-breaker"]

# Plugin system
plugins = ["libloading", "notify"]
wasm-plugins = ["wasmtime"]

# Security
security = ["ring", "rustls"]

# Testing utilities
testing = ["mockall", "proptest", "fake"]

# Full feature set
full = [
    "core",
    "macros",
    "builtin-resources",
    "storage",
    "message-queue",
    "resilience",
    "plugins",
    "wasm-plugins",
    "security",
    "testing"
]

[[example]]
name = "basic_usage"

[[example]]
name = "custom_resource"

[[example]]
name = "with_resilience"

[[example]]
name = "context_aware"

[[example]]
name = "credential_rotation"

[[example]]
name = "dependency_graph"

[[example]]
name = "resource_scoping"

[[example]]
name = "plugin_example"
required-features = ["plugins"]

[[example]]
name = "health_pipeline"

[[bench]]
name = "pool_performance"
harness = false

[[bench]]
name = "resilience"
harness = false

[[bench]]
name = "resource_acquisition"
harness = false

[[bench]]
name = "context_enrichment"
harness = false

[[bench]]
name = "plugin_loading"
harness = false
required-features = ["plugins"]

[package.metadata.docs.rs]
all-features = true
rustdoc-args = ["--cfg", "docsrs"]
```

## Key Components Summary

### Core Traits (from How-To examples)

- **Resource** - базовый trait
- **CloneableResource** - для клонируемых ресурсов
- **ConfigurableResource** - с runtime конфигурацией
- **StatefulResource** - с управлением состоянием
- **RefreshableResource** - обновляемые ресурсы
- **ObservableResource** - с метриками
- **PoolableResource** - поддержка пулинга
- **HealthCheckable** - health checks
- **ContextAware** - контекстная осведомленность
- **CredentialAware** - интеграция с credentials
- **ManagedResource** - полный lifecycle management
- **DynamicResource** - для плагинов

### Enrichers (from ContextEnricher example)

- **UserEnricher** - добавляет user info
- **GeoEnricher** - геолокация
- **SecurityEnricher** - security context
- **TenantEnricher** - tenant информация
- **AnalyticsEnricher** - аналитические метки

### Lifecycle Components

- **LifecycleManager** - управление жизненным циклом
- **LifecycleHook** - хуки для lifecycle events
- **StateHistory** - история изменений состояния
- **AutoLifecycleManager** - автоматическое управление

### Dependency Management

- **DependencyGraph** - граф зависимостей
- **ResourceContainer** - DI контейнер
- **Topological sorting** - правильный порядок инициализации

### Resource Scoping

- **ScopeManager** - управление scope
- **ScopeTree** - иерархия scopes
- **SharingPolicy** - политики sharing между scopes
- **Resource migration** - перемещение между scopes

### Events System

- **EventEmitter** - emit events
- **EventHandler** - обработка событий
- **EventProcessor** - процессинг событий
- **ResourceEvent** - типы событий

### Health Management

- **HealthChecker** - проверки здоровья
- **HealthPipeline** - pipeline проверок
- **HealthAggregator** - агрегация статусов

### State Management

- **StateContainer** - контейнер состояния
- **StatePersistence** - персистентность
- **StateVersioning** - версионирование
- **StateMigration** - миграция состояний

Эта структура полностью покрывает все компоненты, которые мы обсуждали, включая все трейты из How-To, примеры ресурсов, resilience компоненты и систему плагинов!