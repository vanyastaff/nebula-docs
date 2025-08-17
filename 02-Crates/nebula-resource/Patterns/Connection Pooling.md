# Connection Pooling Patterns

## Overview

Connection pooling is a pattern for reusing expensive resources (database connections, network sockets, threads) instead of creating and destroying them for each use. This dramatically improves performance and resource utilization.

## Core Concepts

```
┌──────────────────────────────────────┐
│           Application                 │
└──────────────┬───────────────────────┘
               │ acquire()
               ▼
┌──────────────────────────────────────┐
│         Connection Pool              │
│  ┌────────────────────────────────┐  │
│  │   Available Connections        │  │
│  │  ┌──┐ ┌──┐ ┌──┐ ┌──┐ ┌──┐   │  │
│  │  │C1│ │C2│ │C3│ │C4│ │C5│   │  │
│  │  └──┘ └──┘ └──┘ └──┘ └──┘   │  │
│  └────────────────────────────────┘  │
│  ┌────────────────────────────────┐  │
│  │   In-Use Connections           │  │
│  │  ┌──┐ ┌──┐                    │  │
│  │  │C6│ │C7│                    │  │
│  │  └──┘ └──┘                    │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

## Implementation

### Generic Connection Pool

```rust
use std::sync::Arc;
use tokio::sync::{Semaphore, RwLock, Mutex};
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Generic connection pool
pub struct ConnectionPool<C: Connection> {
    /// Pool configuration
    config: PoolConfig,
    
    /// Available connections
    available: Arc<Mutex<VecDeque<PooledConnection<C>>>>,
    
    /// Semaphore for limiting total connections
    semaphore: Arc<Semaphore>,
    
    /// Connection factory
    factory: Arc<dyn ConnectionFactory<C>>,
    
    /// Pool metrics
    metrics: Arc<PoolMetrics>,
    
    /// Background tasks handle
    background_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Connection trait
#[async_trait]
pub trait Connection: Send + Sync + 'static {
    /// Check if connection is still valid
    async fn is_valid(&self) -> bool;
    
    /// Ping the connection
    async fn ping(&self) -> Result<()>;
    
    /// Reset connection state
    async fn reset(&self) -> Result<()>;
    
    /// Close the connection
    async fn close(self) -> Result<()>;
}

/// Connection factory trait
#[async_trait]
pub trait ConnectionFactory<C: Connection>: Send + Sync {
    /// Create a new connection
    async fn create(&self) -> Result<C>;
    
    /// Validate a connection
    async fn validate(&self, conn: &C) -> Result<()>;
    
    /// Connection configuration
    fn config(&self) -> &ConnectionConfig;
}

/// Pooled connection wrapper
pub struct PooledConnection<C: Connection> {
    /// The actual connection
    conn: Option<C>,
    
    /// Pool reference for returning
    pool: Weak<ConnectionPool<C>>,
    
    /// Connection metadata
    metadata: ConnectionMetadata,
}

#[derive(Debug, Clone)]
struct ConnectionMetadata {
    /// When connection was created
    created_at: Instant,
    
    /// Last time connection was used
    last_used: Instant,
    
    /// Number of times used
    use_count: u64,
    
    /// Connection ID for tracking
    id: uuid::Uuid,
}

impl<C: Connection> ConnectionPool<C> {
    /// Create a new connection pool
    pub async fn new(
        config: PoolConfig,
        factory: impl ConnectionFactory<C> + 'static,
    ) -> Result<Self> {
        let pool = Arc::new(Self {
            config: config.clone(),
            available: Arc::new(Mutex::new(VecDeque::new())),
            semaphore: Arc::new(Semaphore::new(config.max_size)),
            factory: Arc::new(factory),
            metrics: Arc::new(PoolMetrics::new()),
            background_handle: None,
        });
        
        // Pre-warm the pool if configured
        if config.min_idle > 0 {
            pool.clone().warm_up().await?;
        }
        
        // Start background maintenance
        let mut pool_mut = pool.clone();
        let handle = tokio::spawn(async move {
            pool_mut.background_maintenance().await;
        });
        
        // Can't modify self after creating Arc, so we use unsafe
        unsafe {
            let pool_ptr = Arc::as_ptr(&pool) as *mut Self;
            (*pool_ptr).background_handle = Some(handle);
        }
        
        Ok(pool)
    }
    
    /// Acquire a connection from the pool
    pub async fn acquire(&self) -> Result<PooledConnection<C>> {
        self.acquire_with_timeout(self.config.acquire_timeout).await
    }
    
    /// Acquire with custom timeout
    pub async fn acquire_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<PooledConnection<C>> {
        let deadline = Instant::now() + timeout;
        
        loop {
            // Try to get an available connection
            if let Some(conn) = self.try_acquire_available().await? {
                return Ok(conn);
            }
            
            // Try to create a new connection if under limit
            if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
                match self.create_new_connection().await {
                    Ok(conn) => {
                        permit.forget(); // Keep the permit
                        return Ok(conn);
                    }
                    Err(e) => {
                        drop(permit); // Release the permit
                        return Err(e);
                    }
                }
            }
            
            // Wait for a connection to become available
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.metrics.record_timeout();
                return Err(Error::AcquisitionTimeout);
            }
            
            match tokio::time::timeout(remaining, self.wait_for_available()).await {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    self.metrics.record_timeout();
                    return Err(Error::AcquisitionTimeout);
                }
            }
        }
    }
    
    /// Try to acquire an available connection
    async fn try_acquire_available(&self) -> Result<Option<PooledConnection<C>>> {
        let mut available = self.available.lock().await;
        
        while let Some(mut pooled) = available.pop_front() {
            // Check if connection is still valid
            if pooled.metadata.created_at.elapsed() > self.config.max_lifetime {
                self.metrics.record_eviction(EvictionReason::MaxLifetime);
                continue;
            }
            
            if pooled.metadata.last_used.elapsed() > self.config.idle_timeout {
                self.metrics.record_eviction(EvictionReason::IdleTimeout);
                continue;
            }
            
            if let Some(ref conn) = pooled.conn {
                if !conn.is_valid().await {
                    self.metrics.record_eviction(EvictionReason::Invalid);
                    continue;
                }
                
                // Test the connection if configured
                if self.config.test_on_acquire {
                    if conn.ping().await.is_err() {
                        self.metrics.record_eviction(EvictionReason::PingFailed);
                        continue;
                    }
                }
                
                // Update metadata
                pooled.metadata.last_used = Instant::now();
                pooled.metadata.use_count += 1;
                
                self.metrics.record_acquisition();
                return Ok(Some(pooled));
            }
        }
        
        Ok(None)
    }
    
    /// Create a new connection
    async fn create_new_connection(&self) -> Result<PooledConnection<C>> {
        let start = Instant::now();
        let conn = self.factory.create().await?;
        self.metrics.record_connection_created(start.elapsed());
        
        Ok(PooledConnection {
            conn: Some(conn),
            pool: Arc::downgrade(&Arc::new(self.clone())),
            metadata: ConnectionMetadata {
                created_at: Instant::now(),
                last_used: Instant::now(),
                use_count: 0,
                id: uuid::Uuid::new_v4(),
            },
        })
    }
    
    /// Return a connection to the pool
    pub(crate) async fn return_connection(&self, mut pooled: PooledConnection<C>) {
        if let Some(conn) = pooled.conn.take() {
            // Reset the connection if configured
            if self.config.reset_on_return {
                if conn.reset().await.is_err() {
                    self.metrics.record_eviction(EvictionReason::ResetFailed);
                    return;
                }
            }
            
            // Check if we should keep the connection
            let mut available = self.available.lock().await;
            if available.len() < self.config.max_idle {
                pooled.conn = Some(conn);
                available.push_back(pooled);
                self.metrics.record_return();
            } else {
                // Pool is full, close the connection
                let _ = conn.close().await;
                self.metrics.record_eviction(EvictionReason::PoolFull);
            }
        }
    }
    
    /// Warm up the pool
    async fn warm_up(&self) -> Result<()> {
        let mut connections = Vec::new();
        
        for _ in 0..self.config.min_idle {
            match self.create_new_connection().await {
                Ok(conn) => connections.push(conn),
                Err(e) => {
                    // Return created connections to pool
                    for conn in connections {
                        self.return_connection(conn).await;
                    }
                    return Err(e);
                }
            }
        }
        
        // Return all connections to pool
        for conn in connections {
            self.return_connection(conn).await;
        }
        
        Ok(())
    }
    
    /// Background maintenance task
    async fn background_maintenance(&self) {
        let mut interval = tokio::time::interval(self.config.maintenance_interval);
        
        loop {
            interval.tick().await;
            
            // Remove idle connections
            self.remove_idle_connections().await;
            
            // Validate connections
            if self.config.validate_on_maintenance {
                self.validate_connections().await;
            }
            
            // Ensure minimum connections
            self.ensure_min_connections().await;
        }
    }
}
```

### Dynamic Pool Sizing

```rust
pub struct DynamicPool<C: Connection> {
    base_pool: Arc<ConnectionPool<C>>,
    scaler: Arc<PoolScaler>,
    metrics_window: Arc<RwLock<MetricsWindow>>,
}

pub struct PoolScaler {
    config: ScalerConfig,
    last_scale_time: RwLock<Instant>,
    current_size: AtomicUsize,
}

#[derive(Debug, Clone)]
pub struct ScalerConfig {
    /// Minimum pool size
    pub min_size: usize,
    
    /// Maximum pool size
    pub max_size: usize,
    
    /// Target utilization (0.0 to 1.0)
    pub target_utilization: f64,
    
    /// Scale up threshold
    pub scale_up_threshold: f64,
    
    /// Scale down threshold
    pub scale_down_threshold: f64,
    
    /// Cooldown period between scaling operations
    pub cooldown_period: Duration,
    
    /// Scaling factor
    pub scale_factor: f64,
}

impl<C: Connection> DynamicPool<C> {
    /// Auto-scale based on metrics
    pub async fn auto_scale(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        
        loop {
            interval.tick().await;
            
            let metrics = self.collect_metrics().await;
            let decision = self.scaler.decide_scaling(&metrics).await;
            
            match decision {
                ScalingDecision::ScaleUp(amount) => {
                    self.scale_up(amount).await;
                }
                ScalingDecision::ScaleDown(amount) => {
                    self.scale_down(amount).await;
                }
                ScalingDecision::NoChange => {}
            }
        }
    }
    
    async fn collect_metrics(&self) -> PoolMetricsSnapshot {
        let window = self.metrics_window.read().await;
        PoolMetricsSnapshot {
            utilization: window.average_utilization(),
            wait_time_p99: window.wait_time_p99(),
            acquisition_rate: window.acquisition_rate(),
            error_rate: window.error_rate(),
        }
    }
    
    async fn scale_up(&self, amount: usize) {
        info!("Scaling up pool by {} connections", amount);
        
        for _ in 0..amount {
            if let Ok(conn) = self.base_pool.create_new_connection().await {
                self.base_pool.return_connection(conn).await;
            }
        }
        
        self.scaler.current_size.fetch_add(amount, Ordering::Relaxed);
    }
    
    async fn scale_down(&self, amount: usize) {
        info!("Scaling down pool by {} connections", amount);
        
        let mut available = self.base_pool.available.lock().await;
        for _ in 0..amount.min(available.len()) {
            available.pop_back();
        }
        
        self.scaler.current_size.fetch_sub(amount, Ordering::Relaxed);
    }
}
```

### Hierarchical Connection Pools

```rust
/// Multi-level connection pool for different priorities
pub struct HierarchicalPool<C: Connection> {
    /// High priority pool
    high_priority: Arc<ConnectionPool<C>>,
    
    /// Normal priority pool
    normal_priority: Arc<ConnectionPool<C>>,
    
    /// Low priority pool (best effort)
    low_priority: Arc<ConnectionPool<C>>,
    
    /// Shared overflow pool
    overflow: Arc<ConnectionPool<C>>,
}

impl<C: Connection> HierarchicalPool<C> {
    pub async fn acquire(&self, priority: Priority) -> Result<PooledConnection<C>> {
        // Try to acquire from appropriate pool
        let primary_pool = match priority {
            Priority::High => &self.high_priority,
            Priority::Normal => &self.normal_priority,
            Priority::Low => &self.low_priority,
        };
        
        // Try primary pool first
        match primary_pool.try_acquire().await {
            Ok(Some(conn)) => return Ok(conn),
            Ok(None) => {},
            Err(e) => return Err(e),
        }
        
        // Try overflow pool for high/normal priority
        if priority != Priority::Low {
            if let Ok(conn) = self.overflow.try_acquire().await? {
                return Ok(conn);
            }
        }
        
        // Fall back to waiting on primary pool
        primary_pool.acquire().await
    }
    
    /// Rebalance connections between pools
    pub async fn rebalance(&self) {
        // Move connections from low to high priority if needed
        let high_metrics = self.high_priority.metrics.snapshot();
        let low_metrics = self.low_priority.metrics.snapshot();
        
        if high_metrics.wait_time_avg > Duration::from_millis(100) 
            && low_metrics.utilization < 0.5 {
            // Move connections from low to high priority pool
            self.transfer_connections(
                &self.low_priority,
                &self.high_priority,
                2
            ).await;
        }
    }
}
```

### Sharded Connection Pool

```rust
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;

/// Sharded pool for better concurrency
pub struct ShardedPool<C: Connection> {
    shards: Vec<Arc<ConnectionPool<C>>>,
    shard_count: usize,
}

impl<C: Connection> ShardedPool<C> {
    pub fn new(shard_count: usize, config: PoolConfig) -> Self {
        let shards = (0..shard_count)
            .map(|_| Arc::new(ConnectionPool::new(config.clone())))
            .collect();
        
        Self {
            shards,
            shard_count,
        }
    }
    
    /// Acquire from a specific shard
    pub async fn acquire_from_shard(&self, key: impl Hash) -> Result<PooledConnection<C>> {
        let shard_idx = self.get_shard_index(key);
        self.shards[shard_idx].acquire().await
    }
    
    /// Acquire from least loaded shard
    pub async fn acquire_balanced(&self) -> Result<PooledConnection<C>> {
        // Find shard with lowest utilization
        let mut best_shard = 0;
        let mut min_utilization = f64::MAX;
        
        for (idx, shard) in self.shards.iter().enumerate() {
            let utilization = shard.metrics.current_utilization();
            if utilization < min_utilization {
                min_utilization = utilization;
                best_shard = idx;
            }
        }
        
        self.shards[best_shard].acquire().await
    }
    
    fn get_shard_index(&self, key: impl Hash) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % self.shard_count
    }
}
```

## Specialized Pools

### Database Connection Pool

```rust
use sqlx::{PgConnection, Connection as SqlxConnection};

pub struct DatabasePool {
    inner: sqlx::PgPool,
    config: DatabasePoolConfig,
    health_checker: Arc<dyn HealthChecker>,
}

impl DatabasePool {
    pub async fn new(config: DatabasePoolConfig) -> Result<Self> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .connect_timeout(config.connect_timeout)
            .idle_timeout(config.idle_timeout)
            .max_lifetime(config.max_lifetime)
            .test_before_acquire(config.test_before_acquire)
            .connect(&config.database_url)
            .await?;
        
        Ok(Self {
            inner: pool,
            config,
            health_checker: Arc::new(DefaultHealthChecker),
        })
    }
    
    /// Execute query with automatic retry
    pub async fn execute_with_retry<'a, T, F>(&self, f: F) -> Result<T>
    where
        F: Fn(&mut PgConnection) -> Future<Output = Result<T>> + Send,
    {
        let mut retries = 0;
        let max_retries = self.config.max_retries;
        
        loop {
            let mut conn = self.inner.acquire().await?;
            
            match f(&mut conn).await {
                Ok(result) => return Ok(result),
                Err(e) if retries < max_retries && self.is_retryable(&e) => {
                    retries += 1;
                    let delay = self.calculate_retry_delay(retries);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e),
            }
        }
    }
    
    fn is_retryable(&self, error: &Error) -> bool {
        // Check if error is retryable (connection errors, deadlocks, etc.)
        matches!(error, 
            Error::Connection(_) | 
            Error::Deadlock | 
            Error::Timeout
        )
    }
}
```

### HTTP Connection Pool

```rust
use hyper::client::HttpConnector;
use hyper_tls::HttpsConnector;

pub struct HttpConnectionPool {
    client: hyper::Client<HttpsConnector<HttpConnector>>,
    config: HttpPoolConfig,
    rate_limiter: Arc<RateLimiter>,
}

impl HttpConnectionPool {
    pub fn new(config: HttpPoolConfig) -> Self {
        let https = HttpsConnector::new();
        let client = hyper::Client::builder()
            .pool_idle_timeout(config.idle_timeout)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .http2_initial_connection_window_size(config.initial_window_size)
            .http2_max_concurrent_streams(config.max_concurrent_streams)
            .build::<_, hyper::Body>(https);
        
        Self {
            client,
            config,
            rate_limiter: Arc::new(RateLimiter::new(config.rate_limit)),
        }
    }
    
    pub async fn request(&self, req: Request<Body>) -> Result<Response<Body>> {
        // Apply rate limiting
        self.rate_limiter.acquire().await?;
        
        // Execute request
        self.client
            .request(req)
            .await
            .map_err(|e| Error::Http(e))
    }
}
```

## Pool Metrics

```rust
#[derive(Debug, Clone)]
pub struct PoolMetrics {
    /// Total connections created
    connections_created: Arc<AtomicU64>,
    
    /// Total connections destroyed
    connections_destroyed: Arc<AtomicU64>,
    
    /// Current active connections
    active_connections: Arc<AtomicU64>,
    
    /// Current idle connections
    idle_connections: Arc<AtomicU64>,
    
    /// Total acquisitions
    total_acquisitions: Arc<AtomicU64>,
    
    /// Total timeouts
    total_timeouts: Arc<AtomicU64>,
    
    /// Wait time histogram
    wait_times: Arc<RwLock<Histogram>>,
    
    /// Connection lifetime histogram
    lifetimes: Arc<RwLock<Histogram>>,
}

impl PoolMetrics {
    pub fn snapshot(&self) -> MetricsSnapshot {
        let wait_times = self.wait_times.read().unwrap();
        let lifetimes = self.lifetimes.read().unwrap();
        
        MetricsSnapshot {
            connections_created: self.connections_created.load(Ordering::Relaxed),
            connections_destroyed: self.connections_destroyed.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            idle_connections: self.idle_connections.load(Ordering::Relaxed),
            total_acquisitions: self.total_acquisitions.load(Ordering::Relaxed),
            total_timeouts: self.total_timeouts.load(Ordering::Relaxed),
            wait_time_p50: wait_times.percentile(50.0),
            wait_time_p99: wait_times.percentile(99.0),
            avg_lifetime: lifetimes.mean(),
            utilization: self.calculate_utilization(),
        }
    }
    
    fn calculate_utilization(&self) -> f64 {
        let active = self.active_connections.load(Ordering::Relaxed) as f64;
        let total = active + self.idle_connections.load(Ordering::Relaxed) as f64;
        
        if total > 0.0 {
            active / total
        } else {
            0.0
        }
    }
}
```

## Configuration

```yaml
connection_pools:
  database:
    min_size: 5
    max_size: 20
    max_idle: 10
    acquire_timeout: 30s
    idle_timeout: 10m
    max_lifetime: 1h
    test_before_acquire: true
    reset_on_return: true
    maintenance_interval: 30s
    
  http:
    max_idle_per_host: 10
    idle_timeout: 90s
    max_concurrent_streams: 100
    initial_window_size: 65535
    rate_limit: 1000/s
    
  redis:
    min_size: 2
    max_size: 50
    acquire_timeout: 5s
    idle_timeout: 5m
    max_lifetime: 30m
```

## Best Practices

1. **Size pools appropriately** - Not too large (wastes resources) or too small (causes contention)
2. **Set reasonable timeouts** - Prevent indefinite waiting
3. **Validate connections** - Test before use to avoid failures
4. **Monitor pool metrics** - Track utilization and performance
5. **Implement health checks** - Remove bad connections proactively
6. **Use connection warming** - Pre-create connections for better latency
7. **Handle connection leaks** - Track and timeout long-running operations
8. **Configure per resource type** - Different resources need different settings
9. **Implement circuit breakers** - Prevent cascading failures
10. **Test under load** - Ensure pool behaves correctly under stress