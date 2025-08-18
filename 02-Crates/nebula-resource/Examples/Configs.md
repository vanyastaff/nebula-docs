# Resilience Components for nebula-resource

> Переиспользуемые компоненты для resilience: Retry, Circuit Breaker, Rate Limiting, Bulkhead, Timeout

## Core Module Structure

```rust
// nebula-resource/src/resilience/mod.rs
pub mod retry;
pub mod circuit_breaker;
pub mod rate_limiter;
pub mod bulkhead;
pub mod timeout;
pub mod fallback;
pub mod config;

pub use self::retry::*;
pub use self::circuit_breaker::*;
pub use self::rate_limiter::*;
pub use self::bulkhead::*;
pub use self::timeout::*;
pub use self::fallback::*;
pub use self::config::*;

// Re-export common traits
pub use self::traits::*;
```

## 1. Common Configuration

```rust
use serde::{Serialize, Deserialize};
use std::time::Duration;

/// Общая конфигурация resilience для всех ресурсов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResilienceConfig {
    #[serde(default)]
    pub retry: RetryConfig,
    
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    
    #[serde(default)]
    pub rate_limiter: Option<RateLimiterConfig>,
    
    #[serde(default)]
    pub bulkhead: Option<BulkheadConfig>,
    
    #[serde(default)]
    pub timeout: TimeoutConfig,
    
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
}

impl Default for ResilienceConfig {
    fn default() -> Self {
        Self {
            retry: RetryConfig::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
            rate_limiter: None,
            bulkhead: None,
            timeout: TimeoutConfig::default(),
            fallback: None,
        }
    }
}

/// Builder pattern для удобной конфигурации
impl ResilienceConfig {
    pub fn builder() -> ResilienceConfigBuilder {
        ResilienceConfigBuilder::new()
    }
}

pub struct ResilienceConfigBuilder {
    config: ResilienceConfig,
}

impl ResilienceConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: ResilienceConfig::default(),
        }
    }
    
    pub fn with_retry(mut self, retry: RetryConfig) -> Self {
        self.config.retry = retry;
        self
    }
    
    pub fn with_circuit_breaker(mut self, cb: CircuitBreakerConfig) -> Self {
        self.config.circuit_breaker = cb;
        self
    }
    
    pub fn with_rate_limiter(mut self, rl: RateLimiterConfig) -> Self {
        self.config.rate_limiter = Some(rl);
        self
    }
    
    pub fn build(self) -> ResilienceConfig {
        self.config
    }
}
```

## 2. Retry Component

```rust
use std::future::Future;
use std::time::Duration;
use async_trait::async_trait;
use rand::Rng;

/// Конфигурация retry политики
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Максимальное количество попыток
    pub max_attempts: u32,
    
    /// Стратегия retry
    pub strategy: RetryStrategy,
    
    /// Какие ошибки retry
    pub retry_on: RetryOn,
    
    /// Jitter для randomization
    pub jitter: JitterStrategy,
    
    /// Максимальная задержка
    pub max_delay: Duration,
    
    /// Таймаут для всех попыток
    pub overall_timeout: Option<Duration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryStrategy {
    /// Фиксированная задержка
    Fixed { delay: Duration },
    
    /// Линейное увеличение
    Linear { initial: Duration, increment: Duration },
    
    /// Экспоненциальное увеличение
    Exponential { initial: Duration, base: f64 },
    
    /// Fibonacci sequence
    Fibonacci { initial: Duration },
    
    /// Custom function
    #[serde(skip)]
    Custom(Box<dyn Fn(u32) -> Duration + Send + Sync>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JitterStrategy {
    None,
    Full,           // 0 to calculated delay
    Equal,          // 0.5 * delay ± 0.5 * delay
    Decorrelated,   // Advanced jitter
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RetryOn {
    All,
    Transient,      // Only transient errors
    StatusCodes(Vec<u16>),
    Custom(String), // Custom predicate name
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            strategy: RetryStrategy::Exponential {
                initial: Duration::from_millis(100),
                base: 2.0,
            },
            retry_on: RetryOn::Transient,
            jitter: JitterStrategy::Equal,
            max_delay: Duration::from_secs(30),
            overall_timeout: Some(Duration::from_secs(120)),
        }
    }
}

/// Retry executor
pub struct Retry {
    config: RetryConfig,
    metrics: Arc<RetryMetrics>,
}

impl Retry {
    pub fn new(config: RetryConfig) -> Self {
        Self {
            config,
            metrics: Arc::new(RetryMetrics::new()),
        }
    }
    
    /// Execute with retry
    pub async fn execute<F, Fut, T, E>(&self, mut f: F) -> Result<T, E>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        E: RetryableError,
    {
        let start = Instant::now();
        let mut attempt = 0;
        let mut last_error = None;
        
        while attempt < self.config.max_attempts {
            attempt += 1;
            
            // Check overall timeout
            if let Some(timeout) = self.config.overall_timeout {
                if start.elapsed() > timeout {
                    self.metrics.record_timeout();
                    return Err(last_error.unwrap_or_else(|| E::timeout()));
                }
            }
            
            match f().await {
                Ok(result) => {
                    self.metrics.record_success(attempt);
                    return Ok(result);
                }
                Err(error) => {
                    // Check if we should retry this error
                    if !self.should_retry(&error, attempt) {
                        self.metrics.record_failure(attempt);
                        return Err(error);
                    }
                    
                    last_error = Some(error);
                    
                    // Calculate delay if not last attempt
                    if attempt < self.config.max_attempts {
                        let delay = self.calculate_delay(attempt);
                        self.metrics.record_retry(attempt, delay);
                        tokio::time::sleep(delay).await;
                    }
                }
            }
        }
        
        self.metrics.record_exhausted();
        Err(last_error.unwrap())
    }
    
    fn should_retry(&self, error: &impl RetryableError, attempt: u32) -> bool {
        if attempt >= self.config.max_attempts {
            return false;
        }
        
        match &self.config.retry_on {
            RetryOn::All => true,
            RetryOn::Transient => error.is_transient(),
            RetryOn::StatusCodes(codes) => {
                if let Some(code) = error.status_code() {
                    codes.contains(&code)
                } else {
                    false
                }
            }
            RetryOn::Custom(_) => error.is_retryable(),
        }
    }
    
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay = match &self.config.strategy {
            RetryStrategy::Fixed { delay } => *delay,
            RetryStrategy::Linear { initial, increment } => {
                *initial + *increment * (attempt - 1)
            }
            RetryStrategy::Exponential { initial, base } => {
                let multiplier = base.powi(attempt as i32 - 1);
                initial.mul_f64(multiplier)
            }
            RetryStrategy::Fibonacci { initial } => {
                let fib = fibonacci(attempt);
                initial.mul_f64(fib as f64)
            }
            RetryStrategy::Custom(f) => f(attempt),
        };
        
        // Apply jitter
        let with_jitter = self.apply_jitter(base_delay);
        
        // Cap at max delay
        std::cmp::min(with_jitter, self.config.max_delay)
    }
    
    fn apply_jitter(&self, delay: Duration) -> Duration {
        match self.config.jitter {
            JitterStrategy::None => delay,
            JitterStrategy::Full => {
                let mut rng = rand::thread_rng();
                let jitter = rng.gen_range(0..=delay.as_millis() as u64);
                Duration::from_millis(jitter)
            }
            JitterStrategy::Equal => {
                let mut rng = rand::thread_rng();
                let half = delay.as_millis() as u64 / 2;
                let jitter = rng.gen_range(0..=delay.as_millis() as u64);
                Duration::from_millis(half + jitter / 2)
            }
            JitterStrategy::Decorrelated => {
                // Advanced decorrelated jitter
                let mut rng = rand::thread_rng();
                let base = delay.as_millis() as f64;
                let jitter = rng.gen_range(base..=base * 3.0);
                Duration::from_millis(jitter as u64)
            }
        }
    }
}

/// Trait for retryable errors
pub trait RetryableError {
    fn is_transient(&self) -> bool;
    fn is_retryable(&self) -> bool;
    fn status_code(&self) -> Option<u16>;
    fn timeout() -> Self;
}

fn fibonacci(n: u32) -> u32 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}
```

## 3. Circuit Breaker Component

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    
    /// Success threshold to close circuit
    pub success_threshold: u32,
    
    /// Time to wait before half-open
    pub timeout: Duration,
    
    /// Sample size for error rate
    pub sample_size: u32,
    
    /// Error rate threshold (0.0 to 1.0)
    pub error_rate_threshold: f64,
    
    /// Minimum requests before activation
    pub min_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            sample_size: 100,
            error_rate_threshold: 0.5,
            min_requests: 10,
        }
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, PartialEq)]
pub enum CircuitState {
    Closed,     // Normal operation
    Open,       // Failing, reject requests
    HalfOpen,   // Testing if recovered
}

/// Circuit breaker
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    stats: Arc<RwLock<CircuitStats>>,
    metrics: Arc<CircuitBreakerMetrics>,
}

struct CircuitStats {
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    request_count: u32,
    error_count: u32,
    window: Vec<bool>, // Sliding window of results
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            stats: Arc::new(RwLock::new(CircuitStats::new())),
            metrics: Arc::new(CircuitBreakerMetrics::new()),
        }
    }
    
    /// Check if request is allowed
    pub async fn allow_request(&self) -> bool {
        let mut state = self.state.write().await;
        let mut stats = self.stats.write().await;
        
        match *state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if timeout has passed
                if let Some(last_failure) = stats.last_failure_time {
                    if last_failure.elapsed() >= self.config.timeout {
                        *state = CircuitState::HalfOpen;
                        stats.success_count = 0;
                        self.metrics.record_state_change(CircuitState::HalfOpen);
                        true
                    } else {
                        self.metrics.record_rejected();
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                // Allow limited requests in half-open
                stats.request_count < self.config.success_threshold
            }
        }
    }
    
    /// Record success
    pub async fn record_success(&self) {
        let mut state = self.state.write().await;
        let mut stats = self.stats.write().await;
        
        stats.record_result(true);
        
        match *state {
            CircuitState::HalfOpen => {
                stats.success_count += 1;
                if stats.success_count >= self.config.success_threshold {
                    *state = CircuitState::Closed;
                    stats.reset();
                    self.metrics.record_state_change(CircuitState::Closed);
                }
            }
            CircuitState::Closed => {
                stats.failure_count = 0;
            }
            _ => {}
        }
        
        self.metrics.record_success();
    }
    
    /// Record failure
    pub async fn record_failure(&self) {
        let mut state = self.state.write().await;
        let mut stats = self.stats.write().await;
        
        stats.record_result(false);
        stats.last_failure_time = Some(Instant::now());
        
        match *state {
            CircuitState::Closed => {
                stats.failure_count += 1;
                
                // Check failure threshold
                if stats.failure_count >= self.config.failure_threshold {
                    *state = CircuitState::Open;
                    self.metrics.record_state_change(CircuitState::Open);
                }
                
                // Check error rate
                if stats.request_count >= self.config.min_requests {
                    let error_rate = stats.error_count as f64 / stats.request_count as f64;
                    if error_rate >= self.config.error_rate_threshold {
                        *state = CircuitState::Open;
                        self.metrics.record_state_change(CircuitState::Open);
                    }
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open;
                stats.reset();
                self.metrics.record_state_change(CircuitState::Open);
            }
            _ => {}
        }
        
        self.metrics.record_failure();
    }
    
    /// Execute with circuit breaker
    pub async fn execute<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
    {
        if !self.allow_request().await {
            return Err(CircuitBreakerError::Open);
        }
        
        match f().await {
            Ok(result) => {
                self.record_success().await;
                Ok(result)
            }
            Err(error) => {
                self.record_failure().await;
                Err(CircuitBreakerError::Execution(error))
            }
        }
    }
    
    /// Get current state
    pub async fn state(&self) -> CircuitState {
        self.state.read().await.clone()
    }
}

impl CircuitStats {
    fn new() -> Self {
        Self {
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            request_count: 0,
            error_count: 0,
            window: Vec::with_capacity(100),
        }
    }
    
    fn record_result(&mut self, success: bool) {
        self.request_count += 1;
        if !success {
            self.error_count += 1;
        }
        
        // Sliding window
        self.window.push(success);
        if self.window.len() > 100 {
            let removed = self.window.remove(0);
            if !removed {
                self.error_count = self.error_count.saturating_sub(1);
            }
        }
    }
    
    fn reset(&mut self) {
        self.failure_count = 0;
        self.success_count = 0;
        self.request_count = 0;
        self.error_count = 0;
        self.window.clear();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CircuitBreakerError<E> {
    #[error("Circuit breaker is open")]
    Open,
    
    #[error("Execution failed: {0}")]
    Execution(E),
}
```

## 4. Rate Limiter Component

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::time::{Duration, Instant};

/// Rate limiter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterConfig {
    /// Strategy for rate limiting
    pub strategy: RateLimitStrategy,
    
    /// Behavior when limit exceeded
    pub on_limit_exceeded: LimitExceededBehavior,
    
    /// Scope of rate limiting
    pub scope: RateLimitScope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitStrategy {
    /// Token bucket algorithm
    TokenBucket {
        capacity: u32,
        refill_rate: u32, // tokens per second
    },
    
    /// Leaky bucket algorithm
    LeakyBucket {
        capacity: u32,
        leak_rate: u32, // requests per second
    },
    
    /// Fixed window
    FixedWindow {
        requests: u32,
        window: Duration,
    },
    
    /// Sliding window
    SlidingWindow {
        requests: u32,
        window: Duration,
    },
    
    /// Adaptive (based on response times)
    Adaptive {
        target_latency: Duration,
        min_rate: u32,
        max_rate: u32,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LimitExceededBehavior {
    Reject,
    Queue { max_queue_size: usize },
    Delay { max_delay: Duration },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RateLimitScope {
    Global,
    PerClient,
    PerEndpoint,
    PerTenant,
    Custom(String),
}

/// Rate limiter
pub struct RateLimiter {
    config: RateLimiterConfig,
    limiter: Arc<dyn RateLimitBackend>,
    metrics: Arc<RateLimiterMetrics>,
}

#[async_trait]
trait RateLimitBackend: Send + Sync {
    async fn acquire(&self, key: Option<&str>) -> Result<(), RateLimitError>;
    async fn try_acquire(&self, key: Option<&str>) -> bool;
    async fn release(&self, key: Option<&str>);
}

/// Token bucket implementation
struct TokenBucket {
    semaphore: Arc<Semaphore>,
    capacity: u32,
    refill_rate: u32,
}

impl TokenBucket {
    fn new(capacity: u32, refill_rate: u32) -> Self {
        let semaphore = Arc::new(Semaphore::new(capacity as usize));
        let sem_clone = semaphore.clone();
        
        // Start refill task
        tokio::spawn(async move {
            let refill_interval = Duration::from_secs_f64(1.0 / refill_rate as f64);
            let mut interval = tokio::time::interval(refill_interval);
            
            loop {
                interval.tick().await;
                if sem_clone.available_permits() < capacity as usize {
                    sem_clone.add_permits(1);
                }
            }
        });
        
        Self {
            semaphore,
            capacity,
            refill_rate,
        }
    }
}

#[async_trait]
impl RateLimitBackend for TokenBucket {
    async fn acquire(&self, _key: Option<&str>) -> Result<(), RateLimitError> {
        match self.semaphore.clone().acquire_owned().await {
            Ok(permit) => {
                std::mem::forget(permit);
                Ok(())
            }
            Err(_) => Err(RateLimitError::LimitExceeded),
        }
    }
    
    async fn try_acquire(&self, _key: Option<&str>) -> bool {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                std::mem::forget(permit);
                true
            }
            Err(_) => false,
        }
    }
    
    async fn release(&self, _key: Option<&str>) {
        // Token bucket doesn't need explicit release
    }
}

impl RateLimiter {
    pub fn new(config: RateLimiterConfig) -> Self {
        let limiter: Arc<dyn RateLimitBackend> = match &config.strategy {
            RateLimitStrategy::TokenBucket { capacity, refill_rate } => {
                Arc::new(TokenBucket::new(*capacity, *refill_rate))
            }
            // Other strategies...
            _ => todo!(),
        };
        
        Self {
            config,
            limiter,
            metrics: Arc::new(RateLimiterMetrics::new()),
        }
    }
    
    /// Acquire permission
    pub async fn acquire(&self, key: Option<&str>) -> Result<RateLimitGuard, RateLimitError> {
        match self.config.on_limit_exceeded {
            LimitExceededBehavior::Reject => {
                if !self.limiter.try_acquire(key).await {
                    self.metrics.record_rejected();
                    return Err(RateLimitError::LimitExceeded);
                }
            }
            LimitExceededBehavior::Queue { .. } => {
                self.limiter.acquire(key).await?;
            }
            LimitExceededBehavior::Delay { max_delay } => {
                let start = Instant::now();
                while !self.limiter.try_acquire(key).await {
                    if start.elapsed() > max_delay {
                        self.metrics.record_rejected();
                        return Err(RateLimitError::Timeout);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
        
        self.metrics.record_acquired();
        Ok(RateLimitGuard {
            limiter: self.limiter.clone(),
            key: key.map(|s| s.to_string()),
        })
    }
}

/// RAII guard for rate limit
pub struct RateLimitGuard {
    limiter: Arc<dyn RateLimitBackend>,
    key: Option<String>,
}

impl Drop for RateLimitGuard {
    fn drop(&mut self) {
        let limiter = self.limiter.clone();
        let key = self.key.clone();
        tokio::spawn(async move {
            limiter.release(key.as_deref()).await;
        });
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limit exceeded")]
    LimitExceeded,
    
    #[error("Timeout waiting for rate limit")]
    Timeout,
}
```

## 5. Resilience Manager

```rust
/// Unified resilience manager that combines all components
pub struct ResilienceManager {
    config: ResilienceConfig,
    retry: Option<Retry>,
    circuit_breaker: Option<CircuitBreaker>,
    rate_limiter: Option<RateLimiter>,
    bulkhead: Option<Bulkhead>,
    metrics: Arc<ResilienceMetrics>,
}

impl ResilienceManager {
    pub fn new(config: ResilienceConfig) -> Self {
        Self {
            retry: Some(Retry::new(config.retry.clone())),
            circuit_breaker: Some(CircuitBreaker::new(config.circuit_breaker.clone())),
            rate_limiter: config.rate_limiter.as_ref()
                .map(|cfg| RateLimiter::new(cfg.clone())),
            bulkhead: config.bulkhead.as_ref()
                .map(|cfg| Bulkhead::new(cfg.clone())),
            config,
            metrics: Arc::new(ResilienceMetrics::new()),
        }
    }
    
    /// Execute with all resilience patterns
    pub async fn execute<F, Fut, T, E>(&self, f: F) -> Result<T, ResilienceError<E>>
    where
        F: Fn() -> Fut + Clone,
        Fut: Future<Output = Result<T, E>>,
        E: RetryableError + 'static,
    {
        let start = Instant::now();
        
        // Rate limiting
        let _guard = if let Some(limiter) = &self.rate_limiter {
            Some(limiter.acquire(None).await
                .map_err(|e| ResilienceError::RateLimited(e))?)
        } else {
            None
        };
        
        // Bulkhead
        let _permit = if let Some(bulkhead) = &self.bulkhead {
            Some(bulkhead.acquire().await
                .map_err(|e| ResilienceError::BulkheadFull(e))?)
        } else {
            None
        };
        
        // Circuit breaker + Retry
        let result = if let Some(cb) = &self.circuit_breaker {
            if let Some(retry) = &self.retry {
                // Both circuit breaker and retry
                retry.execute(|| {
                    cb.execute(f.clone())
                }).await
                    .map_err(|e| ResilienceError::Execution(e))
            } else {
                // Only circuit breaker
                cb.execute(f).await
                    .map_err(|e| ResilienceError::CircuitOpen(format!("{:?}", e)))
            }
        } else if let Some(retry) = &self.retry {
            // Only retry
            retry.execute(f).await
                .map_err(|e| ResilienceError::Execution(e))
        } else {
            // No resilience
            f().await
                .map_err(|e| ResilienceError::Execution(e))
        };
        
        let duration = start.elapsed();
        self.metrics.record_execution(result.is_ok(), duration);
        
        result
    }
    
    /// Create a wrapper function with resilience
    pub fn wrap<F, Fut, T, E>(&self, f: F) -> impl Fn() -> impl Future<Output = Result<T, ResilienceError<E>>>
    where
        F: Fn() -> Fut + Clone + 'static,
        Fut: Future<Output = Result<T, E>> + 'static,
        E: RetryableError + 'static,
        T: 'static,
    {
        let manager = self.clone();
        move || {
            let f = f.clone();
            let manager = manager.clone();
            async move {
                manager.execute(f).await
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ResilienceError<E> {
    #[error("Rate limited: {0}")]
    RateLimited(RateLimitError),
    
    #[error("Bulkhead full: {0}")]
    BulkheadFull(BulkheadError),
    
    #[error("Circuit open: {0}")]
    CircuitOpen(String),
    
    #[error("Execution failed: {0}")]
    Execution(E),
}
```

## 6. Usage in Resources

```rust
// Пример использования в HttpResource
use nebula_resource::resilience::*;

pub struct HttpResource {
    client: reqwest::Client,
    resilience: ResilienceManager,
}

impl HttpResource {
    pub fn new(config: HttpConfig) -> Self {
        // Используем общую конфигурацию resilience
        let resilience = ResilienceManager::new(config.resilience);
        
        Self {
            client: build_client(&config),
            resilience,
        }
    }
    
    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        // Все resilience patterns применяются автоматически
        self.resilience.execute(|| async {
            self.client
                .get(url)
                .send()
                .await
                .map_err(|e| HttpError::from(e))
        }).await
            .map_err(|e| HttpError::Resilience(e))
    }
}

// Пример использования в DatabaseResource
pub struct DatabaseResource {
    pool: PgPool,
    resilience: ResilienceManager,
}

impl DatabaseResource {
    pub async fn query<T>(&self, sql: &str) -> Result<Vec<T>, DbError> {
        self.resilience.execute(|| async {
            sqlx::query_as(sql)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| DbError::from(e))
        }).await
            .map_err(|e| DbError::Resilience(e))
    }
}

// Пример использования в CacheResource
pub struct CacheResource {
    client: RedisClient,
    resilience: ResilienceManager,
}

impl CacheResource {
    pub async fn get(&self, key: &str) -> Result<Option<String>, CacheError> {
        self.resilience.execute(|| async {
            self.client
                .get(key)
                .await
                .map_err(|e| CacheError::from(e))
        }).await
            .map_err(|e| CacheError::Resilience(e))
    }
}
```

## 7. Configuration Examples

```yaml
# Общая конфигурация для всех ресурсов
resilience:
  retry:
    max_attempts: 3
    strategy:
      type: Exponential
      initial: 100ms
      base: 2.0
    jitter: Equal
    max_delay: 30s
    retry_on: Transient
    
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 3
    timeout: 60s
    error_rate_threshold: 0.5
    min_requests: 10
    
  rate_limiter:
    strategy:
      type: TokenBucket
      capacity: 100
      refill_rate: 10
    on_limit_exceeded: Queue
    scope: Global
    
  bulkhead:
    max_concurrent: 50
    max_queued: 100
    
  timeout:
    request_timeout: 30s
    overall_timeout: 120s

# Использование в ресурсах
resources:
  http:
    type: http
    config:
      base_url: https://api.example.com
      resilience: ${resilience}  # Используем общую конфигурацию
      
  database:
    type: database
    config:
      url: postgresql://localhost/mydb
      resilience: ${resilience}  # Та же конфигурация
      
  cache:
    type: cache
    config:
      url: redis://localhost:6379
      resilience: ${resilience}  # И здесь тоже
```

## 8. Metrics & Monitoring

```rust
/// Unified metrics for all resilience components
pub struct ResilienceMetrics {
    // Retry metrics
    retry_attempts: Histogram,
    retry_success: Counter,
    retry_exhausted: Counter,
    
    // Circuit breaker metrics
    circuit_state: Gauge,
    circuit_opens: Counter,
    circuit_rejected: Counter,
    
    // Rate limiter metrics
    rate_limit_acquired: Counter,
    rate_limit_rejected: Counter,
    rate_limit_queue_size: Gauge,
    
    // Overall metrics
    total_requests: Counter,
    successful_requests: Counter,
    failed_requests: Counter,
    request_duration: Histogram,
}

impl ResilienceMetrics {
    pub fn export_prometheus(&self) -> String {
        // Export metrics in Prometheus format
        format!(
            "# HELP resilience_retry_attempts Number of retry attempts\n\
             # TYPE resilience_retry_attempts histogram\n\
             resilience_retry_attempts_bucket{{le=\"1\"}} {}\n\
             resilience_retry_attempts_bucket{{le=\"2\"}} {}\n\
             resilience_retry_attempts_bucket{{le=\"3\"}} {}\n",
            self.retry_attempts.get_bucket(1),
            self.retry_attempts.get_bucket(2),
            self.retry_attempts.get_bucket(3),
        )
    }
}
```

## Benefits

1. **Единая конфигурация** - Одна конфигурация для всех ресурсов
2. **Переиспользование** - Компоненты используются во всех ресурсах
3. **Композиция** - Легко комбинировать разные паттерны
4. **Тестируемость** - Каждый компонент тестируется отдельно
5. **Метрики** - Единообразные метрики для всех паттернов
6. **Гибкость** - Можно включать/выключать отдельные компоненты