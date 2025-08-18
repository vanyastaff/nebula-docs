---
title:  HttpClient
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Example: HttpClient

> Умный HTTP клиент с retry, circuit breaker, rate limiting и caching

## Overview

Продвинутый HTTP клиент для nebula-resource с поддержкой retry policies, circuit breaker для защиты от сбоев, rate limiting, response caching и автоматическим сбором метрик.

## Implementation

```rust
use nebula_resource::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use reqwest::{Client, Request, Response, StatusCode};
use std::time::{Duration, Instant};
use lru::LruCache;
use std::collections::HashMap;
use async_trait::async_trait;

/// HTTP Client resource
#[derive(Resource)]
#[resource(
    id = "http_client",
    name = "Smart HTTP Client",
    poolable = true
)]
pub struct HttpClientResource;

/// Configuration
#[derive(ResourceConfig, Serialize, Deserialize, Clone)]
pub struct HttpClientConfig {
    /// Base URL for the API
    pub base_url: Option<String>,
    
    /// Default timeout for requests
    #[serde(default = "default_timeout")]
    pub timeout: Duration,
    
    /// Connection pool configuration
    #[serde(default)]
    pub pool: ConnectionPoolConfig,
    
    /// Retry policy
    #[serde(default)]
    pub retry: RetryConfig,
    
    /// Circuit breaker configuration
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    
    /// Rate limiting
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    
    /// Response caching
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    
    /// Default headers
    #[serde(default)]
    pub default_headers: HashMap<String, String>,
    
    /// Authentication
    #[serde(default)]
    pub auth: Option<AuthConfig>,
    
    /// Enable compression
    #[serde(default = "default_true")]
    pub compression: bool,
    
    /// Follow redirects
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    pub max_idle_per_host: usize,
    pub idle_timeout: Duration,
    pub connection_timeout: Duration,
    pub pool_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub exponential_base: f64,
    pub retry_on_status: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub timeout: Duration,
    pub half_open_max_requests: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub requests_per_second: u32,
    pub burst_size: u32,
    pub wait_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub ttl: Duration,
    pub cache_methods: Vec<String>,
    pub cache_status_codes: Vec<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthConfig {
    Bearer { token: String },
    Basic { username: String, password: String },
    ApiKey { header: String, value: String },
    OAuth2 { 
        client_id: String,
        client_secret: String,
        token_url: String,
    },
}

/// HTTP Client instance
pub struct HttpClientInstance {
    client: Client,
    config: HttpClientConfig,
    circuit_breaker: Arc<RwLock<CircuitBreaker>>,
    rate_limiter: Option<Arc<RateLimiter>>,
    cache: Option<Arc<RwLock<ResponseCache>>>,
    metrics: Arc<HttpMetrics>,
}

/// Circuit breaker implementation
struct CircuitBreaker {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    config: CircuitBreakerConfig,
}

#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            config,
        }
    }
    
    fn record_success(&mut self) {
        match self.state {
            CircuitState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            _ => {}
        }
    }
    
    fn record_failure(&mut self) {
        self.last_failure_time = Some(Instant::now());
        
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.config.failure_threshold {
                    self.state = CircuitState::Open;
                }
            }
            CircuitState::HalfOpen => {
                self.state = CircuitState::Open;
                self.failure_count = 0;
                self.success_count = 0;
            }
            _ => {}
        }
    }
    
    fn can_request(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                if let Some(last_failure) = self.last_failure_time {
                    if last_failure.elapsed() >= self.config.timeout {
                        self.state = CircuitState::HalfOpen;
                        self.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => {
                self.success_count < self.config.half_open_max_requests
            }
        }
    }
}

/// Rate limiter using token bucket algorithm
struct RateLimiter {
    semaphore: Arc<Semaphore>,
    refill_task: Option<tokio::task::JoinHandle<()>>,
}

impl RateLimiter {
    fn new(config: RateLimitConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.burst_size as usize));
        let sem_clone = semaphore.clone();
        
        // Start refill task
        let refill_interval = Duration::from_secs_f64(1.0 / config.requests_per_second as f64);
        let refill_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(refill_interval);
            loop {
                interval.tick().await;
                if sem_clone.available_permits() < config.burst_size as usize {
                    sem_clone.add_permits(1);
                }
            }
        });
        
        Self {
            semaphore,
            refill_task: Some(refill_task),
        }
    }
    
    async fn acquire(&self) -> Result<(), RateLimitError> {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => {
                // Permit will be dropped when request completes
                std::mem::forget(permit);
                Ok(())
            }
            Err(_) => {
                // Wait with timeout
                match tokio::time::timeout(
                    Duration::from_secs(5),
                    self.semaphore.clone().acquire_owned()
                ).await {
                    Ok(Ok(permit)) => {
                        std::mem::forget(permit);
                        Ok(())
                    }
                    _ => Err(RateLimitError::TooManyRequests),
                }
            }
        }
    }
}

/// Response cache
struct ResponseCache {
    cache: LruCache<String, CachedResponse>,
    config: CacheConfig,
}

#[derive(Clone)]
struct CachedResponse {
    status: StatusCode,
    headers: HashMap<String, String>,
    body: Vec<u8>,
    cached_at: Instant,
}

impl ResponseCache {
    fn new(config: CacheConfig) -> Self {
        Self {
            cache: LruCache::new(config.max_entries),
            config,
        }
    }
    
    fn get(&mut self, key: &str) -> Option<CachedResponse> {
        if let Some(cached) = self.cache.get(key) {
            if cached.cached_at.elapsed() < self.config.ttl {
                return Some(cached.clone());
            } else {
                self.cache.pop(key);
            }
        }
        None
    }
    
    fn put(&mut self, key: String, response: CachedResponse) {
        self.cache.put(key, response);
    }
    
    fn should_cache(&self, method: &str, status: StatusCode) -> bool {
        self.config.cache_methods.contains(&method.to_string()) &&
        self.config.cache_status_codes.contains(&status.as_u16())
    }
}

/// Resource implementation
#[async_trait]
impl Resource for HttpClientResource {
    type Config = HttpClientConfig;
    type Instance = HttpClientInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        // Build HTTP client
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .pool_idle_timeout(config.pool.idle_timeout)
            .pool_max_idle_per_host(config.pool.max_idle_per_host)
            .connect_timeout(config.pool.connection_timeout);
        
        if config.compression {
            builder = builder.gzip(true).brotli(true);
        }
        
        if !config.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }
        
        // Add default headers
        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in &config.default_headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(key.as_bytes()).unwrap(),
                reqwest::header::HeaderValue::from_str(value).unwrap(),
            );
        }
        
        // Add auth headers
        if let Some(auth) = &config.auth {
            match auth {
                AuthConfig::Bearer { token } => {
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {}", token).parse().unwrap(),
                    );
                }
                AuthConfig::Basic { username, password } => {
                    let credentials = base64::encode(format!("{}:{}", username, password));
                    headers.insert(
                        reqwest::header::AUTHORIZATION,
                        format!("Basic {}", credentials).parse().unwrap(),
                    );
                }
                AuthConfig::ApiKey { header, value } => {
                    headers.insert(
                        reqwest::header::HeaderName::from_bytes(header.as_bytes()).unwrap(),
                        value.parse().unwrap(),
                    );
                }
                AuthConfig::OAuth2 { .. } => {
                    // OAuth2 would be handled separately
                }
            }
        }
        
        builder = builder.default_headers(headers);
        
        let client = builder.build()
            .map_err(|e| ResourceError::InitializationFailed(e.to_string()))?;
        
        // Initialize components
        let circuit_breaker = Arc::new(RwLock::new(
            CircuitBreaker::new(config.circuit_breaker.clone())
        ));
        
        let rate_limiter = config.rate_limit.as_ref()
            .map(|cfg| Arc::new(RateLimiter::new(cfg.clone())));
        
        let cache = config.cache.as_ref()
            .map(|cfg| Arc::new(RwLock::new(ResponseCache::new(cfg.clone()))));
        
        Ok(HttpClientInstance {
            client,
            config: config.clone(),
            circuit_breaker,
            rate_limiter,
            cache,
            metrics: Arc::new(HttpMetrics::new()),
        })
    }
}

impl HttpClientInstance {
    /// Execute HTTP GET request
    pub async fn get(&self, url: &str) -> Result<Response, HttpError> {
        self.request(reqwest::Method::GET, url, None).await
    }
    
    /// Execute HTTP POST request
    pub async fn post(&self, url: &str, body: impl Into<reqwest::Body>) -> Result<Response, HttpError> {
        self.request(reqwest::Method::POST, url, Some(body.into())).await
    }
    
    /// Execute HTTP PUT request
    pub async fn put(&self, url: &str, body: impl Into<reqwest::Body>) -> Result<Response, HttpError> {
        self.request(reqwest::Method::PUT, url, Some(body.into())).await
    }
    
    /// Execute HTTP DELETE request
    pub async fn delete(&self, url: &str) -> Result<Response, HttpError> {
        self.request(reqwest::Method::DELETE, url, None).await
    }
    
    /// Execute HTTP request with retry and circuit breaker
    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<reqwest::Body>,
    ) -> Result<Response, HttpError> {
        let start = Instant::now();
        
        // Build full URL
        let full_url = if let Some(base) = &self.config.base_url {
            format!("{}/{}", base.trim_end_matches('/'), url.trim_start_matches('/'))
        } else {
            url.to_string()
        };
        
        // Check cache for GET requests
        if method == reqwest::Method::GET {
            if let Some(cache) = &self.cache {
                let cache_key = format!("{}:{}", method, full_url);
                if let Some(cached) = cache.write().await.get(&cache_key) {
                    self.metrics.record_cache_hit();
                    // Convert cached response back to Response
                    // This is simplified - real implementation would be more complex
                    return Ok(Response::from(cached));
                }
            }
        }
        
        // Check circuit breaker
        {
            let mut cb = self.circuit_breaker.write().await;
            if !cb.can_request() {
                self.metrics.record_circuit_open();
                return Err(HttpError::CircuitOpen);
            }
        }
        
        // Apply rate limiting
        if let Some(limiter) = &self.rate_limiter {
            limiter.acquire().await
                .map_err(|_| HttpError::RateLimitExceeded)?;
        }
        
        // Retry loop
        let mut attempts = 0;
        let mut last_error = None;
        
        while attempts < self.config.retry.max_attempts {
            attempts += 1;
            
            // Build request
            let mut request = self.client.request(method.clone(), &full_url);
            if let Some(body) = body.clone() {
                request = request.body(body);
            }
            
            // Execute request
            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    
                    // Record success in circuit breaker
                    if status.is_success() {
                        self.circuit_breaker.write().await.record_success();
                        self.metrics.record_success(start.elapsed());
                        
                        // Cache if applicable
                        if let Some(cache) = &self.cache {
                            let mut cache_guard = cache.write().await;
                            if cache_guard.should_cache(&method.to_string(), status) {
                                let cache_key = format!("{}:{}", method, full_url);
                                // Store response in cache (simplified)
                                // Real implementation would properly clone response
                            }
                        }
                        
                        return Ok(response);
                    }
                    
                    // Check if we should retry this status code
                    if self.config.retry.retry_on_status.contains(&status.as_u16()) {
                        last_error = Some(HttpError::StatusCode(status));
                        
                        // Calculate retry delay
                        let delay = self.calculate_retry_delay(attempts);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    
                    // Non-retryable error
                    self.circuit_breaker.write().await.record_failure();
                    self.metrics.record_failure();
                    return Err(HttpError::StatusCode(status));
                }
                Err(e) => {
                    last_error = Some(HttpError::Request(e.to_string()));
                    
                    // Network errors are retryable
                    if attempts < self.config.retry.max_attempts {
                        let delay = self.calculate_retry_delay(attempts);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    
                    // Max retries exceeded
                    self.circuit_breaker.write().await.record_failure();
                    self.metrics.record_failure();
                    return Err(last_error.unwrap());
                }
            }
        }
        
        // Should not reach here, but just in case
        self.circuit_breaker.write().await.record_failure();
        self.metrics.record_failure();
        Err(last_error.unwrap_or(HttpError::Unknown))
    }
    
    /// Calculate retry delay with exponential backoff
    fn calculate_retry_delay(&self, attempt: u32) -> Duration {
        let base_delay = self.config.retry.initial_delay;
        let exponential = self.config.retry.exponential_base.powi(attempt as i32 - 1);
        let delay = base_delay.mul_f64(exponential);
        
        // Add jitter
        let jitter = rand::random::<f64>() * 0.3; // 0-30% jitter
        let delay_with_jitter = delay.mul_f64(1.0 + jitter);
        
        // Cap at max delay
        std::cmp::min(delay_with_jitter, self.config.retry.max_delay)
    }
    
    /// Get circuit breaker state
    pub async fn circuit_state(&self) -> CircuitState {
        self.circuit_breaker.read().await.state.clone()
    }
    
    /// Get metrics
    pub fn metrics(&self) -> HttpMetrics {
        (*self.metrics).clone()
    }
}

/// HTTP metrics
#[derive(Clone)]
struct HttpMetrics {
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    circuit_opens: Arc<AtomicU64>,
    rate_limit_hits: Arc<AtomicU64>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    total_latency: Arc<AtomicU64>,
}

impl HttpMetrics {
    fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            circuit_opens: Arc::new(AtomicU64::new(0)),
            rate_limit_hits: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            total_latency: Arc::new(AtomicU64::new(0)),
        }
    }
    
    fn record_success(&self, latency: Duration) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        self.total_latency.fetch_add(latency.as_millis() as u64, Ordering::Relaxed);
    }
    
    fn record_failure(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.failed_requests.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_circuit_open(&self) {
        self.circuit_opens.fetch_add(1, Ordering::Relaxed);
    }
    
    fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("Circuit breaker is open")]
    CircuitOpen,
    
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    
    #[error("HTTP status code: {0}")]
    StatusCode(StatusCode),
    
    #[error("Request failed: {0}")]
    Request(String),
    
    #[error("Unknown error")]
    Unknown,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Too many requests")]
    TooManyRequests,
}

// Default implementations
fn default_timeout() -> Duration { Duration::from_secs(30) }
fn default_true() -> bool { true }

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 10,
            idle_timeout: Duration::from_secs(90),
            connection_timeout: Duration::from_secs(10),
            pool_timeout: Duration::from_secs(30),
        }
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            exponential_base: 2.0,
            retry_on_status: vec![408, 429, 500, 502, 503, 504],
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            half_open_max_requests: 1,
        }
    }
}
```

## Usage Examples

### Basic Usage

```rust
async fn example_usage(ctx: &ExecutionContext) -> Result<()> {
    let http = ctx.get_resource::<HttpClientInstance>().await?;
    
    // Simple GET request
    let response = http.get("/api/users").await?;
    let users: Vec<User> = response.json().await?;
    
    // POST with JSON body
    let new_user = User {
        name: "John Doe".to_string(),
        email: "john@example.com".to_string(),
    };
    
    let response = http.post("/api/users", serde_json::to_string(&new_user)?).await?;
    
    if response.status().is_success() {
        let created_user: User = response.json().await?;
        println!("Created user: {:?}", created_user);
    }
    
    Ok(())
}
```

### Configuration Examples

```yaml
# http_client.yaml
type: http_client
config:
  base_url: "https://api.example.com"
  timeout: 30s
  compression: true
  follow_redirects: true
  
  # Connection pool
  pool:
    max_idle_per_host: 20
    idle_timeout: 90s
    connection_timeout: 10s
    pool_timeout: 30s
  
  # Retry configuration
  retry:
    max_attempts: 3
    initial_delay: 100ms
    max_delay: 10s
    exponential_base: 2.0
    retry_on_status: [408, 429, 500, 502, 503, 504]
  
  # Circuit breaker
  circuit_breaker:
    failure_threshold: 5
    success_threshold: 3
    timeout: 60s
    half_open_max_requests: 1
  
  # Rate limiting
  rate_limit:
    requests_per_second: 100
    burst_size: 150
    wait_timeout: 5s
  
  # Response caching
  cache:
    max_entries: 1000
    ttl: 300s
    cache_methods: ["GET", "HEAD"]
    cache_status_codes: [200, 203, 204, 206, 300, 301]
  
  # Authentication
  auth:
    type: Bearer
    token: "${API_TOKEN}"
  
  # Default headers
  default_headers:
    User-Agent: "nebula-http-client/1.0"
    Accept: "application/json"
    X-Request-ID: "${REQUEST_ID}"
```

### Advanced Usage

```rust
/// Example with circuit breaker monitoring
async fn monitored_requests(http: &HttpClientInstance) -> Result<()> {
    // Check circuit state
    match http.circuit_state().await {
        CircuitState::Open => {
            warn!("Circuit is open, skipping requests");
            return Ok(());
        }
        CircuitState::HalfOpen => {
            info!("Circuit is half-open, proceeding carefully");
        }
        CircuitState::Closed => {
            debug!("Circuit is closed, normal operation");
        }
    }
    
    // Make requests with monitoring
    for i in 0..10 {
        match http.get(&format!("/api/data/{}", i)).await {
            Ok(response) => {
                info!("Request {} successful: {}", i, response.status());
            }
            Err(HttpError::CircuitOpen) => {
                warn!("Circuit opened during request {}", i);
                break;
            }
            Err(HttpError::RateLimitExceeded) => {
                warn!("Rate limit hit at request {}", i);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(e) => {
                error!("Request {} failed: {}", i, e);
            }
        }
    }
    
    // Get metrics
    let metrics = http.metrics();
    info!("Total requests: {}", metrics.total_requests.load(Ordering::Relaxed));
    info!("Success rate: {:.2}%", 
        metrics.successful_requests.load(Ordering::Relaxed) as f64 / 
        metrics.total_requests.load(Ordering::Relaxed) as f64 * 100.0
    );
    info!("Cache hit rate: {:.2}%",
        metrics.cache_hits.load(Ordering::Relaxed) as f64 /
        (metrics.cache_hits.load(Ordering::Relaxed) + 
         metrics.cache_misses.load(Ordering::Relaxed)) as f64 * 100.0
    );
    
    Ok(())
}
```

## Benefits

1. **Resilience** - Circuit breaker предотвращает каскадные сбои
2. **Performance** - Connection pooling и response caching
3. **Rate Limiting** - Защита от превышения лимитов API
4. **Retry Logic** - Автоматические повторы с exponential backoff
5. **Observability** - Детальные метрики и мониторинг
6. **Flexibility** - Настраиваемые политики для разных сценариев

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockito;
    
    #[tokio::test]
    async fn test_retry_logic() {
        let mut server = mockito::Server::new();
        
        // First two requests fail, third succeeds
        server.mock("GET", "/test")
            .with_status(500)
            .expect(2)
            .create();
            
        server.mock("GET", "/test")
            .with_status(200)
            .with_body("success")
            .expect(1)
            .create();
        
        let config = HttpClientConfig {
            base_url: Some(server.url()),
            retry: RetryConfig {
                max_attempts: 3,
                initial_delay: Duration::from_millis(10),
                ..Default::default()
            },
            ..Default::default()
        };
        
        let client = HttpClientResource.create(&config, &mock_context()).await.unwrap();
        
        let response = client.get("/test").await.unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.text().await.unwrap(), "success");
    }
}
```
