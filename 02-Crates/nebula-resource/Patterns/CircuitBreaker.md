---
title: CircuitBreaker
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Circuit Breaker Pattern

## Overview

The Circuit Breaker pattern prevents cascading failures in distributed systems by monitoring for failures and temporarily blocking requests to failing resources. It acts like an electrical circuit breaker, "tripping" when failures exceed a threshold.

## States

```
┌─────────────┐  success    ┌─────────────┐
│             │ ─────────►   │             │
│   CLOSED    │              │  HALF-OPEN  │
│             │ ◄─────────   │             │
└─────────────┘  threshold   └─────────────┘
      │                            │
      │ failure                    │ failure
      │ threshold                  │
      ▼                            ▼
┌─────────────┐              ┌─────────────┐
│             │   timeout    │             │
│    OPEN     │ ─────────►   │  HALF-OPEN  │
│             │              │             │
└─────────────┘              └─────────────┘
```

## Implementation

### Core Circuit Breaker

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<CircuitState>>,
    failure_count: Arc<RwLock<FailureCounter>>,
    metrics: Arc<CircuitBreakerMetrics>,
}

#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    pub failure_threshold: u32,
    
    /// Time window for counting failures
    pub failure_window: Duration,
    
    /// Number of successes to close circuit from half-open
    pub success_threshold: u32,
    
    /// Time to wait before attempting half-open
    pub timeout: Duration,
    
    /// Maximum requests in half-open state
    pub half_open_max_calls: u32,
    
    /// Failure rate threshold (0.0 to 1.0)
    pub failure_rate_threshold: f64,
    
    /// Minimum number of calls before evaluating failure rate
    pub minimum_calls: u32,
}

#[derive(Debug, Clone)]
enum CircuitState {
    /// Circuit is closed, requests pass through
    Closed,
    
    /// Circuit is open, requests are blocked
    Open {
        opened_at: Instant,
        reason: OpenReason,
    },
    
    /// Circuit is testing if resource has recovered
    HalfOpen {
        started_at: Instant,
        successes: u32,
        failures: u32,
        permits_used: u32,
    },
}

#[derive(Debug, Clone)]
enum OpenReason {
    ConsecutiveFailures(u32),
    FailureRate(f64),
    ManualTrip(String),
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(CircuitState::Closed)),
            failure_count: Arc::new(RwLock::new(FailureCounter::new())),
            metrics: Arc::new(CircuitBreakerMetrics::new()),
        }
    }
    
    /// Execute operation through circuit breaker
    pub async fn call<F, T, E>(&self, operation: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Future<Output = Result<T, E>>,
        E: std::error::Error,
    {
        // Check if circuit allows the call
        self.pre_call().await?;
        
        // Execute the operation
        let start = Instant::now();
        let result = operation().await;
        let duration = start.elapsed();
        
        // Record the result
        self.post_call(result.is_ok(), duration).await;
        
        result.map_err(CircuitBreakerError::OperationError)
    }
    
    /// Check if call is allowed
    async fn pre_call(&self) -> Result<(), CircuitBreakerError<std::convert::Infallible>> {
        let mut state = self.state.write().await;
        
        match &*state {
            CircuitState::Closed => {
                self.metrics.record_call_allowed();
                Ok(())
            }
            
            CircuitState::Open { opened_at, reason } => {
                if opened_at.elapsed() >= self.config.timeout {
                    // Transition to half-open
                    *state = CircuitState::HalfOpen {
                        started_at: Instant::now(),
                        successes: 0,
                        failures: 0,
                        permits_used: 0,
                    };
                    self.metrics.record_state_transition("open", "half_open");
                    self.metrics.record_call_allowed();
                    Ok(())
                } else {
                    self.metrics.record_call_rejected();
                    Err(CircuitBreakerError::Open {
                        reason: reason.clone(),
                        retry_after: self.config.timeout - opened_at.elapsed(),
                    })
                }
            }
            
            CircuitState::HalfOpen { permits_used, .. } => {
                if *permits_used < self.config.half_open_max_calls {
                    *state = match &*state {
                        CircuitState::HalfOpen { started_at, successes, failures, .. } => {
                            CircuitState::HalfOpen {
                                started_at: *started_at,
                                successes: *successes,
                                failures: *failures,
                                permits_used: permits_used + 1,
                            }
                        }
                        _ => unreachable!(),
                    };
                    self.metrics.record_call_allowed();
                    Ok(())
                } else {
                    self.metrics.record_call_rejected();
                    Err(CircuitBreakerError::HalfOpenLimitReached)
                }
            }
        }
    }
    
    /// Record call result
    async fn post_call(&self, success: bool, duration: Duration) {
        let mut state = self.state.write().await;
        
        if success {
            self.metrics.record_success(duration);
            self.handle_success(&mut state).await;
        } else {
            self.metrics.record_failure(duration);
            self.handle_failure(&mut state).await;
        }
    }
    
    /// Handle successful call
    async fn handle_success(&self, state: &mut CircuitState) {
        match state {
            CircuitState::Closed => {
                // Reset failure counter on success in closed state
                let mut counter = self.failure_count.write().await;
                counter.reset();
            }
            
            CircuitState::HalfOpen { successes, failures, started_at, permits_used } => {
                let new_successes = *successes + 1;
                
                if new_successes >= self.config.success_threshold {
                    // Close the circuit
                    *state = CircuitState::Closed;
                    self.metrics.record_state_transition("half_open", "closed");
                    
                    // Reset failure counter
                    let mut counter = self.failure_count.write().await;
                    counter.reset();
                } else {
                    *state = CircuitState::HalfOpen {
                        started_at: *started_at,
                        successes: new_successes,
                        failures: *failures,
                        permits_used: *permits_used,
                    };
                }
            }
            
            CircuitState::Open { .. } => {
                // Shouldn't happen, but handle gracefully
                *state = CircuitState::Closed;
            }
        }
    }
    
    /// Handle failed call
    async fn handle_failure(&self, state: &mut CircuitState) {
        let mut counter = self.failure_count.write().await;
        counter.record_failure();
        
        match state {
            CircuitState::Closed => {
                // Check if we should open the circuit
                if counter.consecutive_failures() >= self.config.failure_threshold {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                        reason: OpenReason::ConsecutiveFailures(counter.consecutive_failures()),
                    };
                    self.metrics.record_state_transition("closed", "open");
                } else if counter.total_calls() >= self.config.minimum_calls {
                    let failure_rate = counter.failure_rate();
                    if failure_rate >= self.config.failure_rate_threshold {
                        *state = CircuitState::Open {
                            opened_at: Instant::now(),
                            reason: OpenReason::FailureRate(failure_rate),
                        };
                        self.metrics.record_state_transition("closed", "open");
                    }
                }
            }
            
            CircuitState::HalfOpen { successes, failures, started_at, permits_used } => {
                let new_failures = *failures + 1;
                
                // Check if we should reopen
                if new_failures >= self.config.failure_threshold {
                    *state = CircuitState::Open {
                        opened_at: Instant::now(),
                        reason: OpenReason::ConsecutiveFailures(new_failures),
                    };
                    self.metrics.record_state_transition("half_open", "open");
                } else {
                    *state = CircuitState::HalfOpen {
                        started_at: *started_at,
                        successes: *successes,
                        failures: new_failures,
                        permits_used: *permits_used,
                    };
                }
            }
            
            CircuitState::Open { .. } => {
                // Already open, nothing to do
            }
        }
    }
    
    /// Get current state
    pub async fn state(&self) -> CircuitBreakerState {
        let state = self.state.read().await;
        match &*state {
            CircuitState::Closed => CircuitBreakerState::Closed,
            CircuitState::Open { .. } => CircuitBreakerState::Open,
            CircuitState::HalfOpen { .. } => CircuitBreakerState::HalfOpen,
        }
    }
    
    /// Manually trip the circuit
    pub async fn trip(&self, reason: String) {
        let mut state = self.state.write().await;
        *state = CircuitState::Open {
            opened_at: Instant::now(),
            reason: OpenReason::ManualTrip(reason),
        };
        self.metrics.record_state_transition("manual", "open");
    }
    
    /// Manually reset the circuit
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = CircuitState::Closed;
        
        let mut counter = self.failure_count.write().await;
        counter.reset();
        
        self.metrics.record_state_transition("manual", "closed");
    }
}
```

### Failure Counter

```rust
#[derive(Debug, Clone)]
struct FailureCounter {
    window: Duration,
    events: VecDeque<FailureEvent>,
    consecutive_failures: u32,
}

#[derive(Debug, Clone)]
struct FailureEvent {
    timestamp: Instant,
    success: bool,
}

impl FailureCounter {
    fn new() -> Self {
        Self {
            window: Duration::from_secs(60),
            events: VecDeque::new(),
            consecutive_failures: 0,
        }
    }
    
    fn record_failure(&mut self) {
        self.cleanup_old_events();
        self.events.push_back(FailureEvent {
            timestamp: Instant::now(),
            success: false,
        });
        self.consecutive_failures += 1;
    }
    
    fn record_success(&mut self) {
        self.cleanup_old_events();
        self.events.push_back(FailureEvent {
            timestamp: Instant::now(),
            success: true,
        });
        self.consecutive_failures = 0;
    }
    
    fn reset(&mut self) {
        self.events.clear();
        self.consecutive_failures = 0;
    }
    
    fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }
    
    fn failure_rate(&self) -> f64 {
        if self.events.is_empty() {
            return 0.0;
        }
        
        let failures = self.events.iter().filter(|e| !e.success).count();
        failures as f64 / self.events.len() as f64
    }
    
    fn total_calls(&self) -> u32 {
        self.events.len() as u32
    }
    
    fn cleanup_old_events(&mut self) {
        let cutoff = Instant::now() - self.window;
        while let Some(front) = self.events.front() {
            if front.timestamp < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}
```

## Advanced Features

### Sliding Window Circuit Breaker

```rust
pub struct SlidingWindowCircuitBreaker {
    config: SlidingWindowConfig,
    window: Arc<RwLock<SlidingWindow>>,
    state: Arc<RwLock<CircuitState>>,
}

#[derive(Debug, Clone)]
pub struct SlidingWindowConfig {
    pub window_type: WindowType,
    pub window_size: usize,
    pub failure_threshold: f64,
    pub minimum_calls: usize,
    pub timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum WindowType {
    /// Count-based sliding window
    CountBased,
    /// Time-based sliding window
    TimeBased(Duration),
}

struct SlidingWindow {
    window_type: WindowType,
    outcomes: VecDeque<CallOutcome>,
    max_size: usize,
}

#[derive(Debug, Clone)]
struct CallOutcome {
    timestamp: Instant,
    success: bool,
    duration: Duration,
}

impl SlidingWindow {
    fn record(&mut self, outcome: CallOutcome) {
        match self.window_type {
            WindowType::CountBased => {
                self.outcomes.push_back(outcome);
                if self.outcomes.len() > self.max_size {
                    self.outcomes.pop_front();
                }
            }
            WindowType::TimeBased(duration) => {
                self.outcomes.push_back(outcome);
                let cutoff = Instant::now() - duration;
                while let Some(front) = self.outcomes.front() {
                    if front.timestamp < cutoff {
                        self.outcomes.pop_front();
                    } else {
                        break;
                    }
                }
            }
        }
    }
    
    fn failure_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        
        let failures = self.outcomes.iter().filter(|o| !o.success).count();
        failures as f64 / self.outcomes.len() as f64
    }
    
    fn call_count(&self) -> usize {
        self.outcomes.len()
    }
    
    fn average_duration(&self) -> Duration {
        if self.outcomes.is_empty() {
            return Duration::ZERO;
        }
        
        let total: Duration = self.outcomes.iter().map(|o| o.duration).sum();
        total / self.outcomes.len() as u32
    }
}
```

### Resource-Specific Circuit Breaker

```rust
use nebula_resource::prelude::*;

pub struct ResourceCircuitBreaker<R: Resource> {
    resource: Arc<R>,
    circuit_breaker: CircuitBreaker,
    health_checker: Arc<dyn HealthChecker>,
}

impl<R: Resource> ResourceCircuitBreaker<R> {
    pub fn new(resource: R, config: CircuitBreakerConfig) -> Self {
        Self {
            resource: Arc::new(resource),
            circuit_breaker: CircuitBreaker::new(config),
            health_checker: Arc::new(DefaultHealthChecker),
        }
    }
    
    /// Execute operation with circuit breaker protection
    pub async fn execute<F, T>(&self, operation: F) -> Result<T>
    where
        F: FnOnce(Arc<R>) -> Future<Output = Result<T>>,
    {
        let resource = self.resource.clone();
        
        self.circuit_breaker
            .call(|| operation(resource))
            .await
            .map_err(|e| match e {
                CircuitBreakerError::Open { reason, retry_after } => {
                    Error::ResourceUnavailable {
                        resource: self.resource.id(),
                        reason: format!("Circuit breaker open: {:?}", reason),
                        retry_after: Some(retry_after),
                    }
                }
                CircuitBreakerError::OperationError(e) => e,
                _ => Error::Internal("Circuit breaker error".into()),
            })
    }
    
    /// Health check with circuit breaker
    pub async fn health_check(&self) -> Result<HealthStatus> {
        self.circuit_breaker
            .call(|| self.resource.health_check())
            .await
            .map_err(|e| Error::HealthCheckFailed {
                resource: self.resource.id(),
                reason: e.to_string(),
            })
    }
    
    /// Auto-recovery with exponential backoff
    pub async fn with_auto_recovery(mut self) -> Self {
        let circuit_breaker = self.circuit_breaker.clone();
        let resource = self.resource.clone();
        let health_checker = self.health_checker.clone();
        
        tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let max_backoff = Duration::from_secs(60);
            
            loop {
                tokio::time::sleep(backoff).await;
                
                if matches!(circuit_breaker.state().await, CircuitBreakerState::Open) {
                    // Try health check
                    if health_checker.check(&*resource).await.is_ok() {
                        circuit_breaker.reset().await;
                        backoff = Duration::from_secs(1); // Reset backoff
                    } else {
                        // Exponential backoff
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
            }
        });
        
        self
    }
}
```

### Distributed Circuit Breaker

```rust
use redis::aio::ConnectionManager;

pub struct DistributedCircuitBreaker {
    local_breaker: CircuitBreaker,
    redis: ConnectionManager,
    key_prefix: String,
    sync_interval: Duration,
}

impl DistributedCircuitBreaker {
    pub async fn new(
        config: CircuitBreakerConfig,
        redis: ConnectionManager,
        service_name: &str,
    ) -> Result<Self> {
        let breaker = Self {
            local_breaker: CircuitBreaker::new(config),
            redis,
            key_prefix: format!("circuit_breaker:{}:", service_name),
            sync_interval: Duration::from_secs(1),
        };
        
        breaker.start_sync().await;
        Ok(breaker)
    }
    
    /// Sync state with Redis
    async fn start_sync(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(self.sync_interval);
            
            loop {
                interval.tick().await;
                
                // Get global state from Redis
                if let Ok(global_state) = self.get_global_state().await {
                    // Update local state if needed
                    self.sync_local_state(global_state).await;
                }
                
                // Push local metrics to Redis
                self.push_metrics().await;
            }
        });
    }
    
    async fn get_global_state(&self) -> Result<GlobalCircuitState> {
        let key = format!("{}state", self.key_prefix);
        let data: String = self.redis.get(&key).await?;
        Ok(serde_json::from_str(&data)?)
    }
    
    async fn push_metrics(&self) {
        let metrics = self.local_breaker.metrics.snapshot();
        let key = format!("{}metrics:{}", self.key_prefix, uuid::Uuid::new_v4());
        
        let _: () = self.redis
            .set_ex(&key, serde_json::to_string(&metrics).unwrap(), 60)
            .await
            .unwrap_or(());
    }
}
```

## Metrics and Monitoring

```rust
#[derive(Debug, Clone)]
pub struct CircuitBreakerMetrics {
    calls_allowed: Arc<AtomicU64>,
    calls_rejected: Arc<AtomicU64>,
    successes: Arc<AtomicU64>,
    failures: Arc<AtomicU64>,
    state_transitions: Arc<RwLock<Vec<StateTransition>>>,
    latencies: Arc<RwLock<Vec<Duration>>>,
}

#[derive(Debug, Clone)]
struct StateTransition {
    from: String,
    to: String,
    timestamp: Instant,
}

impl CircuitBreakerMetrics {
    fn new() -> Self {
        Self {
            calls_allowed: Arc::new(AtomicU64::new(0)),
            calls_rejected: Arc::new(AtomicU64::new(0)),
            successes: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
            state_transitions: Arc::new(RwLock::new(Vec::new())),
            latencies: Arc::new(RwLock::new(Vec::new())),
        }
    }
    
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            calls_allowed: self.calls_allowed.load(Ordering::Relaxed),
            calls_rejected: self.calls_rejected.load(Ordering::Relaxed),
            successes: self.successes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
            success_rate: self.calculate_success_rate(),
            average_latency: self.calculate_average_latency(),
            p99_latency: self.calculate_p99_latency(),
        }
    }
}
```

## Configuration Examples

```yaml
circuit_breaker:
  default:
    failure_threshold: 5
    failure_window: 60s
    success_threshold: 3
    timeout: 30s
    half_open_max_calls: 3
    failure_rate_threshold: 0.5
    minimum_calls: 10
    
  database:
    failure_threshold: 3
    timeout: 10s
    failure_rate_threshold: 0.3
    
  http_service:
    window_type: time_based
    window_duration: 30s
    failure_rate_threshold: 0.5
    minimum_calls: 20
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_circuit_breaker_opens_on_failures() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Simulate failures
        for _ in 0..3 {
            let _ = breaker.call(|| async {
                Err::<(), _>(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Connection failed"
                ))
            }).await;
        }
        
        // Circuit should be open
        assert_eq!(breaker.state().await, CircuitBreakerState::Open);
        
        // Next call should be rejected
        let result = breaker.call(|| async {
            Ok::<_, std::io::Error>(())
        }).await;
        
        assert!(matches!(result, Err(CircuitBreakerError::Open { .. })));
    }
    
    #[tokio::test]
    async fn test_circuit_breaker_half_open_transition() {
        let config = CircuitBreakerConfig {
            failure_threshold: 1,
            timeout: Duration::from_millis(100),
            success_threshold: 2,
            ..Default::default()
        };
        
        let breaker = CircuitBreaker::new(config);
        
        // Open the circuit
        let _ = breaker.call(|| async {
            Err::<(), _>(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Failed"
            ))
        }).await;
        
        assert_eq!(breaker.state().await, CircuitBreakerState::Open);
        
        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should transition to half-open on next call
        let _ = breaker.call(|| async {
            Ok::<_, std::io::Error>(())
        }).await;
        
        assert_eq!(breaker.state().await, CircuitBreakerState::HalfOpen);
    }
}
```

## Best Practices

1. **Set appropriate thresholds** - Balance between stability and availability
2. **Use failure rate over count** - More robust for varying load
3. **Implement health checks** - For automatic recovery
4. **Monitor state transitions** - Track circuit breaker effectiveness
5. **Use timeouts** - Prevent hanging operations
6. **Test failure scenarios** - Ensure proper behavior under stress
7. **Provide fallbacks** - Graceful degradation when circuit is open
8. **Log state changes** - For debugging and auditing
9. **Consider distributed state** - For multi-instance deployments
10. **Tune for each resource** - Different resources need different settings
