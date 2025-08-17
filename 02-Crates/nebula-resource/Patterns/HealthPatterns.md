---
title: HealthPatterns
tags: [nebula, nebula-resource, docs]
status: draft
created: 2025-08-17
---

# Health Monitoring Patterns

## Overview

Health monitoring patterns provide systematic approaches to tracking, evaluating, and responding to the health status of resources and services. These patterns enable proactive detection of issues and automated recovery.

## Health Check Types

```
┌─────────────────────────────────────────┐
│           Health Check Types            │
├─────────────────────────────────────────┤
│ • Liveness  - Is the service alive?     │
│ • Readiness - Ready to handle requests? │
│ • Startup   - Initialization complete?  │
│ • Deep      - All dependencies healthy? │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│         Health Check Pipeline           │
├─────────────────────────────────────────┤
│ Collect → Evaluate → Aggregate → Report │
└─────────────────────────────────────────┘
```

## Implementation

### Comprehensive Health Check System

```rust
use std::sync::Arc;
use tokio::sync::RwLock;
use async_trait::async_trait;
use std::time::{Duration, Instant};

/// Health check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckResult {
    /// Overall status
    pub status: HealthStatus,
    
    /// Individual component checks
    pub components: HashMap<String, ComponentHealth>,
    
    /// Check timestamp
    pub timestamp: Instant,
    
    /// Check duration
    pub duration: Duration,
    
    /// Additional metadata
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Everything is working
    Healthy,
    
    /// Service is working but with issues
    Degraded {
        reasons: Vec<String>,
    },
    
    /// Service is not working
    Unhealthy {
        reasons: Vec<String>,
    },
    
    /// Health status unknown
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub latency: Duration,
    pub metadata: HashMap<String, Value>,
}

/// Health check trait
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Perform health check
    async fn check(&self) -> HealthCheckResult;
    
    /// Check name
    fn name(&self) -> &str;
    
    /// Check timeout
    fn timeout(&self) -> Duration {
        Duration::from_secs(5)
    }
    
    /// Check priority (lower = higher priority)
    fn priority(&self) -> i32 {
        0
    }
}

/// Composite health checker
pub struct CompositeHealthChecker {
    /// Individual health checks
    checks: Vec<Arc<dyn HealthCheck>>,
    
    /// Aggregation strategy
    aggregator: Arc<dyn HealthAggregator>,
    
    /// Cache for recent results
    cache: Arc<RwLock<HealthCache>>,
    
    /// Configuration
    config: HealthCheckConfig,
}

#[derive(Debug, Clone)]
pub struct HealthCheckConfig {
    /// Enable caching
    pub cache_enabled: bool,
    
    /// Cache TTL
    pub cache_ttl: Duration,
    
    /// Parallel execution
    pub parallel_execution: bool,
    
    /// Fail fast on first unhealthy
    pub fail_fast: bool,
    
    /// Include detailed metrics
    pub detailed_metrics: bool,
}

impl CompositeHealthChecker {
    pub async fn check_health(&self) -> HealthCheckResult {
        // Check cache first
        if self.config.cache_enabled {
            if let Some(cached) = self.cache.read().await.get_valid() {
                return cached;
            }
        }
        
        let start = Instant::now();
        let mut component_results = HashMap::new();
        
        if self.config.parallel_execution {
            // Execute checks in parallel
            let futures: Vec<_> = self.checks
                .iter()
                .map(|check| self.execute_check(check.clone()))
                .collect();
            
            let results = futures::future::join_all(futures).await;
            
            for (check, result) in self.checks.iter().zip(results) {
                component_results.insert(check.name().to_string(), result);
                
                if self.config.fail_fast && !result.status.is_healthy() {
                    break;
                }
            }
        } else {
            // Execute checks sequentially
            for check in &self.checks {
                let result = self.execute_check(check.clone()).await;
                let is_healthy = result.status.is_healthy();
                
                component_results.insert(check.name().to_string(), result);
                
                if self.config.fail_fast && !is_healthy {
                    break;
                }
            }
        }
        
        // Aggregate results
        let overall_status = self.aggregator.aggregate(&component_results);
        
        let result = HealthCheckResult {
            status: overall_status,
            components: component_results,
            timestamp: Instant::now(),
            duration: start.elapsed(),
            metadata: self.collect_metadata(),
        };
        
        // Update cache
        if self.config.cache_enabled {
            self.cache.write().await.update(result.clone());
        }
        
        result
    }
    
    async fn execute_check(&self, check: Arc<dyn HealthCheck>) -> ComponentHealth {
        let start = Instant::now();
        
        match timeout(check.timeout(), check.check()).await {
            Ok(result) => ComponentHealth {
                name: check.name().to_string(),
                status: result.status,
                message: None,
                latency: start.elapsed(),
                metadata: result.metadata,
            },
            Err(_) => ComponentHealth {
                name: check.name().to_string(),
                status: HealthStatus::Unhealthy {
                    reasons: vec!["Health check timeout".to_string()],
                },
                message: Some("Check timed out".to_string()),
                latency: start.elapsed(),
                metadata: HashMap::new(),
            },
        }
    }
}
```

### Specific Health Check Implementations

```rust
/// Database health check
pub struct DatabaseHealthCheck {
    pool: Arc<DatabasePool>,
    query: String,
}

#[async_trait]
impl HealthCheck for DatabaseHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        
        match self.pool.acquire().await {
            Ok(mut conn) => {
                // Execute test query
                match conn.execute(&self.query).await {
                    Ok(_) => HealthCheckResult {
                        status: HealthStatus::Healthy,
                        components: HashMap::new(),
                        timestamp: Instant::now(),
                        duration: start.elapsed(),
                        metadata: hashmap! {
                            "pool_size" => json!(self.pool.size()),
                            "active_connections" => json!(self.pool.active_connections()),
                        },
                    },
                    Err(e) => HealthCheckResult {
                        status: HealthStatus::Unhealthy {
                            reasons: vec![format!("Query failed: {}", e)],
                        },
                        components: HashMap::new(),
                        timestamp: Instant::now(),
                        duration: start.elapsed(),
                        metadata: HashMap::new(),
                    },
                }
            }
            Err(e) => HealthCheckResult {
                status: HealthStatus::Unhealthy {
                    reasons: vec![format!("Connection failed: {}", e)],
                },
                components: HashMap::new(),
                timestamp: Instant::now(),
                duration: start.elapsed(),
                metadata: HashMap::new(),
            },
        }
    }
    
    fn name(&self) -> &str {
        "database"
    }
}

/// HTTP endpoint health check
pub struct HttpHealthCheck {
    client: Arc<HttpClient>,
    endpoint: String,
    expected_status: StatusCode,
}

#[async_trait]
impl HealthCheck for HttpHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        
        match self.client.get(&self.endpoint).send().await {
            Ok(response) => {
                if response.status() == self.expected_status {
                    HealthCheckResult {
                        status: HealthStatus::Healthy,
                        components: HashMap::new(),
                        timestamp: Instant::now(),
                        duration: start.elapsed(),
                        metadata: hashmap! {
                            "status_code" => json!(response.status().as_u16()),
                            "latency_ms" => json!(start.elapsed().as_millis()),
                        },
                    }
                } else {
                    HealthCheckResult {
                        status: HealthStatus::Unhealthy {
                            reasons: vec![format!(
                                "Unexpected status: {}",
                                response.status()
                            )],
                        },
                        components: HashMap::new(),
                        timestamp: Instant::now(),
                        duration: start.elapsed(),
                        metadata: HashMap::new(),
                    }
                }
            }
            Err(e) => HealthCheckResult {
                status: HealthStatus::Unhealthy {
                    reasons: vec![format!("Request failed: {}", e)],
                },
                components: HashMap::new(),
                timestamp: Instant::now(),
                duration: start.elapsed(),
                metadata: HashMap::new(),
            },
        }
    }
    
    fn name(&self) -> &str {
        "http_endpoint"
    }
}

/// Disk space health check
pub struct DiskSpaceHealthCheck {
    path: PathBuf,
    warning_threshold: f64,  // Percentage
    critical_threshold: f64, // Percentage
}

#[async_trait]
impl HealthCheck for DiskSpaceHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let start = Instant::now();
        
        match fs2::statvfs(&self.path) {
            Ok(stats) => {
                let total = stats.blocks() * stats.block_size();
                let available = stats.blocks_available() * stats.block_size();
                let used_percentage = ((total - available) as f64 / total as f64) * 100.0;
                
                let status = if used_percentage >= self.critical_threshold {
                    HealthStatus::Unhealthy {
                        reasons: vec![format!(
                            "Disk usage {}% exceeds critical threshold {}%",
                            used_percentage, self.critical_threshold
                        )],
                    }
                } else if used_percentage >= self.warning_threshold {
                    HealthStatus::Degraded {
                        reasons: vec![format!(
                            "Disk usage {}% exceeds warning threshold {}%",
                            used_percentage, self.warning_threshold
                        )],
                    }
                } else {
                    HealthStatus::Healthy
                };
                
                HealthCheckResult {
                    status,
                    components: HashMap::new(),
                    timestamp: Instant::now(),
                    duration: start.elapsed(),
                    metadata: hashmap! {
                        "disk_usage_percentage" => json!(used_percentage),
                        "available_bytes" => json!(available),
                        "total_bytes" => json!(total),
                    },
                }
            }
            Err(e) => HealthCheckResult {
                status: HealthStatus::Unknown,
                components: HashMap::new(),
                timestamp: Instant::now(),
                duration: start.elapsed(),
                metadata: hashmap! {
                    "error" => json!(e.to_string()),
                },
            },
        }
    }
    
    fn name(&self) -> &str {
        "disk_space"
    }
}
```

### Health Aggregation Strategies

```rust
/// Aggregator trait for combining health check results
#[async_trait]
pub trait HealthAggregator: Send + Sync {
    fn aggregate(&self, components: &HashMap<String, ComponentHealth>) -> HealthStatus;
}

/// All healthy aggregator - all components must be healthy
pub struct AllHealthyAggregator;

impl HealthAggregator for AllHealthyAggregator {
    fn aggregate(&self, components: &HashMap<String, ComponentHealth>) -> HealthStatus {
        let mut degraded_reasons = Vec::new();
        let mut unhealthy_reasons = Vec::new();
        
        for (name, health) in components {
            match &health.status {
                HealthStatus::Degraded { reasons } => {
                    degraded_reasons.push(format!("{}: {}", name, reasons.join(", ")));
                }
                HealthStatus::Unhealthy { reasons } => {
                    unhealthy_reasons.push(format!("{}: {}", name, reasons.join(", ")));
                }
                _ => {}
            }
        }
        
        if !unhealthy_reasons.is_empty() {
            HealthStatus::Unhealthy {
                reasons: unhealthy_reasons,
            }
        } else if !degraded_reasons.is_empty() {
            HealthStatus::Degraded {
                reasons: degraded_reasons,
            }
        } else {
            HealthStatus::Healthy
        }
    }
}

/// Weighted aggregator - components have different weights
pub struct WeightedAggregator {
    weights: HashMap<String, f64>,
    healthy_threshold: f64,
    degraded_threshold: f64,
}

impl HealthAggregator for WeightedAggregator {
    fn aggregate(&self, components: &HashMap<String, ComponentHealth>) -> HealthStatus {
        let total_weight: f64 = self.weights.values().sum();
        let mut healthy_weight = 0.0;
        
        for (name, health) in components {
            let weight = self.weights.get(name).unwrap_or(&1.0);
            
            match health.status {
                HealthStatus::Healthy => healthy_weight += weight,
                HealthStatus::Degraded { .. } => healthy_weight += weight * 0.5,
                _ => {}
            }
        }
        
        let health_score = healthy_weight / total_weight;
        
        if health_score >= self.healthy_threshold {
            HealthStatus::Healthy
        } else if health_score >= self.degraded_threshold {
            HealthStatus::Degraded {
                reasons: vec![format!("Health score: {:.2}", health_score)],
            }
        } else {
            HealthStatus::Unhealthy {
                reasons: vec![format!("Health score: {:.2}", health_score)],
            }
        }
    }
}
```

### Continuous Health Monitoring

```rust
pub struct HealthMonitor {
    /// Resources to monitor
    resources: Vec<Arc<dyn Resource>>,
    
    /// Health checker
    checker: Arc<CompositeHealthChecker>,
    
    /// Alert manager
    alert_manager: Arc<AlertManager>,
    
    /// Metrics collector
    metrics: Arc<HealthMetrics>,
    
    /// Configuration
    config: MonitorConfig,
}

#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Check interval
    pub check_interval: Duration,
    
    /// Alert on degraded
    pub alert_on_degraded: bool,
    
    /// Alert on unhealthy
    pub alert_on_unhealthy: bool,
    
    /// Recovery notification
    pub notify_on_recovery: bool,
    
    /// History retention
    pub history_retention: Duration,
}

impl HealthMonitor {
    pub async fn start_monitoring(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.check_interval);
        let mut previous_status = HealthStatus::Unknown;
        
        loop {
            interval.tick().await;
            
            // Perform health check
            let result = self.checker.check_health().await;
            
            // Record metrics
            self.metrics.record(&result);
            
            // Check for status changes
            if result.status != previous_status {
                self.handle_status_change(&previous_status, &result.status).await;
                previous_status = result.status.clone();
            }
            
            // Handle unhealthy status
            match &result.status {
                HealthStatus::Unhealthy { reasons } if self.config.alert_on_unhealthy => {
                    self.alert_manager.send_alert(Alert {
                        severity: AlertSeverity::Critical,
                        title: "Service Unhealthy".to_string(),
                        message: reasons.join("; "),
                        metadata: result.metadata.clone(),
                    }).await;
                }
                HealthStatus::Degraded { reasons } if self.config.alert_on_degraded => {
                    self.alert_manager.send_alert(Alert {
                        severity: AlertSeverity::Warning,
                        title: "Service Degraded".to_string(),
                        message: reasons.join("; "),
                        metadata: result.metadata.clone(),
                    }).await;
                }
                _ => {}
            }
        }
    }
    
    async fn handle_status_change(&self, old: &HealthStatus, new: &HealthStatus) {
        match (old, new) {
            (HealthStatus::Unhealthy { .. }, HealthStatus::Healthy) |
            (HealthStatus::Degraded { .. }, HealthStatus::Healthy) => {
                if self.config.notify_on_recovery {
                    self.alert_manager.send_alert(Alert {
                        severity: AlertSeverity::Info,
                        title: "Service Recovered".to_string(),
                        message: "Service has recovered to healthy status".to_string(),
                        metadata: HashMap::new(),
                    }).await;
                }
            }
            _ => {}
        }
    }
}
```

## Health Check Patterns

### Dependency Health Checks

```rust
pub struct DependencyHealthCheck {
    dependencies: Vec<Dependency>,
    check_strategy: DependencyCheckStrategy,
}

#[derive(Clone)]
pub struct Dependency {
    pub name: String,
    pub checker: Arc<dyn HealthCheck>,
    pub required: bool,
    pub weight: f64,
}

#[derive(Clone)]
pub enum DependencyCheckStrategy {
    /// All dependencies must be healthy
    All,
    /// Only required dependencies must be healthy
    RequiredOnly,
    /// Weighted scoring
    Weighted { threshold: f64 },
}

#[async_trait]
impl HealthCheck for DependencyHealthCheck {
    async fn check(&self) -> HealthCheckResult {
        let mut components = HashMap::new();
        let mut all_healthy = true;
        let mut required_healthy = true;
        let mut weighted_score = 0.0;
        let mut total_weight = 0.0;
        
        for dep in &self.dependencies {
            let result = dep.checker.check().await;
            let is_healthy = result.status.is_healthy();
            
            components.insert(
                dep.name.clone(),
                ComponentHealth {
                    name: dep.name.clone(),
                    status: result.status.clone(),
                    message: None,
                    latency: result.duration,
                    metadata: result.metadata,
                },
            );
            
            if !is_healthy {
                all_healthy = false;
                if dep.required {
                    required_healthy = false;
                }
            }
            
            total_weight += dep.weight;
            if is_healthy {
                weighted_score += dep.weight;
            }
        }
        
        let status = match self.check_strategy {
            DependencyCheckStrategy::All => {
                if all_healthy {
                    HealthStatus::Healthy
                } else {
                    HealthStatus::Unhealthy {
                        reasons: vec!["Not all dependencies healthy".to_string()],
                    }
                }
            }
            DependencyCheckStrategy::RequiredOnly => {
                if required_healthy {
                    if all_healthy {
                        HealthStatus::Healthy
                    } else {
                        HealthStatus::Degraded {
                            reasons: vec!["Optional dependencies unhealthy".to_string()],
                        }
                    }
                } else {
                    HealthStatus::Unhealthy {
                        reasons: vec!["Required dependencies unhealthy".to_string()],
                    }
                }
            }
            DependencyCheckStrategy::Weighted { threshold } => {
                let score = weighted_score / total_weight;
                if score >= threshold {
                    HealthStatus::Healthy
                } else if score >= threshold * 0.7 {
                    HealthStatus::Degraded {
                        reasons: vec![format!("Health score: {:.2}", score)],
                    }
                } else {
                    HealthStatus::Unhealthy {
                        reasons: vec![format!("Health score: {:.2}", score)],
                    }
                }
            }
        };
        
        HealthCheckResult {
            status,
            components,
            timestamp: Instant::now(),
            duration: Duration::from_millis(0),
            metadata: HashMap::new(),
        }
    }
    
    fn name(&self) -> &str {
        "dependencies"
    }
}
```

## Configuration

```yaml
health_monitoring:
  checks:
    - type: database
      name: primary_db
      query: "SELECT 1"
      timeout: 3s
      priority: 1
      
    - type: http
      name: api_endpoint
      endpoint: "https://api.service.com/health"
      expected_status: 200
      timeout: 5s
      priority: 2
      
    - type: disk_space
      name: data_disk
      path: /var/data
      warning_threshold: 80
      critical_threshold: 95
      priority: 3
      
  aggregation:
    strategy: weighted
    weights:
      primary_db: 3.0
      api_endpoint: 2.0
      data_disk: 1.0
    healthy_threshold: 0.9
    degraded_threshold: 0.7
    
  monitoring:
    check_interval: 30s
    alert_on_degraded: true
    alert_on_unhealthy: true
    notify_on_recovery: true
    history_retention: 24h
    
  caching:
    enabled: true
    ttl: 10s
```

## Best Practices

1. **Layer health checks** - Liveness, readiness, and deep checks serve different purposes
2. **Set appropriate timeouts** - Don't let health checks hang indefinitely
3. **Cache results wisely** - Balance freshness with performance
4. **Include dependencies** - Check critical dependencies in deep health checks
5. **Use proper aggregation** - Choose strategy based on service criticality
6. **Monitor trends** - Track health over time, not just current state
7. **Implement graceful degradation** - Don't fail completely if non-critical components are unhealthy
8. **Secure health endpoints** - Don't expose sensitive information
9. **Test health checks** - Ensure they detect real problems
10. **Document thresholds** - Make it clear what triggers each health state