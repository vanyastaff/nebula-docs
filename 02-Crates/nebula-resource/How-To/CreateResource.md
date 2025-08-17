---

title: Create Custom Resource
tags: [nebula-resource, how-to, custom, guide]
status: stable
created: 2025-08-17
---

# Create Custom Resource

Complete guide to creating a custom resource for your specific needs.

## Overview

Custom resources allow you to wrap any external service or stateful component with:

- Automatic lifecycle management
- Health monitoring
- Connection pooling
- Credential management
- Context awareness
- Testing support

## Basic Resource Structure

### Step 1: Define the Resource

```rust
use nebula_resource::prelude::*;
use async_trait::async_trait;

/// Your custom resource definition
#[derive(Resource)]
#[resource(
    id = "weather_api",
    name = "Weather API Client",
    description = "Provides weather data from external API",
    category = "External",
    lifecycle = "global",  // or "workflow", "execution", "action"
    capabilities = ["weather", "forecast", "historical"],
    credentials = ["weather_api_key"],
    health_checks = ["connectivity", "rate_limit"]
)]
#[auto_mock]  // Generates MockWeatherApiResource automatically
pub struct WeatherApiResource;
```

### Step 2: Define Configuration

```rust
#[derive(ResourceConfig, Debug, Clone)]
pub struct WeatherApiConfig {
    /// API endpoint URL
    #[validate(url)]
    #[tier(personal = "https://api.weather.com/free", 
           enterprise = "https://api.weather.com/premium")]
    pub endpoint: String,
    
    /// Rate limit (requests per minute)
    #[validate(range = "1..=1000")]
    #[tier(personal = "max:10", enterprise = "max:100", cloud = "max:1000")]
    pub rate_limit: u32,
    
    /// Request timeout in seconds
    #[validate(range = "1..=60")]
    pub timeout_secs: u64,
    
    /// Enable caching
    #[tier(personal = "false", enterprise = "true")]
    pub enable_cache: bool,
    
    /// Cache TTL in seconds
    #[validate(range = "60..=3600")]
    pub cache_ttl_secs: u64,
    
    /// API key credential reference
    #[credential(id = "weather_api_key")]
    pub api_key_credential: String,
    
    /// Optional webhook for alerts
    #[validate(url)]
    #[tier(personal = "disabled")]
    pub alert_webhook: Option<String>,
}

// Provide defaults
impl Default for WeatherApiConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://api.weather.com/v1".into(),
            rate_limit: 60,
            timeout_secs: 30,
            enable_cache: true,
            cache_ttl_secs: 300,
            api_key_credential: "weather_api_key".into(),
            alert_webhook: None,
        }
    }
}
```

### Step 3: Implement Resource Instance

```rust
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::RwLock;

pub struct WeatherApiInstance {
    id: ResourceInstanceId,
    client: reqwest::Client,
    config: WeatherApiConfig,
    rate_limiter: RateLimiter,
    cache: Arc<DashMap<String, CachedWeatherData>>,
    circuit_breaker: CircuitBreaker,
    metrics: Arc<WeatherMetrics>,
    last_health_check: RwLock<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct CachedWeatherData {
    data: WeatherData,
    cached_at: DateTime<Utc>,
}

impl CachedWeatherData {
    fn is_expired(&self, ttl: Duration) -> bool {
        Utc::now().signed_duration_since(self.cached_at) > chrono::Duration::from_std(ttl).unwrap()
    }
}

#[async_trait]
impl ResourceInstance for WeatherApiInstance {
    fn id(&self) -> &ResourceInstanceId {
        &self.id
    }
    
    async fn health_check(&self) -> Result<HealthStatus, ResourceError> {
        // Check circuit breaker first
        if self.circuit_breaker.is_open() {
            return Ok(HealthStatus::Degraded {
                reason: "Circuit breaker is open".into(),
                performance_impact: 0.5,
            });
        }
        
        // Test API connectivity
        let health_url = format!("{}/health", self.config.endpoint);
        match self.client
            .get(&health_url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                *self.last_health_check.write().await = Utc::now();
                self.circuit_breaker.record_success();
                Ok(HealthStatus::Healthy)
            }
            Ok(response) => {
                self.circuit_breaker.record_failure();
                Ok(HealthStatus::Unhealthy {
                    reason: format!("API returned status: {}", response.status()),
                    recoverable: true,
                })
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                Ok(HealthStatus::Unhealthy {
                    reason: format!("Connection failed: {}", e),
                    recoverable: true,
                })
            }
        }
    }
    
    async fn cleanup(&mut self) -> Result<(), ResourceError> {
        // Clear cache
        self.cache.clear();
        
        // Log cleanup
        log::info!("Cleaned up WeatherApi resource {}", self.id);
        
        Ok(())
    }
    
    fn metrics(&self) -> ResourceMetrics {
        ResourceMetrics {
            requests_total: self.metrics.requests_total.get(),
            errors_total: self.metrics.errors_total.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            average_latency_ms: self.metrics.average_latency_ms(),
            circuit_breaker_state: self.circuit_breaker.state().to_string(),
        }
    }
    
    fn is_reusable(&self) -> bool {
        true  // Can be reused across actions
    }
    
    async fn reset(&mut self) -> Result<(), ResourceError> {
        // Clear request-specific state if any
        Ok(())
    }
}
```

### Step 4: Implement Resource Trait

```rust
#[async_trait]
impl Resource for WeatherApiResource {
    type Config = WeatherApiConfig;
    type Instance = WeatherApiInstance;
    
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError> {
        // Get API key from credential system
        let api_key = context
            .get_credential(&config.api_key_credential)
            .await
            .map_err(|e| ResourceError::MissingCredential(e.to_string()))?;
        
        // Create HTTP client with defaults
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .user_agent("nebula-weather/1.0")
            .default_headers({
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    "X-API-Key",
                    api_key.expose_secret().parse().unwrap()
                );
                headers
            })
            .build()
            .map_err(|e| ResourceError::CreationFailed(e.to_string()))?;
        
        // Test connection
        let test_url = format!("{}/test", config.endpoint);
        client.get(&test_url)
            .send()
            .await
            .map_err(|e| ResourceError::CreationFailed(
                format!("Failed to connect to weather API: {}", e)
            ))?;
        
        context.log_info(&format!(
            "Created WeatherApi resource with endpoint: {}, rate limit: {}/min",
            config.endpoint, config.rate_limit
        ));
        
        Ok(WeatherApiInstance {
            id: ResourceInstanceId::new(),
            client,
            config: config.clone(),
            rate_limiter: RateLimiter::new(config.rate_limit, Duration::from_secs(60)),
            cache: Arc::new(DashMap::new()),
            circuit_breaker: CircuitBreaker::new(CircuitBreakerConfig::default()),
            metrics: Arc::new(WeatherMetrics::new()),
            last_health_check: RwLock::new(Utc::now()),
        })
    }
    
    fn validate_config(&self, config: &Self::Config) -> Result<(), ResourceError> {
        if config.rate_limit == 0 {
            return Err(ResourceError::InvalidConfig {
                field: "rate_limit".into(),
                reason: "Rate limit must be greater than 0".into(),
            });
        }
        
        if config.cache_ttl_secs < 60 {
            return Err(ResourceError::InvalidConfig {
                field: "cache_ttl_secs".into(),
                reason: "Cache TTL must be at least 60 seconds".into(),
            });
        }
        
        Ok(())
    }
    
    fn estimate_requirements(&self, config: &Self::Config) -> ResourceRequirements {
        ResourceRequirements {
            memory_mb: 10 + (config.rate_limit as usize / 10), // Rough estimate
            cpu_millicores: 50,
            network_bandwidth_kbps: config.rate_limit as usize * 10,
            storage_mb: if config.enable_cache { 100 } else { 0 },
        }
    }
    
    fn supports_pooling(&self) -> bool {
        true
    }
    
    fn required_credentials() -> Vec<&'static str> {
        vec!["weather_api_key"]
    }
}
```

### Step 5: Add Business Logic Methods

```rust
impl WeatherApiInstance {
    /// Get current weather with caching
    pub async fn get_current_weather(&self, location: &str) -> Result<WeatherData, WeatherError> {
        let cache_key = format!("current:{}", location);
        
        // Check cache if enabled
        if self.config.enable_cache {
            if let Some(cached) = self.cache.get(&cache_key) {
                if !cached.is_expired(Duration::from_secs(self.config.cache_ttl_secs)) {
                    self.metrics.cache_hits.inc();
                    return Ok(cached.data.clone());
                }
            }
            self.metrics.cache_misses.inc();
        }
        
        // Rate limiting
        self.rate_limiter.wait_if_needed().await;
        
        // Circuit breaker check
        if self.circuit_breaker.is_open() {
            return Err(WeatherError::ServiceUnavailable);
        }
        
        // Make API request
        let start = Instant::now();
        let url = format!("{}/current?location={}", self.config.endpoint, location);
        
        let response = match self.client.get(&url).send().await {
            Ok(resp) => {
                self.circuit_breaker.record_success();
                resp
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.metrics.errors_total.inc();
                return Err(WeatherError::ApiError(e.to_string()));
            }
        };
        
        // Record metrics
        let duration = start.elapsed();
        self.metrics.record_request_duration(duration);
        self.metrics.requests_total.inc();
        
        // Parse response
        let weather_data: WeatherData = response
            .json()
            .await
            .map_err(|e| WeatherError::ParseError(e.to_string()))?;
        
        // Cache if enabled
        if self.config.enable_cache {
            self.cache.insert(
                cache_key,
                CachedWeatherData {
                    data: weather_data.clone(),
                    cached_at: Utc::now(),
                }
            );
        }
        
        Ok(weather_data)
    }
    
    /// Get weather forecast
    pub async fn get_forecast(&self, location: &str, days: u32) -> Result<Forecast, WeatherError> {
        // Similar implementation with caching and error handling
        todo!()
    }
    
    /// Get historical weather data
    pub async fn get_historical(&self, location: &str, date: Date<Utc>) -> Result<WeatherData, WeatherError> {
        // Implementation
        todo!()
    }
    
    /// Subscribe to weather alerts
    pub async fn subscribe_alerts(&self, location: &str, criteria: AlertCriteria) -> Result<AlertSubscription, WeatherError> {
        if self.config.alert_webhook.is_none() {
            return Err(WeatherError::AlertsNotConfigured);
        }
        
        // Implementation
        todo!()
    }
}
```

## Using the Custom Resource

### In an Action

```rust
use nebula_action::prelude::*;

#[derive(Action)]
#[action(id = "weather.check")]
#[resources([WeatherApiResource, LoggerResource])]
pub struct WeatherCheckAction;

#[derive(Deserialize)]
pub struct WeatherInput {
    pub location: String,
    pub include_forecast: bool,
}

#[derive(Serialize)]
pub struct WeatherOutput {
    pub current: WeatherData,
    pub forecast: Option<Forecast>,
}

#[async_trait]
impl ProcessAction for WeatherCheckAction {
    type Input = WeatherInput;
    type Output = WeatherOutput;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // Get resources
        let weather = context.get_resource::<WeatherApiResource>().await?;
        let logger = context.get_resource::<LoggerResource>().await?;
        
        logger.info(&format!("Checking weather for {}", input.location));
        
        // Get current weather
        let current = weather
            .get_current_weather(&input.location)
            .await
            .map_err(|e| ActionError::ExternalServiceError {
                service: "weather_api".into(),
                error: e.to_string(),
            })?;
        
        // Get forecast if requested
        let forecast = if input.include_forecast {
            Some(weather.get_forecast(&input.location, 5).await?)
        } else {
            None
        };
        
        Ok(ActionResult::Success(WeatherOutput {
            current,
            forecast,
        }))
    }
}
```

## Configuration File

```toml
# configs/weather_api.toml
[weather_api]
endpoint = "https://api.weather.com/v1"
rate_limit = 60
timeout_secs = 30
enable_cache = true
cache_ttl_secs = 300

[weather_api.credentials]
api_key_credential = "weather_api_key"

# Tier overrides
[tier.personal]
endpoint = "https://api.weather.com/free"
rate_limit = 10
enable_cache = false

[tier.enterprise]
endpoint = "https://api.weather.com/premium"
rate_limit = 100
alert_webhook = "https://hooks.example.com/weather"
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nebula_resource::testing::*;
    
    #[tokio::test]
    async fn test_weather_resource() {
        // Auto-generated mock
        let mut mock_weather = MockWeatherApiResource::new();
        
        mock_weather
            .expect_get_current_weather()
            .with("London")
            .returns(Ok(WeatherData {
                temperature: 20.0,
                humidity: 65,
                conditions: "Partly cloudy".into(),
            }))
            .once();
        
        let context = TestContext::builder()
            .with_mock_resource(mock_weather)
            .build();
        
        let weather = context.get_resource::<WeatherApiResource>().await.unwrap();
        let result = weather.get_current_weather("London").await.unwrap();
        
        assert_eq!(result.temperature, 20.0);
    }
}
```

## Best Practices

1. **Always implement health checks** - Critical for monitoring
2. **Use caching wisely** - Balance freshness vs performance
3. **Implement circuit breakers** - Prevent cascade failures
4. **Add comprehensive metrics** - For observability
5. **Handle credentials securely** - Never log or expose
6. **Make resources reusable** - Design for pooling
7. **Provide tier-specific configs** - Adjust for deployment tier
8. **Write thorough tests** - Use auto-generated mocks