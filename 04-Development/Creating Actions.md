---
title: Creating Actions
tags: [nebula, docs, development]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Creating Actions

**A comprehensive guide to building production-ready actions for Nebula workflows.** This guide covers action design, implementation patterns, error handling, testing strategies, and best practices.

## Before You Start

Review these prerequisites:

- ✅ Completed [[Getting Started]] tutorial
- ✅ Understand [[03-Concepts/Actions|Actions concept]]
- ✅ Familiar with Rust async/await
- ✅ Reviewed [[02-Crates/nebula-action/Action Types|Action Types]]

## Choosing an Action Type

First, determine which action type fits your use case:

| Type | Use When | Example |
|------|----------|---------|
| **ProcessAction** | Stateless data processing | HTTP API calls, data transformation |
| **StatefulAction** | Need to maintain state | Rate limiting, caching, counters |
| **TriggerAction** | Starting workflows | Webhooks, scheduled tasks, polling |
| **SupplyAction** | Providing shared resources | Connection pools, HTTP clients |
| **StreamingAction** | Long-lived data streams | WebSocket connections, event streams |
| **InteractiveAction** | Requiring user input | Approval workflows, manual steps |
| **TransactionalAction** | Multi-step with rollback | Financial transactions, sagas |

See [[02-Crates/nebula-action/Action Types|Action Types]] for detailed comparison.

## Action Anatomy

Every action has three core components:

### 1. Input Type

Defines what data the action receives:

```rust
#[derive(Debug, Deserialize)]
pub struct MyActionInput {
    /// Required field with validation
    #[serde(deserialize_with = "validate_url")]
    pub url: String,

    /// Optional field with default
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,

    /// Optional field
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
}

fn validate_url<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let url = String::deserialize(deserializer)?;
    if !url.starts_with("https://") {
        return Err(serde::de::Error::custom("URL must use HTTPS"));
    }
    Ok(url)
}

fn default_timeout() -> u64 {
    30
}
```

### 2. Output Type

Defines what data the action returns:

```rust
#[derive(Debug, Serialize)]
pub struct MyActionOutput {
    /// HTTP status code
    pub status: u16,

    /// Response body
    pub body: String,

    /// Response headers
    pub headers: HashMap<String, String>,

    /// Request duration in milliseconds
    pub duration_ms: u64,
}
```

### 3. Action Implementation

Implements the `Action` trait:

```rust
pub struct MyAction {
    // Configuration fields (shared across executions)
    client: Arc<reqwest::Client>,
    max_retries: u32,
}

impl MyAction {
    pub fn new() -> Self {
        Self {
            client: Arc::new(reqwest::Client::new()),
            max_retries: 3,
        }
    }
}

#[async_trait]
impl Action for MyAction {
    type Input = MyActionInput;
    type Output = MyActionOutput;

    fn id(&self) -> &str {
        "http.request"
    }

    fn name(&self) -> &str {
        "HTTP Request"
    }

    fn description(&self) -> &str {
        "Makes HTTP requests with retry logic and timeout support"
    }

    async fn execute(
        &self,
        input: Self::Input,
        context: &Context,
    ) -> Result<Self::Output, ActionError> {
        // Implementation here...
    }
}
```

## Step-by-Step: Building a Complete Action

Let's build a real-world action that fetches GitHub user data with retry logic, caching, and proper error handling.

### Step 1: Define Types

```rust
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct FetchGitHubUserInput {
    /// GitHub username
    pub username: String,

    /// Whether to include user's repositories
    #[serde(default)]
    pub include_repos: bool,
}

#[derive(Debug, Serialize)]
pub struct GitHubUser {
    pub login: String,
    pub name: Option<String>,
    pub bio: Option<String>,
    pub public_repos: u32,
    pub followers: u32,
    pub following: u32,
}

#[derive(Debug, Serialize)]
pub struct FetchGitHubUserOutput {
    pub user: GitHubUser,
    pub repositories: Option<Vec<String>>,
    pub cached: bool,
}
```

### Step 2: Implement Action

```rust
use nebula_action::prelude::*;
use reqwest;
use std::sync::Arc;
use std::time::Instant;

pub struct FetchGitHubUserAction {
    client: Arc<reqwest::Client>,
}

impl FetchGitHubUserAction {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .user_agent("Nebula-Workflow/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            client: Arc::new(client),
        }
    }

    async fn fetch_user(
        &self,
        username: &str,
        context: &Context,
    ) -> Result<GitHubUser, ActionError> {
        let url = format!("https://api.github.com/users/{}", username);

        context.log_debug(&format!("Fetching user from {}", url));

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| {
                context.log_error("HTTP request failed", &e);
                ActionError::transient(format!("Network error: {}", e))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();

            return match status.as_u16() {
                404 => Err(ActionError::validation(format!(
                    "User '{}' not found",
                    username
                ))),
                429 => Err(ActionError::rate_limited("GitHub API rate limit exceeded")),
                500..=599 => Err(ActionError::transient(format!(
                    "GitHub API error: {}",
                    status
                ))),
                _ => Err(ActionError::permanent(format!(
                    "Unexpected status {}: {}",
                    status, body
                ))),
            };
        }

        let user: GitHubUser = response
            .json()
            .await
            .map_err(|e| ActionError::permanent(format!("Invalid JSON response: {}", e)))?;

        Ok(user)
    }

    async fn fetch_repos(
        &self,
        username: &str,
        context: &Context,
    ) -> Result<Vec<String>, ActionError> {
        let url = format!("https://api.github.com/users/{}/repos", username);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ActionError::transient(format!("Network error: {}", e)))?;

        if !response.status().is_success() {
            return Ok(Vec::new()); // Don't fail if repos can't be fetched
        }

        #[derive(Deserialize)]
        struct Repo {
            name: String,
        }

        let repos: Vec<Repo> = response
            .json()
            .await
            .map_err(|e| ActionError::permanent(format!("Invalid JSON: {}", e)))?;

        Ok(repos.into_iter().map(|r| r.name).collect())
    }
}

#[async_trait]
impl Action for FetchGitHubUserAction {
    type Input = FetchGitHubUserInput;
    type Output = FetchGitHubUserOutput;

    fn id(&self) -> &str {
        "github.fetch_user"
    }

    fn name(&self) -> &str {
        "Fetch GitHub User"
    }

    fn description(&self) -> &str {
        "Fetches GitHub user profile and optionally their repositories"
    }

    async fn execute(
        &self,
        input: Self::Input,
        context: &Context,
    ) -> Result<Self::Output, ActionError> {
        let start = Instant::now();

        context.log_info(&format!("Fetching GitHub user: {}", input.username));

        // Check cache first
        let cache_key = format!("github_user:{}", input.username);
        if let Ok(Some(cached)) = context.memory().get::<GitHubUser>(&cache_key).await {
            context.log_info("User found in cache");
            context.record_metric("github.cache_hits", 1);

            return Ok(FetchGitHubUserOutput {
                user: cached,
                repositories: None,
                cached: true,
            });
        }

        context.record_metric("github.cache_misses", 1);

        // Fetch user data
        let user = self.fetch_user(&input.username, context).await?;

        // Fetch repositories if requested
        let repositories = if input.include_repos {
            Some(self.fetch_repos(&input.username, context).await?)
        } else {
            None
        };

        // Cache the result
        context
            .memory()
            .set_with_ttl(&cache_key, &user, std::time::Duration::from_secs(300))
            .await
            .ok(); // Don't fail if caching fails

        let duration = start.elapsed();
        context.record_duration("github.fetch_duration", duration);
        context.record_metric("github.users_fetched", 1);

        context.log_info(&format!(
            "Successfully fetched user {} in {:?}",
            input.username, duration
        ));

        Ok(FetchGitHubUserOutput {
            user,
            repositories,
            cached: false,
        })
    }
}
```

### Step 3: Add Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_valid_user() {
        let action = FetchGitHubUserAction::new();
        let context = TestContext::default();

        let input = FetchGitHubUserInput {
            username: "octocat".to_string(),
            include_repos: false,
        };

        let result = action.execute(input, &context).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.user.login, "octocat");
        assert!(!output.cached);
    }

    #[tokio::test]
    async fn test_fetch_invalid_user() {
        let action = FetchGitHubUserAction::new();
        let context = TestContext::default();

        let input = FetchGitHubUserInput {
            username: "this-user-definitely-does-not-exist-12345".to_string(),
            include_repos: false,
        };

        let result = action.execute(input, &context).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ActionError::Validation(_)
        ));
    }

    #[tokio::test]
    async fn test_caching() {
        let action = FetchGitHubUserAction::new();
        let context = TestContext::default();

        let input = FetchGitHubUserInput {
            username: "octocat".to_string(),
            include_repos: false,
        };

        // First call - not cached
        let result1 = action.execute(input.clone(), &context).await.unwrap();
        assert!(!result1.cached);

        // Second call - should be cached
        let result2 = action.execute(input, &context).await.unwrap();
        assert!(result2.cached);
    }
}
```

## Advanced Patterns

### Pattern 1: Retry with Exponential Backoff

```rust
async fn execute_with_retry<F, Fut, T>(
    &self,
    context: &Context,
    f: F,
) -> Result<T, ActionError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, ActionError>>,
{
    let mut attempt = 0;
    let max_attempts = 3;

    loop {
        attempt += 1;

        match f().await {
            Ok(result) => return Ok(result),
            Err(e) if attempt >= max_attempts => return Err(e),
            Err(ActionError::Transient(_)) => {
                let delay = Duration::from_millis(100 * 2_u64.pow(attempt));
                context.log_info(&format!("Retry attempt {} after {:?}", attempt, delay));
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e), // Don't retry permanent errors
        }
    }
}
```

### Pattern 2: Circuit Breaker

```rust
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub struct CircuitBreaker {
    failures: Arc<AtomicU32>,
    threshold: u32,
    reset_timeout: Duration,
    last_failure: Arc<tokio::sync::Mutex<Option<Instant>>>,
}

impl CircuitBreaker {
    pub fn new(threshold: u32, reset_timeout: Duration) -> Self {
        Self {
            failures: Arc::new(AtomicU32::new(0)),
            threshold,
            reset_timeout,
            last_failure: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    pub async fn call<F, Fut, T>(&self, f: F) -> Result<T, ActionError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, ActionError>>,
    {
        // Check if circuit is open
        if self.failures.load(Ordering::Relaxed) >= self.threshold {
            let mut last_failure = self.last_failure.lock().await;

            if let Some(last) = *last_failure {
                if last.elapsed() < self.reset_timeout {
                    return Err(ActionError::rate_limited("Circuit breaker open"));
                }

                // Reset circuit
                self.failures.store(0, Ordering::Relaxed);
                *last_failure = None;
            }
        }

        // Execute function
        match f().await {
            Ok(result) => {
                self.failures.store(0, Ordering::Relaxed);
                Ok(result)
            }
            Err(e) => {
                self.failures.fetch_add(1, Ordering::Relaxed);
                *self.last_failure.lock().await = Some(Instant::now());
                Err(e)
            }
        }
    }
}
```

### Pattern 3: Batch Processing

```rust
async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    let batch_size = 100;
    let mut results = Vec::new();

    for chunk in input.items.chunks(batch_size) {
        // Check cancellation between batches
        if context.is_cancelled() {
            return Err(ActionError::cancelled());
        }

        // Process batch
        let batch_results = self.process_batch(chunk, context).await?;
        results.extend(batch_results);

        context.record_metric("batches_processed", 1);
    }

    Ok(MyOutput { results })
}
```

## Error Handling Best Practices

### Classify Errors Correctly

```rust
match error_type {
    // Temporary network issues - retry
    NetworkTimeout | ConnectionReset => {
        ActionError::transient("Network issue, will retry")
    }

    // Rate limiting - retry with backoff
    RateLimitExceeded => {
        ActionError::rate_limited("API rate limit")
    }

    // Invalid input - don't retry
    ValidationError => {
        ActionError::validation("Invalid input data")
    }

    // Permanent API errors - don't retry
    NotFound | Unauthorized => {
        ActionError::permanent("Resource not accessible")
    }

    // Workflow cancelled - stop immediately
    Cancelled => {
        ActionError::cancelled()
    }
}
```

### Add Context to Errors

```rust
.map_err(|e| {
    context.log_error("Database query failed", &e);
    ActionError::transient(format!(
        "Failed to query database: {}. Query: {}, Params: {:?}",
        e, query, params
    ))
})?
```

## Testing Strategies

### Unit Tests

Test action logic in isolation:

```rust
#[tokio::test]
async fn test_action_validation() {
    let action = MyAction::new();
    let context = TestContext::default();

    let invalid_input = MyInput {
        value: -1, // Invalid
    };

    let result = action.execute(invalid_input, &context).await;

    assert!(matches!(result, Err(ActionError::Validation(_))));
}
```

### Integration Tests

Test with real external services:

```rust
#[tokio::test]
#[ignore] // Run with: cargo test -- --ignored
async fn test_real_api() {
    let action = FetchGitHubUserAction::new();
    let context = TestContext::default();

    let input = FetchGitHubUserInput {
        username: "octocat".to_string(),
        include_repos: true,
    };

    let result = action.execute(input, &context).await;

    assert!(result.is_ok());
}
```

### Mock External Services

```rust
#[tokio::test]
async fn test_with_mock() {
    use wiremock::{MockServer, Mock, ResponseTemplate};
    use wiremock::matchers::{method, path};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/users/test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "login": "test",
            "name": "Test User"
        })))
        .mount(&mock_server)
        .await;

    // Test with mock server URL
}
```

## Performance Optimization

### Connection Pooling

```rust
pub struct MyAction {
    pool: Arc<PgPool>,
}

impl MyAction {
    pub async fn new() -> Result<Self, Error> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect("postgres://...")
            .await?;

        Ok(Self {
            pool: Arc::new(pool),
        })
    }
}
```

### Parallel Execution

```rust
use futures::future::join_all;

async fn execute(&self, input: Self::Input, context: &Context) -> Result<Self::Output, ActionError> {
    let futures: Vec<_> = input
        .urls
        .iter()
        .map(|url| self.fetch_url(url, context))
        .collect();

    let results = join_all(futures).await;

    // Handle results...
}
```

## Best Practices Checklist

### Design
- ✅ Action does one thing well (single responsibility)
- ✅ Input/output types are well-documented
- ✅ Default values provided for optional fields
- ✅ Action is stateless (or uses StatefulAction trait)

### Implementation
- ✅ Proper error classification (transient vs. permanent)
- ✅ Logging at start, key decisions, and completion
- ✅ Metrics recorded for success/failure
- ✅ Cancellation checked in long-running operations
- ✅ Credentials accessed via context (not hardcoded)

### Testing
- ✅ Unit tests for all code paths
- ✅ Integration tests with real services (optional, marked ignored)
- ✅ Edge cases tested (empty input, invalid data)
- ✅ Error cases tested

### Documentation
- ✅ Action purpose clearly documented
- ✅ Input fields have doc comments
- ✅ Output fields have doc comments
- ✅ Example usage provided

## Related Guides

- [[Getting Started]] — Build your first action
- [[Building Workflows]] — Use actions in workflows
- [[Testing Guide]] — Advanced testing techniques
- [[Best Practices]] — Production patterns
- [[02-Crates/nebula-action/Examples|Examples]] — Real-world action examples

---

**Next**: Learn [[Building Workflows]] or explore [[02-Crates/nebula-action/Action Types|Action Types]].
