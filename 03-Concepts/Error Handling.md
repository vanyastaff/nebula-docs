---
title: Error Handling
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Error Handling

**Error handling in Nebula is explicit, typed, and designed for resilience in distributed workflows.** Unlike traditional systems where errors crash processes, Nebula treats errors as first-class values that can be handled, retried, or compensated.

## Definition

In Nebula, error handling is the systematic approach to:

- **Detecting failures** — Identifying when operations fail
- **Classifying errors** — Understanding why failures occur
- **Deciding recovery** — Choosing appropriate recovery strategy
- **Executing recovery** — Implementing retries, fallbacks, or compensation
- **Propagating failures** — Bubbling up unrecoverable errors
- **Logging context** — Capturing diagnostic information

Error handling is **not** about preventing all errors (impossible in distributed systems). It's about building **resilient systems that gracefully handle failures**.

## Why Error Handling Matters

### The Problem with Traditional Error Handling

Most workflow systems handle errors poorly:

❌ **Silent failures** — Errors swallowed without notice
❌ **Uncategorized errors** — All errors treated the same way
❌ **No automatic recovery** — Manual intervention required
❌ **Lost context** — Diagnostic information missing
❌ **Cascading failures** — One error brings down entire system
❌ **No compensation** — Failed transactions leave inconsistent state

**Real-world consequences**:
- Network glitch → entire workflow fails (should retry)
- Invalid user input → infinite retries (should fail fast)
- Payment processed but shipping failed → customer charged, no product sent
- Distributed transaction half-committed → data corruption

### The Nebula Approach

Nebula's error handling solves these problems:

✅ **Explicit errors** — Result<T, E> forces error handling
✅ **Typed errors** — Rich error types with context
✅ **Automatic recovery** — Retries, fallbacks, circuit breakers
✅ **Error propagation** — Errors bubble up with full context
✅ **Compensation support** — Distributed transaction rollback
✅ **Observability** — All errors logged, traced, and monitored

## Core Principles

### 1. Errors are Values

Errors are not exceptions — they're typed values returned from functions:

```rust
async fn execute(
    &self,
    input: Input,
    context: &Context,
) -> Result<Output, ActionError> {
    // Error is explicit return type
    if input.value < 0 {
        return Err(ActionError::validation("Value must be positive"));
    }

    Ok(Output { result: input.value * 2 })
}
```

**Why?** Compiler enforces error handling. Impossible to ignore errors.

### 2. Errors are Categorized

Not all errors are equal. Nebula categorizes errors by recoverability:

```rust
pub enum ActionError {
    /// Temporary failure - retry may succeed
    Transient(TransientError),

    /// Permanent failure - retry won't help
    Permanent(PermanentError),

    /// Invalid input - fix input and retry
    Validation(ValidationError),

    /// Authorization failure - user lacks permission
    Authorization(AuthError),

    /// Operation cancelled by user/system
    Cancelled(CancelledError),
}
```

**Why?** Different errors need different recovery strategies.

### 3. Automatic Recovery

Nebula automatically retries transient errors:

```rust
// Action declares retry policy
impl Action for FetchAPIAction {
    fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::exponential()
            .max_retries(3)
            .initial_delay(Duration::from_secs(1))
            .max_delay(Duration::from_secs(30))
            .multiplier(2.0)
            .retry_on(|error| matches!(error, ActionError::Transient(_)))
    }
}

// Workflow engine handles retries automatically
let result = action.execute(input, context).await;
// If transient error: retries 3 times with backoff
// If permanent error: fails immediately
```

**Why?** Most transient failures resolve themselves. Automatic retries reduce manual intervention.

### 4. Error Context

Every error carries rich diagnostic context:

```rust
let error = ActionError::transient("Database connection failed")
    .with_source(db_error)                    // Underlying error
    .with_context("user_id", user_id)         // Business context
    .with_context("retry_count", attempts)    // Operational context
    .with_timestamp(Utc::now());              // When it occurred

// Automatically logged with full context
context.log_error("Action failed", &error);
// Output: [ERROR] Action failed: Database connection failed
//         user_id: 12345, retry_count: 2
//         caused by: Connection timeout after 30s
```

**Why?** Debugging distributed systems requires context. Errors should be self-documenting.

### 5. Fail Fast vs. Fail Safe

Different situations require different strategies:

**Fail Fast** (for permanent errors):
```rust
// Invalid input - fail immediately
if email.is_empty() {
    return Err(ActionError::validation("Email cannot be empty"));
}
// Don't retry validation errors
```

**Fail Safe** (for transient errors):
```rust
// Network error - retry with backoff
match api_call().await {
    Err(e) if e.is_timeout() => {
        return Err(ActionError::transient("API timeout").with_source(e));
    }
    // Automatic retry will kick in
}
```

**Why?** Retrying permanent errors wastes resources. Failing fast on transient errors misses recovery opportunities.

## Error Types

### ActionError

Errors from individual actions:

```rust
pub enum ActionError {
    /// Network timeout, rate limit, temporary unavailability
    Transient(TransientError),

    /// Invalid data format, missing required fields
    Permanent(PermanentError),

    /// User input validation failure
    Validation(ValidationError),

    /// Permission denied, invalid credentials
    Authorization(AuthError),

    /// User or system cancelled operation
    Cancelled(CancelledError),
}
```

**When to use**: Any error within a single action execution.

**Example**:
```rust
async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    // Validation error
    if input.amount <= 0 {
        return Err(ActionError::validation("Amount must be positive"));
    }

    // Transient error (will retry)
    let response = http_client.get(&input.url).await
        .map_err(|e| ActionError::transient("HTTP request failed")
            .with_source(e))?;

    // Permanent error (won't retry)
    let data: MyData = serde_json::from_str(&response.body)
        .map_err(|e| ActionError::permanent("Invalid JSON format")
            .with_source(e))?;

    Ok(Output { data })
}
```

### WorkflowError

Errors from workflow orchestration:

```rust
pub enum WorkflowError {
    /// Action in workflow failed
    ActionFailed {
        node_id: String,
        error: ActionError,
    },

    /// Invalid workflow definition
    InvalidDefinition(String),

    /// Workflow execution timeout
    Timeout {
        duration: Duration,
    },

    /// Cyclic dependency detected
    CyclicDependency {
        path: Vec<String>,
    },

    /// Node not found in workflow
    NodeNotFound {
        node_id: String,
    },
}
```

**When to use**: Errors in workflow orchestration, not individual actions.

**Example**:
```rust
let workflow = WorkflowBuilder::new("my_workflow")
    .add_node("step1", Action1)
    .add_node("step2", Action2)
    .add_edge("step1", "step2", |o| o)
    .add_edge("step2", "step1", |o| o)  // Cycle!
    .build()?;  // Returns WorkflowError::CyclicDependency
```

### CredentialError

Errors from credential operations:

```rust
pub enum CredentialError {
    /// Credential not found in storage
    NotFound { id: String },

    /// Credential expired
    Expired {
        id: String,
        expired_at: DateTime<Utc>,
    },

    /// Decryption failed
    DecryptionFailed { id: String },

    /// Invalid credential format
    InvalidFormat { id: String, reason: String },

    /// Storage backend unavailable
    StorageUnavailable { backend: String },
}
```

**When to use**: Errors accessing or managing credentials.

**Example**:
```rust
async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    let api_key = context.get_credential("github_token").await
        .map_err(|e| match e {
            CredentialError::NotFound { id } => {
                ActionError::permanent(format!("Credential {} not configured", id))
            }
            CredentialError::Expired { .. } => {
                ActionError::transient("Credential expired, needs refresh")
            }
            _ => ActionError::permanent("Credential access failed")
        })?;

    // Use api_key...
}
```

## Error Recovery Strategies

### Retry with Exponential Backoff

Automatically retry transient failures with increasing delays:

```rust
impl Action for MyAction {
    fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::exponential()
            .max_retries(5)
            .initial_delay(Duration::from_millis(100))
            .max_delay(Duration::from_secs(60))
            .multiplier(2.0)
            .jitter(0.1)  // Add randomness to prevent thundering herd
            .retry_on(|error| {
                matches!(error,
                    ActionError::Transient(_) |
                    ActionError::Authorization(_)  // Maybe token expired
                )
            })
    }
}

// Retry schedule:
// Attempt 1: immediate
// Attempt 2: ~100ms (+ jitter)
// Attempt 3: ~200ms (+ jitter)
// Attempt 4: ~400ms (+ jitter)
// Attempt 5: ~800ms (+ jitter)
// Attempt 6: ~1600ms (+ jitter)
```

**Use when**: Temporary network issues, rate limiting, transient service unavailability.

**Don't use when**: Validation errors, authorization failures, permanent data issues.

### Fallback Actions

Try alternative when primary fails:

```rust
let workflow = WorkflowBuilder::new("resilient_workflow")
    .add_node("primary_api", PrimaryAPIAction)
    .add_node("fallback_api", FallbackAPIAction)
    .add_node("cache_lookup", CacheLookupAction)
    .add_node("process", ProcessAction)

    // Normal path
    .add_edge("primary_api", "process", |o| o)

    // First fallback: try different API
    .add_error_edge("primary_api", "fallback_api", |e| {
        json!({ "reason": e.to_string() })
    })
    .add_edge("fallback_api", "process", |o| o)

    // Second fallback: use cached data
    .add_error_edge("fallback_api", "cache_lookup", |_| json!({}))
    .add_edge("cache_lookup", "process", |o| o)

    .build()?;
```

**Use when**: Multiple ways to accomplish the same goal, degraded service acceptable.

### Circuit Breaker

Stop calling failing service to prevent cascading failures:

```rust
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitState>>,
    config: CircuitBreakerConfig,
}

pub struct CircuitBreakerConfig {
    /// Number of failures before opening circuit
    failure_threshold: u32,

    /// How long to wait before testing service again
    timeout: Duration,

    /// Number of successful requests to close circuit
    success_threshold: u32,
}

enum CircuitState {
    /// Normal operation
    Closed { failure_count: u32 },

    /// Too many failures, stop calling service
    Open { opened_at: Instant },

    /// Testing if service recovered
    HalfOpen { success_count: u32 },
}

impl CircuitBreaker {
    async fn call<F, T>(&self, f: F) -> Result<T, ActionError>
    where
        F: Future<Output = Result<T, ActionError>>,
    {
        match self.state.read().await.clone() {
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() < self.config.timeout {
                    // Circuit still open
                    return Err(ActionError::transient("Circuit breaker open"));
                } else {
                    // Timeout elapsed, try half-open
                    *self.state.write().await = CircuitState::HalfOpen {
                        success_count: 0
                    };
                }
            }
            CircuitState::Closed { .. } | CircuitState::HalfOpen { .. } => {}
        }

        // Execute operation
        match f.await {
            Ok(result) => {
                self.on_success().await;
                Ok(result)
            }
            Err(e) => {
                self.on_failure().await;
                Err(e)
            }
        }
    }

    async fn on_success(&self) {
        let mut state = self.state.write().await;
        *state = match *state {
            CircuitState::HalfOpen { success_count } => {
                if success_count + 1 >= self.config.success_threshold {
                    CircuitState::Closed { failure_count: 0 }
                } else {
                    CircuitState::HalfOpen {
                        success_count: success_count + 1
                    }
                }
            }
            _ => CircuitState::Closed { failure_count: 0 },
        };
    }

    async fn on_failure(&self) {
        let mut state = self.state.write().await;
        *state = match *state {
            CircuitState::Closed { failure_count } => {
                if failure_count + 1 >= self.config.failure_threshold {
                    CircuitState::Open {
                        opened_at: Instant::now()
                    }
                } else {
                    CircuitState::Closed {
                        failure_count: failure_count + 1
                    }
                }
            }
            CircuitState::HalfOpen { .. } => {
                CircuitState::Open { opened_at: Instant::now() }
            }
            current => current,
        };
    }
}

// Usage in action
pub struct ResilientAPIAction {
    circuit_breaker: CircuitBreaker,
}

impl Action for ResilientAPIAction {
    async fn execute(&self, input: Input, context: &Context)
        -> Result<Output, ActionError>
    {
        self.circuit_breaker.call(async {
            // Call external API
            let response = http_client.get(&input.url).await?;
            Ok(Output { data: response })
        }).await
    }
}
```

**Use when**: Calling external services that may become unavailable, preventing cascading failures.

### Compensation (Saga Pattern)

Undo previous operations when later steps fail:

```rust
let workflow = WorkflowBuilder::new("order_saga")
    // Forward actions
    .add_node("reserve_inventory", ReserveInventoryAction)
    .add_node("charge_payment", ChargePaymentAction)
    .add_node("send_confirmation", SendConfirmationAction)

    // Compensation actions
    .add_node("release_inventory", ReleaseInventoryAction)
    .add_node("refund_payment", RefundPaymentAction)
    .add_node("cancel_notification", CancelNotificationAction)

    // Normal flow
    .add_edge("reserve_inventory", "charge_payment", |o| o)
    .add_edge("charge_payment", "send_confirmation", |o| o)

    // Compensation flow
    .add_error_edge("charge_payment", "release_inventory", |e| {
        json!({ "reason": "payment_failed" })
    })

    .add_error_edge("send_confirmation", "refund_payment", |e| {
        json!({ "reason": "notification_failed" })
    })
    .add_edge("refund_payment", "release_inventory", |_| json!({}))
    .add_edge("release_inventory", "cancel_notification", |_| json!({}))

    .build()?;
```

**Compensation action example**:
```rust
pub struct ReleaseInventoryAction;

impl Action for ReleaseInventoryAction {
    type Input = CompensationInput;
    type Output = CompensationOutput;

    async fn execute(&self, input: Input, context: &Context)
        -> Result<Output, ActionError>
    {
        // Retrieve what was reserved
        let reservation_id = input.reservation_id;

        // Release inventory
        inventory_service
            .release(reservation_id)
            .await
            .map_err(|e| ActionError::transient("Failed to release inventory")
                .with_source(e))?;

        context.log_info(&format!(
            "Compensated: Released inventory reservation {}",
            reservation_id
        ));

        Ok(CompensationOutput {
            compensated: true
        })
    }
}
```

**Use when**: Distributed transactions, multi-step processes that need rollback capability.

### Timeout

Prevent operations from running forever:

```rust
use tokio::time::timeout;

async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    let operation = async {
        // Long-running operation
        external_api.call().await
    };

    match timeout(Duration::from_secs(30), operation).await {
        Ok(Ok(result)) => Ok(Output { data: result }),
        Ok(Err(e)) => Err(ActionError::transient("API call failed")
            .with_source(e)),
        Err(_) => Err(ActionError::transient("Operation timed out after 30s")),
    }
}
```

**Use when**: Calling external APIs, database queries, any operation that might hang.

## Error Propagation

### Bubbling Errors Up

Errors propagate through workflow layers:

```
Action Error
    ↓
Node Error
    ↓
Workflow Error
    ↓
Engine Error
    ↓
User/Logging System
```

Each layer adds context:

```rust
// Action level
let api_result = call_api().await
    .map_err(|e| ActionError::transient("API call failed")
        .with_source(e)
        .with_context("url", &url))?;

// Workflow level
let workflow_result = workflow.execute(params).await
    .map_err(|e| WorkflowError::ActionFailed {
        node_id: "fetch_api".to_string(),
        error: e,
    })?;

// Engine level
let engine_result = engine.run_workflow(workflow_id).await
    .map_err(|e| EngineError::WorkflowFailed {
        workflow_id,
        error: e,
    })?;

// Logged with full context chain
```

### Error Context Chain

Each error preserves the full chain of causation:

```rust
let error = ActionError::permanent("Failed to parse response")
    .with_source(json_error)                    // caused by serde_json::Error
    .with_context("response_body", &body)       // context: what we tried to parse
    .with_context("endpoint", &url)             // context: where it came from
    .with_context("user_id", user_id);          // context: business entity

// Error output:
// Failed to parse response
//   endpoint: https://api.example.com/users/123
//   user_id: 123
//   response_body: "{invalid json}"
//   caused by: expected `,` at line 1 column 15
```

## Best Practices

### Error Handling

- ✅ **Use specific error types** — ActionError::validation vs ActionError::transient
- ✅ **Add context to errors** — Include relevant IDs, values, state
- ✅ **Preserve error chains** — Use .with_source() to maintain causation
- ✅ **Log errors with context** — Use context.log_error()
- ✅ **Handle errors at right level** — Retry in action, compensate in workflow
- ❌ **Don't swallow errors** — Always log or propagate
- ❌ **Don't retry permanent errors** — Wastes resources
- ❌ **Don't lose error context** — Always preserve the source

### Retry Policies

- ✅ **Use exponential backoff** — Prevents thundering herd
- ✅ **Add jitter** — Randomizes retry timing
- ✅ **Set max retries** — Prevent infinite loops
- ✅ **Set max delay** — Cap maximum wait time
- ✅ **Only retry transient errors** — Check error type
- ❌ **Don't retry validation errors** — Will always fail
- ❌ **Don't use fixed delays** — Creates synchronized retry storms
- ❌ **Don't retry forever** — Set reasonable limits

### Circuit Breakers

- ✅ **Use for external services** — Protect against cascading failures
- ✅ **Set appropriate thresholds** — Balance sensitivity vs stability
- ✅ **Monitor circuit state** — Track open/closed transitions
- ✅ **Log circuit events** — Opens, closes, trips
- ✅ **Test half-open state** — Verify service recovery
- ❌ **Don't use for all errors** — Only for service unavailability
- ❌ **Don't set thresholds too low** — Avoids spurious trips
- ❌ **Don't forget to reset** — Circuit must be able to close

### Compensation

- ✅ **Make compensations idempotent** — Safe to retry
- ✅ **Log compensation actions** — Track what was undone
- ✅ **Store compensation data** — What to undo, how to undo it
- ✅ **Handle compensation failures** — Have fallback plan
- ✅ **Test compensation paths** — Often forgotten in testing
- ❌ **Don't assume compensation succeeds** — Can fail too
- ❌ **Don't leave partial state** — Complete compensation or alert
- ❌ **Don't forget edge cases** — What if compensation is duplicate?

## Common Patterns

### Retry with Fallback

Try multiple strategies:

```rust
async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    // Try primary with retries
    let mut attempts = 0;
    let primary_result = loop {
        match call_primary_api(&input).await {
            Ok(data) => break Ok(data),
            Err(e) if attempts < 3 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_secs(2_u64.pow(attempts))).await;
                continue;
            }
            Err(e) => break Err(e),
        }
    };

    // If primary failed, try fallback
    let data = match primary_result {
        Ok(data) => data,
        Err(primary_error) => {
            context.log_warn("Primary API failed, trying fallback", &primary_error);

            call_fallback_api(&input).await
                .map_err(|fallback_error| {
                    ActionError::permanent("Both primary and fallback failed")
                        .with_context("primary_error", primary_error)
                        .with_context("fallback_error", fallback_error)
                })?
        }
    };

    Ok(Output { data })
}
```

### Graceful Degradation

Provide partial results instead of complete failure:

```rust
async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    let mut results = Vec::new();
    let mut errors = Vec::new();

    // Try to fetch from multiple sources
    for source in &input.sources {
        match fetch_from_source(source).await {
            Ok(data) => results.push(data),
            Err(e) => {
                errors.push((source.clone(), e));
                context.log_warn(&format!("Source {} failed", source), &e);
            }
        }
    }

    // If we got at least some results, succeed with partial data
    if !results.is_empty() {
        Ok(Output {
            data: results,
            partial: !errors.is_empty(),
            failed_sources: errors,
        })
    } else {
        // All sources failed
        Err(ActionError::permanent("All data sources failed")
            .with_context("errors", errors))
    }
}
```

### Error Aggregation

Collect multiple errors before failing:

```rust
async fn execute(&self, input: Input, context: &Context)
    -> Result<Output, ActionError>
{
    let mut validation_errors = Vec::new();

    // Validate all fields, collect all errors
    if input.email.is_empty() {
        validation_errors.push("Email is required");
    }
    if !input.email.contains('@') {
        validation_errors.push("Email must contain @");
    }
    if input.age < 18 {
        validation_errors.push("Age must be at least 18");
    }

    // Return all validation errors at once (better UX)
    if !validation_errors.is_empty() {
        return Err(ActionError::validation("Multiple validation errors")
            .with_context("errors", validation_errors));
    }

    Ok(Output { validated: true })
}
```

## Related Concepts

- [[Actions]] — How actions produce and handle errors
- [[Workflows]] — How workflows orchestrate error recovery
- [[03-Concepts/Credentials|Credentials]] — Credential-related errors
- [[Security Model]] — Security and authorization errors
- [[Event System]] — Error events and notifications

## Implementation Guides

- [[Building Workflows#Error Handling]] — Workflow-level error handling
- [[Creating Actions#Error Handling]] — Action-level error handling
- [[02-Crates/nebula-action/Error Model|Error Model]] — Error type reference
- [[Best Practices#Error Handling]] — Production error handling patterns

---

**Next**: Learn about [[Expression System]] or explore [[Event System]].
