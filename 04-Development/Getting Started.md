---
title: Getting Started
tags: [nebula, docs, development]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Getting Started

**Build your first Nebula action in 10 minutes.** This guide walks you through setting up a development environment, creating a simple action, testing it, and using it in a workflow.

## Prerequisites

Before you begin, ensure you have:

- **Rust** 1.70 or later ([install](https://rustup.rs/))
- **Cargo** (comes with Rust)
- **Basic Rust knowledge** — Understanding of structs, traits, async/await
- **Text editor** — VS Code, IntelliJ IDEA, or any Rust-compatible editor

Verify your installation:

```bash
rustc --version  # Should show 1.70+
cargo --version
```

## Step 1: Create a New Project

Create a new Rust library project:

```bash
cargo new --lib my-nebula-actions
cd my-nebula-actions
```

This creates a new directory with this structure:

```
my-nebula-actions/
├── Cargo.toml
├── src/
│   └── lib.rs
```

## Step 2: Add Dependencies

Edit `Cargo.toml` to add Nebula dependencies:

```toml
[package]
name = "my-nebula-actions"
version = "0.1.0"
edition = "2021"

[dependencies]
nebula-action = "0.1"
nebula-core = "0.1"
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"

[dev-dependencies]
tokio-test = "0.4"
```

Install dependencies:

```bash
cargo build
```

## Step 3: Write Your First Action

Open `src/lib.rs` and replace its contents with:

```rust
use nebula_action::prelude::*;
use serde::{Deserialize, Serialize};

/// Input data for the greeting action
#[derive(Debug, Deserialize)]
pub struct GreetInput {
    /// Name of the person to greet
    pub name: String,

    /// Optional custom greeting message
    #[serde(default = "default_greeting")]
    pub greeting: String,
}

fn default_greeting() -> String {
    "Hello".to_string()
}

/// Output data from the greeting action
#[derive(Debug, Serialize)]
pub struct GreetOutput {
    /// The generated greeting message
    pub message: String,

    /// Timestamp when greeting was generated
    pub timestamp: String,
}

/// A simple action that generates personalized greetings
pub struct GreetAction;

impl Action for GreetAction {
    type Input = GreetInput;
    type Output = GreetOutput;

    fn id(&self) -> &str {
        "greet"
    }

    fn name(&self) -> &str {
        "Greet Action"
    }

    fn description(&self) -> &str {
        "Generates a personalized greeting message"
    }

    async fn execute(
        &self,
        input: Self::Input,
        context: &Context,
    ) -> Result<Self::Output, ActionError> {
        // Log the start of execution
        context.log_info(&format!("Greeting {}", input.name));

        // Validate input
        if input.name.trim().is_empty() {
            return Err(ActionError::validation("Name cannot be empty"));
        }

        // Generate greeting message
        let message = format!("{}, {}!", input.greeting, input.name);

        // Get current timestamp
        let timestamp = chrono::Utc::now().to_rfc3339();

        // Record metrics
        context.record_metric("greetings_generated", 1);

        // Log successful completion
        context.log_info(&format!("Generated greeting: {}", message));

        Ok(GreetOutput {
            message,
            timestamp,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_greet_action() {
        let action = GreetAction;
        let context = TestContext::default();

        let input = GreetInput {
            name: "Alice".to_string(),
            greeting: "Hello".to_string(),
        };

        let result = action.execute(input, &context).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.message, "Hello, Alice!");
    }

    #[tokio::test]
    async fn test_greet_action_empty_name() {
        let action = GreetAction;
        let context = TestContext::default();

        let input = GreetInput {
            name: "".to_string(),
            greeting: "Hello".to_string(),
        };

        let result = action.execute(input, &context).await;

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ActionError::Validation(_)
        ));
    }

    #[tokio::test]
    async fn test_greet_action_custom_greeting() {
        let action = GreetAction;
        let context = TestContext::default();

        let input = GreetInput {
            name: "Bob".to_string(),
            greeting: "Welcome".to_string(),
        };

        let result = action.execute(input, &context).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.message, "Welcome, Bob!");
    }
}
```

### What's Happening Here?

1. **Input/Output Types** — Defined with `#[derive(Deserialize/Serialize)]` for type safety
2. **Action Trait** — Implemented with `id()`, `name()`, `description()`, and `execute()`
3. **Validation** — Input validated before processing
4. **Logging** — Context used for structured logging
5. **Metrics** — Success tracked with `record_metric()`
6. **Error Handling** — Returns `ActionError` for validation failures
7. **Tests** — Three test cases covering happy path, validation, and custom input

## Step 4: Test Your Action

Run the tests:

```bash
cargo test
```

You should see output like:

```
running 3 tests
test tests::test_greet_action ... ok
test tests::test_greet_action_empty_name ... ok
test tests::test_greet_action_custom_greeting ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured
```

Run a specific test with verbose output:

```bash
cargo test test_greet_action -- --nocapture
```

## Step 5: Use Your Action in a Workflow

Create a simple workflow that uses your action. Add this to `src/lib.rs`:

```rust
#[cfg(test)]
mod workflow_tests {
    use super::*;
    use nebula_workflow::prelude::*;

    #[tokio::test]
    async fn test_greet_workflow() {
        // Create workflow
        let workflow = WorkflowBuilder::new("greeting_workflow")
            .add_node("greet", GreetAction)
            .build()
            .unwrap();

        // Execute workflow with parameters
        let params = json!({
            "name": "Charlie",
            "greeting": "Hi"
        });

        let result = workflow.execute(params).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.contains("Hi, Charlie!"));
    }
}
```

## Step 6: Add More Features

### Add Logging

Actions automatically log to the context:

```rust
context.log_info("Processing started");
context.log_debug(&format!("Input: {:?}", input));
context.log_error("Something went wrong", &error);
```

### Add Metrics

Track action performance:

```rust
let start = std::time::Instant::now();
// ... do work ...
let duration = start.elapsed();

context.record_duration("processing_time", duration);
context.record_metric("items_processed", count);
```

### Add Retry Logic

Handle transient failures:

```rust
// This error will trigger automatic retries
return Err(ActionError::transient("Network timeout"));

// This error won't be retried
return Err(ActionError::permanent("Invalid data format"));
```

### Use Credentials

Access secrets securely:

```rust
async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    // Retrieve credential (automatically redacted from logs)
    let api_key: ApiKeyCredential = context
        .get_credential("my_api_key")
        .await?;

    // Use credential
    let client = HttpClient::new()
        .bearer_auth(&api_key.token);

    // ...
}
```

## Common Patterns

### HTTP API Call

```rust
use reqwest;

async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    let client = reqwest::Client::new();

    let response = client
        .get(&input.url)
        .send()
        .await
        .map_err(|e| ActionError::transient(e))?;

    let data: MyData = response
        .json()
        .await
        .map_err(|e| ActionError::permanent(e))?;

    Ok(MyOutput { data })
}
```

### Database Query

```rust
use sqlx::PgPool;

async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    // Get database credential
    let db_cred = context.get_credential("postgres").await?;

    // Connect to database
    let pool = PgPool::connect(&db_cred.connection_string())
        .await
        .map_err(|e| ActionError::transient(e))?;

    // Execute query
    let users = sqlx::query_as::<_, User>("SELECT * FROM users WHERE active = true")
        .fetch_all(&pool)
        .await
        .map_err(|e| ActionError::transient(e))?;

    Ok(MyOutput { users })
}
```

### Transform Data

```rust
async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    // Validate input
    if input.data.is_empty() {
        return Err(ActionError::validation("Data cannot be empty"));
    }

    // Transform data
    let transformed: Vec<_> = input.data
        .iter()
        .filter(|item| item.is_valid())
        .map(|item| item.transform())
        .collect();

    context.log_info(&format!("Transformed {} items", transformed.len()));

    Ok(MyOutput { data: transformed })
}
```

## Common Pitfalls

### ❌ Don't: Store state in action struct

```rust
// BAD - state lost between executions
pub struct MyAction {
    counter: u32,  // This won't persist!
}
```

Use `StatefulAction` instead or store in workflow memory.

### ❌ Don't: Block async execution

```rust
// BAD - blocks the async runtime
let result = std::thread::sleep(Duration::from_secs(5));
```

Use async sleep instead:

```rust
// GOOD - async sleep
tokio::time::sleep(Duration::from_secs(5)).await;
```

### ❌ Don't: Ignore cancellation

```rust
// BAD - doesn't check for cancellation
for item in items {
    process(item).await;
}
```

Check cancellation periodically:

```rust
// GOOD - respects cancellation
for item in items {
    if context.is_cancelled() {
        return Err(ActionError::cancelled());
    }
    process(item).await;
}
```

### ❌ Don't: Log credentials

```rust
// BAD - credentials in logs
context.log_info(&format!("Using API key: {}", api_key));
```

Credentials are automatically redacted, but avoid manual logging:

```rust
// GOOD - credentials auto-redacted
context.log_info("Using API credential");
```

## Next Steps

Now that you've created your first action, explore:

1. **[[Creating Actions]]** — Deep dive into action development
2. **[[Building Workflows]]** — Compose actions into workflows
3. **[[02-Crates/nebula-action/Action Types|Action Types]]** — Different action types
4. **[[02-Crates/nebula-action/Examples|Examples]]** — Real-world action examples
5. **[[Testing Guide]]** — Testing strategies
6. **[[Best Practices]]** — Production-ready patterns

## Troubleshooting

### Build Errors

**Error: Cannot find `nebula-action`**
- Run `cargo update` to fetch latest dependencies
- Check that `Cargo.toml` has correct version

**Error: Async trait method not recognized**
- Ensure you're using `async fn` in the trait implementation
- Add `#[async_trait]` if using the `async-trait` crate

### Runtime Errors

**Error: Credential not found**
- Ensure credential is stored before workflow execution
- Check credential ID matches exactly
- Verify credential scope includes your workflow

**Error: Validation failed**
- Check input types match expected schema
- Ensure all required fields are provided
- Validate data before passing to action

### Testing Issues

**Test fails with timeout**
- Increase test timeout: `#[tokio::test(flavor = "multi_thread")]`
- Check for infinite loops or blocking code
- Use `-- --nocapture` to see logs

**Mock context not working**
- Use `TestContext::default()` for basic tests
- Use `TestContext::with_credential()` for credential tests
- Check that context is passed correctly

## Resources

- [[02-Crates/nebula-action/README|nebula-action Documentation]]
- [[03-Concepts/Actions|Actions Concept]]
- [[Rust async book]](https://rust-lang.github.io/async-book/)
- [[Serde documentation]](https://serde.rs/)

---

**Congratulations!** You've built your first Nebula action. Next: [[Creating Actions]] for advanced patterns.
