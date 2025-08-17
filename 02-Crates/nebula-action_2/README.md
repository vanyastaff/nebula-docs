---

title: Nebula Action
tags: [nebula, nebula-action, rust, crate, workflow, automation]
status: stable
created: 2025-08-17
version: 0.2.0

---

# Nebula Action

Core action system for Nebula workflow engine - a Rust crate providing trait-based abstractions for workflow automation.

## Overview

Nebula Action is a comprehensive framework for building type-safe, composable workflow actions in Rust. Think of it as the building blocks for complex automation - from simple data transformations to distributed transactions.

## Features

- **10+ Action Types** - ProcessAction, StatefulAction, StreamingAction, TransactionalAction, and more
- **Type Safety** - Full Rust type system with compile-time guarantees
- **Async First** - Built on Tokio for high-performance async execution
- **Idempotency** - Built-in support for safe retries and deduplication
- **Observability** - Structured logging, metrics, and distributed tracing
- **Testability** - Comprehensive testing utilities and mocks
- **Extensibility** - Easy to create custom action types

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
nebula-action = "0.2"
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
serde = { version = "1", features = ["derive"] }
```

Create your first action:

```rust
use nebula_action::prelude::*;
use async_trait::async_trait;

pub struct HelloAction;

#[async_trait]
impl ProcessAction for HelloAction {
    type Input = String;
    type Output = String;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        context.log_info(&format!("Processing: {}", input));
        Ok(ActionResult::Success(format!("Hello, {}!", input)))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let action = HelloAction;
    let context = ExecutionContext::new();
    
    let result = action.execute("World".to_string(), &context).await?;
    
    match result {
        ActionResult::Success(output) => println!("{}", output),
        _ => println!("Unexpected result"),
    }
    
    Ok(())
}
```

## Documentation Structure

- **[Getting Started](https://claude.ai/chat/Getting-Started/_index.md)** - Installation, setup, and first steps
- **[Action Types](https://claude.ai/chat/ActionTypes.md)** - Overview of all action types
- **[How-To Guides](https://claude.ai/chat/How-To/_index.md)** - Step-by-step guides for each action type
- **[Examples](https://claude.ai/chat/Examples/_index.md)** - Real-world use cases and code samples
- **[Patterns](https://claude.ai/chat/Patterns/_index.md)** - Design patterns and best practices
- **[Architecture](https://claude.ai/chat/Architecture.md)** - System design and internals
- **[API Reference](https://claude.ai/chat/Reference/_index.md)** - Complete API documentation

## Core Concepts

### Actions

The fundamental unit of work. Each action is a Rust struct implementing one of the action traits.

### ActionResult

Controls workflow execution flow - success, retry, skip, branch, etc.

### ExecutionContext

Provides runtime services - logging, metrics, credentials, resources.

### Idempotency

Ensures actions can be safely retried without duplicate effects.

## Action Types at a Glance

|Type|Purpose|State|Example Use Case|
|---|---|---|---|
|ProcessAction|Stateless transformation|❌|API calls, calculations|
|StatefulAction|Maintains state between runs|✅|Multi-step wizards|
|StreamingAction|Process data streams|❌|CSV processing, logs|
|TransactionalAction|ACID guarantees|✅|Payments, distributed writes|
|TriggerAction|Event sources|❌|Webhooks, message queues|
|SupplyAction|Resource providers|✅|Database pools, clients|
|InteractiveAction|Human interaction|✅|Approvals, forms|
|QueueAction|Background jobs|✅|Email sending, reports|
|ScheduleAction|Time-based execution|❌|Cron jobs, cleanup|
|WebhookAction|HTTP endpoints|❌|External integrations|

## Example: Multi-Service Aggregator

```rust
use nebula_action::prelude::*;

pub struct DataAggregator;

#[async_trait]
impl ProcessAction for DataAggregator {
    type Input = AggregateRequest;
    type Output = AggregateResponse;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // Parallel data fetching
        let (db_data, api_data, cache_data) = tokio::join!(
            self.fetch_from_database(&input, context),
            self.fetch_from_api(&input, context),
            self.fetch_from_cache(&input, context)
        );
        
        // Aggregate results
        let aggregated = self.merge_results(
            db_data?,
            api_data?,
            cache_data.unwrap_or_default()
        );
        
        // Return with metrics
        context.record_metric("items_aggregated", aggregated.len() as f64, &[]);
        
        Ok(ActionResult::Success(aggregated))
    }
}
```

## Performance

- **Zero-cost abstractions** - Trait-based design with no runtime overhead
- **Async/await** - Non-blocking I/O for maximum throughput
- **Connection pooling** - Reuse expensive resources
- **Streaming** - Process large datasets without loading into memory
- **Parallel execution** - Built-in support for concurrent operations

## Testing

```rust
#[cfg(test)]
mod tests {
    use nebula_action::testing::*;
    
    #[tokio::test]
    async fn test_action() {
        let action = MyAction::new();
        let context = TestContext::builder()
            .with_variable("key", json!("value"))
            .with_mock_client(MockHttpClient::new())
            .build();
        
        let result = action.execute(input, &context).await.unwrap();
        
        assert!(matches!(result, ActionResult::Success(_)));
        assert_eq!(context.get_counter("processed"), Some(1.0));
    }
}
```

## Contributing

See [CONTRIBUTING.md](https://claude.ai/chat/CONTRIBUTING.md) for development setup and guidelines.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](https://claude.ai/chat/LICENSE-APACHE))
- MIT license ([LICENSE-MIT](https://claude.ai/chat/LICENSE-MIT))

at your option.

## Support

- [Documentation](https://docs.nebula-action.dev/)
- [GitHub Issues](https://github.com/nebula/nebula-action/issues)
- [Discord Community](https://discord.gg/nebula)

## Roadmap

See [Roadmap.md](https://claude.ai/chat/Roadmap.md) for planned features and improvements.