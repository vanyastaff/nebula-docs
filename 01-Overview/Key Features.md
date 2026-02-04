---
title: Key Features
tags: [nebula, docs, overview]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Key Features

Nebula provides a comprehensive set of features for building robust, type-safe workflow automation systems. Each feature is designed with production use in mind.

## Nodes & Actions

**Composable units of work with clear input/output contracts**

Actions are the building blocks of Nebula workflows. Each action is a self-contained, typed unit of work that can be:

- Combined into workflows (nodes execute actions)
- Reused across multiple workflows
- Tested in isolation
- Versioned independently

```rust
use nebula_action::prelude::*;

#[derive(Deserialize)]
struct HttpRequestInput {
    url: String,
    method: String,
}

#[derive(Serialize)]
struct HttpRequestOutput {
    status: u16,
    body: String,
}

simple_action!(
    HttpRequest,
    "http.request",
    HttpRequestInput,
    HttpRequestOutput,
    |_action, input, _ctx| async move {
        // Implementation here
        Ok(HttpRequestOutput { status: 200, body: "...".into() })
    }
);
```

**See**: [[03-Concepts/Actions|Actions concept]], [[Creating Actions]]

## Parameters & Validation

**Declarative parameter configuration with compile-time schema validation**

Parameters are validated at compile time using Rust's type system and derive macros:

```rust
use nebula_parameter::prelude::*;

#[derive(Parameters)]
struct EmailParams {
    #[param(required, validate = "email")]
    to: String,

    #[param(default = "noreply@example.com")]
    from: String,

    #[param(validate = "min_length(1)")]
    subject: String,
}
```

Invalid configurations are caught before deployment, not at runtime.

**See**: [[02-Crates/nebula-parameter/README|nebula-parameter]]

## Expression Language

**Runtime expressions for conditional logic and data transformation**

Use expressions to access workflow context, transform data, and make decisions:

```rust
// In workflow definition
node! {
    id: "send_notification",
    action: "slack.send_message",
    condition: "${workflow.status == 'success'}",
    input: {
        channel: "${env.SLACK_CHANNEL}",
        message: "Processed ${context.record_count} records"
    }
}
```

Expressions support:
- Variable interpolation (`${variable}`)
- Conditional logic (`if`, `match`)
- Data transformation (filters, maps)
- Built-in functions (date, string, math)

**See**: [[03-Concepts/Expression System|Expression System]], [[Using Expressions]]

## Scoped Memory & Caching

**Per-workflow isolated memory with optional distributed caching**

Each workflow execution gets its own isolated memory scope for sharing data between actions:

```rust
// Action 1: Store data in memory
context.memory().set("user_id", user.id).await?;

// Action 2: Retrieve data from memory
let user_id: i64 = context.memory().get("user_id").await?;
```

Optional features:
- **In-memory caching** — Fast local cache for frequently accessed data
- **Distributed caching** — Redis/Memcached integration for multi-instance deployments
- **TTL support** — Automatic expiration of cached values

**See**: [[02-Crates/nebula-memory/README|nebula-memory]]

## Credentials

**Secure credential injection without exposing secrets to action code**

Credentials are managed separately from workflows and actions:

- **Encrypted at rest** — AES-256 encryption for stored credentials
- **Injected at runtime** — Actions receive credentials via secure context
- **Never logged** — Credentials automatically redacted from logs and traces
- **Provider integrations** — AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Kubernetes Secrets

```rust
// Action code never sees the raw credential
async fn execute(&self, input: Input, context: &Context) -> Result<Output> {
    // Credentials injected securely
    let api_key = context.get_credential("api_key").await?;

    // Use credential (automatically redacted from logs)
    let client = HttpClient::new().bearer_auth(&api_key);
    // ...
}
```

**See**: [[03-Concepts/Credentials|Credentials concept]], [[02-Crates/nebula-credential/README|nebula-credential]]

## EventBus

**Async event system for triggering workflows and inter-action communication**

The EventBus enables event-driven workflows:

- **Workflow triggers** — Start workflows in response to events
- **Inter-action communication** — Actions can publish/subscribe to events
- **External integrations** — Kafka, RabbitMQ, NATS, Redis Streams
- **Event replay** — Replay events for debugging and recovery

```rust
// Publish an event
context.publish_event(Event {
    topic: "user.created",
    payload: json!({ "user_id": user.id }),
}).await?;

// Subscribe to events (in action definition)
#[action(triggers = ["user.created", "user.updated"])]
struct UserNotificationAction;
```

**See**: [[03-Concepts/Event System|Event System]], [[02-Crates/nebula-event/README|nebula-event]]

## SDK & UI

**Rust SDK + web UI for building and monitoring workflows**

### Rust SDK

Rich SDK for building actions and workflows programmatically:

```rust
use nebula_sdk::prelude::*;

let workflow = WorkflowBuilder::new("data_pipeline")
    .add_node(FetchDataAction::new())
    .add_node(TransformAction::new())
    .add_node(StoreAction::new())
    .connect("fetch", "transform")
    .connect("transform", "store")
    .build()?;

workflow.execute().await?;
```

### Web UI

Browser-based interface for:
- Visual workflow editor (drag-and-drop)
- Execution monitoring and logs
- Credential management
- Action catalog browsing
- Performance metrics and dashboards

**See**: [[02-Crates/nebula-sdk/README|nebula-sdk]], [[02-Crates/nebula-ui/README|nebula-ui]]

## Feature Comparison Table

| Feature | Purpose | When to Use | Learn More |
|---------|---------|-------------|-----------|
| **Actions** | Reusable units of work | Building workflow logic | [[Creating Actions]] |
| **Parameters** | Type-safe configuration | Validating action inputs | [[02-Crates/nebula-parameter/README\|nebula-parameter]] |
| **Expressions** | Dynamic data access | Runtime conditional logic | [[Using Expressions]] |
| **Memory** | Share data between actions | Workflow state management | [[02-Crates/nebula-memory/README\|nebula-memory]] |
| **Credentials** | Secure secret management | API keys, passwords, tokens | [[02-Crates/nebula-credential/README\|nebula-credential]] |
| **EventBus** | Event-driven workflows | Reactive automation | [[02-Crates/nebula-event/README\|nebula-event]] |
| **SDK** | Programmatic workflow building | Complex workflows | [[02-Crates/nebula-sdk/README\|nebula-sdk]] |

## Additional Capabilities

Beyond these core features, Nebula also provides:

- **Error handling** — Rich error types with automatic retry logic
- **Observability** — Built-in logging, metrics, and distributed tracing
- **Testing** — Mock contexts and test utilities for action development
- **Versioning** — Action versioning and compatibility checking
- **Performance** — High throughput with minimal overhead
- **Extensibility** — Plugin system for custom action types

---

**Next**: Learn about [[Core Principles]] or start [[Getting Started]].
