---
title: What is Nebula
tags: [nebula, docs, overview]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# What is Nebula

**Nebula is a high-performance workflow automation engine written in Rust that combines type-safe action execution with event-driven orchestration for reliable automation at scale.**

## The Problem

Modern automation platforms face common challenges:

- **Lack of type safety** — Runtime errors in production due to unvalidated configurations
- **Poor observability** — Black-box execution makes debugging nearly impossible
- **Limited composability** — Workflows can't be easily reused or extended
- **Security concerns** — Credentials exposed in logs and configurations
- **Performance bottlenecks** — Slow execution engines that don't scale

Traditional workflow engines (like Apache Airflow, Temporal, or even n8n) often sacrifice type safety and performance for flexibility, leading to fragile systems that break in production.

## The Solution

Nebula solves these problems by leveraging **Rust's type system** and **modern async programming** to create workflows that are:

- **Type-safe by design** — Catch errors at compile time, not runtime
- **Observable by default** — Every action produces structured logs, metrics, and traces
- **Composable** — Build complex workflows from simple, reusable actions
- **Secure** — Credentials never appear in logs or configurations
- **High-performance** — Async Rust enables efficient concurrent execution

## Core Pillars

### 1. Type Safety

Workflows are defined using strongly-typed Rust structs and traits, not YAML or JSON configurations. This means:

```rust
// Action inputs/outputs are validated at compile time
#[derive(Deserialize)]
struct FetchDataInput {
    url: String,
    timeout: Duration,
}

#[derive(Serialize)]
struct FetchDataOutput {
    status: u16,
    body: String,
}
```

If your workflow tries to connect incompatible actions, the compiler catches it before deployment.

### 2. Observable by Default

Every action execution is instrumented with:

- **Structured logging** — Context-aware logs with trace IDs
- **Metrics** — Duration, success/failure rates, resource usage
- **Distributed tracing** — End-to-end request tracking across actions

No manual instrumentation required — observability is built into the framework.

### 3. Composable Actions

Actions are self-contained units of work that can be:

- Combined into workflows
- Reused across multiple workflows
- Versioned independently
- Tested in isolation

```rust
// Compose simple actions into complex workflows
workflow! {
    fetch_data -> validate_schema -> transform -> store -> notify
}
```

### 4. Secure Credentials

Credentials are managed separately from workflows:

- Stored encrypted at rest
- Injected at runtime via secure context
- Never logged or serialized
- Support for external providers (AWS Secrets Manager, HashiCorp Vault)

### 5. High Performance

Built on Rust's async runtime (Tokio):

- Efficient concurrent execution
- Minimal memory footprint
- Low latency (microsecond-level overhead)
- Scales to millions of actions per day

## What Makes Nebula Different

| Feature | Traditional Workflows | Nebula |
|---------|----------------------|---------|
| **Type Safety** | Runtime validation (YAML/JSON) | Compile-time validation (Rust) |
| **Error Handling** | Manual try-catch everywhere | Result<T, E> with rich error types |
| **Observability** | Manual instrumentation | Built-in logging, metrics, tracing |
| **Performance** | Interpreted execution | Compiled native code |
| **Composability** | Limited reuse | Trait-based action composition |
| **Security** | Credentials in configs | Secure credential injection |

## When to Use Nebula

Nebula is ideal for:

- **Data pipelines** — ETL, data transformation, validation workflows
- **Event processing** — React to events from multiple sources
- **Scheduled automation** — Cron-like jobs with complex logic
- **API orchestration** — Chain multiple API calls with error handling
- **Infrastructure automation** — Provision, configure, and monitor systems

### Real-World Example

**Problem**: Process customer orders by validating payment, updating inventory, sending notifications, and logging to analytics.

**Traditional approach**: Write custom code with manual error handling, logging, and retry logic.

**Nebula approach**: Compose pre-built actions into a type-safe workflow:

```rust
workflow! {
    validate_payment
        .on_success(update_inventory)
        .on_success(send_confirmation_email)
        .on_success(log_to_analytics)
        .on_failure(refund_and_notify)
}
```

Each action is tested, reusable, and observable. If `update_inventory` fails, the workflow automatically executes the failure path.

## What Nebula is NOT

- **Not a generic task queue** — Use RabbitMQ or Kafka for that
- **Not a data processing framework** — Use Apache Spark or Polars for big data
- **Not a service mesh** — Use Istio or Linkerd for that
- **Not a low-code platform** — Nebula is code-first and requires Rust knowledge

## Getting Started

Ready to build your first workflow?

1. Read [[Key Features]] to understand what Nebula can do
2. Follow [[Getting Started]] to create your first action
3. Explore [[Crates Overview]] to see available building blocks
4. Check out [[06-Examples/_Index|Examples]] for real-world patterns

## Learn More

- [[Core Principles]] — Design philosophy and architectural decisions
- [[Use Cases]] — Industry-specific examples
- [[Comparison]] — How Nebula compares to alternatives
- [[Architecture Overview]] — System design and components

---

**Next**: Explore [[Key Features]] to see what you can build with Nebula.
