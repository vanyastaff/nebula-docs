---
title: Actions
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Actions

**An Action is a self-contained, typed unit of work that performs a specific task within a Nebula workflow.** Actions are the fundamental building blocks that make workflows composable, testable, and observable.

## Definition

In Nebula, an action represents a discrete operation with:

- **Clearly defined inputs** — Typed input structure (Rust struct)
- **Clearly defined outputs** — Typed output structure or error
- **Deterministic behavior** — Same inputs produce same outputs
- **Isolated execution** — No shared mutable state
- **Built-in observability** — Automatic logging, metrics, and tracing

Actions are **not** arbitrary code blocks or scripts. They are structured, typed components that follow a contract enforced by Rust's type system.

## Why Actions Matter

### The Problem with Traditional Workflow Steps

In traditional workflow engines (Airflow, n8n, Zapier), workflow steps are often:

❌ **Untyped** — Configuration via YAML/JSON with runtime validation
❌ **Opaque** — Black-box execution with limited visibility
❌ **Tightly coupled** — Hard to reuse across workflows
❌ **Difficult to test** — Require full workflow context
❌ **Version-fragile** — Breaking changes discovered at runtime

### The Nebula Approach

Nebula actions solve these problems:

✅ **Type-safe** — Inputs/outputs validated at compile time
✅ **Observable** — Every execution produces structured logs, metrics, traces
✅ **Reusable** — Same action used in multiple workflows
✅ **Testable** — Actions tested in isolation with mock context
✅ **Versioned** — Explicit versioning with compatibility checking

## Core Principles

### 1. Single Responsibility

Each action should do **one thing well**. Instead of a monolithic "ProcessOrder" action that validates payment, updates inventory, and sends notifications, create three focused actions:

- `ValidatePayment` action
- `UpdateInventory` action
- `SendOrderNotification` action

**Why?** Focused actions are easier to:
- Test in isolation
- Reuse in different workflows
- Understand and maintain
- Replace or upgrade independently

### 2. Type Safety

Actions use Rust's type system to enforce correctness:

- **Input validation** happens at compile time (not runtime)
- **Output contracts** are explicit and enforced
- **Error types** are rich and structured
- **No silent failures** — all errors must be handled

If you try to connect incompatible actions (Action A outputs `String`, Action B expects `i64`), the compiler catches it before deployment.

### 3. Determinism

Given the same inputs, an action should produce the same outputs. This means:

- **No global mutable state** — Actions don't modify shared memory
- **No hidden dependencies** — All dependencies injected via context
- **Predictable** — Easy to reason about behavior
- **Testable** — Same input always produces same result in tests

**Non-deterministic actions** (like `GenerateRandomId`) are explicitly marked and handled specially.

### 4. Isolation

Actions execute in isolation from each other:

- **No direct communication** between actions (use workflow context or events)
- **Separate memory scopes** — Each workflow run gets isolated memory
- **Resource boundaries** — Actions can't exhaust global resources
- **Failure containment** — One action failure doesn't crash others

### 5. Observability by Default

Every action execution automatically produces:

- **Structured logs** — With context (workflow ID, action ID, trace ID)
- **Metrics** — Duration, success/failure rates, resource usage
- **Distributed traces** — End-to-end request tracking
- **Error context** — Rich error information for debugging

No manual instrumentation required — observability is built into the framework.

## Action Lifecycle

Every action goes through a standard lifecycle:

```
1. Registration
   ↓
2. Initialization
   ↓
3. Configuration (parameters validated)
   ↓
4. Execution (input → logic → output)
   ↓
5. Result (success or error)
   ↓
6. Cleanup (resources released)
```

### Phase Details

**1. Registration** — Action is registered in the action registry with metadata (ID, version, input/output schemas)

**2. Initialization** — Action instance is created (constructor called)

**3. Configuration** — Parameters are validated and applied to the action instance

**4. Execution** — Action receives input and context, performs its logic, returns output or error

**5. Result** — Output is serialized and passed to the next action, or error is handled by the workflow

**6. Cleanup** — Resources are released (connections closed, files cleaned up)

See [[02-Crates/nebula-action/Action Lifecycle|Action Lifecycle]] for implementation details.

## Action Types

Nebula supports multiple action types, each optimized for different use cases:

### ProcessAction (Most Common)

**Purpose**: Stateless synchronous or asynchronous processing

**Use when**: You need to transform data, call APIs, or perform calculations

**Examples**: HTTP requests, data validation, JSON transformation, database queries

**Characteristics**:
- No state between executions
- Fast initialization
- Simple to test

### StatefulAction

**Purpose**: Maintain state across multiple executions

**Use when**: You need rate limiting, caching, counters, or accumulators

**Examples**: Rate limiter, request deduplicator, cache manager, metric aggregator

**Characteristics**:
- Persistent state across executions
- State can be stored in memory or external storage
- More complex lifecycle

### TriggerAction

**Purpose**: Entry point for workflows (event sources)

**Use when**: You need to start workflows based on external events

**Examples**: Webhook listeners, scheduled tasks, file watchers, message queue consumers

**Characteristics**:
- Long-lived (always running)
- Produces events that start workflows
- Can be polled or push-based

### SupplyAction (Resource Providers)

**Purpose**: Provide shared resources to other actions

**Use when**: You need connection pooling, shared clients, or resource management

**Examples**: Database connection pools, HTTP clients, logger instances, cache clients

**Characteristics**:
- Initialized once, reused many times
- Manages resource lifecycle
- Typically wrapped around existing resources

### StreamingAction

**Purpose**: Process long-lived streams of data

**Use when**: You need to handle WebSocket connections, database cursors, or continuous data streams

**Examples**: Real-time data processing, log streaming, event stream processing

**Characteristics**:
- Long-lived connections
- Backpressure handling
- Graceful shutdown support

### InteractiveAction

**Purpose**: Wait for human or system input during workflow execution

**Use when**: You need approval workflows, manual validation, or external system confirmation

**Examples**: Approval requests, manual data entry, external API callbacks

**Characteristics**:
- Workflow pauses until input received
- Timeout support
- Resumable execution

### TransactionalAction

**Purpose**: Multi-step operations with rollback support

**Use when**: You need ACID guarantees or compensating transactions

**Examples**: Financial transactions, multi-database updates, distributed sagas

**Characteristics**:
- Implements undo/compensation logic
- Two-phase commit support
- Failure recovery

See [[02-Crates/nebula-action/Action Types|Action Types]] for detailed comparison.

## Action Composition

Actions are designed to be composed into workflows. Composition patterns include:

### Sequential Composition

Actions execute one after another:

```
Action A → Action B → Action C
```

Output of Action A becomes input of Action B.

### Parallel Composition

Actions execute concurrently:

```
       ┌─ Action B ─┐
Action A             Action D
       └─ Action C ─┘
```

Action B and C run in parallel after Action A completes.

### Conditional Composition

Actions execute based on conditions:

```
Action A → [if condition] → Action B
                         → [else] → Action C
```

Decision based on Action A's output.

### Error Handling Composition

Actions have fallback paths:

```
Action A → [success] → Action B
        → [error] → Action C (error handler)
```

Error path executes different logic.

### Loop Composition

Actions repeat until condition met:

```
Action A → [while condition] → Action B → Action A
        → [done] → Action C
```

Iterative processing pattern.

See [[Workflows]] for workflow composition patterns.

## Action Context

Every action receives a **Context** object that provides:

### Logging

Actions log events with automatic context:

```rust
context.log_info("Processing started");
context.log_error("Failed to connect", &error);
```

Logs include: workflow ID, action ID, trace ID, timestamp

### Metrics

Actions record metrics:

```rust
context.record_metric("requests", 1);
context.record_duration("processing_time", duration);
```

Metrics automatically aggregated and exported.

### Credentials

Actions access credentials securely:

```rust
let api_key = context.get_credential("github_token").await?;
```

Credentials automatically redacted from logs.

### Memory

Actions share data via workflow memory:

```rust
context.memory().set("user_id", user.id).await?;
let user_id = context.memory().get("user_id").await?;
```

Memory is scoped to workflow execution.

### Events

Actions publish and subscribe to events:

```rust
context.publish_event("user.created", &user_data).await?;
```

Enable event-driven workflows.

### Cancellation

Actions respect cancellation signals:

```rust
if context.is_cancelled() {
    return Err(ActionError::cancelled());
}
```

Graceful shutdown on workflow cancellation.

See [[02-Crates/nebula-action/README|nebula-action]] for Context API details.

## When to Create a Custom Action

Create a custom action when you need:

✅ **Reusable logic** — Same operation used in multiple workflows
✅ **Type safety** — Compile-time validation of inputs/outputs
✅ **Testability** — Logic that needs isolated testing
✅ **Observability** — Operation that needs logging, metrics, tracing
✅ **Error handling** — Complex error scenarios with retry logic
✅ **Integration** — External system integration (API, database, queue)

**Don't create an action for**:

❌ **One-off logic** — Use inline expressions or scripts
❌ **Simple transformations** — Use expression language
❌ **Configuration** — Use parameters instead

## Action vs. Function

| Aspect | Action | Regular Function |
|--------|--------|------------------|
| **Purpose** | Workflow building block | Code reuse |
| **Type safety** | Input/output schemas | Function signature |
| **Observability** | Built-in logging, metrics | Manual instrumentation |
| **Error handling** | Rich error types, retries | Result<T, E> |
| **Testing** | Mock context, test utilities | Standard unit tests |
| **Composition** | Workflow orchestration | Function calls |
| **Reusability** | Across workflows | Within codebase |
| **Versioning** | Explicit version tracking | Implicit (git) |

**Rule of thumb**: If it's part of a workflow and needs observability, make it an action. If it's internal logic, keep it a function.

## Common Patterns

### Retry Pattern

Actions can specify retry policies for transient failures:

- **Exponential backoff** — Wait longer between retries
- **Max retries** — Limit retry attempts
- **Retry conditions** — Only retry specific errors

### Circuit Breaker Pattern

Actions can fail fast when external services are down:

- **Open circuit** — Stop calling failing service
- **Half-open** — Test if service recovered
- **Closed circuit** — Normal operation

### Bulkhead Pattern

Actions can limit concurrent executions:

- **Concurrency limits** — Max parallel executions
- **Queue depth** — Max pending requests
- **Timeout** — Max execution time

### Idempotency Pattern

Actions can be safely retried:

- **Idempotency keys** — Detect duplicate requests
- **State checking** — Skip if already completed
- **Side-effect tracking** — Prevent duplicate effects

See [[Creating Actions]] for implementation examples.

## Best Practices

### Design

- **Keep actions focused** — Single responsibility principle
- **Make inputs explicit** — No hidden dependencies
- **Design for testability** — Pure functions when possible
- **Handle all errors** — No silent failures

### Implementation

- **Use strong types** — Leverage Rust's type system
- **Log at key points** — Start, decisions, completion
- **Add metrics** — Track performance and errors
- **Respect cancellation** — Check `context.is_cancelled()`

### Testing

- **Test happy path** — Normal execution
- **Test error cases** — All error scenarios
- **Test edge cases** — Boundary conditions
- **Test cancellation** — Graceful shutdown

### Documentation

- **Document purpose** — What does the action do?
- **Document inputs** — What data is required?
- **Document outputs** — What data is produced?
- **Document errors** — What can go wrong?

## Related Concepts

- [[Workflows]] — How actions are composed into workflows
- [[Error Handling]] — How actions handle and propagate errors
- [[Credentials]] — How actions access secure credentials
- [[Expression System]] — How actions use runtime expressions
- [[Event System]] — How actions communicate via events

## Implementation Guides

- [[Creating Actions]] — Step-by-step guide to building actions
- [[02-Crates/nebula-action/README|nebula-action]] — Action framework reference
- [[02-Crates/nebula-action/Action Types|Action Types]] — Detailed type comparison
- [[02-Crates/nebula-action/Examples|Examples]] — Real-world action implementations

---

**Next**: Understand [[Workflows]] or start [[Creating Actions]].
