---
title: Building Workflows
tags: [nebula, docs, development]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Building Workflows

**Compose actions into powerful workflows with sequential, parallel, and conditional execution.** This guide walks you through building production-ready workflows with proper error handling, testing, and observability.

## Prerequisites

Before building workflows, you should have:

- **Rust** 1.70+ installed
- **Understanding of Actions** — Read [[Creating Actions]] first
- **At least one action** — Either built yourself or from the library
- **Basic async Rust knowledge** — Familiarity with `async`/`await`

Verify you have the dependencies:

```toml
[dependencies]
nebula-workflow = "0.1"
nebula-action = "0.1"
nebula-core = "0.1"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1.0", features = ["full"] }
anyhow = "1.0"

[dev-dependencies]
tokio-test = "0.4"
```

## What is a Workflow?

A workflow is a **directed acyclic graph (DAG)** of actions that:

- **Defines execution order** — Which actions run when
- **Passes data between actions** — Output of one becomes input of another
- **Handles errors gracefully** — Retries, fallbacks, compensation
- **Manages state** — Shared memory for intermediate data
- **Provides observability** — Logs, metrics, traces

Think of a workflow as a **blueprint for automation** that orchestrates multiple actions.

## Your First Workflow

Let's create a simple workflow that greets a user and logs the result.

### Step 1: Define Your Actions

First, create two simple actions (or use existing ones):

```rust
use nebula_action::prelude::*;
use serde::{Deserialize, Serialize};

// Action 1: Greet user
#[derive(Debug, Deserialize)]
pub struct GreetInput {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct GreetOutput {
    pub message: String,
}

pub struct GreetAction;

impl Action for GreetAction {
    type Input = GreetInput;
    type Output = GreetOutput;

    fn id(&self) -> &str { "greet" }
    fn name(&self) -> &str { "Greet User" }
    fn description(&self) -> &str { "Generate greeting message" }

    async fn execute(
        &self,
        input: Self::Input,
        context: &Context,
    ) -> Result<Self::Output, ActionError> {
        let message = format!("Hello, {}!", input.name);
        context.log_info(&format!("Generated: {}", message));
        Ok(GreetOutput { message })
    }
}

// Action 2: Log message
#[derive(Debug, Deserialize)]
pub struct LogInput {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct LogOutput {
    pub logged: bool,
}

pub struct LogAction;

impl Action for LogAction {
    type Input = LogInput;
    type Output = LogOutput;

    fn id(&self) -> &str { "log" }
    fn name(&self) -> &str { "Log Message" }
    fn description(&self) -> &str { "Log a message" }

    async fn execute(
        &self,
        input: Self::Input,
        context: &Context,
    ) -> Result<Self::Output, ActionError> {
        context.log_info(&format!("MESSAGE: {}", input.message));
        Ok(LogOutput { logged: true })
    }
}
```

### Step 2: Build the Workflow

Use `WorkflowBuilder` to compose actions:

```rust
use nebula_workflow::prelude::*;
use serde_json::json;

async fn create_greeting_workflow() -> Result<Workflow, WorkflowError> {
    let workflow = WorkflowBuilder::new("greeting_workflow")
        .description("Greet user and log the message")

        // Add first node: greet the user
        .add_node("greet_user", GreetAction)

        // Add second node: log the greeting
        .add_node("log_greeting", LogAction)

        // Connect nodes: greet_user → log_greeting
        .add_edge("greet_user", "log_greeting", |greet_output| {
            // Map GreetOutput to LogInput
            json!({
                "message": greet_output["message"]
            })
        })

        .build()?;

    Ok(workflow)
}
```

### Step 3: Execute the Workflow

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create workflow
    let workflow = create_greeting_workflow().await?;

    // Define input parameters
    let params = json!({
        "name": "Alice"
    });

    // Execute workflow
    let result = workflow.execute(params).await?;

    println!("Workflow completed: {:?}", result);

    Ok(())
}
```

**Output**:
```
[INFO] Generated: Hello, Alice!
[INFO] MESSAGE: Hello, Alice!
Workflow completed: { "logged": true }
```

## Workflow Execution Patterns

### Sequential Execution

Actions run one after another:

```rust
let workflow = WorkflowBuilder::new("sequential_workflow")
    .add_node("step_1", FetchDataAction)
    .add_node("step_2", ValidateDataAction)
    .add_node("step_3", TransformDataAction)
    .add_node("step_4", StoreDataAction)

    // Chain them together
    .add_edge("step_1", "step_2", |output| output)
    .add_edge("step_2", "step_3", |output| output)
    .add_edge("step_3", "step_4", |output| output)

    .build()?;
```

**When to use**: Each step depends on the previous step's output.

### Parallel Execution

Actions run concurrently:

```rust
let workflow = WorkflowBuilder::new("parallel_workflow")
    .add_node("fetch_data", FetchDataAction)

    // These three run in parallel after fetch_data
    .add_node("send_email", SendEmailAction)
    .add_node("send_sms", SendSMSAction)
    .add_node("send_slack", SendSlackAction)

    // All three depend on fetch_data
    .add_edge("fetch_data", "send_email", |output| {
        json!({ "email": output["user"]["email"] })
    })
    .add_edge("fetch_data", "send_sms", |output| {
        json!({ "phone": output["user"]["phone"] })
    })
    .add_edge("fetch_data", "send_slack", |output| {
        json!({ "user_id": output["user"]["id"] })
    })

    // Aggregate results
    .add_node("aggregate", AggregateResultsAction)
    .add_edge("send_email", "aggregate", |output| output)
    .add_edge("send_sms", "aggregate", |output| output)
    .add_edge("send_slack", "aggregate", |output| output)

    .build()?;
```

**When to use**: Steps are independent and can run simultaneously.

### Conditional Execution

Actions run based on conditions:

```rust
let workflow = WorkflowBuilder::new("conditional_workflow")
    .add_node("check_payment", CheckPaymentAction)

    // Conditional branches
    .add_node("process_approved", ProcessApprovedAction)
    .add_node("process_declined", ProcessDeclinedAction)

    // Add conditional edges
    .add_edge_conditional(
        "check_payment",
        "process_approved",
        |output| output["status"] == "approved",
        |output| output
    )
    .add_edge_conditional(
        "check_payment",
        "process_declined",
        |output| output["status"] == "declined",
        |output| output
    )

    .build()?;
```

**When to use**: Execution path depends on data or business logic.

### Loop Execution

Actions repeat until a condition is met:

```rust
let workflow = WorkflowBuilder::new("loop_workflow")
    .add_node("fetch_page", FetchPageAction)
    .add_node("process_items", ProcessItemsAction)

    // Loop back if there are more pages
    .add_edge("fetch_page", "process_items", |output| output)
    .add_edge_conditional(
        "process_items",
        "fetch_page",
        |output| output["has_next_page"] == true,
        |output| json!({ "page": output["next_page"] })
    )

    .build()?;
```

**When to use**: Processing paginated data or iterating until completion.

## Data Flow Between Nodes

### Using Edge Transformers

Edge transformers map one action's output to another's input:

```rust
.add_edge("node_a", "node_b", |output| {
    // Transform NodeA output to NodeB input
    json!({
        "user_id": output["id"],
        "email": output["contact"]["email"]
    })
})
```

### Using Workflow Memory

Share data across multiple nodes:

```rust
// In first action
async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    let user_id = fetch_user().await?;

    // Store in workflow memory
    context.memory().set("user_id", user_id).await?;

    Ok(output)
}

// In second action (later in workflow)
async fn execute(
    &self,
    input: Self::Input,
    context: &Context,
) -> Result<Self::Output, ActionError> {
    // Retrieve from workflow memory
    let user_id: u64 = context.memory().get("user_id").await?;

    // Use the user_id...
    Ok(output)
}
```

### Using Workflow Parameters

Pass parameters when starting the workflow:

```rust
// Define workflow with parameter access
.add_node("fetch_user", FetchUserAction)
.add_edge_from_start("fetch_user", |params| {
    json!({
        "user_id": params["user_id"],
        "include_details": params.get("details").unwrap_or(&json!(false))
    })
})

// Execute with parameters
let result = workflow.execute(json!({
    "user_id": 123,
    "details": true
})).await?;
```

## Error Handling

### Retry Failed Actions

Configure automatic retries for transient failures:

```rust
let workflow = WorkflowBuilder::new("retry_workflow")
    .add_node("fetch_api", FetchAPIAction)
    .configure_node("fetch_api", |config| {
        config
            .max_retries(3)
            .backoff_strategy(BackoffStrategy::Exponential {
                initial_delay: Duration::from_secs(1),
                max_delay: Duration::from_secs(30),
                multiplier: 2.0,
            })
            .retry_on(|error| {
                // Only retry transient errors
                matches!(error, ActionError::Transient(_))
            })
    })
    .build()?;
```

### Fallback Actions

Execute alternative action on failure:

```rust
let workflow = WorkflowBuilder::new("fallback_workflow")
    .add_node("primary_api", PrimaryAPIAction)
    .add_node("fallback_api", FallbackAPIAction)
    .add_node("process_data", ProcessDataAction)

    // Normal path: primary_api → process_data
    .add_edge("primary_api", "process_data", |output| output)

    // Error path: primary_api fails → fallback_api → process_data
    .add_error_edge("primary_api", "fallback_api", |error| {
        json!({ "retry": true })
    })
    .add_edge("fallback_api", "process_data", |output| output)

    .build()?;
```

### Compensation (Saga Pattern)

Undo previous actions on failure:

```rust
let workflow = WorkflowBuilder::new("saga_workflow")
    .add_node("reserve_inventory", ReserveInventoryAction)
    .add_node("charge_payment", ChargePaymentAction)
    .add_node("ship_order", ShipOrderAction)

    // Compensation actions
    .add_node("release_inventory", ReleaseInventoryAction)
    .add_node("refund_payment", RefundPaymentAction)

    // Normal flow
    .add_edge("reserve_inventory", "charge_payment", |output| output)
    .add_edge("charge_payment", "ship_order", |output| output)

    // Compensation flow (if charge_payment fails)
    .add_error_edge("charge_payment", "release_inventory", |_| json!({}))

    // Compensation flow (if ship_order fails)
    .add_error_edge("ship_order", "refund_payment", |_| json!({}))
    .add_edge("refund_payment", "release_inventory", |_| json!({}))

    .build()?;
```

## Testing Workflows

### Unit Test: Happy Path

Test normal workflow execution:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_greeting_workflow_success() {
        let workflow = create_greeting_workflow().await.unwrap();

        let result = workflow.execute(json!({
            "name": "Bob"
        })).await;

        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output["logged"], true);
    }
}
```

### Unit Test: Error Path

Test error handling:

```rust
#[tokio::test]
async fn test_workflow_handles_invalid_input() {
    let workflow = create_greeting_workflow().await.unwrap();

    let result = workflow.execute(json!({
        "name": ""  // Empty name should fail validation
    })).await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        WorkflowError::ActionFailed { .. }
    ));
}
```

### Integration Test: With Mock Actions

Test workflow logic without external dependencies:

```rust
use nebula_workflow::testing::*;

#[tokio::test]
async fn test_workflow_with_mocks() {
    let mut mock_registry = MockActionRegistry::new();

    // Register mock actions
    mock_registry.register_mock("fetch_user", |input| {
        Ok(json!({
            "user_id": 123,
            "email": "test@example.com"
        }))
    });

    mock_registry.register_mock("send_email", |input| {
        Ok(json!({ "sent": true }))
    });

    let workflow = WorkflowBuilder::new("test_workflow")
        .with_registry(mock_registry)
        .add_node("fetch_user", "fetch_user")
        .add_node("send_email", "send_email")
        .add_edge("fetch_user", "send_email", |output| {
            json!({ "to": output["email"] })
        })
        .build()
        .unwrap();

    let result = workflow.execute(json!({})).await.unwrap();
    assert_eq!(result["sent"], true);
}
```

### Test Parallel Execution

Verify nodes run in parallel:

```rust
#[tokio::test]
async fn test_parallel_execution_performance() {
    use std::time::Instant;

    let workflow = WorkflowBuilder::new("parallel_test")
        .add_node("slow_1", SlowAction::new(Duration::from_secs(2)))
        .add_node("slow_2", SlowAction::new(Duration::from_secs(2)))
        .add_node("slow_3", SlowAction::new(Duration::from_secs(2)))

        // All three depend on start (run in parallel)
        .build()
        .unwrap();

    let start = Instant::now();
    let result = workflow.execute(json!({})).await;
    let duration = start.elapsed();

    assert!(result.is_ok());

    // If parallel, should take ~2s, not ~6s
    assert!(duration < Duration::from_secs(3));
}
```

## Advanced Patterns

### Fan-Out / Fan-In

Process multiple items in parallel, then aggregate:

```rust
let workflow = WorkflowBuilder::new("fanout_fanin")
    .add_node("fetch_items", FetchItemsAction)

    // Map: Process each item in parallel
    .add_map_node("process_item", ProcessItemAction, |items| {
        items["items"].as_array().unwrap().clone()
    })

    // Reduce: Aggregate results
    .add_node("aggregate", AggregateAction)
    .add_edge("process_item", "aggregate", |outputs| {
        json!({ "results": outputs })
    })

    .build()?;
```

### Circuit Breaker

Stop calling failing service:

```rust
let workflow = WorkflowBuilder::new("circuit_breaker_workflow")
    .add_node("external_service", ExternalServiceAction)
    .configure_node("external_service", |config| {
        config.circuit_breaker(CircuitBreakerConfig {
            failure_threshold: 5,
            timeout: Duration::from_secs(60),
            half_open_requests: 1,
        })
    })
    .build()?;
```

### Timeout

Prevent workflows from running forever:

```rust
let workflow = WorkflowBuilder::new("timeout_workflow")
    .add_node("long_running", LongRunningAction)
    .configure_node("long_running", |config| {
        config.timeout(Duration::from_secs(30))
    })
    .build()?;
```

### Subworkflows

Break complex workflows into smaller, reusable pieces:

```rust
// Define subworkflow
async fn create_user_onboarding_workflow() -> Result<Workflow, WorkflowError> {
    WorkflowBuilder::new("user_onboarding")
        .add_node("send_welcome_email", SendEmailAction)
        .add_node("create_profile", CreateProfileAction)
        .add_edge("send_welcome_email", "create_profile", |o| o)
        .build()
}

// Use in main workflow
let main_workflow = WorkflowBuilder::new("main_workflow")
    .add_node("register_user", RegisterUserAction)

    // Embed subworkflow
    .add_subworkflow("onboard_user", create_user_onboarding_workflow().await?)

    .add_edge("register_user", "onboard_user", |output| output)
    .build()?;
```

## Real-World Example: Order Processing

Complete workflow with error handling, retries, and compensation:

```rust
async fn create_order_processing_workflow() -> Result<Workflow, WorkflowError> {
    WorkflowBuilder::new("order_processing")
        .description("Process customer orders with inventory, payment, and shipping")

        // Step 1: Validate order
        .add_node("validate_order", ValidateOrderAction)

        // Step 2: Reserve inventory
        .add_node("reserve_inventory", ReserveInventoryAction)
        .configure_node("reserve_inventory", |config| {
            config
                .max_retries(3)
                .timeout(Duration::from_secs(10))
        })

        // Step 3: Charge payment
        .add_node("charge_payment", ChargePaymentAction)
        .configure_node("charge_payment", |config| {
            config
                .max_retries(2)
                .timeout(Duration::from_secs(30))
        })

        // Step 4: Ship order (parallel tasks)
        .add_node("create_shipping_label", CreateShippingLabelAction)
        .add_node("send_confirmation_email", SendEmailAction)
        .add_node("update_crm", UpdateCRMAction)

        // Compensation actions
        .add_node("release_inventory", ReleaseInventoryAction)
        .add_node("refund_payment", RefundPaymentAction)
        .add_node("notify_customer_failure", NotifyCustomerAction)

        // Normal flow
        .add_edge("validate_order", "reserve_inventory", |o| o)
        .add_edge("reserve_inventory", "charge_payment", |o| o)
        .add_edge("charge_payment", "create_shipping_label", |o| o)
        .add_edge("charge_payment", "send_confirmation_email", |o| o)
        .add_edge("charge_payment", "update_crm", |o| o)

        // Error handling: charge_payment fails → refund
        .add_error_edge("charge_payment", "release_inventory", |_| json!({}))
        .add_edge("release_inventory", "notify_customer_failure", |_| {
            json!({ "reason": "Payment failed" })
        })

        // Error handling: create_shipping_label fails → compensate
        .add_error_edge("create_shipping_label", "refund_payment", |_| json!({}))
        .add_edge("refund_payment", "release_inventory", |_| json!({}))
        .add_edge("release_inventory", "notify_customer_failure", |_| {
            json!({ "reason": "Shipping failed" })
        })

        .build()
}
```

## Best Practices

### Design

- ✅ **Keep workflows focused** — One clear purpose per workflow
- ✅ **Limit complexity** — Max 10-15 nodes per workflow
- ✅ **Use subworkflows** — Break complex workflows into smaller ones
- ✅ **Name nodes clearly** — Descriptive IDs (`fetch_user`, not `node_1`)
- ✅ **Document data flow** — Comment edge transformations

### Error Handling

- ✅ **Handle all errors** — Every node should have error path
- ✅ **Use retries wisely** — Only for transient errors
- ✅ **Add compensation** — Undo actions in distributed transactions
- ✅ **Set timeouts** — Prevent hung workflows
- ✅ **Log failures** — Capture context for debugging

### Performance

- ✅ **Parallelize when possible** — Independent nodes run concurrently
- ✅ **Avoid tight loops** — Add delays in polling loops
- ✅ **Use connection pooling** — Reuse HTTP clients, DB connections
- ✅ **Monitor execution time** — Track and optimize slow workflows
- ✅ **Limit fan-out** — Too many parallel tasks can overwhelm systems

### Testing

- ✅ **Test happy path** — Normal execution flow
- ✅ **Test error paths** — All error scenarios
- ✅ **Test edge cases** — Boundary conditions
- ✅ **Test with mocks** — Isolate workflow logic
- ✅ **Test parallel execution** — Verify concurrency works

### Observability

- ✅ **Add logging** — Log key decisions and transitions
- ✅ **Track metrics** — Duration, success rate, throughput
- ✅ **Use tracing** — Distributed tracing for complex workflows
- ✅ **Dashboard workflows** — Monitor critical workflows
- ✅ **Alert on failures** — Notify on-call for important workflows

## Common Pitfalls

### ❌ Don't: Create cyclic dependencies

```rust
// BAD - creates infinite loop
.add_edge("node_a", "node_b", |o| o)
.add_edge("node_b", "node_a", |o| o)  // Cycle!
```

**Solution**: Use conditional edges for loops:

```rust
// GOOD - controlled loop
.add_edge("node_a", "node_b", |o| o)
.add_edge_conditional(
    "node_b",
    "node_a",
    |o| o["continue"] == true,  // Exit condition
    |o| o
)
```

### ❌ Don't: Ignore data type mismatches

```rust
// BAD - action expects different type
.add_edge("fetch_user", "send_email", |output| {
    output  // SendEmail expects { "to": "..." }, not entire user object
})
```

**Solution**: Transform data explicitly:

```rust
// GOOD - explicit transformation
.add_edge("fetch_user", "send_email", |output| {
    json!({ "to": output["email"] })
})
```

### ❌ Don't: Forget error handling

```rust
// BAD - no error handling
.add_node("charge_payment", ChargePaymentAction)
// What happens if payment fails?
```

**Solution**: Add error edges:

```rust
// GOOD - explicit error handling
.add_node("charge_payment", ChargePaymentAction)
.add_error_edge("charge_payment", "refund", |error| {
    json!({ "reason": error.to_string() })
})
```

### ❌ Don't: Use blocking code in actions

```rust
// BAD - blocks async runtime
async fn execute(...) -> Result<...> {
    std::thread::sleep(Duration::from_secs(5));  // Blocks!
    Ok(output)
}
```

**Solution**: Use async sleep:

```rust
// GOOD - async sleep
async fn execute(...) -> Result<...> {
    tokio::time::sleep(Duration::from_secs(5)).await;
    Ok(output)
}
```

### ❌ Don't: Share mutable state between actions

```rust
// BAD - mutable state not safe
static mut COUNTER: u32 = 0;

async fn execute(...) -> Result<...> {
    unsafe { COUNTER += 1; }  // Race condition!
    Ok(output)
}
```

**Solution**: Use workflow memory or stateful actions:

```rust
// GOOD - use workflow memory
async fn execute(..., context: &Context) -> Result<...> {
    let count: u32 = context.memory().get("counter").await.unwrap_or(0);
    context.memory().set("counter", count + 1).await?;
    Ok(output)
}
```

## Workflow Triggers

### Manual Trigger

Start workflows via API or CLI:

```rust
let workflow = create_order_workflow().await?;

// Manual execution
let result = workflow.execute(json!({
    "order_id": 12345
})).await?;
```

### Scheduled Trigger

Run workflows on a schedule:

```rust
use nebula_workflow::triggers::ScheduledTrigger;

let trigger = ScheduledTrigger::new("0 2 * * *")  // Every day at 2 AM
    .with_workflow(create_daily_report_workflow().await?);

trigger.start().await?;
```

### Event-Based Trigger

Start workflows from events:

```rust
use nebula_workflow::triggers::EventTrigger;

let trigger = EventTrigger::new("order.created")
    .with_workflow(create_order_workflow().await?);

trigger.start().await?;
```

### Webhook Trigger

HTTP endpoint that starts workflows:

```rust
use nebula_workflow::triggers::WebhookTrigger;

let trigger = WebhookTrigger::new("/api/webhooks/github")
    .with_workflow(create_github_workflow().await?);

trigger.start().await?;
```

## Debugging Workflows

### Enable Detailed Logging

```rust
// Set log level
std::env::set_var("RUST_LOG", "nebula_workflow=debug");

let workflow = WorkflowBuilder::new("debug_workflow")
    .enable_debug_logging(true)
    .build()?;
```

### Inspect Workflow State

```rust
// Get execution status
let execution = workflow.execute(params).await?;

// View execution graph
println!("Execution ID: {}", execution.id);
println!("Status: {:?}", execution.status);
println!("Duration: {:?}", execution.duration);

// View node states
for node in execution.nodes {
    println!("Node {}: {:?}", node.id, node.status);
}
```

### Replay Failed Workflows

```rust
// Get failed execution
let execution_id = "exec_123";
let execution = workflow_engine.get_execution(execution_id).await?;

// Retry from failure point
let result = workflow_engine.retry_execution(execution_id).await?;
```

## Next Steps

Now that you can build workflows, explore:

1. **[[03-Concepts/Workflows|Workflow Concepts]]** — Deep dive into workflow theory
2. **[[02-Crates/nebula-workflow/README|nebula-workflow]]** — Full API reference
3. **[[Testing Guide]]** — Advanced testing strategies
4. **[[06-Examples/_Index|Workflow Examples]]** — Real-world patterns
5. **[[Deployment Guide]]** — Running workflows in production
6. **[[Best Practices]]** — Production-ready patterns

## Troubleshooting

### Workflow Build Errors

**Error: Node not found**
- Ensure node IDs in edges match exactly
- Check for typos in node names

**Error: Cyclic dependency detected**
- Use conditional edges for loops
- Draw workflow graph to visualize dependencies

### Runtime Errors

**Error: Type mismatch in edge transformation**
- Verify edge transformer output matches next action's input type
- Add explicit type annotations in edge transformers

**Error: Workflow timeout**
- Increase node timeout configurations
- Check for infinite loops
- Review long-running actions

**Error: Deadlock detected**
- Ensure no circular waits in parallel execution
- Review conditional edges for exit conditions

### Performance Issues

**Workflow runs slowly**
- Identify bottlenecks with metrics
- Parallelize independent nodes
- Use connection pooling
- Add caching where appropriate

**High memory usage**
- Limit fan-out degree
- Process large datasets in batches
- Clear workflow memory when done

## Resources

- [[03-Concepts/Workflows|Workflows Concept]]
- [[02-Crates/nebula-workflow/README|nebula-workflow Documentation]]
- [[Creating Actions|Action Development Guide]]
- [[Rust async book]](https://rust-lang.github.io/async-book/)

---

**Congratulations!** You can now build complex, production-ready workflows. Next: [[Deployment Guide]] to run workflows at scale.
