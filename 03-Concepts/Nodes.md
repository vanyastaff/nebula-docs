---
title: Nodes
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Nodes

**Nodes are the executable units within a workflow DAG that encapsulate actions and define data flow.** Each node represents a single step in the workflow's execution graph, with explicit inputs, outputs, and dependencies.

## Definition

In Nebula, a node is:

- **An action wrapper** — Wraps an Action with workflow-specific configuration
- **A DAG vertex** — Part of the directed acyclic graph structure
- **Uniquely identified** — Has unique ID within workflow
- **Explicitly connected** — Dependencies defined via edges
- **Independently executable** — Can run in parallel if dependencies allow
- **State-tracked** — Execution state monitored and persisted

Nodes are **not** the actions themselves. They're **workflow-specific instances** of actions with configuration and connections.

## Why Nodes Matter

### The Problem with Monolithic Workflows

Without nodes, workflows are rigid:

❌ **No reusability** — Same action can't be used multiple times
❌ **No parallelism** — All steps run sequentially
❌ **No conditional execution** — Can't skip steps based on conditions
❌ **Poor visibility** — Can't see which step is executing
❌ **Difficult debugging** — Can't replay individual steps
❌ **No composability** — Can't build complex flows from simple steps

**Real-world consequences**:
- Need same API call twice → duplicate code
- Independent steps run sequentially → slow workflows
- Can't skip optional steps → waste resources
- Workflow fails → must restart entire workflow

### The Nebula Approach

Nodes solve these problems:

✅ **Reusable actions** — Same action, multiple nodes
✅ **Parallel execution** — Independent nodes run concurrently
✅ **Conditional execution** — Nodes run only when needed
✅ **Clear visibility** — See status of each node
✅ **Granular control** — Retry/skip individual nodes
✅ **Composable workflows** — Build complex from simple

## Core Principles

### 1. Nodes are Action Instances

A node wraps an action with workflow-specific configuration:

```rust
// Define action once
pub struct FetchUserAction;

// Use in multiple nodes with different configurations
let workflow = WorkflowBuilder::new("my_workflow")
    // Node 1: Fetch current user
    .add_node("fetch_current_user", FetchUserAction)
    .configure_node("fetch_current_user", |config| {
        config
            .with_timeout(Duration::from_secs(5))
            .with_retry_policy(RetryPolicy::exponential())
    })

    // Node 2: Fetch admin user (same action, different config)
    .add_node("fetch_admin", FetchUserAction)
    .configure_node("fetch_admin", |config| {
        config
            .with_timeout(Duration::from_secs(10))  // Longer timeout
            .with_retry_policy(RetryPolicy::none())  // No retries
    })

    .build()?;
```

**Why?** Same action, different use cases.

### 2. Nodes are DAG Vertices

Nodes form a directed acyclic graph:

```
         ┌──────────┐
         │  Start   │
         └────┬─────┘
              │
         ┌────▼─────┐
         │ Node A   │
         │(Fetch)   │
         └────┬─────┘
              │
        ┌─────┴──────┐
        │            │
   ┌────▼─────┐ ┌───▼──────┐
   │ Node B   │ │ Node C   │
   │(Validate)│ │(Transform)│
   └────┬─────┘ └───┬──────┘
        │            │
        └─────┬──────┘
              │
         ┌────▼─────┐
         │ Node D   │
         │ (Store)  │
         └────┬─────┘
              │
         ┌────▼─────┐
         │   End    │
         └──────────┘
```

**Properties**:
- **Directed**: Edges have direction (A → B, not B → A)
- **Acyclic**: No cycles (A → B → A forbidden)
- **Connected**: All nodes reachable from start

### 3. Nodes Execute Independently

Each node has isolated execution context:

```rust
// Node A and Node B can execute in parallel
// because they have no dependencies between them
let workflow = WorkflowBuilder::new("parallel_workflow")
    .add_node("fetch_user", FetchUserAction)      // Node 1
    .add_node("fetch_settings", FetchSettingsAction)  // Node 2 (independent)

    // Both depend on start, run in parallel
    .build()?;

// Execution timeline:
// t=0:  Start
// t=1:  Node 1 (fetch_user) starts    | Node 2 (fetch_settings) starts
// t=2:  Node 1 continues               | Node 2 continues
// t=3:  Node 1 completes               | Node 2 completes
// t=4:  End
```

**Why?** Maximize parallelism for faster workflows.

### 4. Nodes Track State

Each node maintains execution state:

```rust
pub struct NodeExecution {
    pub node_id: String,
    pub state: NodeState,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration: Option<Duration>,
    pub retry_count: u32,
    pub error: Option<ActionError>,
}

pub enum NodeState {
    /// Not yet started (waiting for dependencies)
    Pending,

    /// Currently executing
    Running,

    /// Completed successfully
    Completed,

    /// Failed with error
    Failed,

    /// Skipped (condition not met)
    Skipped,

    /// Retrying after failure
    Retrying { attempt: u32 },

    /// Cancelled by user/system
    Cancelled,
}

// Query node state
let node_state = workflow_execution.get_node_state("fetch_user")?;
match node_state {
    NodeState::Running => println!("Node is currently executing"),
    NodeState::Failed => println!("Node failed: {:?}", node_execution.error),
    NodeState::Completed => println!("Node completed successfully"),
    _ => {}
}
```

**Why?** Visibility into workflow progress, debugging failed nodes.

### 5. Nodes are Configurable

Each node can override action defaults:

```rust
let workflow = WorkflowBuilder::new("configured_workflow")
    .add_node("fetch_api", FetchAPIAction)
    .configure_node("fetch_api", |config| {
        config
            // Override action timeout
            .with_timeout(Duration::from_secs(30))

            // Custom retry policy
            .with_retry_policy(
                RetryPolicy::exponential()
                    .max_retries(5)
                    .initial_delay(Duration::from_millis(100))
            )

            // Resource limits
            .with_memory_limit(256 * 1024 * 1024)  // 256 MB

            // Conditional execution
            .run_if(|context| {
                context.get_variable("enable_api_fetch")
                    .unwrap_or(&false)
                    == &true
            })

            // Success criteria
            .success_when(|output| {
                output["status"] == "success"
            })
    })
    .build()?;
```

**Why?** Workflow-specific behavior without modifying action.

## Node Structure

### Node Definition

```rust
pub struct Node {
    /// Unique node ID within workflow
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Optional description
    pub description: Option<String>,

    /// Action to execute
    pub action: Arc<dyn Action>,

    /// Node configuration
    pub config: NodeConfig,

    /// Dependencies (incoming edges)
    pub dependencies: Vec<String>,

    /// Dependents (outgoing edges)
    pub dependents: Vec<String>,

    /// Metadata (key-value pairs)
    pub metadata: HashMap<String, String>,
}

pub struct NodeConfig {
    /// Execution timeout
    pub timeout: Option<Duration>,

    /// Retry policy
    pub retry_policy: RetryPolicy,

    /// Memory limit
    pub memory_limit: Option<usize>,

    /// CPU limit (% of one core)
    pub cpu_limit: Option<f32>,

    /// Conditional execution predicate
    pub run_condition: Option<RunCondition>,

    /// Success criteria
    pub success_criteria: Option<SuccessCriteria>,

    /// On success callback
    pub on_success: Option<Box<dyn Fn(&Output) + Send + Sync>>,

    /// On failure callback
    pub on_failure: Option<Box<dyn Fn(&ActionError) + Send + Sync>>,
}
```

### Creating Nodes

```rust
// Simple node
let workflow = WorkflowBuilder::new("simple")
    .add_node("step1", MyAction)
    .build()?;

// Node with name and description
let workflow = WorkflowBuilder::new("documented")
    .add_node_with_name("step1", MyAction, "Fetch User Data")
    .add_node_description("step1", "Fetches user profile from database")
    .build()?;

// Node with full configuration
let workflow = WorkflowBuilder::new("configured")
    .add_node("step1", MyAction)
    .configure_node("step1", |config| {
        config
            .with_name("Fetch User Data")
            .with_description("Fetches user profile from database")
            .with_timeout(Duration::from_secs(10))
            .with_metadata("team", "backend")
            .with_metadata("priority", "high")
    })
    .build()?;
```

## Node Types

### Process Node

Standard synchronous/asynchronous action execution:

```rust
let workflow = WorkflowBuilder::new("process")
    .add_node("fetch", FetchDataAction)
    .add_node("process", ProcessDataAction)
    .add_node("store", StoreDataAction)

    .add_edge("fetch", "process", |o| o)
    .add_edge("process", "store", |o| o)

    .build()?;
```

**Use when**: Standard sequential or parallel processing.

### Conditional Node

Executes only if condition met:

```rust
let workflow = WorkflowBuilder::new("conditional")
    .add_node("check_user", CheckUserAction)

    .add_node("send_welcome", SendWelcomeEmailAction)
    .configure_node("send_welcome", |config| {
        config.run_if(|context| {
            // Only run if user is new
            context.get_node_output::<bool>("check_user", "is_new_user")
                .unwrap_or(false)
        })
    })

    .add_edge("check_user", "send_welcome", |o| o)

    .build()?;

// If check_user returns is_new_user = false,
// send_welcome is skipped (NodeState::Skipped)
```

**Use when**: Optional steps based on runtime conditions.

### Fan-Out Node

Spawns multiple parallel executions:

```rust
let workflow = WorkflowBuilder::new("fanout")
    .add_node("fetch_users", FetchUsersAction)

    // Fan-out: Process each user in parallel
    .add_fanout_node("process_user", ProcessUserAction)
    .configure_node("process_user", |config| {
        config.fanout_on(|context| {
            // Return array of items to process
            context.get_node_output::<Vec<User>>("fetch_users", "users")
                .unwrap_or_default()
        })
    })

    .add_edge("fetch_users", "process_user", |o| o)

    .build()?;

// If fetch_users returns 10 users,
// 10 parallel instances of process_user execute
```

**Use when**: Processing collections in parallel (batch operations).

### Fork/Join Node

Executes multiple nodes, waits for all to complete:

```rust
let workflow = WorkflowBuilder::new("fork_join")
    .add_node("fetch_data", FetchDataAction)

    // Fork: Three parallel operations
    .add_node("send_email", SendEmailAction)
    .add_node("send_sms", SendSMSAction)
    .add_node("send_push", SendPushAction)

    // All three depend on fetch_data (fork)
    .add_edge("fetch_data", "send_email", |o| o)
    .add_edge("fetch_data", "send_sms", |o| o)
    .add_edge("fetch_data", "send_push", |o| o)

    // Join: Aggregate results
    .add_node("aggregate", AggregateResultsAction)
    .add_edge("send_email", "aggregate", |o| o)
    .add_edge("send_sms", "aggregate", |o| o)
    .add_edge("send_push", "aggregate", |o| o)

    .build()?;

// aggregate waits for all three to complete
```

**Use when**: Parallel operations with aggregation.

### Subworkflow Node

Embeds another workflow as a node:

```rust
// Define reusable subworkflow
let user_onboarding = WorkflowBuilder::new("user_onboarding")
    .add_node("create_profile", CreateProfileAction)
    .add_node("send_welcome", SendWelcomeAction)
    .add_edge("create_profile", "send_welcome", |o| o)
    .build()?;

// Use as node in main workflow
let main_workflow = WorkflowBuilder::new("main")
    .add_node("register_user", RegisterUserAction)

    .add_subworkflow_node("onboard", user_onboarding)

    .add_edge("register_user", "onboard", |o| o)

    .build()?;
```

**Use when**: Reusing workflows, managing complexity.

## Node Lifecycle

### Lifecycle Phases

```
1. CREATED
   ↓
2. PENDING (waiting for dependencies)
   ↓
3. READY (dependencies satisfied)
   ↓
4. RUNNING (executing action)
   ↓
   ├─→ 5a. COMPLETED (success)
   ├─→ 5b. FAILED (error)
   │    ↓
   │    └─→ RETRYING (if retry policy allows)
   │         ↓
   │         └─→ back to RUNNING
   └─→ 5c. SKIPPED (condition not met)
```

### Lifecycle Hooks

```rust
let workflow = WorkflowBuilder::new("lifecycle_hooks")
    .add_node("my_node", MyAction)
    .configure_node("my_node", |config| {
        config
            // Before node starts
            .on_before_start(|context| {
                context.log_info("Node starting...");
            })

            // After node completes successfully
            .on_success(|output| {
                println!("Node succeeded with output: {:?}", output);
            })

            // After node fails
            .on_failure(|error| {
                eprintln!("Node failed: {}", error);
            })

            // After node completes (success or failure)
            .on_complete(|result| {
                match result {
                    Ok(output) => println!("Completed successfully"),
                    Err(error) => eprintln!("Completed with error"),
                }
            })

            // After node is skipped
            .on_skip(|reason| {
                println!("Node skipped: {}", reason);
            })
    })
    .build()?;
```

## Node Dependencies

### Defining Dependencies

Dependencies defined via edges:

```rust
let workflow = WorkflowBuilder::new("dependencies")
    .add_node("A", ActionA)
    .add_node("B", ActionB)
    .add_node("C", ActionC)
    .add_node("D", ActionD)

    // A must complete before B
    .add_edge("A", "B", |o| o)

    // A must complete before C
    .add_edge("A", "C", |o| o)

    // Both B and C must complete before D
    .add_edge("B", "D", |o| o)
    .add_edge("C", "D", |o| o)

    .build()?;

// Execution order:
// 1. A runs first
// 2. B and C run in parallel (both depend only on A)
// 3. D runs last (waits for both B and C)
```

### Data Dependencies

Data flows through edges:

```rust
let workflow = WorkflowBuilder::new("data_flow")
    .add_node("fetch_user", FetchUserAction)
    .add_node("send_email", SendEmailAction)

    // Pass user email to send_email node
    .add_edge("fetch_user", "send_email", |user_output| {
        json!({
            "to": user_output["email"],
            "subject": "Welcome!"
        })
    })

    .build()?;
```

### Optional Dependencies

Some dependencies can be optional:

```rust
let workflow = WorkflowBuilder::new("optional_deps")
    .add_node("fetch_user", FetchUserAction)
    .add_node("fetch_preferences", FetchPreferencesAction)
    .add_node("send_email", SendEmailAction)

    // Required dependency
    .add_edge("fetch_user", "send_email", |o| o)

    // Optional dependency (may fail, but send_email still runs)
    .add_optional_edge("fetch_preferences", "send_email", |o| o)

    .build()?;

// If fetch_preferences fails, send_email still executes
// (with default preferences)
```

## Conditional Execution

### Run Conditions

Nodes can have execution conditions:

```rust
let workflow = WorkflowBuilder::new("conditional")
    .add_node("check_balance", CheckBalanceAction)
    .add_node("process_payment", ProcessPaymentAction)
    .add_node("insufficient_funds", InsufficientFundsAction)

    // Process payment only if balance sufficient
    .configure_node("process_payment", |config| {
        config.run_if(|context| {
            let balance = context.get_node_output::<f64>("check_balance", "balance")?;
            let amount = context.get_workflow_param::<f64>("amount")?;
            Ok(balance >= amount)
        })
    })

    // Insufficient funds handler runs if payment skipped
    .configure_node("insufficient_funds", |config| {
        config.run_if(|context| {
            context.get_node_state("process_payment")? == NodeState::Skipped
        })
    })

    .build()?;
```

### Conditional Edges

Edges can be conditional:

```rust
let workflow = WorkflowBuilder::new("conditional_edges")
    .add_node("check_payment", CheckPaymentAction)
    .add_node("approved", ApprovedAction)
    .add_node("declined", DeclinedAction)

    // Edge to approved (if status == "approved")
    .add_edge_conditional(
        "check_payment",
        "approved",
        |output| output["status"] == "approved",
        |output| output
    )

    // Edge to declined (if status == "declined")
    .add_edge_conditional(
        "check_payment",
        "declined",
        |output| output["status"] == "declined",
        |output| output
    )

    .build()?;
```

## Parallel Execution

### Automatic Parallelism

Nebula automatically parallelizes independent nodes:

```rust
let workflow = WorkflowBuilder::new("auto_parallel")
    .add_node("start", StartAction)

    // These four nodes have no dependencies between them
    // They all depend only on "start", so they run in parallel
    .add_node("task1", Task1Action)
    .add_node("task2", Task2Action)
    .add_node("task3", Task3Action)
    .add_node("task4", Task4Action)

    .add_edge("start", "task1", |o| o)
    .add_edge("start", "task2", |o| o)
    .add_edge("start", "task3", |o| o)
    .add_edge("start", "task4", |o| o)

    .build()?;

// Execution: All four tasks execute concurrently
```

### Concurrency Limits

Limit concurrent node execution:

```rust
let workflow = WorkflowBuilder::new("concurrency_limited")
    .with_max_concurrent_nodes(3)  // Max 3 nodes at once

    .add_node("task1", TaskAction)
    .add_node("task2", TaskAction)
    .add_node("task3", TaskAction)
    .add_node("task4", TaskAction)
    .add_node("task5", TaskAction)

    .build()?;

// Even though all 5 tasks can run in parallel,
// only 3 execute at a time (resource protection)
```

## Best Practices

### Node Design

- ✅ **Use descriptive IDs** — `fetch_user_profile` not `node1`
- ✅ **Single responsibility** — One clear purpose per node
- ✅ **Idempotent actions** — Safe to retry
- ✅ **Configure timeouts** — Prevent hung nodes
- ✅ **Handle failures** — Define error edges
- ❌ **Don't create monolithic nodes** — Break into smaller nodes
- ❌ **Don't hardcode data** — Use workflow parameters
- ❌ **Don't ignore state** — Check node state before proceeding

### Dependencies

- ✅ **Minimize dependencies** — Enable more parallelism
- ✅ **Explicit dependencies** — Clear data flow
- ✅ **Avoid long chains** — Parallelize when possible
- ✅ **Document dependencies** — Why does B depend on A?
- ❌ **Don't create unnecessary deps** — Reduces parallelism
- ❌ **Don't create circular deps** — DAG must be acyclic

### Configuration

- ✅ **Set appropriate timeouts** — Based on expected duration
- ✅ **Configure retry policies** — Match error characteristics
- ✅ **Use resource limits** — Prevent resource exhaustion
- ✅ **Add metadata** — Team, priority, SLA
- ❌ **Don't use infinite timeouts** — Workflows can hang
- ❌ **Don't retry everything** — Some errors permanent

### Monitoring

- ✅ **Log node transitions** — Track state changes
- ✅ **Record metrics** — Duration, success rate
- ✅ **Alert on failures** — Critical node failures
- ✅ **Track retry counts** — High retries indicate issues
- ❌ **Don't ignore skipped nodes** — May indicate logic errors

## Related Concepts

- [[Workflows]] — How nodes compose into workflows
- [[Actions]] — What nodes execute
- [[Error Handling]] — How nodes handle failures
- [[Expression System]] — Node conditional logic

## Implementation Guides

- [[Building Workflows#Nodes]] — Creating and configuring nodes
- [[02-Crates/nebula-workflow/README|nebula-workflow]] — Workflow and node API
- [[02-Crates/nebula-node/README|nebula-node]] — Node system reference

---

**Next**: Learn about [[Resource Scopes]] or explore [[State Management]].
