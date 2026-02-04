---
title: Workflows
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Workflows

**A Workflow is a directed acyclic graph (DAG) of nodes that orchestrates the execution of actions to accomplish a complex task.** Workflows define the order, conditions, and error handling for action execution.

## Definition

In Nebula, a workflow is a structured composition of actions that:

- **Defines execution order** — Sequential, parallel, or conditional
- **Passes data between actions** — Output of one action becomes input of another
- **Handles errors** — Defines fallback paths and error recovery
- **Manages state** — Isolated memory scope for workflow execution
- **Produces observability** — Logs, metrics, and traces for entire workflow

Workflows are **not** imperative scripts. They are declarative definitions of how actions should be orchestrated.

## Anatomy of a Workflow

Every workflow consists of:

### 1. Trigger

**What starts the workflow?**

- **Scheduled** — Cron-like time-based triggers
- **Event-driven** — Triggered by events (webhooks, message queues)
- **Manual** — Started by user or API call
- **Polling** — Periodic checks for external changes

### 2. Nodes

**What actions execute?**

Each node in the workflow:
- Has a unique ID (for referencing)
- Executes a specific action
- Receives input (from previous nodes or workflow parameters)
- Produces output (passed to next nodes)
- Can have conditional execution (only run if condition met)

### 3. Edges

**How are nodes connected?**

Edges define data flow and execution order:
- **Sequential** — Node B runs after Node A
- **Parallel** — Nodes B and C run concurrently after Node A
- **Conditional** — Node B runs only if condition true
- **Error path** — Node C runs if Node A fails

### 4. State

**How is data shared?**

Each workflow execution has:
- **Workflow parameters** — Input data for the workflow
- **Node outputs** — Results from each action
- **Workflow memory** — Shared key-value store for intermediate data
- **Context** — Metadata (workflow ID, user, timestamp)

## Why Workflows Matter

### The Problem with Imperative Code

Traditional automation scripts have issues:

❌ **Hard to visualize** — Logic buried in code
❌ **Difficult to modify** — Changes require code changes
❌ **Poor observability** — Hard to see execution flow
❌ **No error recovery** — Manual intervention on failure
❌ **Not reusable** — Specific to one use case

### The Nebula Approach

Workflows solve these problems:

✅ **Visual** — Graph-based representation
✅ **Declarative** — Define what to do, not how
✅ **Observable** — See execution in real-time
✅ **Resilient** — Automatic error handling and retries
✅ **Reusable** — Same workflow with different parameters

## Workflow Execution Model

### Sequential Execution

Actions run one after another:

```
Node A (Fetch Data)
   ↓
Node B (Validate Data)
   ↓
Node C (Transform Data)
   ↓
Node D (Store Data)
```

**Use when**: Each step depends on the previous step's output.

**Example**: Data pipeline where validation needs fetched data, transformation needs validated data.

### Parallel Execution

Actions run concurrently:

```
       ┌─ Node B (Send Email) ─┐
Node A                           Node D (Aggregate Results)
       └─ Node C (Send SMS) ────┘
```

**Use when**: Steps are independent and can run simultaneously.

**Example**: Send notifications via multiple channels (email, SMS, Slack) in parallel.

### Conditional Execution

Actions run based on conditions:

```
Node A (Check Payment)
   ↓
[if approved] → Node B (Ship Order)
   ↓
[if declined] → Node C (Refund Customer)
```

**Use when**: Execution path depends on data or business logic.

**Example**: Different actions for approved vs. declined payments.

### Loop Execution

Actions repeat until condition met:

```
Node A (Fetch Page)
   ↓
Node B (Process Items)
   ↓
[has_next_page] → Node A (Fetch Next Page)
   ↓
[no_more_pages] → Node C (Finalize)
```

**Use when**: Processing paginated data or iterating until completion.

**Example**: Fetch all pages from an API, process each item, stop when no more pages.

### Error Handling

Actions have fallback paths:

```
Node A (Call External API)
   ↓
[success] → Node B (Process Response)
   ↓
[error] → Node C (Log Error) → Node D (Notify Admin)
```

**Use when**: External dependencies might fail.

**Example**: API call fails, log error and notify admin instead of crashing workflow.

## Data Flow

### Passing Data Between Nodes

Nodes communicate via typed inputs/outputs:

```
Node A: FetchUser
  Output: { user_id: 123, email: "user@example.com" }
     ↓
Node B: SendEmail
  Input: { to: ${node_a.output.email}, subject: "Welcome" }
```

Output from Node A becomes input to Node B using **expressions**.

### Workflow Memory

Nodes can store/retrieve data in shared memory:

```
Node A: FetchUser
  Action: Store user_id in memory
     ↓
Node B: FetchOrders
  Action: Retrieve user_id from memory
     ↓
Node C: ProcessOrders
  Action: Retrieve user_id from memory
```

**Use when**: Multiple nodes need access to the same data.

### Workflow Parameters

Workflows accept parameters at start:

```
Workflow Parameters:
  - user_id: 123
  - date_range: "2024-01-01 to 2024-12-31"

Node A: FetchData
  Input: { user_id: ${workflow.params.user_id} }
```

**Use when**: Workflow behavior needs to be customizable.

## Control Flow Patterns

### Fan-Out / Fan-In

Execute multiple nodes in parallel, then aggregate:

```
          ┌─ Node B (Process A) ─┐
          ├─ Node C (Process B) ─┤
Node A ───┼─ Node D (Process C) ─┼─── Node F (Aggregate)
          ├─ Node E (Process D) ─┘
```

**Use when**: Independent parallel processing followed by aggregation.

**Example**: Fetch data from multiple sources, process in parallel, combine results.

### Branch and Merge

Conditional execution with multiple paths merging:

```
                 ┌─ Node B (Path A) ─┐
Node A (Check) ──┤                     ├─ Node D (Continue)
                 └─ Node C (Path B) ─┘
```

**Use when**: Different processing paths that converge.

**Example**: Different validation logic based on data type, then common processing.

### Saga Pattern

Long-running transactions with compensation:

```
Node A (Reserve Inventory)
   ↓
Node B (Charge Payment)
   ↓ [success]
Node C (Ship Order)
   ↓ [error]
Node D (Refund Payment) → Node E (Release Inventory)
```

**Use when**: Multi-step transactions that need rollback on failure.

**Example**: E-commerce order processing with compensation logic.

### Map-Reduce

Process collection of items in parallel:

```
Node A (Fetch Items: [item1, item2, item3])
   ↓
   ├─ Node B (Process item1) ─┐
   ├─ Node B (Process item2) ─┤ (parallel instances)
   └─ Node B (Process item3) ─┘
   ↓
Node C (Aggregate Results)
```

**Use when**: Processing a collection where each item is independent.

**Example**: Bulk email send, image processing, data transformation.

## Workflow State Management

### Execution States

Every workflow execution has a state:

- **Pending** — Waiting to start
- **Running** — Currently executing
- **Paused** — Waiting for external input
- **Completed** — Finished successfully
- **Failed** — Terminated with error
- **Cancelled** — Manually stopped

### Node States

Each node within a workflow has a state:

- **Waiting** — Not yet started
- **Running** — Currently executing
- **Completed** — Finished successfully
- **Failed** — Error occurred
- **Skipped** — Condition not met
- **Retrying** — Failed, attempting retry

### State Persistence

Workflow state is persisted to enable:

- **Resume** — Continue after pause or failure
- **Replay** — Re-execute from specific point
- **Audit** — View execution history
- **Debug** — Inspect intermediate states

## Error Handling Strategies

### Retry with Backoff

Automatically retry failed actions:

```
Node A (Call API)
  Retry policy:
    - Max retries: 3
    - Backoff: exponential (1s, 2s, 4s)
    - Retry on: transient errors only
```

**Use when**: Transient failures (network issues, rate limits).

### Fallback Actions

Execute alternative action on failure:

```
Node A (Primary API)
   ↓ [error]
Node B (Fallback API)
```

**Use when**: Multiple ways to accomplish the same goal.

### Circuit Breaker

Stop calling failing service:

```
Node A (External Service)
  Circuit breaker:
    - Threshold: 5 failures in 60s
    - Open duration: 30s
    - Half-open: test with 1 request
```

**Use when**: Protecting against cascading failures.

### Compensation

Undo previous actions on failure:

```
Node A (Reserve Inventory) [success]
   ↓
Node B (Charge Payment) [error]
   ↓
Node C (Release Inventory) [compensation for A]
```

**Use when**: Distributed transactions requiring rollback.

## Workflow Triggers

### Time-Based Triggers

Run workflows on a schedule:

```
Trigger: Cron("0 2 * * *")  // Every day at 2 AM
Workflow: DailyReportGenerator
```

**Use when**: Periodic batch jobs, daily reports, cleanup tasks.

### Event-Based Triggers

Start workflows from events:

```
Trigger: Event("user.created")
Workflow: UserOnboarding
```

**Use when**: React to system or external events.

### Webhook Triggers

HTTP endpoints that start workflows:

```
Trigger: Webhook("/api/webhooks/github")
Workflow: ProcessGitHubEvent
```

**Use when**: External systems need to trigger workflows.

### Manual Triggers

User or API initiated:

```
Trigger: Manual
Workflow: DataMigration
```

**Use when**: Ad-hoc tasks, migrations, manual processes.

## Best Practices

### Design

- **Keep workflows focused** — One clear purpose per workflow
- **Limit complexity** — Max 10-15 nodes per workflow
- **Use subworkflows** — Break complex workflows into smaller ones
- **Name nodes clearly** — Descriptive IDs ("fetch_user", not "node_1")

### Error Handling

- **Handle all errors** — Every node should have error path
- **Use retries wisely** — Only for transient errors
- **Log failures** — Capture context for debugging
- **Notify on critical failures** — Alert on-call for important workflows

### Performance

- **Parallelize when possible** — Independent nodes should run in parallel
- **Avoid tight loops** — Add delays in polling loops
- **Set timeouts** — Prevent hung workflows
- **Monitor execution time** — Track and optimize slow workflows

### Testing

- **Test happy path** — Normal execution flow
- **Test error paths** — All error scenarios
- **Test edge cases** — Boundary conditions
- **Test with real data** — Avoid surprises in production

### Observability

- **Add logging** — Log key decisions and transitions
- **Track metrics** — Duration, success rate, throughput
- **Use tracing** — Distributed tracing for complex workflows
- **Dashboard workflows** — Monitor critical workflows

## Workflow vs. Action vs. Function

| Aspect | Workflow | Action | Function |
|--------|----------|--------|----------|
| **Purpose** | Orchestration | Unit of work | Code reuse |
| **Composition** | Multiple actions | Single operation | Multiple functions |
| **State** | Workflow memory | Isolated context | Local variables |
| **Execution** | Sequential/parallel | Always sequential | Direct call |
| **Error handling** | Fallback paths | Retries | Result<T, E> |
| **Observability** | Full execution graph | Action metrics | Manual |
| **Reusability** | Parameterized templates | Across workflows | Within code |

## When to Use Workflows

Create a workflow when you need:

✅ **Multi-step process** — More than one action
✅ **Error recovery** — Fallback logic or retries
✅ **Conditional logic** — Different paths based on data
✅ **Parallel execution** — Independent operations
✅ **Long-running** — Takes more than a few seconds
✅ **Visibility** — Need to see execution progress

**Don't use workflows for**:

❌ **Single action** — Just call the action directly
❌ **Synchronous APIs** — Use regular API endpoints
❌ **Real-time processing** — Use streaming instead
❌ **Simple scripts** — Use regular functions

## Related Concepts

- [[Actions]] — Building blocks of workflows
- [[Error Handling]] — How workflows handle failures
- [[Expression System]] — Dynamic data access in workflows
- [[Event System]] — Event-driven workflow triggers
- [[Nodes]] — Individual workflow steps

## Implementation Guides

- [[Building Workflows]] — Step-by-step guide
- [[02-Crates/nebula-workflow/README|nebula-workflow]] — Workflow framework
- [[02-Crates/nebula-sdk/README|nebula-sdk]] — SDK for building workflows
- [[06-Examples/_Index|Examples]] — Real-world workflow patterns

---

**Next**: Learn about [[Building Workflows]] or explore [[Error Handling]].
