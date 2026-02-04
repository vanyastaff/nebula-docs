---
title: Event System
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Event System

**The Event System enables decoupled, asynchronous communication between workflows, actions, and external systems through publishable events.** Events allow components to react to changes without direct dependencies, making systems more scalable and maintainable.

## Definition

In Nebula, events are:

- **First-class values** — Typed, structured messages
- **Asynchronous** — Published and consumed independently
- **Durable** — Optionally persisted for replay
- **Filterable** — Subscribers can filter by event type, source, properties
- **Ordered** — Delivered in the order published (within a stream)
- **Observable** — All events logged and traced

Events are **not** synchronous function calls. They're **fire-and-forget messages** that enable loose coupling.

## Why Events Matter

### The Problem with Direct Calls

Without events, components are tightly coupled:

❌ **Hard-coded dependencies** — Action A directly calls Action B
❌ **Tight coupling** — Changes to B break A
❌ **No scalability** — Can't add new consumers without modifying producer
❌ **No replay** — Can't reprocess past actions
❌ **Synchronous** — Caller waits for all downstream processing
❌ **No audit trail** — State changes not recorded

**Real-world consequences**:
- Order placed → Must update inventory, send email, notify warehouse (3 direct calls)
- Add new notification channel → Modify order placement code
- Replay failed order → No way to reprocess
- Track state changes → Manual logging everywhere

### The Nebula Approach

Events solve these problems:

✅ **Decoupled** — Publishers don't know subscribers
✅ **Extensible** — Add subscribers without changing publishers
✅ **Async** — Publishers continue immediately
✅ **Durable** — Events persisted for replay
✅ **Auditable** — Complete event log
✅ **Scalable** — Multiple subscribers process in parallel

## Core Principles

### 1. Publish-Subscribe Pattern

Publishers emit events, subscribers consume them:

```rust
// Publisher: Order service
pub struct PlaceOrderAction;

impl Action for PlaceOrderAction {
    async fn execute(&self, input: Input, context: &Context)
        -> Result<Output, ActionError>
    {
        // Process order
        let order = create_order(&input)?;

        // Publish event (fire-and-forget)
        context.publish_event("order.created", &OrderCreatedEvent {
            order_id: order.id,
            user_id: order.user_id,
            total: order.total,
            items: order.items.clone(),
            timestamp: Utc::now(),
        }).await?;

        Ok(Output { order_id: order.id })
    }
}

// Subscriber 1: Inventory service
pub struct UpdateInventoryAction;

impl EventSubscriber for UpdateInventoryAction {
    fn event_types(&self) -> Vec<&str> {
        vec!["order.created"]
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        let order: OrderCreatedEvent = event.payload()?;

        // Update inventory
        for item in &order.items {
            inventory_service.decrement(item.sku, item.quantity).await?;
        }

        Ok(())
    }
}

// Subscriber 2: Email service
pub struct SendOrderConfirmationAction;

impl EventSubscriber for SendOrderConfirmationAction {
    fn event_types(&self) -> Vec<&str> {
        vec!["order.created"]
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        let order: OrderCreatedEvent = event.payload()?;

        // Send confirmation email
        email_service.send_confirmation(order.user_id, order.order_id).await?;

        Ok(())
    }
}
```

**Why?** PlaceOrderAction doesn't know about inventory or emails. Add new subscribers without code changes.

### 2. Event Sourcing

Store events as source of truth, derive state from events:

```rust
// Events represent state changes
#[derive(Serialize, Deserialize)]
pub enum UserEvent {
    UserCreated { id: u64, email: String, name: String },
    EmailChanged { id: u64, new_email: String },
    PasswordChanged { id: u64 },
    UserDeleted { id: u64 },
}

// Replay events to reconstruct state
pub struct UserAggregate {
    id: u64,
    email: String,
    name: String,
    is_deleted: bool,
}

impl UserAggregate {
    fn apply_event(&mut self, event: &UserEvent) {
        match event {
            UserEvent::UserCreated { id, email, name } => {
                self.id = *id;
                self.email = email.clone();
                self.name = name.clone();
                self.is_deleted = false;
            }
            UserEvent::EmailChanged { new_email, .. } => {
                self.email = new_email.clone();
            }
            UserEvent::PasswordChanged { .. } => {
                // Password stored elsewhere
            }
            UserEvent::UserDeleted { .. } => {
                self.is_deleted = true;
            }
        }
    }

    // Reconstruct user from event stream
    fn from_events(events: Vec<UserEvent>) -> Self {
        let mut user = UserAggregate::default();
        for event in events {
            user.apply_event(&event);
        }
        user
    }
}
```

**Why?** Complete audit trail, time travel debugging, replay capabilities.

### 3. Event-Driven Workflows

Workflows triggered by events:

```rust
// Workflow triggered by "payment.received" event
let workflow = WorkflowBuilder::new("process_payment")
    .trigger(EventTrigger::new("payment.received"))
    .add_node("validate_payment", ValidatePaymentAction)
    .add_node("update_order", UpdateOrderAction)
    .add_node("notify_user", NotifyUserAction)

    .add_edge("validate_payment", "update_order", |o| o)
    .add_edge("update_order", "notify_user", |o| o)

    .build()?;

// When event published, workflow starts automatically
context.publish_event("payment.received", &PaymentReceivedEvent {
    order_id: 123,
    amount: 99.99,
    payment_method: "credit_card",
}).await?;
// → Workflow starts with event data as input
```

**Why?** Workflows react to external events without polling.

### 4. Event Filtering

Subscribers filter events by criteria:

```rust
impl EventSubscriber for HighValueOrdersAction {
    fn event_types(&self) -> Vec<&str> {
        vec!["order.created"]
    }

    // Only handle high-value orders
    fn filter(&self, event: &Event) -> bool {
        if let Ok(order) = event.payload::<OrderCreatedEvent>() {
            order.total > 1000.0
        } else {
            false
        }
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        // Only called for orders > $1000
        let order: OrderCreatedEvent = event.payload()?;
        notify_manager_about_high_value_order(&order).await?;
        Ok(())
    }
}
```

**Why?** Subscribers only process relevant events, reducing noise.

### 5. Event Durability

Events persisted for replay and auditing:

```rust
// Configure event persistence
let event_bus = EventBusBuilder::new()
    .with_storage(PostgresEventStore::new(&db_pool))
    .with_retention(Duration::days(90))  // Keep 90 days
    .with_snapshots(true)  // Periodic snapshots for performance
    .build()?;

// Publish durable event
context.publish_event("user.created", &user_event)
    .with_retention(Duration::days(365))  // Keep for 1 year
    .await?;

// Replay events from specific point
let events = event_store
    .get_events("user.created")
    .since(timestamp)
    .until(now())
    .await?;

for event in events {
    // Reprocess event
    handle_event(&event).await?;
}
```

**Why?** Recovery from failures, historical analysis, compliance.

## Event Structure

### Event Anatomy

Every event has:

```rust
pub struct Event {
    /// Unique event ID
    pub id: EventId,

    /// Event type (e.g., "order.created", "user.deleted")
    pub event_type: String,

    /// Source that published the event
    pub source: EventSource,

    /// Event payload (typed data)
    pub payload: serde_json::Value,

    /// When event was published
    pub timestamp: DateTime<Utc>,

    /// Correlation ID (links related events)
    pub correlation_id: Option<String>,

    /// Causation ID (event that caused this event)
    pub causation_id: Option<EventId>,

    /// Metadata (custom key-value pairs)
    pub metadata: HashMap<String, String>,
}
```

### Event Types

Events follow hierarchical naming:

```
{domain}.{entity}.{action}

Examples:
  order.created
  order.updated
  order.cancelled
  order.items.added
  order.payment.completed
  user.created
  user.email.changed
  user.deleted
  inventory.stock.depleted
  notification.email.sent
```

**Best practices**:
- Use lowercase
- Use dots for hierarchy
- Past tense for completed actions
- Specific, not generic

### Event Payload

Payload contains event data:

```rust
#[derive(Serialize, Deserialize)]
pub struct OrderCreatedEvent {
    /// Order ID
    pub order_id: u64,

    /// User who created the order
    pub user_id: u64,

    /// Order total amount
    pub total: f64,

    /// Currency code
    pub currency: String,

    /// Order items
    pub items: Vec<OrderItem>,

    /// Shipping address
    pub shipping_address: Address,

    /// When order was created
    pub created_at: DateTime<Utc>,
}

// Publish typed event
context.publish_event("order.created", &OrderCreatedEvent {
    order_id: 123,
    user_id: 456,
    total: 99.99,
    currency: "USD".to_string(),
    items: vec![/* ... */],
    shipping_address: address,
    created_at: Utc::now(),
}).await?;
```

### Correlation and Causation

Track event relationships:

```rust
// Initial event (e.g., user clicks "Place Order")
let order_event = context.publish_event("order.created", &order_data)
    .with_correlation_id(request_id)  // Group related events
    .await?;

// Caused event (triggered by order.created)
context.publish_event("inventory.reserved", &inventory_data)
    .with_correlation_id(request_id)  // Same correlation ID
    .with_causation_id(order_event.id)  // Caused by order.created
    .await?;

// Another caused event
context.publish_event("email.sent", &email_data)
    .with_correlation_id(request_id)
    .with_causation_id(order_event.id)
    .await?;

// Query all events in this flow
let related_events = event_store
    .get_by_correlation_id(request_id)
    .await?;
// Returns: order.created, inventory.reserved, email.sent
```

**Why?** Distributed tracing, debugging complex flows.

## Event Bus

### Publishing Events

```rust
// Simple publish
context.publish_event("user.created", &UserCreatedEvent {
    user_id: 123,
    email: "user@example.com".to_string(),
}).await?;

// With options
context.publish_event("order.placed", &order_data)
    .with_correlation_id(request_id)
    .with_causation_id(previous_event_id)
    .with_metadata("user_agent", user_agent)
    .with_metadata("ip_address", ip_addr)
    .with_retention(Duration::days(365))
    .await?;

// Publish multiple events (atomic batch)
context.publish_events(vec![
    ("inventory.reserved", &inventory_event),
    ("payment.pending", &payment_event),
    ("order.created", &order_event),
]).await?;
// All published or none (transactional)
```

### Subscribing to Events

```rust
// Implement EventSubscriber trait
pub struct MyEventHandler;

impl EventSubscriber for MyEventHandler {
    fn id(&self) -> &str {
        "my_event_handler"
    }

    fn event_types(&self) -> Vec<&str> {
        vec!["order.created", "order.updated"]
    }

    fn filter(&self, event: &Event) -> bool {
        // Optional: filter by criteria
        true
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        match event.event_type.as_str() {
            "order.created" => {
                let order: OrderCreatedEvent = event.payload()?;
                // Handle order created
                self.process_new_order(&order, context).await?;
            }
            "order.updated" => {
                let order: OrderUpdatedEvent = event.payload()?;
                // Handle order updated
                self.process_order_update(&order, context).await?;
            }
            _ => {}
        }
        Ok(())
    }
}

// Register subscriber
event_bus.subscribe(Box::new(MyEventHandler)).await?;
```

### Wildcard Subscriptions

```rust
impl EventSubscriber for AuditLogger {
    fn event_types(&self) -> Vec<&str> {
        // Subscribe to all order events
        vec!["order.*"]
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        // Log all order events
        audit_log.record(event).await?;
        Ok(())
    }
}

// Other wildcard patterns
"user.*"           // All user events
"*.created"        // All created events
"order.items.*"    // All order item events
"**"               // All events (use sparingly!)
```

## Event Patterns

### Saga Pattern with Events

Distributed transaction using events and compensation:

```rust
// Order saga coordinator
pub struct OrderSagaCoordinator;

impl EventSubscriber for OrderSagaCoordinator {
    fn event_types(&self) -> Vec<&str> {
        vec![
            "order.created",
            "inventory.reserved",
            "inventory.reservation_failed",
            "payment.completed",
            "payment.failed",
        ]
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        match event.event_type.as_str() {
            "order.created" => {
                // Step 1: Reserve inventory
                let order: OrderCreatedEvent = event.payload()?;
                context.publish_event("inventory.reserve_requested", &order)
                    .with_correlation_id(event.correlation_id)
                    .with_causation_id(event.id)
                    .await?;
            }
            "inventory.reserved" => {
                // Step 2: Process payment
                context.publish_event("payment.process_requested", &data)
                    .with_correlation_id(event.correlation_id)
                    .await?;
            }
            "payment.completed" => {
                // Success! Confirm order
                context.publish_event("order.confirmed", &data)
                    .with_correlation_id(event.correlation_id)
                    .await?;
            }
            "payment.failed" => {
                // Compensation: Release inventory
                context.publish_event("inventory.release_requested", &data)
                    .with_correlation_id(event.correlation_id)
                    .await?;

                context.publish_event("order.cancelled", &data)
                    .with_correlation_id(event.correlation_id)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }
}
```

### Event Aggregation

Collect multiple events before acting:

```rust
pub struct OrderCompletionAggregator {
    pending_orders: Arc<RwLock<HashMap<u64, OrderCompletionState>>>,
}

struct OrderCompletionState {
    order_id: u64,
    inventory_reserved: bool,
    payment_completed: bool,
    email_sent: bool,
}

impl EventSubscriber for OrderCompletionAggregator {
    fn event_types(&self) -> Vec<&str> {
        vec![
            "inventory.reserved",
            "payment.completed",
            "email.sent",
        ]
    }

    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        let order_id = event.metadata.get("order_id")
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(ActionError::validation("Missing order_id"))?;

        let mut orders = self.pending_orders.write().await;
        let state = orders.entry(order_id).or_insert(OrderCompletionState {
            order_id,
            inventory_reserved: false,
            payment_completed: false,
            email_sent: false,
        });

        // Update state based on event
        match event.event_type.as_str() {
            "inventory.reserved" => state.inventory_reserved = true,
            "payment.completed" => state.payment_completed = true,
            "email.sent" => state.email_sent = true,
            _ => {}
        }

        // Check if all completed
        if state.inventory_reserved && state.payment_completed && state.email_sent {
            // All tasks done!
            context.publish_event("order.fully_processed", &order_id).await?;
            orders.remove(&order_id);
        }

        Ok(())
    }
}
```

### Event Replay

Replay events for recovery or testing:

```rust
// Replay all events since timestamp
pub async fn replay_events(
    event_store: &EventStore,
    since: DateTime<Utc>,
) -> Result<(), Error> {
    let events = event_store
        .get_events_since(since)
        .await?;

    for event in events {
        // Republish event
        event_bus.replay_event(&event).await?;
    }

    Ok(())
}

// Rebuild aggregate from events
pub async fn rebuild_user(
    user_id: u64,
    event_store: &EventStore,
) -> Result<User, Error> {
    let events = event_store
        .get_events_for_aggregate("user", user_id)
        .await?;

    let mut user = User::default();
    for event in events {
        user.apply_event(&event)?;
    }

    Ok(user)
}
```

### Dead Letter Queue

Handle failed event processing:

```rust
impl EventSubscriber for MyHandler {
    async fn handle_event(&self, event: &Event, context: &Context)
        -> Result<(), ActionError>
    {
        match self.process_event(event).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_transient() => {
                // Transient error - retry
                Err(e)
            }
            Err(e) => {
                // Permanent error - send to dead letter queue
                context.publish_event("dlq.event_failed", &DeadLetterEvent {
                    original_event: event.clone(),
                    error: e.to_string(),
                    handler: self.id().to_string(),
                    timestamp: Utc::now(),
                }).await?;

                // Don't propagate error (already handled)
                Ok(())
            }
        }
    }
}
```

## Best Practices

### Event Design

- ✅ **Use specific event types** — `order.created` not `order.event`
- ✅ **Include all relevant data** — Avoid requiring lookups
- ✅ **Use past tense** — Events already happened
- ✅ **Keep payloads immutable** — Events are historical facts
- ✅ **Version event schemas** — Support evolution
- ❌ **Don't use events for RPC** — Events are not function calls
- ❌ **Don't make events too large** — Link to data if needed
- ❌ **Don't include secrets** — Events may be logged

### Event Naming

- ✅ **Use hierarchical names** — `domain.entity.action`
- ✅ **Be consistent** — Follow team conventions
- ✅ **Be specific** — `user.email.changed` not `user.updated`
- ✅ **Use lowercase** — Easier to work with
- ❌ **Don't use verbs in present tense** — Past tense only
- ❌ **Don't abbreviate** — Clarity over brevity

### Subscribers

- ✅ **Make idempotent** — Handle duplicate events
- ✅ **Process quickly** — Don't block event bus
- ✅ **Log failures** — Track what went wrong
- ✅ **Use correlation IDs** — Link related events
- ✅ **Handle out-of-order delivery** — Events may arrive late
- ❌ **Don't assume order** — Use version numbers if needed
- ❌ **Don't modify events** — Events are immutable
- ❌ **Don't wait for confirmation** — Async by design

### Performance

- ✅ **Batch publish when possible** — Reduce overhead
- ✅ **Use filtering** — Subscribe only to needed events
- ✅ **Configure retention** — Don't keep events forever
- ✅ **Use snapshots** — Avoid replaying millions of events
- ❌ **Don't publish too frequently** — Batch if possible
- ❌ **Don't subscribe to all events** — Use specific types

## Related Concepts

- [[Workflows]] — Event-triggered workflows
- [[Actions]] — Event publishers and subscribers
- [[Error Handling]] — Handling event processing errors
- [[Expression System]] — Event filtering expressions

## Implementation Guides

- [[02-Crates/nebula-eventbus/README|nebula-eventbus]] — Event bus implementation
- [[02-Crates/nebula-eventbus/Event Types|Event Types]] — Defining custom events
- [[02-Crates/nebula-eventbus/Subscriptions|Subscriptions]] — Subscribing to events
- [[06-Examples/_Index#Event-Driven Workflows|Examples]] — Event-driven workflow patterns

---

**Next**: Learn about [[Security Model]] or explore [[State Management]].
