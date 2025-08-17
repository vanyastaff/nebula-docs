---
title: Action Types
tags: [nebula, nebula-action, rust, crate, types]
status: stable
created: 2025-08-17

---

# Action Types

Comprehensive guide to action types in the nebula-action Rust crate.

## Quick decision guide

```rust
// Choose your action type based on requirements:
match your_requirement {
    Simple => ProcessAction,      // Stateless transformation
    NeedsState => StatefulAction, // Persistent state between runs
    EventSource => TriggerAction, // Initiates workflows
    Resource => SupplyAction,     // Provides shared resources
    Stream => StreamingAction,    // Processes data streams
    UserInput => InteractiveAction, // Requires human interaction
    Transaction => TransactionalAction, // ACID guarantees
}
```

## ProcessAction

Stateless data transformation - the workhorse of actions.

```rust
use nebula_action::prelude::*;
use async_trait::async_trait;

pub struct UppercaseAction;

#[async_trait]
impl ProcessAction for UppercaseAction {
    type Input = String;
    type Output = String;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        context.log_info(&format!("Processing {} chars", input.len()));
        Ok(ActionResult::Success(input.to_uppercase()))
    }
}
```

**When to use:**

- Data transformation
- API calls without state
- Calculations
- Format conversion

**Key traits:**

- No state persistence
- Fully async
- Type-safe I/O

## StatefulAction

Maintains state across executions with automatic persistence.

```rust
#[derive(Serialize, Deserialize, Default)]
pub struct WizardState {
    step: u32,
    data: HashMap<String, Value>,
    started_at: Option<DateTime<Utc>>,
}

pub struct SetupWizard;

#[async_trait]
impl StatefulAction for SetupWizard {
    type State = WizardState;
    type Input = WizardInput;
    type Output = WizardOutput;
    
    async fn execute_with_state(
        &self,
        input: Self::Input,
        state: &mut Self::State,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // State automatically persisted after execution
        state.step += 1;
        state.data.insert(input.field_name, input.field_value);
        
        if state.step >= 5 {
            Ok(ActionResult::Break {
                output: WizardOutput::from(state),
                reason: BreakReason::Completed,
            })
        } else {
            Ok(ActionResult::Continue {
                output: WizardOutput::partial(state),
                progress: LoopProgress::new(state.step, 5),
                delay: None,
            })
        }
    }
    
    async fn migrate_state(
        &self,
        old_state: serde_json::Value,
        old_version: semver::Version,
    ) -> Result<Self::State, ActionError> {
        // Handle version migrations
        if old_version.major < 2 {
            // Migration logic
        }
        serde_json::from_value(old_state)
            .map_err(|e| ActionError::StateMigrationFailed(e.to_string()))
    }
}
```

**When to use:**

- Multi-step workflows
- Accumulating results
- Session management
- Progress tracking

**State management:**

- Automatic persistence
- Version migration support
- Atomic updates
- Configurable backends (Redis, PostgreSQL, etc.)

## TriggerAction

Event sources that initiate workflows.

```rust
pub struct KafkaTrigger {
    consumer: Arc<StreamConsumer>,
}

#[async_trait]
impl TriggerAction for KafkaTrigger {
    type Config = KafkaConfig;
    type Event = KafkaMessage;
    
    async fn start(
        &self,
        config: Self::Config,
        context: &TriggerContext,
    ) -> Result<TriggerEventStream<Self::Event>, ActionError> {
        let stream = self.consumer
            .stream()
            .map(|msg| self.parse_message(msg))
            .boxed();
            
        Ok(stream)
    }
    
    async fn stop(&self) -> Result<(), ActionError> {
        self.consumer.unsubscribe();
        Ok(())
    }
}
```

**Common triggers:**

- Webhooks (HTTP endpoints)
- Message queues (Kafka, RabbitMQ)
- File watchers
- Cron schedules
- Database changes

## SupplyAction

Provides shared resources to other actions.

```rust
pub struct PostgresSupplier;

#[async_trait]
impl SupplyAction for PostgresSupplier {
    type Config = PgConfig;
    type Resource = PgPool;
    
    async fn create(
        &self,
        config: Self::Config,
        context: &ExecutionContext,
    ) -> Result<Self::Resource, ActionError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(&config.database_url)
            .await?;
            
        context.log_info("PostgreSQL pool created");
        Ok(pool)
    }
    
    async fn health_check(
        &self,
        resource: &Self::Resource
    ) -> Result<HealthStatus, ActionError> {
        sqlx::query("SELECT 1")
            .fetch_one(resource)
            .await
            .map(|_| HealthStatus::Healthy)
            .or_else(|e| Ok(HealthStatus::Unhealthy {
                reason: e.to_string(),
                recoverable: true,
            }))
    }
    
    async fn destroy(&self, resource: Self::Resource) -> Result<(), ActionError> {
        resource.close().await;
        Ok(())
    }
}
```

**Common resources:**

- Database connections
- HTTP clients
- Cache connections
- File handles
- Cloud service clients

## StreamingAction

Processes data streams with backpressure support.

```rust
pub struct CsvProcessor;

#[async_trait]
impl StreamingAction for CsvProcessor {
    type Input = FileStream;
    type Output = ProcessedRecord;
    type Error = CsvError;
    
    async fn process_stream(
        &self,
        input: Self::Input,
        context: &StreamContext,
    ) -> Result<ActionStream<Self::Output>, Self::Error> {
        let stream = input
            .lines()
            .map(|line| self.parse_csv_line(line))
            .filter_map(|result| async move { result.ok() })
            .map(|record| self.transform_record(record))
            .buffer_unordered(10) // Parallel processing
            .throttle(Duration::from_millis(10)); // Rate limiting
            
        Ok(Box::pin(stream))
    }
    
    fn backpressure_config(&self) -> BackpressureConfig {
        BackpressureConfig {
            buffer_size: 1000,
            high_watermark: 0.8,
            low_watermark: 0.2,
            strategy: BackpressureStrategy::DropOldest,
        }
    }
}
```

**Features:**

- Backpressure handling
- Windowing operations
- Parallel processing
- Rate limiting

## InteractiveAction

Requires user interaction during execution.

```rust
pub struct ApprovalAction;

#[async_trait]
impl InteractiveAction for ApprovalAction {
    type Request = ApprovalRequest;
    type Response = ApprovalResponse;
    type Output = ApprovalResult;
    
    async fn create_interaction(
        &self,
        input: Self::Request,
        context: &ExecutionContext,
    ) -> Result<InteractionHandle, ActionError> {
        let handle = InteractionHandle::new()
            .with_timeout(Duration::from_secs(3600))
            .with_ui_schema(json!({
                "type": "approval",
                "fields": ["reason", "notes"],
                "required": ["reason"]
            }));
            
        context.emit_event(Event::ApprovalRequested {
            id: handle.id(),
            details: input,
        }).await?;
        
        Ok(handle)
    }
    
    async fn handle_response(
        &self,
        response: Self::Response,
        handle: InteractionHandle,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        if response.approved {
            Ok(ActionResult::Success(ApprovalResult::Approved {
                approver: response.user_id,
                timestamp: Utc::now(),
                notes: response.notes,
            }))
        } else {
            Ok(ActionResult::Skip {
                reason: format!("Rejected by {}", response.user_id),
            })
        }
    }
}
```

**Use cases:**

- Manual approvals
- User input forms
- Confirmation dialogs
- Multi-factor authentication

## TransactionalAction

Provides ACID guarantees with two-phase commit.

```rust
pub struct PaymentTransaction;

#[async_trait]
impl TransactionalAction for PaymentTransaction {
    type Input = PaymentRequest;
    type Output = PaymentResult;
    type RollbackData = PaymentRollback;
    
    async fn prepare(
        &self,
        input: Self::Input,
        context: &TransactionContext,
    ) -> Result<TransactionVote, ActionError> {
        // Phase 1: Prepare
        let can_proceed = self.check_balance(&input).await?
            && self.validate_merchant(&input).await?
            && self.reserve_funds(&input).await?;
            
        if can_proceed {
            Ok(TransactionVote::Commit)
        } else {
            Ok(TransactionVote::Abort)
        }
    }
    
    async fn commit(
        &self,
        input: Self::Input,
        context: &TransactionContext,
    ) -> Result<Self::Output, ActionError> {
        // Phase 2: Commit
        let result = self.execute_payment(&input).await?;
        context.log_info(&format!("Payment {} committed", result.transaction_id));
        Ok(result)
    }
    
    async fn rollback(
        &self,
        rollback_data: Self::RollbackData,
        context: &TransactionContext,
    ) -> Result<(), ActionError> {
        // Compensate
        self.release_funds(&rollback_data).await?;
        self.notify_failure(&rollback_data).await?;
        Ok(())
    }
}
```

**Features:**

- Two-phase commit protocol
- Automatic rollback on failure
- Distributed transaction support
- Saga pattern implementation

## QueueAction

Background job processing with persistence.

```rust
pub struct EmailQueueProcessor;

#[async_trait]
impl QueueAction for EmailQueueProcessor {
    type Job = EmailJob;
    type Result = EmailResult;
    
    async fn process_job(
        &self,
        job: Self::Job,
        context: &QueueContext,
    ) -> Result<Self::Result, ActionError> {
        // Process with retry logic
        for attempt in 0..3 {
            match self.send_email(&job).await {
                Ok(result) => return Ok(result),
                Err(e) if attempt < 2 => {
                    context.log_warning(&format!("Attempt {} failed: {}", attempt + 1, e));
                    tokio::time::sleep(Duration::from_secs(2_u64.pow(attempt))).await;
                }
                Err(e) => return Err(ActionError::from(e)),
            }
        }
        unreachable!()
    }
    
    fn queue_config(&self) -> QueueConfig {
        QueueConfig {
            max_retries: 3,
            retry_delay: RetryDelay::Exponential {
                base: Duration::from_secs(1),
                max: Duration::from_secs(60),
            },
            visibility_timeout: Duration::from_secs(300),
            dead_letter_after: 5,
        }
    }
}
```

## ScheduleAction

Time-based execution with cron support.

```rust
pub struct DailyReportAction;

#[async_trait]
impl ScheduleAction for DailyReportAction {
    type Input = ReportConfig;
    type Output = Report;
    
    fn schedule(&self) -> Schedule {
        // Run at 9 AM every weekday
        "0 9 * * MON-FRI".parse().unwrap()
    }
    
    async fn execute_scheduled(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        let report = self.generate_report(&input).await?;
        self.send_report(&report).await?;
        Ok(ActionResult::Success(report))
    }
}
```

## WebhookAction

HTTP endpoint that triggers workflows.

```rust
pub struct StripeWebhook;

#[async_trait]
impl WebhookAction for StripeWebhook {
    type Payload = StripeEvent;
    type Response = WebhookResponse;
    
    async fn verify_signature(
        &self,
        headers: &HeaderMap,
        body: &[u8],
        context: &ExecutionContext,
    ) -> Result<(), ActionError> {
        let signature = headers
            .get("Stripe-Signature")
            .ok_or(ActionError::InvalidInput {
                field: "signature".into(),
                reason: "Missing Stripe signature".into(),
            })?;
            
        let secret = context.get_credential("stripe_webhook_secret").await?;
        stripe::Webhook::verify(body, signature, &secret.expose())?;
        Ok(())
    }
    
    async fn handle_webhook(
        &self,
        payload: Self::Payload,
        context: &ExecutionContext,
    ) -> Result<Self::Response, ActionError> {
        match payload.event_type {
            "payment_intent.succeeded" => {
                self.handle_payment_success(payload).await
            }
            "customer.subscription.deleted" => {
                self.handle_subscription_cancelled(payload).await
            }
            _ => Ok(WebhookResponse::Acknowledged),
        }
    }
}
```

## PollingAction

Periodically checks external state.

```rust
pub struct GmailPoller;

#[async_trait]
impl PollingAction for GmailPoller {
    type State = GmailPollingState;
    type Event = EmailMessage;
    
    fn poll_interval(&self) -> Duration {
        Duration::from_secs(60) // Check every minute
    }
    
    async fn poll(
        &self,
        state: &mut Self::State,
        context: &ExecutionContext,
    ) -> Result<Vec<Self::Event>, ActionError> {
        let gmail = context.get_client::<GmailClient>("gmail").await?;
        
        let messages = gmail
            .messages()
            .list()
            .after(state.last_check)
            .unread()
            .execute()
            .await?;
            
        state.last_check = Utc::now();
        state.total_polled += messages.len();
        
        Ok(messages)
    }
}
```

## Composition patterns

### Sequential composition

```rust
let workflow = compose![
    ValidateInput,
    FetchData,
    ProcessData,
    SaveResults,
];
```

### Parallel composition

```rust
let parallel = parallel![
    DatabaseQuery,
    ApiCall,
    CacheCheck,
].with_aggregation(AggregationStrategy::FirstSuccess);
```

### Conditional branching

```rust
let conditional = branch!(
    condition: |input| input.amount > 1000,
    then: HighValueProcess,
    else: StandardProcess,
);
```

## Best practices

1. **Choose the simplest type** - Start with ProcessAction, upgrade only when needed
2. **Handle errors explicitly** - Use specific ActionError variants
3. **Log appropriately** - Use context logging for observability
4. **Test state migrations** - Always test StatefulAction migrations
5. **Set timeouts** - Configure appropriate timeouts for external calls
6. **Use idempotency** - Design actions to be safely retryable
7. **Monitor resources** - Track resource usage in SupplyAction