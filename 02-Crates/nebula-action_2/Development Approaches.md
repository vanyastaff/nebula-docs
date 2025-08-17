---
title: Development Approaches
tags: [nebula, nebula-action, crate]
status: draft
created: 2025-08-17
---

# Development Approaches

There are two common paths to implement actions:

### 1) Quick path — SimpleAction helper or macro
Good for small, atomic operations with minimal boilerplate.
```rust
simple_action!(GreetingAction, "example.greeting", GreetingInput, GreetingOutput, |_, input, ctx| async move {
    ctx.log_info(&format!("Generating greeting for {}", input.name));
    Ok(GreetingOutput { message: format!("Hello, {}!", input.name), timestamp: chrono::Utc::now().to_rfc3339() })
});
```

### 2) Full control — implement the trait directly
Use when you need custom lifecycle, metrics, or advanced `ActionResult` usage.
```rust
#[async_trait]
impl ProcessAction for CustomGreetingAction {
    type Input = CustomGreetingInput;
    type Output = CustomGreetingOutput;

    async fn execute(
        &self,
        input: Self::Input,
        context: &ExecutionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        let timer = context.start_timer("greeting_generation");
        // ... do work ...
        timer.stop_and_record();
        Ok(ActionResult::Success(CustomGreetingOutput { /* ... */ }))
    }
}
```

### ExecutionContext cheatsheet
- Logging: `log_info/log_warning/log_error/log_debug`
- Metrics: `record_metric`, `increment_counter`, `start_timer`
- Variables: `get_variable`, `set_variable`
- Credentials / Clients: `get_credential`, `get_client::<T>("kind")`
- Resources: `get_resource::<T>()`
- Cancellation: `is_cancelled()`, `cancellation_token()`
