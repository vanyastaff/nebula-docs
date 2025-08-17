---
title: Example: HTTP Request (ProcessAction)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Example: HTTP Request (ProcessAction)

A complete, typed HTTP action with timeouts, headers, and metrics.

```rust
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::HashMap;

#[derive(Default)]
pub struct HttpRequestAction {
    client: reqwest::Client,
}

#[derive(Deserialize)]
pub struct HttpInput {
    pub url: String,
    #[serde(default = "default_method")]
    pub method: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    pub body: Option<Value>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
}
fn default_method() -> String { "GET".into() }
fn default_timeout() -> u64 { 10_000 }

#[derive(Serialize)]
pub struct HttpOutput {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub elapsed_ms: u64,
}

#[async_trait]
impl ProcessAction for HttpRequestAction {
    type Input = HttpInput;
    type Output = HttpOutput;

    async fn execute(&self, input: Self::Input, ctx: &ExecutionContext) -> Result<ActionResult<Self::Output>, ActionError> {
        let start = std::time::Instant::now();
        let mut req = match input.method.to_uppercase().as_str() {
            "GET" => self.client.get(&input.url),
            "POST" => self.client.post(&input.url),
            "PUT" => self.client.put(&input.url),
            "DELETE" => self.client.delete(&input.url),
            "PATCH" => self.client.patch(&input.url),
            other => return Err(ActionError::InvalidInput { field: "method".into(), reason: format!("unsupported {}", other) }),
        };
        for (k, v) in &input.headers { req = req.header(k, v); }
        if let Some(b) = &input.body { req = req.json(b); }
        req = req.timeout(std::time::Duration::from_millis(input.timeout_ms));

        let resp = req.send().await.map_err(|e| ActionError::ExternalServiceError { service: "http".into(), error: e.to_string() })?;
        let status = resp.status().as_u16();
        let headers = resp.headers().iter().map(|(k,v)| (k.to_string(), v.to_str().unwrap_or("").to_string())).collect();
        let body = resp.json::<Value>().await.unwrap_or(Value::Null);
        let elapsed_ms = start.elapsed().as_millis() as u64;

        ctx.record_metric("http_request_duration_ms", elapsed_ms as f64, &[("method",&input.method),("status",&status.to_string())]);
        Ok(ActionResult::Success(HttpOutput { status, headers, body, elapsed_ms }))
    }
}
```
