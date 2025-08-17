---
title: Testing Harness & Examples
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Testing Harness & Examples

A lightweight test harness helps simulate contexts/time.

```rust
pub struct TestClock(std::time::Instant);
pub struct TestContext { pub clock: TestClock /* + stubs for clients/resources */ }

impl TestContext {
    pub fn new() -> Self { Self { clock: TestClock(std::time::Instant::now()) } }
    pub fn into_exec_ctx(self) -> ExecutionContext { ExecutionContext{} }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn slugify_basic() {
        let ctx = TestContext::new().into_exec_ctx();
        let out = Slugify.execute(In{ title: "Hello World".into() }, &ctx).await.unwrap();
        match out {
            ActionResult::Success(res) => assert_eq!(res.slug, "hello-world"),
            _ => panic!("unexpected"),
        }
    }
}
```
