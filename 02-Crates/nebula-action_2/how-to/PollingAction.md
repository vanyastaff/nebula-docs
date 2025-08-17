---
title: How to: PollingAction (Deep)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# How to: PollingAction (Deep)

**Purpose.** Periodically pull new/changed items with deduplication.

## Cursor design
- Include `last_id`/`updated_at`/`page_token`.
- Keep **opaque** to callers; serialize with `serde`.

## Lease usage
`Lease` bounds the time per poll tick. Always check `lease.remaining_ms()` before another network call.

## Example: Gmail-like polling
```rust
#[derive(Deserialize)] struct Cfg { api_base: String, page_size: u32 }
#[derive(Serialize, Deserialize, Default)] struct Cursor { page_token: Option<String>, last_msg_id: Option<String> }
#[derive(Serialize)] struct Item { id: String, subject: String }

pub struct GmailPoller;

#[async_trait]
impl PollingAction for GmailPoller {
    type Config = Cfg; type Cursor = Cursor; type Item = Item;
    async fn poll(&self, cfg: Cfg, cursor: &mut Cursor, lease: &Lease, ctx: &ExecutionContext)
        -> Result<PollResult<Item, Cursor>, ActionError> {
        let mut items = Vec::new();
        loop {
            if lease.remaining_ms() < 200 { break; }
            // fetch page using cursor.page_token...
            // push Item{s}, update cursor.page_token
            if /* no more pages */ true { break; }
        }
        ctx.record_metric("items_polled", items.len() as f64, &[]);
        Ok(PollResult::items(items, cursor.clone()).with_backoff_ms(5000))
    }
}
```
