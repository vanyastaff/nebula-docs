---
title: How to: WebhookAction (Deep)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# How to: WebhookAction (Deep)

**Purpose.** Handle inbound HTTP callbacks securely and reliably.

## Signature & Context
See [[Reference/Traits#Specialized contexts]]. `WebhookContext` provides:
- `request_id()` — for tracing
- `callback_url()` — full URL exposed to provider
- `respond(status, body)` — low-level response API (optional)

## Security recipe
1. **Signature verification** (HMAC or public-key). Example (HMAC-SHA256):
```rust
fn verify(sig: &str, payload: &[u8], secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(payload);
    mac.verify_slice(&hex::decode(sig).unwrap()).is_ok()
}
```
2. **Replay protection**: `nonce + timestamp`, reject if `|now - ts| > 5m` or nonce reused.
3. **Idempotency**: store provider delivery ID; short-circuit duplicates.
4. **Least logging**: log only event type & delivery ID.

## Example: Stripe-like webhook
```rust
#[derive(Deserialize)] struct Cfg { secret: String }
#[derive(Deserialize)] struct Req { raw: bytes::Bytes, signature: String }
#[derive(Serialize)] struct Resp { accepted: bool }

pub struct StripeWebhook;

#[async_trait]
impl WebhookAction for StripeWebhook {
    type Config = Cfg; type Request = Req; type Response = Resp;
    async fn subscribe(&self, _cfg: Cfg, _wctx: &WebhookContext) -> Result<(), ActionError> { Ok(()) }
    async fn handle(&self, req: Req, ctx: &WebhookContext) -> Result<ActionResult<Resp>, ActionError> {
        if !verify(&req.signature, &req.raw, "secret") {
            return Err(ActionError::PreconditionFailed("invalid signature".into()));
        }
        // deduplicate via delivery id in headers...
        Ok(ActionResult::Success(Resp { accepted: true }))
    }
    async fn unsubscribe(&self) -> Result<(), ActionError> { Ok(()) }
}
```
