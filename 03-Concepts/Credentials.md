---
title: Credentials
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Credentials

**Credentials are secure, typed representations of authentication data that actions use to access external systems.** Nebula's credential system ensures secrets never appear in logs, configurations, or traces while making them easily accessible at runtime.

## Definition

In Nebula, credentials are:

- **Encrypted at rest** — AES-256-GCM encryption for stored credentials
- **Injected at runtime** — Securely passed to actions via context
- **Never logged** — Automatically redacted from logs and traces
- **Versioned** — Support for rotation and rollback
- **Scoped** — Limited to specific workflows or actions
- **Auditable** — Access tracked for compliance

Credentials are **not** plain text strings or environment variables. They are structured, encrypted objects with lifecycle management.

## Why Credentials Matter

### The Problem with Traditional Secret Management

Most systems handle secrets poorly:

❌ **Hardcoded in code** — Secrets committed to version control
❌ **Environment variables** — Visible in process listings
❌ **Configuration files** — Unencrypted on disk
❌ **Logged accidentally** — Secrets leaked in application logs
❌ **No rotation** — Secrets never updated
❌ **No audit trail** — Unknown who accessed what

**Real-world consequences**:
- API keys leaked on GitHub → compromised accounts
- Database passwords in logs → data breaches
- Expired credentials → production outages
- Shared credentials → impossible to revoke access

### The Nebula Approach

Nebula's credential system solves these problems:

✅ **Never in version control** — Stored separately from code
✅ **Encrypted at rest** — AES-256-GCM with unique keys
✅ **Auto-redacted from logs** — Marked fields never logged
✅ **Automatic rotation** — Update without redeploying
✅ **Complete audit trail** — Who accessed what, when
✅ **Scoped access** — Workflows only access what they need

## Core Principles

### 1. Separation of Secrets and Code

**Code** (in version control):
```rust
async fn fetch_data(context: &Context) -> Result<Data> {
    // No hardcoded secrets!
    let api_cred = context.get_credential("github_api").await?;
    // Use credential...
}
```

**Credentials** (in secure storage):
```
Stored separately in:
- AWS Secrets Manager
- HashiCorp Vault
- Azure Key Vault
- Kubernetes Secrets
- Encrypted local storage
```

Code and secrets are completely decoupled.

### 2. Encryption in Transit and at Rest

**At rest**: Credentials encrypted with AES-256-GCM before storage
**In transit**: TLS for network communication
**In memory**: Decrypted only when needed, zeroized after use

Even if storage is compromised, credentials remain secure.

### 3. Automatic Redaction

Fields marked `#[secret]` are automatically redacted:

```rust
#[derive(Credential)]
struct ApiCredential {
    #[secret]
    api_key: String,  // Redacted in logs

    endpoint: String,  // Not secret, can be logged
}

// Logs show: ApiCredential { api_key: [REDACTED], endpoint: "api.example.com" }
```

No chance of accidentally logging secrets.

### 4. Lifecycle Management

Credentials have a managed lifecycle:

```
Create → Store → Retrieve → Use → Rotate → Expire → Archive
```

- **Create**: Define credential type and values
- **Store**: Encrypt and persist to secure storage
- **Retrieve**: Decrypt and inject into action context
- **Use**: Action uses credential (automatically redacted)
- **Rotate**: Update to new values without downtime
- **Expire**: Credentials can have expiration dates
- **Archive**: Old credentials retained for audit

### 5. Least Privilege Access

Credentials are scoped to minimize blast radius:

- **Workflow-scoped**: Only accessible by specific workflows
- **Action-scoped**: Only accessible by specific actions
- **Time-scoped**: Temporary credentials with expiration
- **Environment-scoped**: Different credentials for dev/staging/prod

If one workflow is compromised, others remain secure.

## Credential Types

### Static Credentials

**What**: Fixed secrets that don't change frequently

**Examples**:
- API keys (Stripe, SendGrid, GitHub)
- Database passwords
- TLS/SSL certificates
- SSH keys

**Characteristics**:
- Simple to use
- Require manual rotation
- Good for services without auto-rotation

### Dynamic Credentials

**What**: Short-lived credentials generated on-demand

**Examples**:
- OAuth2 access tokens
- AWS STS temporary credentials
- JWT tokens with expiration

**Characteristics**:
- Auto-expire after time limit
- Automatically refreshed
- Reduced risk if compromised

### Composite Credentials

**What**: Multiple credentials combined

**Examples**:
- OAuth2 (access token + refresh token + expiry)
- Database (host + port + username + password)
- AWS (access key ID + secret access key + session token + region)

**Characteristics**:
- Logical grouping of related secrets
- All fields encrypted together
- Versioned as a unit

## Credential Lifecycle

### Creation

Define credential type and initial values:

```rust
#[derive(Credential)]
struct SlackCredential {
    #[secret]
    bot_token: String,
    workspace_id: String,
}

let cred = SlackCredential {
    bot_token: "xoxb-...".into(),
    workspace_id: "T123ABC".into(),
};
```

### Storage

Encrypt and persist to storage backend:

```rust
manager.store("slack_bot", cred).await?;
```

Credential is encrypted with unique key before storage.

### Retrieval

Decrypt and inject into action:

```rust
let slack: SlackCredential = context.get_credential("slack_bot").await?;
```

Credential decrypted in memory, passed to action.

### Usage

Action uses credential (automatically secured):

```rust
// bot_token automatically redacted if logged
let client = SlackClient::new(&slack.bot_token);
```

### Rotation

Update credential without downtime:

```rust
let new_cred = SlackCredential {
    bot_token: "xoxb-new-token".into(),
    workspace_id: "T123ABC".into(),
};

manager.rotate("slack_bot", new_cred).await?;
```

Old credential still works briefly, then new one takes over.

### Expiration

Credentials can auto-expire:

```rust
#[derive(Credential)]
struct TemporaryToken {
    #[secret]
    token: String,
    expires_at: DateTime<Utc>,
}

// Automatically refreshed before expiration
let token = context.get_credential_auto_refresh("temp_token").await?;
```

### Archival

Old credentials retained for audit:

```rust
// Previous versions accessible for audit
let history = manager.get_credential_history("slack_bot").await?;
```

## Storage Backends

Nebula supports multiple credential storage backends:

### Local Storage (Development)

Encrypted files on disk:
- Simple setup
- No external dependencies
- Suitable for development/testing
- Not recommended for production

### AWS Secrets Manager

Managed secret storage:
- Automatic encryption
- Auto-rotation support
- IAM-based access control
- Audit logging via CloudTrail

### HashiCorp Vault

Enterprise secret management:
- Dynamic secrets
- Secret leasing
- Detailed audit logs
- High availability

### Azure Key Vault

Azure-native secret storage:
- HSM-backed encryption
- Azure AD integration
- Compliance certifications
- Geo-replication

### Kubernetes Secrets

Container-native secrets:
- Integrated with K8s RBAC
- Automatic mounting
- Namespace isolation
- Works with service accounts

See [[02-Crates/nebula-credential/Integrations/README|Integrations]] for setup guides.

## Security Model

### Encryption

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key derivation**: PBKDF2 with high iteration count
- **IV**: Random, unique per credential
- **Key storage**: Separate from credential data (HSM support)

### Access Control

**Role-Based Access Control (RBAC)**:
- Roles: admin, developer, workflow
- Permissions: create, read, update, delete
- Scoping: workspace, environment, workflow

**Attribute-Based Access Control (ABAC)**:
- Context-aware decisions
- Time-based access
- Location-based restrictions

### Audit Logging

Every credential access logged:
- **Who**: User or workflow ID
- **What**: Credential ID
- **When**: Timestamp with timezone
- **Where**: IP address, location
- **Result**: Success or failure

Logs immutable and tamper-proof.

## Integration with Actions

### Runtime Injection

Actions receive credentials via context:

```rust
async fn execute(&self, input: Input, context: &Context) -> Result<Output> {
    // Type-safe credential retrieval
    let db: PostgresCredential = context.get_credential("postgres").await?;

    // Use credential
    let pool = PgPool::connect(&db.connection_string()).await?;
    // ...
}
```

### Automatic Redaction

Credentials never leak in logs:

```rust
// This is safe - secret fields auto-redacted
context.log_info(&format!("Using credential: {:?}", db));
// Output: "Using credential: PostgresCredential { host: localhost, password: [REDACTED] }"
```

### Caching

Credentials cached for performance:

```rust
// First call: fetch from storage
let cred1 = context.get_credential("api_key").await?;

// Second call: served from cache (fast)
let cred2 = context.get_credential("api_key").await?;
```

Cache TTL configurable, invalidated on rotation.

## Rotation Strategies

### Manual Rotation

Operator updates credentials:

```rust
manager.rotate("api_key", new_credential).await?;
```

**Use when**: Credentials rarely change, manual control preferred.

### Scheduled Rotation

Auto-rotate on schedule:

```rust
manager.schedule_rotation("database", Duration::days(90)).await?;
```

**Use when**: Compliance requires periodic rotation (e.g., every 90 days).

### Event-Triggered Rotation

Rotate on specific events:

```rust
// Rotate if credential compromised
on_security_event(|event| {
    if event.credential_compromised {
        manager.emergency_rotate(&event.credential_id).await?;
    }
});
```

**Use when**: Security events require immediate rotation.

### Auto-Refresh

Credentials refresh themselves:

```rust
#[derive(Credential)]
struct OAuth2Credential {
    access_token: String,
    refresh_token: String,
    expires_at: DateTime<Utc>,
}

impl SelfRefreshing for OAuth2Credential {
    async fn refresh(&self) -> Result<Self> {
        // Use refresh_token to get new access_token
    }
}
```

**Use when**: Credentials have built-in refresh mechanism (OAuth2, AWS STS).

## Best Practices

### Storage

- ✅ Use managed storage (AWS, Vault, Azure) in production
- ✅ Enable encryption at rest
- ✅ Separate encryption keys from credential data
- ✅ Use HSM for key storage when possible
- ❌ Don't store credentials in version control
- ❌ Don't use plain text storage

### Access

- ✅ Use least privilege (minimum required access)
- ✅ Scope credentials to specific workflows
- ✅ Enable audit logging
- ✅ Review access logs regularly
- ❌ Don't share credentials across environments
- ❌ Don't use long-lived static credentials if avoidable

### Rotation

- ✅ Rotate credentials regularly (90 days or less)
- ✅ Test rotation process before emergency
- ✅ Have rollback plan
- ✅ Notify affected teams before rotation
- ❌ Don't rotate without testing
- ❌ Don't delete old credentials immediately (keep for audit)

### Testing

- ✅ Use test credentials for dev/staging
- ✅ Test with expired credentials
- ✅ Test rotation scenarios
- ✅ Validate redaction works
- ❌ Don't use production credentials in tests
- ❌ Don't commit test credentials to git

## Compliance

### GDPR

- Credentials containing personal data encrypted
- Access logs for audit trail
- Right to deletion (credential archival)
- Breach notification (audit logs)

### SOC 2

- Encryption at rest and in transit
- Access control and audit logging
- Credential rotation policies
- Incident response procedures

### HIPAA

- PHI protection via encryption
- Access controls and audit trails
- Credential lifecycle management
- Security incident procedures

### PCI DSS

- Encryption for payment credentials
- Access control requirements
- Key management procedures
- Audit logging compliance

See [[02-Crates/nebula-credential/Advanced/ComplianceIntegration|Compliance Integration]] for details.

## Related Concepts

- [[Actions]] — How actions consume credentials
- [[Security Model]] — Overall security architecture
- [[Error Handling]] — Handling credential access errors
- [[Resource Scopes]] — Credential scoping model

## Implementation Guides

- [[02-Crates/nebula-credential/README|nebula-credential]] — Credential management framework
- [[02-Crates/nebula-credential/Getting-Started/QuickStart|Quick Start]] — First credential setup
- [[02-Crates/nebula-credential/How-To/RotateCredentials|Rotation Guide]] — Rotation strategies
- [[02-Crates/nebula-credential/Examples/README|Examples]] — Real-world credential types

---

**Next**: Learn about [[02-Crates/nebula-credential/README|nebula-credential]] or explore [[Security Model]].
