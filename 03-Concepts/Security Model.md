---
title: Security Model
tags: [nebula, docs, concept]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Security Model

**Nebula's security model provides defense-in-depth protection for workflows, actions, and data through multiple layers of authentication, authorization, encryption, and isolation.** Security is built into the framework, not added as an afterthought.

## Definition

Nebula's security model encompasses:

- **Authentication** — Verifying identity of users, services, and workflows
- **Authorization** — Controlling access to resources and operations
- **Encryption** — Protecting data at rest and in transit
- **Isolation** — Sandboxing workflows and actions
- **Auditing** — Recording all security-relevant events
- **Compliance** — Meeting regulatory requirements (GDPR, SOC 2, HIPAA, PCI DSS)

Security is **not** a single feature. It's a **comprehensive system** of overlapping protections.

## Why Security Matters

### The Problem with Traditional Workflow Security

Most workflow engines have weak security:

❌ **No authentication** — Anyone can trigger workflows
❌ **No authorization** — All users have full access
❌ **Unencrypted secrets** — Credentials stored in plaintext
❌ **No isolation** — Workflows can access each other's data
❌ **No audit trail** — Security events not logged
❌ **No compliance** — Can't meet regulatory requirements

**Real-world consequences**:
- API key leaked → entire system compromised
- No access control → internal users access sensitive data
- No audit trail → can't investigate security incidents
- No isolation → one malicious workflow compromises others
- No compliance → regulatory fines, loss of trust

### The Nebula Approach

Nebula's security model solves these problems:

✅ **Multi-layered authentication** — Users, services, workflows all authenticated
✅ **Fine-grained authorization** — RBAC and ABAC support
✅ **Encrypted credentials** — AES-256-GCM encryption
✅ **Sandboxed execution** — Workflows isolated from each other
✅ **Complete audit trail** — All security events logged
✅ **Compliance-ready** — Built-in support for regulations

## Core Principles

### 1. Defense in Depth

Multiple layers of security protect against different threats:

```
┌──────────────────────────────────────────┐
│ Layer 7: Compliance & Audit             │ GDPR, SOC 2, HIPAA
├──────────────────────────────────────────┤
│ Layer 6: Application Security           │ Input validation, output encoding
├──────────────────────────────────────────┤
│ Layer 5: Workflow Isolation             │ Sandboxing, resource limits
├──────────────────────────────────────────┤
│ Layer 4: Authorization                  │ RBAC, ABAC, least privilege
├──────────────────────────────────────────┤
│ Layer 3: Authentication                 │ Users, services, workflows
├──────────────────────────────────────────┤
│ Layer 2: Encryption                     │ At rest (AES-256), in transit (TLS)
├──────────────────────────────────────────┤
│ Layer 1: Network Security               │ Firewalls, VPC, private subnets
└──────────────────────────────────────────┘
```

**Why?** If one layer fails, others still provide protection.

### 2. Least Privilege

Users, services, and workflows get minimum required permissions:

```rust
// User can only execute specific workflows
let user_permissions = Permissions::new()
    .allow("workflow:execute", "order_processing")
    .allow("workflow:execute", "user_onboarding")
    .deny("workflow:create")
    .deny("workflow:delete");

// Service account can only access specific credentials
let service_permissions = Permissions::new()
    .allow("credential:read", "database_readonly")
    .deny("credential:read", "database_admin")
    .deny("credential:write");

// Workflow can only access scoped resources
let workflow_scope = Scope::new()
    .with_credentials(vec!["github_api", "slack_webhook"])
    .with_memory_limit(100_MB)
    .with_execution_timeout(Duration::from_secs(300));
```

**Why?** Limits blast radius if credentials compromised.

### 3. Zero Trust

Never trust, always verify:

```rust
// Every request authenticated and authorized
async fn execute_workflow(
    request: WorkflowRequest,
    auth_context: &AuthContext,
) -> Result<WorkflowExecution, SecurityError> {
    // Authenticate user
    let user = authenticate(auth_context).await?;

    // Authorize workflow execution
    authorize(&user, "workflow:execute", &request.workflow_id).await?;

    // Validate workflow definition
    validate_workflow_definition(&request.definition)?;

    // Verify resource access
    verify_resource_access(&user, &request.resources).await?;

    // Execute with isolation
    execute_isolated(request, &user).await
}
```

**Why?** No implicit trust, even for internal requests.

### 4. Secure by Default

Security features enabled out of the box:

```rust
// Default configuration is secure
let engine = NebulaEngine::builder()
    .with_auth_required(true)              // Authentication mandatory
    .with_encryption_at_rest(true)         // Credentials encrypted
    .with_tls_required(true)               // TLS for network traffic
    .with_audit_logging(true)              // All events logged
    .with_workflow_isolation(true)         // Sandboxed execution
    .with_resource_limits_enabled(true)    // DoS protection
    .build()?;

// Users must explicitly disable security (discouraged)
```

**Why?** Most users accept defaults. Make defaults secure.

### 5. Fail Securely

Security failures deny access, not grant it:

```rust
async fn authorize_action(
    user: &User,
    action: &str,
    resource: &str,
) -> Result<(), SecurityError> {
    // If authorization service fails, deny access (fail closed)
    match auth_service.check_permission(user, action, resource).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(SecurityError::Forbidden {
            user_id: user.id,
            action: action.to_string(),
            resource: resource.to_string(),
        }),
        Err(e) => {
            // Service failure = deny access + alert
            audit_log.security_event("authorization_service_failed", &e).await;
            alert_security_team("Authorization service down", &e).await;
            Err(SecurityError::AuthorizationUnavailable)
        }
    }
}
```

**Why?** Prefer security over availability when in doubt.

## Authentication

### User Authentication

Users authenticate via multiple methods:

```rust
pub enum AuthenticationMethod {
    /// Username and password
    Password {
        username: String,
        password_hash: String,
    },

    /// API key
    ApiKey {
        key_id: String,
        key_hash: String,
    },

    /// OAuth2 / OpenID Connect
    OAuth2 {
        provider: String,
        token: String,
    },

    /// Multi-factor authentication
    MFA {
        primary: Box<AuthenticationMethod>,
        second_factor: SecondFactor,
    },

    /// Mutual TLS (certificate-based)
    mTLS {
        certificate: X509Certificate,
    },
}

pub enum SecondFactor {
    TOTP { code: String },
    SMS { code: String },
    WebAuthn { assertion: Vec<u8> },
}
```

**Example: API Key Authentication**:
```rust
pub struct ApiKeyAuth;

impl Authenticator for ApiKeyAuth {
    async fn authenticate(&self, request: &Request) -> Result<User, AuthError> {
        // Extract API key from header
        let api_key = request
            .headers()
            .get("X-API-Key")
            .ok_or(AuthError::MissingCredentials)?;

        // Hash the key
        let key_hash = hash_api_key(api_key);

        // Lookup in database
        let user = user_store
            .find_by_api_key_hash(&key_hash)
            .await?
            .ok_or(AuthError::InvalidCredentials)?;

        // Check if key is active
        if !user.api_key_active {
            audit_log.auth_attempt_failed(
                "api_key_inactive",
                &user.id,
            ).await;
            return Err(AuthError::CredentialsRevoked);
        }

        // Log successful authentication
        audit_log.auth_success("api_key", &user.id).await;

        Ok(user)
    }
}
```

### Service Authentication

Services authenticate using service accounts:

```rust
#[derive(Debug)]
pub struct ServiceAccount {
    pub id: String,
    pub name: String,
    pub credentials: ServiceCredentials,
    pub permissions: Permissions,
    pub created_at: DateTime<Utc>,
}

pub enum ServiceCredentials {
    /// Client certificate (mTLS)
    Certificate {
        cert: X509Certificate,
        private_key: PrivateKey,
    },

    /// JWT with service account key
    JWT {
        key_id: String,
        private_key: PrivateKey,
    },

    /// Kubernetes service account token
    K8sServiceAccount {
        namespace: String,
        account_name: String,
    },
}

// Service authenticates with JWT
let token = jwt::encode(
    &jwt::Header::new(jwt::Algorithm::RS256),
    &Claims {
        iss: "service-account-id".to_string(),
        sub: "service-account-id".to_string(),
        aud: "nebula-api".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp(),
    },
    &service_account.private_key,
)?;
```

### Workflow Authentication

Workflows execute with authenticated identity:

```rust
pub struct WorkflowIdentity {
    /// Who triggered the workflow
    pub initiator: Principal,

    /// Service account running the workflow
    pub service_account: Option<ServiceAccount>,

    /// Workflow-specific identity
    pub workflow_id: String,

    /// Inherited permissions from initiator
    pub inherited_permissions: Permissions,

    /// Additional workflow-granted permissions
    pub workflow_permissions: Permissions,
}

pub enum Principal {
    User { user_id: String, username: String },
    Service { service_id: String, name: String },
    System { component: String },
}
```

## Authorization

### Role-Based Access Control (RBAC)

Users assigned roles with permissions:

```rust
#[derive(Debug)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub permissions: Vec<Permission>,
}

#[derive(Debug)]
pub struct Permission {
    pub action: String,       // e.g., "workflow:execute"
    pub resource: String,      // e.g., "workflow:order-processing"
    pub conditions: Vec<Condition>,
}

// Predefined roles
let admin = Role {
    id: "admin".into(),
    name: "Administrator".into(),
    permissions: vec![
        Permission::allow_all(),
    ],
};

let developer = Role {
    id: "developer".into(),
    name: "Developer".into(),
    permissions: vec![
        Permission::new("workflow:create"),
        Permission::new("workflow:read"),
        Permission::new("workflow:update"),
        Permission::new("workflow:execute"),
        Permission::new("credential:read").with_tag("dev"),
    ],
};

let operator = Role {
    id: "operator".into(),
    name: "Operator".into(),
    permissions: vec![
        Permission::new("workflow:read"),
        Permission::new("workflow:execute"),
        Permission::new("credential:read").with_tag("prod"),
    ],
};

// Assign role to user
user_store.assign_role(&user_id, &developer).await?;

// Check permission
if user.has_permission("workflow:execute", "order-processing")? {
    execute_workflow(workflow).await?;
}
```

### Attribute-Based Access Control (ABAC)

Context-aware authorization decisions:

```rust
pub struct AuthorizationContext {
    pub user: User,
    pub resource: Resource,
    pub action: String,
    pub environment: Environment,
}

pub struct Environment {
    pub ip_address: IpAddr,
    pub time: DateTime<Utc>,
    pub location: Option<String>,
    pub device_type: Option<String>,
}

// Policy: Only allow workflow execution during business hours from office IP
let policy = Policy::new("business-hours-only")
    .when(|ctx: &AuthorizationContext| {
        // Check time
        let hour = ctx.environment.time.hour();
        let is_business_hours = hour >= 9 && hour < 17;

        // Check IP address (office network)
        let is_office_ip = ctx.environment.ip_address
            .is_in_network("10.0.0.0/8");

        is_business_hours && is_office_ip
    })
    .then_allow("workflow:execute");

// Policy: Only allow credential access from specific locations
let geo_policy = Policy::new("geo-restriction")
    .when(|ctx: &AuthorizationContext| {
        ctx.environment.location
            .as_ref()
            .map(|loc| loc == "US" || loc == "EU")
            .unwrap_or(false)
    })
    .then_allow("credential:read");
```

### Resource Scopes

Resources isolated by scopes:

```rust
pub struct ResourceScope {
    pub workspace_id: String,
    pub environment: Environment,
    pub tags: HashMap<String, String>,
}

pub enum Environment {
    Development,
    Staging,
    Production,
}

// Workflows in different scopes are isolated
let dev_workflow = Workflow {
    scope: ResourceScope {
        workspace_id: "acme-corp".into(),
        environment: Environment::Development,
        tags: hashmap!{"team" => "backend"},
    },
    // ...
};

let prod_workflow = Workflow {
    scope: ResourceScope {
        workspace_id: "acme-corp".into(),
        environment: Environment::Production,
        tags: hashmap!{"team" => "backend"},
    },
    // ...
};

// Dev workflow cannot access prod credentials
let prod_cred = context.get_credential("prod-db").await; // Error: Scope mismatch
```

## Encryption

### Data at Rest

All sensitive data encrypted:

```rust
pub struct EncryptionConfig {
    /// Algorithm: AES-256-GCM (authenticated encryption)
    pub algorithm: EncryptionAlgorithm,

    /// Key derivation: PBKDF2 with high iteration count
    pub key_derivation: KeyDerivation,

    /// Unique IV per encrypted value
    pub iv_generation: IVGeneration,

    /// Encryption key storage
    pub key_storage: KeyStorage,
}

pub enum KeyStorage {
    /// Hardware Security Module
    HSM { hsm_config: HsmConfig },

    /// Cloud KMS (AWS, GCP, Azure)
    CloudKMS { kms_config: KmsConfig },

    /// Local encrypted keystore (dev only)
    Local { keystore_path: PathBuf },
}

// Encrypt credential
pub async fn encrypt_credential(
    credential: &Credential,
    encryption_key: &EncryptionKey,
) -> Result<EncryptedCredential, EncryptionError> {
    // Generate unique IV
    let iv = generate_random_iv();

    // Serialize credential
    let plaintext = serde_json::to_vec(credential)?;

    // Encrypt with AES-256-GCM
    let ciphertext = aes_gcm_encrypt(&plaintext, encryption_key, &iv)?;

    // Compute authentication tag
    let tag = compute_auth_tag(&ciphertext, encryption_key);

    Ok(EncryptedCredential {
        ciphertext,
        iv,
        tag,
        key_id: encryption_key.id.clone(),
        algorithm: EncryptionAlgorithm::AES256GCM,
    })
}
```

### Data in Transit

TLS for all network communication:

```rust
pub struct TlsConfig {
    /// Minimum TLS version
    pub min_version: TlsVersion,

    /// Allowed cipher suites (strong only)
    pub cipher_suites: Vec<CipherSuite>,

    /// Certificate validation
    pub cert_validation: CertValidation,

    /// Mutual TLS (optional)
    pub mtls_enabled: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            min_version: TlsVersion::TLS13,
            cipher_suites: vec![
                CipherSuite::TLS_AES_256_GCM_SHA384,
                CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            ],
            cert_validation: CertValidation::Strict,
            mtls_enabled: false,
        }
    }
}

// Create TLS-enabled HTTP client
let client = reqwest::Client::builder()
    .min_tls_version(reqwest::tls::Version::TLS_13)
    .https_only(true)
    .build()?;
```

## Isolation

### Workflow Sandboxing

Each workflow executes in isolated sandbox:

```rust
pub struct WorkflowSandbox {
    /// Memory limit
    pub memory_limit: usize,

    /// CPU limit (% of single core)
    pub cpu_limit: f32,

    /// Execution timeout
    pub timeout: Duration,

    /// Network access policy
    pub network_policy: NetworkPolicy,

    /// File system access policy
    pub filesystem_policy: FilesystemPolicy,

    /// Allowed system calls
    pub syscall_whitelist: Vec<Syscall>,
}

pub enum NetworkPolicy {
    /// No network access
    Deny,

    /// Allow specific hosts
    AllowList { hosts: Vec<String> },

    /// Deny specific hosts
    DenyList { hosts: Vec<String> },

    /// Allow all (not recommended)
    Allow,
}

pub enum FilesystemPolicy {
    /// No file system access
    Deny,

    /// Read-only access to specific paths
    ReadOnly { paths: Vec<PathBuf> },

    /// Read-write access to specific paths
    ReadWrite { paths: Vec<PathBuf> },
}

// Execute workflow in sandbox
let sandbox = WorkflowSandbox {
    memory_limit: 512 * 1024 * 1024,  // 512 MB
    cpu_limit: 0.5,  // 50% of one core
    timeout: Duration::from_secs(300),  // 5 minutes
    network_policy: NetworkPolicy::AllowList {
        hosts: vec![
            "api.github.com".into(),
            "api.stripe.com".into(),
        ],
    },
    filesystem_policy: FilesystemPolicy::ReadOnly {
        paths: vec![PathBuf::from("/etc/nebula/config")],
    },
    syscall_whitelist: vec![
        Syscall::Read,
        Syscall::Write,
        Syscall::Open,
        Syscall::Close,
        // No exec, fork, etc.
    ],
};

let result = execute_in_sandbox(workflow, sandbox).await?;
```

### Expression Sandboxing

Expressions cannot execute dangerous operations:

```rust
// Expression parser validates AST
pub fn validate_expression(expr: &Expr) -> Result<(), ValidationError> {
    match expr {
        // ❌ System calls not allowed
        Expr::FunctionCall { name: "system", .. } => {
            Err(ValidationError::ForbiddenFunction("system"))
        }

        // ❌ File access not allowed
        Expr::FunctionCall { name: "file.read", .. } => {
            Err(ValidationError::ForbiddenFunction("file.read"))
        }

        // ❌ Network access not allowed
        Expr::FunctionCall { name: "http.get", .. } => {
            Err(ValidationError::ForbiddenFunction("http.get"))
        }

        // ❌ Eval not allowed
        Expr::FunctionCall { name: "eval", .. } => {
            Err(ValidationError::ForbiddenFunction("eval"))
        }

        // ✅ Safe operations allowed
        Expr::FunctionCall { name, args } => {
            validate_safe_function(name)?;
            for arg in args {
                validate_expression(arg)?;
            }
            Ok(())
        }

        _ => Ok(()),
    }
}
```

## Input Validation

### Request Validation

All inputs validated before processing:

```rust
pub trait Validate {
    fn validate(&self) -> Result<(), ValidationError>;
}

impl Validate for WorkflowRequest {
    fn validate(&self) -> Result<(), ValidationError> {
        // Validate workflow ID
        if self.workflow_id.is_empty() {
            return Err(ValidationError::required_field("workflow_id"));
        }

        if self.workflow_id.len() > 256 {
            return Err(ValidationError::max_length("workflow_id", 256));
        }

        if !self.workflow_id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(ValidationError::invalid_format(
                "workflow_id",
                "alphanumeric, dash, underscore only"
            ));
        }

        // Validate parameters
        validate_json_depth(&self.parameters, 10)?;
        validate_json_size(&self.parameters, 1024 * 1024)?; // 1 MB max

        // Validate credentials list
        if self.credentials.len() > 100 {
            return Err(ValidationError::max_items("credentials", 100));
        }

        for cred_id in &self.credentials {
            validate_credential_id(cred_id)?;
        }

        Ok(())
    }
}

// Prevent deeply nested JSON (DoS attack)
fn validate_json_depth(value: &serde_json::Value, max_depth: usize) -> Result<(), ValidationError> {
    fn check_depth(value: &serde_json::Value, current_depth: usize, max_depth: usize) -> Result<(), ValidationError> {
        if current_depth > max_depth {
            return Err(ValidationError::max_depth_exceeded(max_depth));
        }

        match value {
            serde_json::Value::Object(map) => {
                for (_, v) in map {
                    check_depth(v, current_depth + 1, max_depth)?;
                }
            }
            serde_json::Value::Array(arr) => {
                for v in arr {
                    check_depth(v, current_depth + 1, max_depth)?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    check_depth(value, 0, max_depth)
}
```

### SQL Injection Prevention

Parameterized queries prevent SQL injection:

```rust
// ❌ VULNERABLE - Never do this
let query = format!(
    "SELECT * FROM users WHERE username = '{}'",
    user_input  // Attacker can inject: ' OR '1'='1
);

// ✅ SAFE - Use parameterized queries
let users = sqlx::query_as::<_, User>(
    "SELECT * FROM users WHERE username = $1"
)
.bind(user_input)  // Automatically escaped
.fetch_all(&pool)
.await?;
```

### XSS Prevention

Output encoding prevents cross-site scripting:

```rust
use html_escape::encode_text;

// ❌ VULNERABLE
let html = format!("<div>{}</div>", user_input);

// ✅ SAFE
let html = format!("<div>{}</div>", encode_text(user_input));

// Example:
// user_input = "<script>alert('XSS')</script>"
// Encoded:     "&lt;script&gt;alert('XSS')&lt;/script&gt;"
```

## Audit Logging

### Security Events

All security-relevant events logged:

```rust
#[derive(Debug, Serialize)]
pub struct SecurityEvent {
    pub event_id: String,
    pub event_type: SecurityEventType,
    pub timestamp: DateTime<Utc>,
    pub principal: Principal,
    pub resource: Option<String>,
    pub action: String,
    pub result: EventResult,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub metadata: HashMap<String, String>,
}

pub enum SecurityEventType {
    AuthenticationAttempt,
    AuthenticationSuccess,
    AuthenticationFailure,
    AuthorizationCheck,
    AuthorizationDenied,
    CredentialAccess,
    CredentialRotation,
    WorkflowExecution,
    PolicyViolation,
    SecurityAlert,
}

pub enum EventResult {
    Success,
    Failure { reason: String },
    Denied { reason: String },
}

// Log security event
audit_log.record(SecurityEvent {
    event_id: Uuid::new_v4().to_string(),
    event_type: SecurityEventType::CredentialAccess,
    timestamp: Utc::now(),
    principal: Principal::User {
        user_id: user.id.clone(),
        username: user.username.clone(),
    },
    resource: Some("credential:database-prod".to_string()),
    action: "read".to_string(),
    result: EventResult::Success,
    ip_address: Some(request.ip_address),
    user_agent: Some(request.user_agent.clone()),
    metadata: hashmap! {
        "workflow_id" => workflow.id.clone(),
    },
}).await?;
```

### Immutable Audit Trail

Audit logs are tamper-proof:

```rust
pub struct AuditLog {
    /// Events signed with HMAC
    hmac_key: SecretKey,

    /// Events stored in append-only log
    storage: AppendOnlyStorage,

    /// Periodic merkle tree snapshots
    merkle_tree: MerkleTree,
}

impl AuditLog {
    pub async fn record(&self, event: SecurityEvent) -> Result<(), AuditError> {
        // Serialize event
        let event_json = serde_json::to_string(&event)?;

        // Sign event with HMAC
        let signature = hmac_sha256(&event_json, &self.hmac_key);

        // Create signed entry
        let entry = SignedLogEntry {
            event: event_json,
            signature,
            timestamp: Utc::now(),
        };

        // Append to log (cannot modify previous entries)
        self.storage.append(&entry).await?;

        // Update merkle tree
        self.merkle_tree.add_leaf(hash(&entry)).await?;

        Ok(())
    }

    // Verify log integrity
    pub async fn verify_integrity(&self) -> Result<bool, AuditError> {
        // Verify merkle tree
        let is_valid = self.merkle_tree.verify().await?;

        if !is_valid {
            alert_security_team("Audit log tampering detected!").await;
        }

        Ok(is_valid)
    }
}
```

## Threat Model

### Threats

Nebula protects against these threats:

| Threat | Mitigation |
|--------|------------|
| **Credential theft** | Encryption at rest (AES-256-GCM), access control, audit logging |
| **Unauthorized workflow execution** | Authentication, RBAC/ABAC authorization |
| **Privilege escalation** | Least privilege, scope isolation, permission boundaries |
| **Code injection** | Input validation, expression sandboxing, parameterized queries |
| **Man-in-the-middle** | TLS 1.3, certificate pinning, mTLS |
| **Denial of service** | Rate limiting, resource limits, timeout enforcement |
| **Data exfiltration** | Network policies, audit logging, data classification |
| **Insider threats** | Audit trail, least privilege, separation of duties |
| **Supply chain attacks** | Dependency scanning, signature verification |

### Attack Scenarios

**Scenario 1: Stolen API Key**

1. Attacker obtains API key
2. Attempts to execute workflow
3. ✅ Rate limiting detects unusual activity
4. ✅ Audit log records all attempts
5. ✅ Security team alerted
6. ✅ API key rotated

**Scenario 2: Malicious Expression**

1. Attacker submits expression: `${system("rm -rf /")}`
2. ✅ Expression parser rejects (system() forbidden)
3. ✅ Audit log records attempt
4. ✅ User account flagged for review

**Scenario 3: Privilege Escalation Attempt**

1. Developer tries to access production credentials
2. ✅ Authorization check fails (scope mismatch)
3. ✅ Audit log records denied access
4. ✅ Security team notified

## Best Practices

### Authentication

- ✅ **Enforce strong passwords** — Min 12 chars, complexity requirements
- ✅ **Enable MFA** — For all human users
- ✅ **Use service accounts** — For automation, not personal credentials
- ✅ **Rotate credentials** — Regular rotation (90 days or less)
- ✅ **Monitor for breaches** — Check against known breached credentials
- ❌ **Don't store passwords in plaintext** — Use bcrypt/argon2
- ❌ **Don't share credentials** — One credential per user/service

### Authorization

- ✅ **Apply least privilege** — Minimum required permissions
- ✅ **Use RBAC for roles** — Standard role definitions
- ✅ **Use ABAC for dynamic** — Context-aware decisions
- ✅ **Review permissions regularly** — Quarterly access reviews
- ✅ **Separate production access** — Strict controls on prod
- ❌ **Don't give admin access by default** — Require justification
- ❌ **Don't bypass authorization** — Even for "trusted" requests

### Encryption

- ✅ **Encrypt all credentials** — AES-256-GCM minimum
- ✅ **Use TLS 1.3** — For all network communication
- ✅ **Store keys in HSM/KMS** — Not in application code
- ✅ **Rotate encryption keys** — Periodic key rotation
- ✅ **Use unique IVs** — Never reuse initialization vectors
- ❌ **Don't use weak algorithms** — No DES, MD5, SHA1
- ❌ **Don't hardcode keys** — Use key management systems

### Auditing

- ✅ **Log all security events** — Authentication, authorization, access
- ✅ **Make logs immutable** — Append-only storage
- ✅ **Monitor logs actively** — Real-time alerting
- ✅ **Retain logs long-term** — 1+ years for compliance
- ✅ **Review logs regularly** — Look for anomalies
- ❌ **Don't log secrets** — Credentials auto-redacted
- ❌ **Don't make logs world-readable** — Restrict access

## Compliance

### GDPR (General Data Protection Regulation)

- ✅ **Encryption** — Personal data encrypted at rest
- ✅ **Access control** — Only authorized access to personal data
- ✅ **Audit trail** — Log all access to personal data
- ✅ **Right to deletion** — Can delete user data
- ✅ **Data minimization** — Only collect necessary data
- ✅ **Breach notification** — Alert within 72 hours

### SOC 2

- ✅ **Access control** — RBAC/ABAC implemented
- ✅ **Encryption** — Data encrypted at rest and in transit
- ✅ **Audit logging** — Complete audit trail
- ✅ **Change management** — Version control, approvals
- ✅ **Incident response** — Security incident procedures

### HIPAA (Health Insurance Portability and Accountability Act)

- ✅ **Encryption** — PHI encrypted with AES-256
- ✅ **Access control** — Role-based access to PHI
- ✅ **Audit trail** — All PHI access logged
- ✅ **Automatic logoff** — Session timeouts
- ✅ **Integrity controls** — Tamper-proof audit logs

### PCI DSS (Payment Card Industry Data Security Standard)

- ✅ **Encryption** — Card data encrypted
- ✅ **Access control** — Least privilege for card data
- ✅ **Network segmentation** — Isolated cardholder data environment
- ✅ **Vulnerability management** — Regular security scans
- ✅ **Monitoring** — Real-time alerting on security events

## Related Concepts

- [[Credentials]] — Secure credential management
- [[Error Handling]] — Security error handling
- [[Workflows]] — Workflow isolation
- [[Actions]] — Action security

## Implementation Guides

- [[02-Crates/nebula-credential/README|nebula-credential]] — Credential security
- [[02-Crates/nebula-credential/Security/README|Security]] — Detailed security documentation
- [[Best Practices#Security]] — Security best practices

---

**Next**: Learn about [[State Management]] or explore [[Resource Scopes]].
