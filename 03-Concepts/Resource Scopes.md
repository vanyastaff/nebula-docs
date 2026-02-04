---
title: Resource Scopes
tags: [nebula, concepts, resource-management, isolation, multi-tenancy]
status: published
created: 2025-08-17
updated: 2025-11-09
---

# Resource Scopes

**Resource Scopes** define boundaries for organizing, isolating, and controlling access to resources in Nebula. They provide logical containers that group [[Workflows]], [[Actions]], [[Credentials]], and other resources, enabling multi-tenancy, environment separation, and fine-grained access control.

## Why Resource Scopes Matter

In production workflow automation systems, you need to:

1. **Isolate tenants** - Keep different customers' workflows and data completely separated
2. **Separate environments** - Development, staging, and production must not interfere with each other
3. **Control access** - Users should only access resources they're authorized for
4. **Organize at scale** - Manage hundreds of workflows across teams and projects
5. **Ensure compliance** - Meet regulatory requirements for data isolation (GDPR, HIPAA, SOC 2)

Without proper scoping, you risk:
- **Data leakage** between customers
- **Production incidents** from development testing
- **Security breaches** from overly broad permissions
- **Operational chaos** from disorganized resources

**Resource Scopes solve this** by providing hierarchical, enforceable boundaries with clear ownership and access control.

## Core Principles

### 1. Hierarchical Organization

Scopes are organized in a tree hierarchy, with each scope inheriting policies from its parent:

```
Organization
├── Workspace: Engineering
│   ├── Environment: Development
│   ├── Environment: Staging
│   └── Environment: Production
└── Workspace: Marketing
    ├── Environment: Development
    └── Environment: Production
```

**Why**: Hierarchies allow centralized policy management with local customization.

### 2. Default Deny

By default, resources in one scope cannot access resources in another scope unless explicitly granted.

```rust
// Workflow in workspace A cannot access credentials in workspace B
let credential = credential_store
    .get("workspace_b_credential")
    .await?;  // ❌ Error: Permission denied
```

**Why**: Prevents accidental cross-scope access and data leakage.

### 3. Scope Inheritance

Child scopes inherit permissions and configurations from parent scopes, but can override them:

```rust
pub struct ScopePolicy {
    pub parent_scope: Option<ScopeId>,
    pub inherited_policies: Vec<Policy>,
    pub overrides: HashMap<String, PolicyOverride>,
}
```

**Why**: Enables centralized defaults with local customization flexibility.

### 4. Resource Affinity

Resources are bound to exactly one scope and cannot exist in multiple scopes simultaneously:

```rust
pub struct Workflow {
    pub id: String,
    pub scope: ScopeId,  // Exactly one scope
    // ...
}
```

**Why**: Ensures clear ownership and prevents ambiguity in access control.

### 5. Scope Immutability

Once a resource is created in a scope, it cannot be moved to a different scope (can only be cloned):

```rust
impl WorkflowStore {
    pub async fn move_workflow(&self, workflow_id: &str, new_scope: ScopeId)
        -> Result<(), StoreError>
    {
        Err(StoreError::OperationNotSupported(
            "Workflows cannot be moved between scopes. Use clone_to_scope instead.".into()
        ))
    }
}
```

**Why**: Prevents security issues from scope migration and maintains audit trail integrity.

## Scope Types

Nebula supports multiple scope types that can be composed hierarchically:

### 1. Organization Scope

The root scope representing an entire organization or tenant:

```rust
pub struct Organization {
    pub id: String,
    pub name: String,
    pub owner: UserId,
    pub created_at: DateTime<Utc>,
    pub billing_plan: BillingPlan,
    pub global_policies: Vec<Policy>,
}

impl Organization {
    pub async fn create(name: &str, owner: UserId) -> Result<Self, ScopeError> {
        let org = Organization {
            id: format!("org_{}", Uuid::new_v4()),
            name: name.to_string(),
            owner,
            created_at: Utc::now(),
            billing_plan: BillingPlan::Free,
            global_policies: vec![
                Policy::RequireEncryption,
                Policy::AuditAllActions,
            ],
        };

        // Create default workspace
        Workspace::create(&org.id, "default").await?;

        Ok(org)
    }
}
```

**Use cases**:
- Multi-tenant SaaS platforms
- Enterprise installations with multiple business units
- Root-level policies and billing

### 2. Workspace Scope

A logical grouping within an organization, typically aligned with teams or projects:

```rust
pub struct Workspace {
    pub id: String,
    pub organization_id: String,
    pub name: String,
    pub description: Option<String>,
    pub members: Vec<WorkspaceMember>,
    pub settings: WorkspaceSettings,
}

pub struct WorkspaceSettings {
    pub default_timeout: Duration,
    pub max_parallel_workflows: u32,
    pub allowed_action_types: Vec<String>,
    pub resource_quotas: ResourceQuotas,
}

impl Workspace {
    pub async fn create(org_id: &str, name: &str) -> Result<Self, ScopeError> {
        let workspace = Workspace {
            id: format!("ws_{}", Uuid::new_v4()),
            organization_id: org_id.to_string(),
            name: name.to_string(),
            description: None,
            members: vec![],
            settings: WorkspaceSettings::default(),
        };

        // Create default environments
        Environment::create(&workspace.id, "development").await?;
        Environment::create(&workspace.id, "production").await?;

        Ok(workspace)
    }

    pub async fn add_member(
        &mut self,
        user_id: UserId,
        role: WorkspaceRole
    ) -> Result<(), ScopeError> {
        if self.members.iter().any(|m| m.user_id == user_id) {
            return Err(ScopeError::MemberAlreadyExists);
        }

        self.members.push(WorkspaceMember {
            user_id,
            role,
            joined_at: Utc::now(),
        });

        Ok(())
    }
}
```

**Use cases**:
- Team-based resource isolation
- Project-specific workflow collections
- Department-level access control

### 3. Environment Scope

Represents deployment environments with different configurations and policies:

```rust
pub struct Environment {
    pub id: String,
    pub workspace_id: String,
    pub name: String,
    pub environment_type: EnvironmentType,
    pub config: EnvironmentConfig,
}

pub enum EnvironmentType {
    Development,
    Staging,
    Production,
    Custom(String),
}

pub struct EnvironmentConfig {
    pub allow_debug_mode: bool,
    pub auto_approve_workflows: bool,
    pub require_approval_for_credentials: bool,
    pub retention_days: u32,
    pub alert_channels: Vec<String>,
}

impl Environment {
    pub async fn create(workspace_id: &str, name: &str) -> Result<Self, ScopeError> {
        let env_type = match name.to_lowercase().as_str() {
            "development" | "dev" => EnvironmentType::Development,
            "staging" | "stage" => EnvironmentType::Staging,
            "production" | "prod" => EnvironmentType::Production,
            _ => EnvironmentType::Custom(name.to_string()),
        };

        let config = match env_type {
            EnvironmentType::Development => EnvironmentConfig {
                allow_debug_mode: true,
                auto_approve_workflows: true,
                require_approval_for_credentials: false,
                retention_days: 7,
                alert_channels: vec![],
            },
            EnvironmentType::Production => EnvironmentConfig {
                allow_debug_mode: false,
                auto_approve_workflows: false,
                require_approval_for_credentials: true,
                retention_days: 90,
                alert_channels: vec!["slack://alerts".to_string()],
            },
            _ => EnvironmentConfig::default(),
        };

        Ok(Environment {
            id: format!("env_{}", Uuid::new_v4()),
            workspace_id: workspace_id.to_string(),
            name: name.to_string(),
            environment_type: env_type,
            config,
        })
    }
}
```

**Use cases**:
- SDLC stage separation (dev/staging/prod)
- Environment-specific configurations
- Progressive rollout and testing

### 4. Namespace Scope

Fine-grained logical partitions within an environment for organizing related resources:

```rust
pub struct Namespace {
    pub id: String,
    pub environment_id: String,
    pub name: String,
    pub tags: HashMap<String, String>,
    pub resource_limits: ResourceLimits,
}

pub struct ResourceLimits {
    pub max_workflows: Option<u32>,
    pub max_credentials: Option<u32>,
    pub max_concurrent_executions: Option<u32>,
    pub cpu_quota: Option<f32>,
    pub memory_quota: Option<ByteSize>,
}

impl Namespace {
    pub fn new(environment_id: &str, name: &str) -> Self {
        Namespace {
            id: format!("ns_{}", Uuid::new_v4()),
            environment_id: environment_id.to_string(),
            name: name.to_string(),
            tags: HashMap::new(),
            resource_limits: ResourceLimits::default(),
        }
    }

    pub fn with_tags(mut self, tags: HashMap<String, String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.resource_limits = limits;
        self
    }
}
```

**Use cases**:
- Microservice-aligned workflow groups
- Feature-based organization
- Resource quota enforcement

## Scope Hierarchy and Resolution

### Scope Path

Resources are addressed using hierarchical scope paths:

```rust
pub struct ScopePath {
    pub organization: String,
    pub workspace: Option<String>,
    pub environment: Option<String>,
    pub namespace: Option<String>,
}

impl ScopePath {
    pub fn parse(path: &str) -> Result<Self, ScopeError> {
        // Parse paths like: "org/workspace/environment/namespace"
        let parts: Vec<&str> = path.split('/').collect();

        match parts.len() {
            1 => Ok(ScopePath {
                organization: parts[0].to_string(),
                workspace: None,
                environment: None,
                namespace: None,
            }),
            2 => Ok(ScopePath {
                organization: parts[0].to_string(),
                workspace: Some(parts[1].to_string()),
                environment: None,
                namespace: None,
            }),
            3 => Ok(ScopePath {
                organization: parts[0].to_string(),
                workspace: Some(parts[1].to_string()),
                environment: Some(parts[2].to_string()),
                namespace: None,
            }),
            4 => Ok(ScopePath {
                organization: parts[0].to_string(),
                workspace: Some(parts[1].to_string()),
                environment: Some(parts[2].to_string()),
                namespace: Some(parts[3].to_string()),
            }),
            _ => Err(ScopeError::InvalidPath(path.to_string())),
        }
    }

    pub fn to_string(&self) -> String {
        let mut parts = vec![self.organization.clone()];

        if let Some(ws) = &self.workspace {
            parts.push(ws.clone());
        }
        if let Some(env) = &self.environment {
            parts.push(env.clone());
        }
        if let Some(ns) = &self.namespace {
            parts.push(ns.clone());
        }

        parts.join("/")
    }
}

// Usage examples:
// "acme"                           → Organization only
// "acme/engineering"               → Organization + Workspace
// "acme/engineering/production"    → Organization + Workspace + Environment
// "acme/engineering/production/api"→ Full path with namespace
```

### Scope Resolution

When accessing a resource, Nebula resolves the scope path and checks permissions:

```rust
pub struct ScopeResolver {
    org_store: Arc<OrganizationStore>,
    workspace_store: Arc<WorkspaceStore>,
    environment_store: Arc<EnvironmentStore>,
    namespace_store: Arc<NamespaceStore>,
}

impl ScopeResolver {
    pub async fn resolve(&self, path: &ScopePath) -> Result<ResolvedScope, ScopeError> {
        // Resolve organization
        let org = self.org_store
            .get(&path.organization)
            .await?
            .ok_or(ScopeError::OrganizationNotFound)?;

        // Resolve workspace if specified
        let workspace = if let Some(ws_name) = &path.workspace {
            Some(self.workspace_store
                .get_by_name(&org.id, ws_name)
                .await?
                .ok_or(ScopeError::WorkspaceNotFound)?)
        } else {
            None
        };

        // Resolve environment if specified
        let environment = if let Some(env_name) = &path.environment {
            let ws = workspace.as_ref()
                .ok_or(ScopeError::MissingWorkspace)?;
            Some(self.environment_store
                .get_by_name(&ws.id, env_name)
                .await?
                .ok_or(ScopeError::EnvironmentNotFound)?)
        } else {
            None
        };

        // Resolve namespace if specified
        let namespace = if let Some(ns_name) = &path.namespace {
            let env = environment.as_ref()
                .ok_or(ScopeError::MissingEnvironment)?;
            Some(self.namespace_store
                .get_by_name(&env.id, ns_name)
                .await?
                .ok_or(ScopeError::NamespaceNotFound)?)
        } else {
            None
        };

        Ok(ResolvedScope {
            organization: org,
            workspace,
            environment,
            namespace,
        })
    }

    pub async fn check_access(
        &self,
        user: &User,
        scope: &ResolvedScope,
        permission: Permission,
    ) -> Result<bool, ScopeError> {
        // Check organization-level access
        if !self.has_org_permission(user, &scope.organization, permission).await? {
            return Ok(false);
        }

        // Check workspace-level access if workspace is specified
        if let Some(workspace) = &scope.workspace {
            if !self.has_workspace_permission(user, workspace, permission).await? {
                return Ok(false);
            }
        }

        // Environment and namespace checks follow similar pattern...

        Ok(true)
    }
}
```

## Resource Isolation

### Multi-Tenancy Isolation

Nebula ensures complete isolation between organizations:

```rust
pub struct IsolationEnforcer {
    scope_resolver: Arc<ScopeResolver>,
}

impl IsolationEnforcer {
    pub async fn enforce_isolation<T: ScopedResource>(
        &self,
        user: &User,
        resource: &T,
        action: Action,
    ) -> Result<(), IsolationError> {
        // Get user's scope context
        let user_scope = self.scope_resolver
            .get_user_scope(user)
            .await?;

        // Get resource's scope
        let resource_scope = resource.scope();

        // Check if scopes match at organization level
        if user_scope.organization != resource_scope.organization {
            return Err(IsolationError::CrossTenantAccess {
                user_org: user_scope.organization,
                resource_org: resource_scope.organization,
            });
        }

        // Check workspace-level isolation
        if user_scope.workspace != resource_scope.workspace {
            // Cross-workspace access requires explicit permission
            if !self.has_cross_workspace_permission(user, &resource_scope, action).await? {
                return Err(IsolationError::CrossWorkspaceAccess);
            }
        }

        Ok(())
    }
}

pub trait ScopedResource {
    fn scope(&self) -> &ScopeId;
    fn can_share_across_scopes(&self) -> bool {
        false  // Default: resources cannot be shared
    }
}

impl ScopedResource for Workflow {
    fn scope(&self) -> &ScopeId {
        &self.scope
    }
}

impl ScopedResource for Credential {
    fn scope(&self) -> &ScopeId {
        &self.scope
    }

    fn can_share_across_scopes(&self) -> bool {
        false  // Credentials are NEVER shared across scopes
    }
}
```

### Environment Isolation

Environments within the same workspace are isolated by default:

```rust
pub struct EnvironmentIsolation {
    pub allow_cross_environment_access: bool,
    pub allow_promotion: bool,
    pub promotion_path: Vec<String>,
}

impl EnvironmentIsolation {
    pub fn production_isolation() -> Self {
        EnvironmentIsolation {
            allow_cross_environment_access: false,
            allow_promotion: true,
            promotion_path: vec![
                "development".to_string(),
                "staging".to_string(),
                "production".to_string(),
            ],
        }
    }

    pub async fn can_promote(
        &self,
        workflow: &Workflow,
        from_env: &Environment,
        to_env: &Environment,
    ) -> Result<bool, IsolationError> {
        if !self.allow_promotion {
            return Ok(false);
        }

        // Check promotion path
        let from_idx = self.promotion_path
            .iter()
            .position(|e| e == &from_env.name)
            .ok_or(IsolationError::InvalidPromotionSource)?;

        let to_idx = self.promotion_path
            .iter()
            .position(|e| e == &to_env.name)
            .ok_or(IsolationError::InvalidPromotionTarget)?;

        // Can only promote forward in the path
        if to_idx <= from_idx {
            return Err(IsolationError::BackwardPromotion);
        }

        // Can only promote to the next environment in sequence
        if to_idx != from_idx + 1 {
            return Err(IsolationError::SkippedPromotionStage);
        }

        Ok(true)
    }
}
```

## Credential Scoping

[[Credentials]] are strictly scoped and cannot be shared across scopes:

```rust
pub struct ScopedCredentialStore {
    store: Arc<CredentialStore>,
    scope_resolver: Arc<ScopeResolver>,
}

impl ScopedCredentialStore {
    pub async fn get(
        &self,
        credential_id: &str,
        context: &ExecutionContext,
    ) -> Result<Credential, CredentialError> {
        // Get credential from store
        let credential = self.store.get(credential_id).await?;

        // Verify credential scope matches execution context scope
        if credential.scope != context.scope {
            return Err(CredentialError::ScopeMismatch {
                credential_scope: credential.scope.clone(),
                context_scope: context.scope.clone(),
            });
        }

        // Verify user has permission to access credential
        self.scope_resolver
            .check_access(&context.user, &credential.scope, Permission::ReadCredential)
            .await?;

        Ok(credential)
    }

    pub async fn create(
        &self,
        name: &str,
        credential_type: CredentialType,
        data: SecretData,
        scope: ScopeId,
        user: &User,
    ) -> Result<Credential, CredentialError> {
        // Verify user has permission to create credentials in this scope
        self.scope_resolver
            .check_access(user, &scope, Permission::CreateCredential)
            .await?;

        let credential = Credential {
            id: format!("cred_{}", Uuid::new_v4()),
            name: name.to_string(),
            credential_type,
            scope: scope.clone(),
            data: self.encrypt_data(data, &scope).await?,
            created_at: Utc::now(),
            created_by: user.id.clone(),
        };

        self.store.save(&credential).await?;

        Ok(credential)
    }
}
```

## Workflow Resource Limits

Scopes enforce resource quotas to prevent resource exhaustion:

```rust
pub struct ResourceQuotas {
    pub max_workflows: Option<u32>,
    pub max_workflow_executions_per_day: Option<u32>,
    pub max_concurrent_executions: Option<u32>,
    pub max_execution_time: Option<Duration>,
    pub max_memory_per_execution: Option<ByteSize>,
    pub max_storage: Option<ByteSize>,
}

pub struct QuotaEnforcer {
    scope_resolver: Arc<ScopeResolver>,
    metrics: Arc<MetricsCollector>,
}

impl QuotaEnforcer {
    pub async fn check_quota(
        &self,
        scope: &ScopeId,
        resource_type: ResourceType,
    ) -> Result<QuotaStatus, QuotaError> {
        let resolved_scope = self.scope_resolver
            .resolve_by_id(scope)
            .await?;

        // Get quotas from scope hierarchy (most specific wins)
        let quotas = self.get_effective_quotas(&resolved_scope).await?;

        // Get current usage
        let usage = self.metrics
            .get_resource_usage(scope, resource_type)
            .await?;

        match resource_type {
            ResourceType::Workflow => {
                if let Some(max) = quotas.max_workflows {
                    if usage.workflows >= max {
                        return Err(QuotaError::WorkflowLimitExceeded {
                            current: usage.workflows,
                            limit: max,
                        });
                    }
                }
            }
            ResourceType::ConcurrentExecutions => {
                if let Some(max) = quotas.max_concurrent_executions {
                    if usage.concurrent_executions >= max {
                        return Err(QuotaError::ConcurrentExecutionLimitExceeded {
                            current: usage.concurrent_executions,
                            limit: max,
                        });
                    }
                }
            }
            // ... other resource types
        }

        Ok(QuotaStatus::Available {
            used: usage,
            limit: quotas,
        })
    }

    async fn get_effective_quotas(&self, scope: &ResolvedScope) -> Result<ResourceQuotas, QuotaError> {
        let mut quotas = ResourceQuotas::default();

        // Start with organization quotas
        quotas.merge(scope.organization.resource_quotas.clone());

        // Override with workspace quotas if present
        if let Some(workspace) = &scope.workspace {
            quotas.merge(workspace.settings.resource_quotas.clone());
        }

        // Override with environment quotas if present
        if let Some(environment) = &scope.environment {
            if let Some(env_quotas) = &environment.resource_quotas {
                quotas.merge(env_quotas.clone());
            }
        }

        // Override with namespace quotas if present (most specific)
        if let Some(namespace) = &scope.namespace {
            quotas.merge(namespace.resource_limits.clone());
        }

        Ok(quotas)
    }
}
```

## Complete Example: Multi-Tenant SaaS Platform

Here's a real-world example of setting up scopes for a multi-tenant SaaS platform:

```rust
use nebula::{Organization, Workspace, Environment, Namespace, Workflow};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create organization for customer "Acme Corp"
    let acme = Organization::create("Acme Corp", UserId::new("admin@acme.com")).await?;

    // 2. Create workspaces for different teams
    let engineering = Workspace::create(&acme.id, "engineering").await?;
    let marketing = Workspace::create(&acme.id, "marketing").await?;

    // 3. Set workspace-level resource quotas
    engineering.settings.resource_quotas = ResourceQuotas {
        max_workflows: Some(100),
        max_concurrent_executions: Some(50),
        max_memory_per_execution: Some(ByteSize::gb(2)),
        ..Default::default()
    };

    // 4. Create environments in engineering workspace
    let dev = Environment::create(&engineering.id, "development").await?;
    let staging = Environment::create(&engineering.id, "staging").await?;
    let prod = Environment::create(&engineering.id, "production").await?;

    // 5. Configure production environment with strict policies
    prod.config = EnvironmentConfig {
        allow_debug_mode: false,
        auto_approve_workflows: false,
        require_approval_for_credentials: true,
        retention_days: 365,  // Compliance requirement
        alert_channels: vec![
            "slack://engineering-alerts".to_string(),
            "pagerduty://on-call".to_string(),
        ],
    };

    // 6. Create namespaces for microservices
    let api_namespace = Namespace::new(&prod.id, "api")
        .with_tags(HashMap::from([
            ("team".to_string(), "backend".to_string()),
            ("service".to_string(), "api-gateway".to_string()),
        ]))
        .with_limits(ResourceLimits {
            max_workflows: Some(20),
            max_concurrent_executions: Some(10),
            cpu_quota: Some(4.0),
            memory_quota: Some(ByteSize::gb(8)),
            ..Default::default()
        });

    let worker_namespace = Namespace::new(&prod.id, "worker")
        .with_tags(HashMap::from([
            ("team".to_string(), "backend".to_string()),
            ("service".to_string(), "background-worker".to_string()),
        ]))
        .with_limits(ResourceLimits {
            max_workflows: Some(50),
            max_concurrent_executions: Some(100),
            cpu_quota: Some(16.0),
            memory_quota: Some(ByteSize::gb(32)),
            ..Default::default()
        });

    // 7. Create scoped credentials
    let credential_store = ScopedCredentialStore::new();

    // Development database credential
    let dev_db = credential_store.create(
        "postgres_dev",
        CredentialType::DatabaseConnection,
        SecretData::from(json!({
            "host": "dev-db.internal",
            "username": "dev_user",
            "password": "dev_password",
            "database": "acme_dev",
        })),
        ScopeId::from_environment(&dev),
        &admin_user,
    ).await?;

    // Production database credential (separate from dev)
    let prod_db = credential_store.create(
        "postgres_prod",
        CredentialType::DatabaseConnection,
        SecretData::from(json!({
            "host": "prod-db.internal",
            "username": "prod_user",
            "password": "prod_password",
            "database": "acme_prod",
        })),
        ScopeId::from_environment(&prod),
        &admin_user,
    ).await?;

    // 8. Create workflow in production API namespace
    let workflow = WorkflowBuilder::new("process_order")
        .scope(ScopeId::from_namespace(&api_namespace))
        .add_node("validate_order", ValidateOrderAction)
        .add_node("query_inventory", QueryInventoryAction)
        .configure_node("query_inventory", |config| {
            config.credential("postgres_prod");  // Will only access prod DB
        })
        .add_node("send_confirmation", SendEmailAction)
        .add_edge("validate_order", "query_inventory", |o| o)
        .add_edge("query_inventory", "send_confirmation", |o| o)
        .build()?;

    // 9. Execute workflow with scope enforcement
    let context = ExecutionContext::new()
        .scope(ScopeId::from_namespace(&api_namespace))
        .user(api_user)
        .environment_vars(HashMap::from([
            ("ENV".to_string(), "production".to_string()),
        ]));

    let result = workflow.execute(context).await?;

    println!("Workflow executed in scope: {}", result.scope.to_string());
    // Output: "acme/engineering/production/api"

    Ok(())
}
```

## Scope-Based Access Control

Scopes integrate with [[Security Model]] for fine-grained access control:

```rust
pub struct ScopeAccessControl {
    rbac: Arc<RBACEngine>,
    abac: Arc<ABACEngine>,
}

impl ScopeAccessControl {
    pub async fn authorize(
        &self,
        user: &User,
        resource: &dyn ScopedResource,
        action: Action,
    ) -> Result<AuthorizationDecision, AccessControlError> {
        // Get resource scope
        let scope = resource.scope();

        // Check RBAC: Does user have role in this scope?
        let roles = self.rbac.get_user_roles(user, scope).await?;

        if roles.is_empty() {
            return Ok(AuthorizationDecision::Deny {
                reason: "User has no roles in this scope".to_string(),
            });
        }

        // Check if any role grants permission for this action
        let rbac_decision = self.rbac
            .evaluate_roles(&roles, resource, action)
            .await?;

        if rbac_decision.is_deny() {
            return Ok(rbac_decision);
        }

        // Check ABAC: Additional attribute-based constraints
        let abac_decision = self.abac.evaluate(user, resource, action, scope).await?;

        // Combine decisions (both must allow)
        Ok(AuthorizationDecision::combine(rbac_decision, abac_decision))
    }
}

// Example: User roles scoped to workspace
pub struct ScopedRole {
    pub user_id: UserId,
    pub scope: ScopeId,
    pub role: Role,
    pub granted_at: DateTime<Utc>,
    pub granted_by: UserId,
}

// User can have different roles in different scopes
// Example:
// - Admin role in "acme/engineering/development"
// - Developer role in "acme/engineering/staging"
// - Viewer role in "acme/engineering/production"
```

## Best Practices

### 1. Use Hierarchical Scopes

```rust
// ✅ GOOD: Hierarchical organization
Organization: "acme"
└── Workspace: "engineering"
    ├── Environment: "development"
    ├── Environment: "staging"
    └── Environment: "production"
        ├── Namespace: "api"
        └── Namespace: "worker"

// ❌ BAD: Flat structure with no hierarchy
Organization: "acme"
├── Scope: "eng-dev-api"
├── Scope: "eng-dev-worker"
├── Scope: "eng-staging-api"
└── Scope: "eng-prod-api"
```

**Why**: Hierarchies enable policy inheritance and centralized management.

### 2. Isolate Environments Strictly

```rust
// ✅ GOOD: Separate credentials per environment
dev_db_credential.scope = "acme/engineering/development"
prod_db_credential.scope = "acme/engineering/production"

// ❌ BAD: Shared credential across environments
shared_db_credential.scope = "acme/engineering"  // Used in both dev and prod
```

**Why**: Prevents production incidents from development activities.

### 3. Set Resource Quotas at Appropriate Level

```rust
// ✅ GOOD: Quotas at workspace level, overrides at namespace
workspace.resource_quotas.max_concurrent_executions = Some(100);
api_namespace.resource_limits.max_concurrent_executions = Some(10);
worker_namespace.resource_limits.max_concurrent_executions = Some(90);

// ❌ BAD: No quotas, risking resource exhaustion
workspace.resource_quotas = ResourceQuotas::unlimited();
```

**Why**: Prevents noisy neighbors and ensures fair resource distribution.

### 4. Use Namespaces for Logical Grouping

```rust
// ✅ GOOD: Namespaces aligned with microservices
let api_ns = Namespace::new(&prod.id, "api");
let auth_ns = Namespace::new(&prod.id, "auth");
let billing_ns = Namespace::new(&prod.id, "billing");

// ❌ BAD: All workflows in single environment without namespaces
let prod = Environment::create(&workspace.id, "production").await?;
// All workflows go directly into prod environment
```

**Why**: Better organization, easier to manage, and enables fine-grained quotas.

### 5. Enforce Promotion Paths

```rust
// ✅ GOOD: Controlled promotion through environments
workflow.promote_from("development").to("staging").await?;
workflow.promote_from("staging").to("production").await?;

// ❌ BAD: Direct deployment to production from development
workflow.deploy_to("production").await?;  // Skips staging
```

**Why**: Ensures workflows are tested before reaching production.

### 6. Tag Resources for Discoverability

```rust
// ✅ GOOD: Rich tagging for organization
namespace.tags = HashMap::from([
    ("team", "backend"),
    ("service", "api-gateway"),
    ("cost-center", "engineering"),
    ("criticality", "high"),
]);

// ❌ BAD: No tags, hard to find resources
namespace.tags = HashMap::new();
```

**Why**: Enables filtering, cost attribution, and policy application.

### 7. Audit Scope Changes

```rust
// ✅ GOOD: Audit trail for scope modifications
impl Workspace {
    pub async fn add_member(&mut self, user_id: UserId, role: Role, added_by: UserId)
        -> Result<(), ScopeError>
    {
        self.members.push(WorkspaceMember { user_id, role, joined_at: Utc::now() });

        audit_log::record(AuditEvent::ScopeMemberAdded {
            scope: self.id.clone(),
            user_id,
            role,
            added_by,
            timestamp: Utc::now(),
        }).await?;

        Ok(())
    }
}
```

**Why**: Compliance requirements and security incident investigation.

## Related Concepts

- [[Security Model]] - Authentication and authorization mechanisms
- [[Credentials]] - Scoped credential management
- [[Workflows]] - Workflow execution within scopes
- [[Nodes]] - Node execution respects scope boundaries
- [[Event System]] - Events are scoped to prevent cross-scope leakage

## Further Reading

- **Multi-Tenancy Architecture**: [[docs/architecture/multi-tenancy.md]]
- **Access Control Deep Dive**: [[docs/security/access-control.md]]
- **Resource Quotas and Limits**: [[docs/operations/resource-management.md]]
- **Environment Promotion**: [[docs/workflows/promotion.md]]
- **Compliance and Auditing**: [[docs/security/compliance.md]]