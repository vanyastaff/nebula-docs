---
title: Scoped Resources
tags: [nebula, nebula-resource, docs, scopes, multi-tenancy]
status: complete
created: 2025-08-17
updated: 2025-11-09
---

# Scoped Resources

**Scoped Resources** позволяют изолировать ресурсы по различным контекстам: workflow, action, tenant, user. Это критично для мультитенантных приложений, изоляции данных, квотирования и безопасности.

## Зачем нужны Scoped Resources?

```mermaid
graph TD
    A[Global ResourceManager] --> B[Tenant A Scope]
    A --> C[Tenant B Scope]
    A --> D[Tenant C Scope]

    B --> B1[DB Pool A]
    B --> B2[Redis A]
    B --> B3[Kafka A]

    C --> C1[DB Pool B]
    C --> C2[Redis B]
    C --> C3[Kafka B]

    D --> D1[DB Pool C]
    D --> D2[Redis C]
    D --> D3[Kafka C]

    style B fill:#e1f5ff
    style C fill:#fff4e1
    style D fill:#ffe1f5
```

**Проблемы без scoping:**
- Tenant A может видеть данные Tenant B
- Невозможно установить квоты per-tenant
- Утечка ресурсов между контекстами
- Сложность с billing и аудитом

**С scoping:**
- ✅ Полная изоляция между tenants
- ✅ Квоты per-scope
- ✅ Автоматическая очистка при завершении scope
- ✅ Простой аудит использования

## Типы Scope

```rust
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub enum Scope {
    /// Глобальный scope (shared across all)
    Global,

    /// Scope для конкретного tenant
    Tenant(TenantId),

    /// Scope для конкретного workflow
    Workflow(WorkflowId),

    /// Scope для конкретного action в workflow
    Action {
        workflow_id: WorkflowId,
        action_id: ActionId,
    },

    /// Scope для конкретного пользователя
    User(UserId),

    /// Custom scope
    Custom(String),

    /// Nested scopes (иерархия)
    Nested {
        parent: Box<Scope>,
        child: Box<Scope>,
    },
}

impl Scope {
    /// Проверить, является ли scope дочерним
    pub fn is_child_of(&self, parent: &Scope) -> bool {
        match self {
            Scope::Nested { parent: p, .. } => {
                p.as_ref() == parent || p.is_child_of(parent)
            }
            _ => false,
        }
    }

    /// Создать nested scope
    pub fn nest(&self, child: Scope) -> Scope {
        Scope::Nested {
            parent: Box::new(self.clone()),
            child: Box::new(child),
        }
    }
}
```

## ScopedResourceManager

```rust
use nebula_resource::{ScopedResourceManager, Scope};

pub struct ScopedResourceManager {
    /// Глобальный resource manager
    global_manager: Arc<ResourceManager>,

    /// Scope-specific managers
    scoped_managers: Arc<RwLock<HashMap<Scope, Arc<ResourceManager>>>>,

    /// Конфигурация
    config: ScopedConfig,

    /// Метрики
    metrics: Arc<MetricsCollector>,
}

#[derive(Debug, Clone)]
pub struct ScopedConfig {
    /// Автоматически создавать scope если не существует
    pub auto_create_scopes: bool,

    /// Максимальное количество scopes
    pub max_scopes: usize,

    /// TTL для неактивных scopes (автоматическая очистка)
    pub scope_ttl: Option<Duration>,

    /// Квоты per-scope
    pub per_scope_quota: Option<ResourceQuota>,
}

impl ScopedResourceManager {
    pub fn new(config: ScopedConfig) -> Self {
        Self {
            global_manager: Arc::new(ResourceManager::builder().build()),
            scoped_managers: Arc::new(RwLock::new(HashMap::new())),
            config,
            metrics: Arc::new(MetricsCollector::new()),
        }
    }

    /// Создать новый scope
    pub async fn create_scope(&self, scope: Scope) -> Result<(), ScopeError> {
        let mut managers = self.scoped_managers.write().await;

        // Проверить лимит
        if managers.len() >= self.config.max_scopes {
            return Err(ScopeError::TooManyScopes {
                current: managers.len(),
                max: self.config.max_scopes,
            });
        }

        // Создать scoped manager
        let scoped_manager = ResourceManager::builder()
            .with_scope(scope.clone())
            .with_quota(self.config.per_scope_quota.clone())
            .build();

        managers.insert(scope.clone(), Arc::new(scoped_manager));

        self.metrics.increment_counter("scopes.created", &[
            ("scope_type", scope.type_name()),
        ]);

        info!("Created scope: {:?}", scope);
        Ok(())
    }

    /// Получить manager для scope
    pub async fn get_scoped_manager(&self, scope: &Scope)
        -> Result<Arc<ResourceManager>, ScopeError> {
        let managers = self.scoped_managers.read().await;

        match managers.get(scope) {
            Some(manager) => Ok(manager.clone()),
            None if self.config.auto_create_scopes => {
                drop(managers);
                self.create_scope(scope.clone()).await?;
                self.get_scoped_manager(scope).await
            }
            None => Err(ScopeError::ScopeNotFound(scope.clone())),
        }
    }

    /// Acquire ресурс в scope
    pub async fn acquire_scoped<R: Resource>(
        &self,
        scope: &Scope,
    ) -> Result<ResourceGuard<R>, ResourceError> {
        let manager = self.get_scoped_manager(scope).await?;
        manager.acquire::<R>().await
    }

    /// Удалить scope и все его ресурсы
    pub async fn cleanup_scope(&self, scope: &Scope) -> Result<(), ScopeError> {
        let mut managers = self.scoped_managers.write().await;

        if let Some(manager) = managers.remove(scope) {
            info!("Cleaning up scope: {:?}", scope);

            // Graceful shutdown всех ресурсов в scope
            manager.shutdown_all().await?;

            self.metrics.increment_counter("scopes.cleaned_up", &[
                ("scope_type", scope.type_name()),
            ]);
        }

        Ok(())
    }
}
```

## Практические примеры

### 1. Multi-Tenant SaaS Application

```rust
use nebula_resource::{ScopedResourceManager, Scope};

#[derive(Clone, Hash, Eq, PartialEq)]
pub struct TenantId(String);

pub struct MultiTenantApp {
    scoped_manager: Arc<ScopedResourceManager>,
}

impl MultiTenantApp {
    pub async fn new() -> Result<Self> {
        let config = ScopedConfig {
            auto_create_scopes: true,
            max_scopes: 1000, // До 1000 tenant scopes
            scope_ttl: Some(Duration::from_hours(24)), // Auto-cleanup после 24h неактивности
            per_scope_quota: Some(ResourceQuota {
                max_connections: 10, // Каждый tenant: max 10 DB connections
                max_memory_mb: 100,  // max 100 MB memory
                max_cpu_percent: 5,  // max 5% CPU
            }),
        };

        let scoped_manager = ScopedResourceManager::new(config);

        Ok(Self {
            scoped_manager: Arc::new(scoped_manager),
        })
    }

    /// Обработать запрос от tenant
    pub async fn handle_tenant_request(
        &self,
        tenant_id: TenantId,
        request: Request,
    ) -> Result<Response> {
        // Создать tenant scope
        let tenant_scope = Scope::Tenant(tenant_id.clone());

        // Acquire database connection для этого tenant
        let db = self.scoped_manager
            .acquire_scoped::<PostgresPool>(&tenant_scope)
            .await?;

        // Query выполняется с tenant-specific connection
        // Автоматическая изоляция данных!
        let results = db.query(&request.sql, &request.params).await?;

        // Connection автоматически вернется в tenant-specific pool
        Ok(Response::from_results(results))
    }

    /// Onboard нового tenant
    pub async fn onboard_tenant(&self, tenant_id: TenantId) -> Result<()> {
        info!("Onboarding tenant: {:?}", tenant_id);

        let tenant_scope = Scope::Tenant(tenant_id.clone());

        // Создать scope для tenant
        self.scoped_manager.create_scope(tenant_scope.clone()).await?;

        // Зарегистрировать ресурсы для tenant
        let manager = self.scoped_manager.get_scoped_manager(&tenant_scope).await?;

        // Tenant-specific database
        let db_config = PostgresPoolConfig {
            connection_string: format!(
                "postgresql://tenant_{}:password@localhost/tenant_{}",
                tenant_id.0, tenant_id.0
            ),
            min_connections: 2,
            max_connections: 10, // Квота enforcement
            ..Default::default()
        };
        manager.register_with_config::<PostgresPool>(db_config).await?;

        // Tenant-specific Redis
        let redis_config = RedisPoolConfig {
            nodes: vec![format!("redis://localhost:6379/tenant_{}", tenant_id.0)],
            pool_size: 5,
            ..Default::default()
        };
        manager.register_with_config::<RedisPool>(redis_config).await?;

        info!("Tenant {} onboarded successfully", tenant_id.0);
        Ok(())
    }

    /// Offboard tenant (удалить все ресурсы)
    pub async fn offboard_tenant(&self, tenant_id: TenantId) -> Result<()> {
        info!("Offboarding tenant: {:?}", tenant_id);

        let tenant_scope = Scope::Tenant(tenant_id.clone());

        // Очистить все ресурсы tenant
        self.scoped_manager.cleanup_scope(&tenant_scope).await?;

        info!("Tenant {} offboarded successfully", tenant_id.0);
        Ok(())
    }
}
```

**Важно учитывать:**

```rust
// ✅ ПРАВИЛЬНО: Всегда используйте tenant scope
async fn correct_tenant_query(app: &MultiTenantApp, tenant_id: TenantId) -> Result<()> {
    let tenant_scope = Scope::Tenant(tenant_id);

    let db = app.scoped_manager
        .acquire_scoped::<PostgresPool>(&tenant_scope)
        .await?;

    // Query изолирован для этого tenant
    let users = db.query("SELECT * FROM users", &[]).await?;

    Ok(())
}

// ❌ НЕПРАВИЛЬНО: Использование глобального scope
async fn wrong_tenant_query(app: &MultiTenantApp) -> Result<()> {
    let db = app.scoped_manager
        .acquire_scoped::<PostgresPool>(&Scope::Global) // УТЕЧКА ДАННЫХ!
        .await?;

    // Query может видеть данные ВСЕХ tenants!
    let users = db.query("SELECT * FROM users", &[]).await?;

    Ok(())
}
```

### 2. Workflow-Scoped Resources

```rust
pub struct WorkflowExecutor {
    scoped_manager: Arc<ScopedResourceManager>,
}

impl WorkflowExecutor {
    /// Выполнить workflow с isolated resources
    pub async fn execute_workflow(
        &self,
        workflow_id: WorkflowId,
        workflow_def: WorkflowDefinition,
    ) -> Result<WorkflowResult> {
        info!("Executing workflow: {}", workflow_id);

        // Создать workflow scope
        let workflow_scope = Scope::Workflow(workflow_id.clone());
        self.scoped_manager.create_scope(workflow_scope.clone()).await?;

        // Register resources для этого workflow
        let manager = self.scoped_manager
            .get_scoped_manager(&workflow_scope)
            .await?;

        manager.register::<PostgresPool>().await?;
        manager.register::<Redis>().await?;
        manager.register::<HttpClient>().await?;

        // Execute actions
        let mut results = Vec::new();

        for action in workflow_def.actions {
            // Создать action scope (nested под workflow)
            let action_scope = Scope::Action {
                workflow_id: workflow_id.clone(),
                action_id: action.id.clone(),
            };

            let action_result = self.execute_action(
                &action_scope,
                action,
            ).await?;

            results.push(action_result);
        }

        // Cleanup workflow scope
        self.scoped_manager.cleanup_scope(&workflow_scope).await?;

        Ok(WorkflowResult { results })
    }

    async fn execute_action(
        &self,
        action_scope: &Scope,
        action: ActionDefinition,
    ) -> Result<ActionResult> {
        // Ресурсы доступны из parent workflow scope
        let db = self.scoped_manager
            .acquire_scoped::<PostgresPool>(action_scope)
            .await?;

        // Execute action logic
        let result = action.execute(db).await?;

        Ok(result)
    }
}
```

**Автоматическая очистка при ошибках:**

```rust
impl WorkflowExecutor {
    pub async fn execute_workflow_with_cleanup(
        &self,
        workflow_id: WorkflowId,
        workflow_def: WorkflowDefinition,
    ) -> Result<WorkflowResult> {
        let workflow_scope = Scope::Workflow(workflow_id.clone());

        // Create scope
        self.scoped_manager.create_scope(workflow_scope.clone()).await?;

        // Execute с автоматической очисткой при любом исходе
        let result = async {
            // Setup resources
            let manager = self.scoped_manager
                .get_scoped_manager(&workflow_scope)
                .await?;

            manager.register::<PostgresPool>().await?;

            // Execute workflow
            self.run_workflow_actions(&workflow_scope, workflow_def).await
        }.await;

        // ВСЕГДА cleanup scope, даже при ошибке
        if let Err(e) = self.scoped_manager.cleanup_scope(&workflow_scope).await {
            error!("Failed to cleanup workflow scope: {}", e);
        }

        result
    }
}
```

### 3. User-Scoped Resources (для quota enforcement)

```rust
pub struct UserResourceManager {
    scoped_manager: Arc<ScopedResourceManager>,
    user_quotas: Arc<RwLock<HashMap<UserId, UserQuota>>>,
}

#[derive(Clone)]
pub struct UserQuota {
    pub max_concurrent_requests: usize,
    pub max_db_connections: usize,
    pub max_memory_mb: usize,
    pub rate_limit: RateLimit,
}

impl UserResourceManager {
    pub async fn execute_user_request(
        &self,
        user_id: UserId,
        request: Request,
    ) -> Result<Response> {
        // Проверить квоту
        let quota = self.get_user_quota(&user_id).await?;

        // Создать user scope
        let user_scope = Scope::User(user_id.clone());

        // Проверить текущее использование
        let current_usage = self.get_current_usage(&user_scope).await?;

        if current_usage.concurrent_requests >= quota.max_concurrent_requests {
            return Err(Error::QuotaExceeded {
                resource: "concurrent_requests",
                limit: quota.max_concurrent_requests,
                current: current_usage.concurrent_requests,
            });
        }

        // Acquire resources в user scope (автоматически enforces quotas)
        let db = self.scoped_manager
            .acquire_scoped::<PostgresPool>(&user_scope)
            .await?;

        // Execute request
        let result = db.query(&request.sql, &request.params).await?;

        Ok(Response::from_result(result))
    }

    async fn get_current_usage(&self, scope: &Scope) -> Result<ResourceUsage> {
        let manager = self.scoped_manager.get_scoped_manager(scope).await?;

        Ok(ResourceUsage {
            concurrent_requests: manager.active_resource_count().await,
            memory_mb: manager.memory_usage_mb().await,
            cpu_percent: manager.cpu_usage_percent().await,
        })
    }
}
```

### 4. Nested Scopes (иерархия)

```rust
// Tenant -> Workflow -> Action hierarchy
async fn nested_scopes_example(
    manager: &ScopedResourceManager,
    tenant_id: TenantId,
    workflow_id: WorkflowId,
    action_id: ActionId,
) -> Result<()> {
    // Создать иерархию scopes
    let tenant_scope = Scope::Tenant(tenant_id);
    let workflow_scope = tenant_scope.nest(Scope::Workflow(workflow_id));
    let action_scope = workflow_scope.nest(Scope::Custom(action_id));

    // Создать scopes
    manager.create_scope(tenant_scope.clone()).await?;
    manager.create_scope(workflow_scope.clone()).await?;
    manager.create_scope(action_scope.clone()).await?;

    // Resources в action scope могут видеть ресурсы из parent scopes
    let db = manager.acquire_scoped::<PostgresPool>(&action_scope).await?;

    // Cleanup cascades: удаление tenant -> удаляет workflow -> удаляет action
    manager.cleanup_scope(&tenant_scope).await?;

    Ok(())
}
```

## Scope Isolation Guarantees

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tenant_isolation() {
        let manager = ScopedResourceManager::new(ScopedConfig::default());

        let tenant_a = Scope::Tenant(TenantId("tenant-a".to_string()));
        let tenant_b = Scope::Tenant(TenantId("tenant-b".to_string()));

        // Create scopes
        manager.create_scope(tenant_a.clone()).await.unwrap();
        manager.create_scope(tenant_b.clone()).await.unwrap();

        // Register DB для каждого tenant
        let manager_a = manager.get_scoped_manager(&tenant_a).await.unwrap();
        manager_a.register_with_config::<PostgresPool>(
            PostgresPoolConfig {
                connection_string: "postgresql://localhost/tenant_a".to_string(),
                ..Default::default()
            }
        ).await.unwrap();

        let manager_b = manager.get_scoped_manager(&tenant_b).await.unwrap();
        manager_b.register_with_config::<PostgresPool>(
            PostgresPoolConfig {
                connection_string: "postgresql://localhost/tenant_b".to_string(),
                ..Default::default()
            }
        ).await.unwrap();

        // Acquire для tenant A
        let db_a = manager.acquire_scoped::<PostgresPool>(&tenant_a).await.unwrap();

        // Acquire для tenant B
        let db_b = manager.acquire_scoped::<PostgresPool>(&tenant_b).await.unwrap();

        // Verify isolation: разные connection strings
        assert_ne!(
            db_a.connection_string(),
            db_b.connection_string()
        );

        // Tenant A НЕ может получить ресурсы tenant B
        let result = manager.acquire_scoped::<PostgresPool>(&tenant_b).await;
        // Different instance returned
    }

    #[tokio::test]
    async fn test_scope_cleanup_isolation() {
        let manager = ScopedResourceManager::new(ScopedConfig::default());

        let tenant_a = Scope::Tenant(TenantId("tenant-a".to_string()));
        let tenant_b = Scope::Tenant(TenantId("tenant-b".to_string()));

        manager.create_scope(tenant_a.clone()).await.unwrap();
        manager.create_scope(tenant_b.clone()).await.unwrap();

        // Cleanup tenant A
        manager.cleanup_scope(&tenant_a).await.unwrap();

        // Tenant B still accessible
        let manager_b = manager.get_scoped_manager(&tenant_b).await.unwrap();
        assert!(manager_b.is_healthy());

        // Tenant A не доступен
        let result = manager.get_scoped_manager(&tenant_a).await;
        assert!(result.is_err());
    }
}
```

## Scope Lifecycle Management

```rust
pub struct ScopeLifecycleManager {
    scoped_manager: Arc<ScopedResourceManager>,
    active_scopes: Arc<RwLock<HashMap<Scope, ScopeMetadata>>>,
}

#[derive(Clone)]
pub struct ScopeMetadata {
    pub created_at: DateTime<Utc>,
    pub last_accessed: Arc<RwLock<DateTime<Utc>>>,
    pub access_count: Arc<AtomicU64>,
    pub resource_count: Arc<AtomicUsize>,
}

impl ScopeLifecycleManager {
    /// Автоматическая очистка неактивных scopes
    pub async fn start_cleanup_scheduler(self: Arc<Self>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_mins(5));

            loop {
                interval.tick().await;

                if let Err(e) = self.cleanup_inactive_scopes().await {
                    error!("Scope cleanup failed: {}", e);
                }
            }
        })
    }

    async fn cleanup_inactive_scopes(&self) -> Result<()> {
        let scopes = self.active_scopes.read().await;
        let now = Utc::now();
        let ttl = Duration::from_hours(24);

        let mut to_cleanup = Vec::new();

        for (scope, metadata) in scopes.iter() {
            let last_accessed = *metadata.last_accessed.read().await;
            let inactive_duration = now - last_accessed;

            if inactive_duration > ttl.into() {
                info!(
                    "Scope {:?} inactive for {:?}, scheduling cleanup",
                    scope, inactive_duration
                );
                to_cleanup.push(scope.clone());
            }
        }

        drop(scopes);

        // Cleanup inactive scopes
        for scope in to_cleanup {
            if let Err(e) = self.scoped_manager.cleanup_scope(&scope).await {
                error!("Failed to cleanup scope {:?}: {}", scope, e);
            } else {
                self.active_scopes.write().await.remove(&scope);
            }
        }

        Ok(())
    }

    /// Track scope access
    pub async fn track_access(&self, scope: &Scope) {
        if let Some(metadata) = self.active_scopes.read().await.get(scope) {
            *metadata.last_accessed.write().await = Utc::now();
            metadata.access_count.fetch_add(1, Ordering::Relaxed);
        }
    }
}
```

## Performance Considerations

### 1. Scope Creation Overhead

```rust
// ❌ НЕПРАВИЛЬНО: Создавать scope для каждого запроса
async fn bad_per_request_scope(manager: &ScopedResourceManager) -> Result<()> {
    for request in requests {
        let scope = Scope::Custom(format!("request-{}", request.id));
        manager.create_scope(scope.clone()).await?; // Дорого!

        let db = manager.acquire_scoped::<PostgresPool>(&scope).await?;
        // ... process request

        manager.cleanup_scope(&scope).await?; // Дорого!
    }
    Ok(())
}

// ✅ ПРАВИЛЬНО: Использовать долгоживущие scopes
async fn good_long_lived_scopes(manager: &ScopedResourceManager) -> Result<()> {
    // Создать scope один раз
    let user_scope = Scope::User(user_id);
    manager.create_scope(user_scope.clone()).await?;

    // Reuse для множества запросов
    for request in requests {
        let db = manager.acquire_scoped::<PostgresPool>(&user_scope).await?;
        // ... process request
    }

    // Cleanup только в конце
    manager.cleanup_scope(&user_scope).await?;

    Ok(())
}
```

### 2. Scope Caching

```rust
pub struct CachedScopeManager {
    inner: Arc<ScopedResourceManager>,
    scope_cache: Arc<DashMap<Scope, Arc<ResourceManager>>>,
}

impl CachedScopeManager {
    pub async fn acquire_scoped<R: Resource>(
        &self,
        scope: &Scope,
    ) -> Result<ResourceGuard<R>> {
        // Fast path: check cache
        if let Some(manager) = self.scope_cache.get(scope) {
            return manager.acquire::<R>().await;
        }

        // Slow path: create scope
        let manager = self.inner.get_scoped_manager(scope).await?;
        self.scope_cache.insert(scope.clone(), manager.clone());

        manager.acquire::<R>().await
    }
}
```

## Monitoring & Metrics

```rust
pub struct ScopeMetrics {
    pub active_scopes: Gauge,
    pub scopes_created: Counter,
    pub scopes_cleaned_up: Counter,
    pub scope_access_count: Counter,
    pub resources_per_scope: Histogram,
}

impl ScopedResourceManager {
    pub fn metrics(&self) -> ScopeMetrics {
        ScopeMetrics {
            active_scopes: self.metrics.gauge("scopes.active"),
            scopes_created: self.metrics.counter("scopes.created"),
            scopes_cleaned_up: self.metrics.counter("scopes.cleaned_up"),
            scope_access_count: self.metrics.counter("scopes.accesses"),
            resources_per_scope: self.metrics.histogram("scopes.resources"),
        }
    }

    pub async fn export_metrics(&self) -> MetricsSnapshot {
        let scopes = self.scoped_managers.read().await;

        MetricsSnapshot {
            total_scopes: scopes.len(),
            scopes_by_type: self.count_scopes_by_type(&scopes),
            resources_per_scope: self.count_resources_per_scope(&scopes).await,
        }
    }
}
```

## Best Practices

### 1. Всегда cleanup scopes

```rust
// ✅ ПРАВИЛЬНО: Use RAII или explicit cleanup
async fn with_scope_cleanup(manager: &ScopedResourceManager) -> Result<()> {
    let scope = Scope::Workflow(workflow_id);

    // Create
    manager.create_scope(scope.clone()).await?;

    // Use
    let result = do_work_with_scope(&manager, &scope).await;

    // ALWAYS cleanup
    manager.cleanup_scope(&scope).await?;

    result
}

// Или с guard pattern
struct ScopeGuard {
    manager: Arc<ScopedResourceManager>,
    scope: Scope,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        let manager = self.manager.clone();
        let scope = self.scope.clone();

        // Cleanup в background
        tokio::spawn(async move {
            if let Err(e) = manager.cleanup_scope(&scope).await {
                error!("Failed to cleanup scope: {}", e);
            }
        });
    }
}
```

### 2. Используйте hierarchical scopes для связанных ресурсов

```rust
// ✅ ПРАВИЛЬНО: Tenant -> Workflow -> Action
let tenant_scope = Scope::Tenant(tenant_id);
let workflow_scope = tenant_scope.nest(Scope::Workflow(workflow_id));
let action_scope = workflow_scope.nest(Scope::Custom(action_id));

// Cleanup tenant удалит все вложенные scopes
manager.cleanup_scope(&tenant_scope).await?;
```

### 3. Set reasonable TTLs

```rust
let config = ScopedConfig {
    scope_ttl: Some(match scope_type {
        // Short-lived scopes
        ScopeType::Request => Duration::from_mins(5),

        // Medium-lived scopes
        ScopeType::Workflow => Duration::from_hours(1),

        // Long-lived scopes
        ScopeType::Tenant => Duration::from_hours(24),

        // Permanent scopes (no TTL)
        ScopeType::Global => None,
    }),
    ..Default::default()
};
```

## Complete Example: Multi-Tenant SaaS

```rust
use nebula_resource::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize scoped manager
    let scoped_manager = Arc::new(ScopedResourceManager::new(ScopedConfig {
        auto_create_scopes: true,
        max_scopes: 10000,
        scope_ttl: Some(Duration::from_hours(24)),
        per_scope_quota: Some(ResourceQuota {
            max_connections: 20,
            max_memory_mb: 500,
            max_cpu_percent: 10,
        }),
    }));

    // Start cleanup scheduler
    let cleanup_manager = scoped_manager.clone();
    tokio::spawn(async move {
        let lifecycle = Arc::new(ScopeLifecycleManager::new(cleanup_manager));
        lifecycle.start_cleanup_scheduler().await;
    });

    // Handle requests
    let app = MultiTenantApp {
        scoped_manager: scoped_manager.clone(),
    };

    // Example: Onboard tenant
    app.onboard_tenant(TenantId("acme-corp".to_string())).await?;

    // Example: Handle tenant request
    let response = app.handle_tenant_request(
        TenantId("acme-corp".to_string()),
        Request {
            sql: "SELECT * FROM users WHERE active = true".to_string(),
            params: vec![],
        },
    ).await?;

    // Example: Offboard tenant
    app.offboard_tenant(TenantId("acme-corp".to_string())).await?;

    Ok(())
}
```

## Links

- [[02-Crates/nebula-resource/Architecture|Resource Architecture]]
- [[02-Crates/nebula-resource/Built-in Resources|Built-in Resources]]
- [[02-Crates/nebula-resource/Examples|Usage Examples]]
- [[02-Crates/nebula-resource/Resource Lifecycle|Resource Lifecycle]]
- [[04-Development/Multi-Tenancy]]
- [[04-Development/Security Best Practices]]
