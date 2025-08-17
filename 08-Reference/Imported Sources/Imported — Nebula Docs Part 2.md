---
title: Imported — Nebula Docs Part 2
tags: [nebula, imported]
created: 2025-08-17
---

# Imported — Nebula Docs Part 2

> Imported source from prior notes. Keep original structure; cross-link into sections as needed.

# Nebula Crates Documentation - Part 2 (Updated)

## 4. nebula-memory

### Overview

**nebula-memory** управляет памятью и кэшированием данных во время выполнения workflow. Предоставляет эффективные механизмы для хранения промежуточных результатов, optimized для различных resource scopes, и интеграцию с expression system.

### Architecture

```rust
// Основной менеджер памяти с поддержкой scoped allocation
pub struct MemoryManager {
    global_arena: Arc<GlobalArena>,
    execution_arenas: Arc<DashMap<ExecutionId, ExecutionArena>>,
    workflow_arenas: Arc<DashMap<WorkflowId, WorkflowArena>>,
    cache: Arc<TieredMemoryCache>,
    limits: MemoryLimits,
    metrics: MemoryMetrics,
}

// Scoped arenas для различных lifecycle
pub struct ExecutionArena {
    execution_id: ExecutionId,
    arena: Arena,
    allocated_bytes: AtomicUsize,
    max_allocation: usize,
    created_at: SystemTime,
}

pub struct WorkflowArena {
    workflow_id: WorkflowId,
    arena: Arena,
    execution_count: AtomicU32,
    shared_data: Arc<RwLock<HashMap<String, Value>>>,
}

// Многоуровневый кэш для expression results и node outputs
pub struct TieredMemoryCache {
    l1_hot: LruCache<CacheKey, Arc<CacheEntry>>,        // Горячий кэш в памяти
    l2_warm: RwLock<BTreeMap<CacheKey, CacheEntry>>,    // Теплый кэш  
    l3_external: Option<Box<dyn ExternalCache>>,        // Внешний кэш (Redis)
    expression_cache: ExpressionResultCache,            // Специальный кэш для expressions
}

// Кэш результатов expression evaluation
pub struct ExpressionResultCache {
    cache: LruCache<ExpressionCacheKey, ExpressionResult>,
    dependency_graph: DependencyGraph,  // Отслеживает зависимости expressions
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ExpressionCacheKey {
    expression: String,
    context_hash: u64,  // Hash от контекста для cache invalidation
    node_dependencies: BTreeSet<NodeId>,  // Узлы от которых зависит expression
}
```

### Expression-Aware Caching

```rust
impl TieredMemoryCache {
    // Кэширование с учетом expression dependencies
    pub async fn cache_expression_result(
        &self,
        expression: &str,
        context: &ExecutionContext,
        result: Value,
    ) -> Result<(), CacheError> {
        let dependencies = self.extract_expression_dependencies(expression)?;
        let context_hash = self.compute_context_hash(context, &dependencies).await?;
        
        let cache_key = ExpressionCacheKey {
            expression: expression.to_string(),
            context_hash,
            node_dependencies: dependencies,
        };
        
        let cache_entry = ExpressionResult {
            value: result,
            computed_at: SystemTime::now(),
            dependencies: cache_key.node_dependencies.clone(),
        };
        
        self.expression_cache.cache.put(cache_key, cache_entry);
        
        // Регистрируем зависимости для invalidation
        self.expression_cache.dependency_graph
            .register_expression_dependencies(expression, &dependencies);
        
        Ok(())
    }
    
    // Получение cached result с проверкой dependencies
    pub async fn get_cached_expression_result(
        &self,
        expression: &str,
        context: &ExecutionContext,
    ) -> Option<Value> {
        let dependencies = self.extract_expression_dependencies(expression).ok()?;
        let context_hash = self.compute_context_hash(context, &dependencies).await.ok()?;
        
        let cache_key = ExpressionCacheKey {
            expression: expression.to_string(),
            context_hash,
            node_dependencies: dependencies,
        };
        
        self.expression_cache.cache.get(&cache_key)
            .map(|entry| entry.value.clone())
    }
    
    // Invalidation кэша при изменении node outputs
    pub async fn invalidate_dependent_expressions(&self, changed_node: &NodeId) {
        let dependent_expressions = self.expression_cache.dependency_graph
            .get_dependent_expressions(changed_node);
        
        for expression in dependent_expressions {
            self.expression_cache.cache.retain(|key, _| {
                key.expression != expression || !key.node_dependencies.contains(changed_node)
            });
        }
        
        self.metrics.record_cache_invalidation(changed_node);
    }
    
    // Извлечение зависимостей из expression
    fn extract_expression_dependencies(&self, expression: &str) -> Result<BTreeSet<NodeId>, CacheError> {
        let mut dependencies = BTreeSet::new();
        
        // Парсим expression и находим все $nodes.{node_id} references
        let ast = self.parse_expression(expression)?;
        self.collect_node_references(&ast, &mut dependencies);
        
        Ok(dependencies)
    }
}
```

### Scoped Memory Management

```rust
impl MemoryManager {
    // Создание arena с правильным scope
    pub async fn create_scoped_arena(&self, scope: ResourceScope) -> Result<ScopedArena, MemoryError> {
        match scope.lifecycle {
            ResourceLifecycle::Execution => {
                let arena = self.execution_arenas
                    .entry(scope.execution_id.clone())
                    .or_insert_with(|| ExecutionArena::new(scope.execution_id.clone()));
                    
                Ok(ScopedArena::Execution(arena.clone()))
            }
            ResourceLifecycle::Workflow => {
                let arena = self.workflow_arenas
                    .entry(scope.workflow_id.clone())
                    .or_insert_with(|| WorkflowArena::new(scope.workflow_id.clone()));
                    
                Ok(ScopedArena::Workflow(arena.clone()))
            }
            ResourceLifecycle::Global => {
                Ok(ScopedArena::Global(self.global_arena.clone()))
            }
            ResourceLifecycle::Action => {
                // Action-scoped память создается и уничтожается для каждого action
                Ok(ScopedArena::Action(ActionArena::new()))
            }
        }
    }
    
    // Cleanup scoped arenas
    pub async fn cleanup_execution_arena(&self, execution_id: &ExecutionId) -> Result<(), MemoryError> {
        if let Some((_, arena)) = self.execution_arenas.remove(execution_id) {
            // Освобождаем memory arena
            arena.cleanup().await?;
            
            // Invalidate связанные cache entries
            self.cache.invalidate_execution_cache(execution_id).await?;
            
            self.metrics.record_arena_cleanup("execution", arena.allocated_bytes());
        }
        
        Ok(())
    }
    
    pub async fn cleanup_workflow_arena(&self, workflow_id: &WorkflowId) -> Result<(), MemoryError> {
        if let Some((_, arena)) = self.workflow_arenas.remove(workflow_id) {
            arena.cleanup().await?;
            self.cache.invalidate_workflow_cache(workflow_id).await?;
            self.metrics.record_arena_cleanup("workflow", arena.allocated_bytes());
        }
        
        Ok(())
    }
}

// Scoped arena wrapper
pub enum ScopedArena {
    Global(Arc<GlobalArena>),
    Workflow(Arc<WorkflowArena>),
    Execution(Arc<ExecutionArena>),
    Action(ActionArena),
}

impl ScopedArena {
    pub fn alloc<T>(&self, data: T) -> Result<&T, MemoryError> {
        match self {
            ScopedArena::Global(arena) => arena.alloc(data),
            ScopedArena::Workflow(arena) => arena.alloc(data),
            ScopedArena::Execution(arena) => arena.alloc(data),
            ScopedArena::Action(arena) => arena.alloc(data),
        }
    }
}
```

### Integration with ExecutionContext

```rust
// ExecutionContext интегрируется с memory manager
impl ExecutionContext {
    pub async fn allocate_scoped_memory<T>(&self, data: T, scope: ResourceLifecycle) -> Result<&T, MemoryError> {
        let resource_scope = ResourceScope {
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            action_id: self.current_node_id.clone(),
            lifecycle: scope,
        };
        
        let arena = self.memory_manager.create_scoped_arena(resource_scope).await?;
        arena.alloc(data)
    }
    
    // Кэширование expression results с автоматической invalidation
    pub async fn cache_expression_result(&self, expression: &str, result: Value) -> Result<(), CacheError> {
        self.memory_manager.cache()
            .cache_expression_result(expression, self, result)
            .await
    }
    
    pub async fn get_cached_expression_result(&self, expression: &str) -> Option<Value> {
        self.memory_manager.cache()
            .get_cached_expression_result(expression, self)
            .await
    }
}
```

### Examples

```rust
use nebula_memory::*;

// Создание memory manager с limits
let limits = MemoryLimits {
    max_global_heap: 500 * 1024 * 1024,    // 500MB global
    max_workflow_heap: 100 * 1024 * 1024,  // 100MB per workflow
    max_execution_heap: 50 * 1024 * 1024,  // 50MB per execution
    max_action_heap: 10 * 1024 * 1024,     // 10MB per action
    expression_cache_size: 1000,           // 1000 cached expressions
    gc_threshold: 0.8,
};

let memory_manager = MemoryManager::new(limits);

// Работа с scoped allocation
let execution_data = context.allocate_scoped_memory(
    large_dataset, 
    ResourceLifecycle::Execution
).await?;  // Будет очищено в конце execution

let workflow_metrics = context.allocate_scoped_memory(
    MetricsCollector::new(),
    ResourceLifecycle::Workflow  
).await?;  // Живет весь workflow

// Expression caching с dependency tracking
let expensive_expression = "$nodes.data_processing.result | filter(item => item.score > 80) | map(item => item.enhanced_data)";

// Первый раз - вычисляется и кэшируется
let result1 = context.evaluate_expression(expensive_expression).await?;

// Второй раз - возвращается из кэша
let result2 = context.evaluate_expression(expensive_expression).await?;
assert_eq!(result1, result2);

// При изменении data_processing node - кэш автоматически invalidates
context.update_node_output("data_processing", new_output).await?;
// Следующий вызов пересчитает expression
let result3 = context.evaluate_expression(expensive_expression).await?;
```

---

## 5. nebula-expression

### Overview

**nebula-expression** предоставляет мощный язык выражений для динамической обработки данных в workflow. Поддерживает доступ к node outputs, workflow variables, условную логику, функциональное программирование и безопасное выполнение пользовательского кода.

### Architecture

```rust
// Основной движок выражений с кэшированием и dependency tracking
pub struct ExpressionEngine {
    parser: Parser,
    compiler: Compiler,
    runtime: Runtime,
    cache: Arc<ExpressionCache>,
    dependency_tracker: DependencyTracker,
    security_sandbox: SecuritySandbox,
}

// AST для выражений с поддержкой всех Nebula конструкций
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    // Literals
    Literal(Value),
    
    // Variables and references
    Variable(String),
    NodeReference { node_id: String, field_path: String },      // $nodes.create_user.result.email
    WorkflowVariable(String),                                   // $workflow.variables.base_url
    ExecutionMetadata(String),                                  // $execution.start_time
    UserContext(String),                                        // $user.id
    Environment(String),                                        // $environment.API_BASE_URL
    
    // Object and array access
    FieldAccess { object: Box<Expression>, field: String },
    IndexAccess { array: Box<Expression>, index: Box<Expression> },
    
    // Function calls
    FunctionCall { name: String, args: Vec<Expression> },
    
    // Operators
    BinaryOp { left: Box<Expression>, op: BinaryOperator, right: Box<Expression> },
    UnaryOp { op: UnaryOperator, operand: Box<Expression> },
    
    // Control flow
    Conditional { 
        condition: Box<Expression>, 
        then_expr: Box<Expression>, 
        else_expr: Box<Expression> 
    },
    
    // Functional programming
    Pipeline(Vec<Expression>),  // expression | filter(...) | map(...)
    Lambda { params: Vec<String>, body: Box<Expression> },
    
    // String interpolation
    StringTemplate { template: String, expressions: Vec<Expression> },  // "Hello ${user.name}!"
}
```

### Language Features

```rust
// Поддерживаемые операторы
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOperator {
    // Arithmetic
    Add, Subtract, Multiply, Divide, Modulo, Power,
    
    // Comparison  
    Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual,
    
    // Logical
    And, Or,
    
    // String operations
    Contains, StartsWith, EndsWith, RegexMatch,
    
    // Collection operations
    In, NotIn,
    
    // Null coalescing
    NullCoalesce,  // ??
}

// Встроенные функции для workflow operations
pub struct BuiltinFunctions;

impl BuiltinFunctions {
    // String functions
    pub fn length(s: &str) -> usize { s.len() }
    pub fn uppercase(s: &str) -> String { s.to_uppercase() }
    pub fn lowercase(s: &str) -> String { s.to_lowercase() }
    pub fn trim(s: &str) -> String { s.trim().to_string() }
    pub fn split(s: &str, delimiter: &str) -> Vec<String> {
        s.split(delimiter).map(String::from).collect()
    }
    pub fn replace(s: &str, from: &str, to: &str) -> String {
        s.replace(from, to)
    }
    pub fn substring(s: &str, start: usize, end: Option<usize>) -> String {
        match end {
            Some(e) => s.chars().skip(start).take(e - start).collect(),
            None => s.chars().skip(start).collect(),
        }
    }
    
    // Array functions  
    pub fn map<T, U, F>(array: &[T], func: F) -> Vec<U> 
    where F: Fn(&T) -> U {
        array.iter().map(func).collect()
    }
    
    pub fn filter<T, F>(array: &[T], predicate: F) -> Vec<&T>
    where F: Fn(&T) -> bool {
        array.iter().filter(|item| predicate(item)).collect()
    }
    
    pub fn reduce<T, U, F>(array: &[T], init: U, func: F) -> U
    where F: Fn(U, &T) -> U {
        array.iter().fold(init, func)
    }
    
    pub fn find<T, F>(array: &[T], predicate: F) -> Option<&T>
    where F: Fn(&T) -> bool {
        array.iter().find(|item| predicate(item))
    }
    
    pub fn join(array: &[String], separator: &str) -> String {
        array.join(separator)
    }
    
    pub fn unique<T: Clone + PartialEq>(array: &[T]) -> Vec<T> {
        let mut result = Vec::new();
        for item in array {
            if !result.contains(item) {
                result.push(item.clone());
            }
        }
        result
    }
    
    pub fn sort<T: Clone + Ord>(array: &[T]) -> Vec<T> {
        let mut result = array.to_vec();
        result.sort();
        result
    }
    
    // Object functions
    pub fn keys(obj: &serde_json::Map<String, Value>) -> Vec<String> {
        obj.keys().cloned().collect()
    }
    
    pub fn values(obj: &serde_json::Map<String, Value>) -> Vec<Value> {
        obj.values().cloned().collect()
    }
    
    pub fn has_key(obj: &serde_json::Map<String, Value>, key: &str) -> bool {
        obj.contains_key(key)
    }
    
    // Math functions
    pub fn abs(n: f64) -> f64 { n.abs() }
    pub fn round(n: f64) -> f64 { n.round() }
    pub fn floor(n: f64) -> f64 { n.floor() }
    pub fn ceil(n: f64) -> f64 { n.ceil() }
    pub fn min(a: f64, b: f64) -> f64 { a.min(b) }
    pub fn max(a: f64, b: f64) -> f64 { a.max(b) }
    pub fn sqrt(n: f64) -> f64 { n.sqrt() }
    pub fn pow(base: f64, exp: f64) -> f64 { base.powf(exp) }
    
    // Date/time functions
    pub fn now() -> DateTime<Utc> { Utc::now() }
    pub fn format_date(date: &DateTime<Utc>, format: &str) -> String {
        date.format(format).to_string()
    }
    pub fn parse_date(date_str: &str, format: &str) -> Result<DateTime<Utc>, chrono::ParseError> {
        DateTime::parse_from_str(date_str, format)
            .map(|dt| dt.with_timezone(&Utc))
    }
    pub fn add_days(date: &DateTime<Utc>, days: i64) -> DateTime<Utc> {
        *date + chrono::Duration::days(days)
    }
    pub fn diff_days(date1: &DateTime<Utc>, date2: &DateTime<Utc>) -> i64 {
        (date1.date_naive() - date2.date_naive()).num_days()
    }
    
    // Type conversion functions
    pub fn to_string(value: &Value) -> String {
        match value {
            Value::String(s) => s.to_string(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => serde_json::to_string(value).unwrap_or_default(),
        }
    }
    
    pub fn to_number(value: &Value) -> Result<f64, ConversionError> {
        match value {
            Value::Number(n) => Ok(n.as_f64().unwrap_or_default()),
            Value::String(s) => s.parse().map_err(ConversionError::ParseError),
            _ => Err(ConversionError::UnsupportedType),
        }
    }
    
    pub fn to_bool(value: &Value) -> bool {
        match value {
            Value::Bool(b) => *b,
            Value::Null => false,
            Value::Number(n) => n.as_f64().unwrap_or_default() != 0.0,
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
            _ => true,
        }
    }
}
```

### Syntax Examples for Workflow Context

```javascript
// Node output access
$nodes.create_user.result.email
$nodes.validation.success
$nodes.api_call.result.data[0].id

// Workflow variables
$workflow.variables.base_url
$workflow.config.timeout
$workflow.metadata.created_by

// Execution context
$execution.id
$execution.start_time
$execution.user_id

// User context (from authentication/session)
$user.id
$user.email
$user.premium
$user.permissions

// Environment variables
$environment.NODE_ENV
$environment.API_BASE_URL
$environment.DATABASE_URL

// Pipeline operations (functional programming style)
$nodes.users_query.result 
| filter(user => user.active == true)
| map(user => {
    name: user.full_name,
    email: user.email,
    score: user.rating * 10
})
| sort(user => user.score)
| take(10)

// Conditional expressions
if $nodes.validation.success then 
    $nodes.process_success.result 
else 
    $nodes.process_error.result

// Complex conditions
if $user.premium && $nodes.order.result.amount > 1000 then
    "premium_processing"
else if $user.trial && $nodes.order.result.amount < 100 then
    "trial_processing"  
else
    "standard_processing"

// String interpolation
"Welcome ${user.name}! Your order #${nodes.create_order.result.id} is confirmed."
"API endpoint: ${workflow.variables.base_url}/users/${nodes.create_user.result.id}"

// Null coalescing and safe navigation
$nodes.user_lookup.result.address?.city ?? "Unknown City"
$workflow.variables.timeout ?? 30

// Array and object operations
{
    user_id: $nodes.create_user.result.id,
    preferences: {
        theme: $user.preferences?.theme ?? "light",
        notifications: $user.preferences?.notifications ?? true
    },
    tags: $nodes.categorize.result | filter(tag => tag.confidence > 0.8) | map(tag => tag.name)
}

// Advanced filtering and data transformation  
$nodes.orders.result
| filter(order => order.status == "completed" && order.amount > 100)
| group_by(order => order.customer_id)
| map((customer_id, orders) => {
    customer_id: customer_id,
    total_orders: orders.length,
    total_amount: orders | map(o => o.amount) | sum(),
    avg_amount: orders | map(o => o.amount) | avg()
})
| sort(customer => customer.total_amount)
| reverse()
```

### Security Sandbox

```rust
// Безопасное выполнение пользовательских expressions
pub struct SecuritySandbox {
    max_execution_time: Duration,
    max_memory_usage: usize,
    max_call_depth: usize,
    allowed_functions: HashSet<String>,
    blocked_patterns: Vec<regex::Regex>,
}

impl SecuritySandbox {
    pub fn validate_expression(&self, expr: &str) -> Result<(), SecurityError> {
        // 1. Проверка на запрещенные паттерны
        for pattern in &self.blocked_patterns {
            if pattern.is_match(expr) {
                return Err(SecurityError::BlockedPattern(pattern.to_string()));
            }
        }
        
        // 2. Проверка длины expression
        if expr.len() > 10000 {
            return Err(SecurityError::ExpressionTooLong);
        }
        
        // 3. Парсинг и проверка AST
        let ast = self.parse_expression(expr)?;
        self.validate_ast(&ast)?;
        
        Ok(())
    }
    
    fn validate_ast(&self, expr: &Expression) -> Result<(), SecurityError> {
        match expr {
            Expression::FunctionCall { name, args } => {
                // Проверяем разрешенные функции
                if !self.allowed_functions.contains(name) {
                    return Err(SecurityError::UnauthorizedFunction(name.clone()));
                }
                
                // Рекурсивно проверяем аргументы
                for arg in args {
                    self.validate_ast(arg)?;
                }
            }
            Expression::BinaryOp { left, right, .. } => {
                self.validate_ast(left)?;
                self.validate_ast(right)?;
            }
            Expression::Pipeline(expressions) => {
                // Ограничиваем длину pipeline
                if expressions.len() > 50 {
                    return Err(SecurityError::PipelineTooLong);
                }
                
                for expr in expressions {
                    self.validate_ast(expr)?;
                }
            }
            _ => {
                // Рекурсивная проверка вложенных expressions
                // ... остальные варианты
            }
        }
        
        Ok(())
    }
}
```

### Caching and Performance

```rust
// Кэширование compiled expressions с dependency tracking
impl ExpressionEngine {
    pub async fn evaluate_with_caching(
        &self,
        expression: &str,
        context: &ExecutionContext,
    ) -> Result<Value, ExpressionError> {
        // Проверяем кэш
        if let Some(cached_result) = context.get_cached_expression_result(expression).await {
            self.metrics.record_cache_hit();
            return Ok(cached_result);
        }
        
        // Компилируем и выполняем
        let compiled = self.compile_with_caching(expression).await?;
        let result = self.runtime.execute(&compiled, context).await?;
        
        // Кэшируем результат
        context.cache_expression_result(expression, result.clone()).await?;
        self.metrics.record_cache_miss();
        
        Ok(result)
    }
    
    async fn compile_with_caching(&self, expression: &str) -> Result<CompiledExpression, ExpressionError> {
        if let Some(compiled) = self.cache.get_compiled(expression) {
            return Ok(compiled);
        }
        
        // Компилируем новое expression
        let ast = self.parser.parse(expression)?;
        let compiled = self.compiler.compile(ast)?;
        
        // Кэшируем compiled expression
        self.cache.store_compiled(expression.to_string(), compiled.clone());
        
        Ok(compiled)
    }
}
```

### Examples

```rust
use nebula_expression::*;

// Создание expression engine
let engine = ExpressionEngine::builder()
    .with_security_sandbox(SecuritySandbox::strict())
    .with_cache_size(1000)
    .with_max_execution_time(Duration::from_secs(5))
    .build();

// Простые expressions
let simple_access = engine.evaluate(
    "$nodes.input.result.user_email",
    &context
).await?;

let string_interpolation = engine.evaluate(
    r#"Welcome ${user.name}! Order #${nodes.create_order.result.id} confirmed."#,
    &context
).await?;

// Pipeline обработка данных
let pipeline_result = engine.evaluate(r#"
    $nodes.fetch_users.result
    | filter(user => user.active == true && user.age >= 18)
    | map(user => {
        id: user.id,
        name: user.full_name,
        email: user.email,
        premium: user.subscription_type == "premium"
    })
    | sort(user => user.name)
    | take(50)
"#, &context).await?;

// Условная логика
let conditional_result = engine.evaluate(r#"
    if $user.premium && $nodes.order.result.amount > 1000 then {
        processing_type: "premium_fast_track",
        fee: 0,
        estimated_delivery: add_days(now(), 1)
    } else if $nodes.order.result.amount > 500 then {
        processing_type: "priority", 
        fee: 10,
        estimated_delivery: add_days(now(), 3)
    } else {
        processing_type: "standard",
        fee: 5,
        estimated_delivery: add_days(now(), 7)
    }
"#, &context).await?;

// Работа с массивами и объектами
let data_aggregation = engine.evaluate(r#"
    $nodes.orders.result
    | filter(order => order.status == "completed")
    | group_by(order => order.customer_id)
    | map((customer_id, orders) => {
        customer_id: customer_id,
        order_count: orders.length,
        total_spent: orders | map(o => o.amount) | sum(),
        average_order: orders | map(o => o.amount) | avg(),
        last_order_date: orders | map(o => o.created_at) | max(),
        preferred_category: orders | map(o => o.category) | mode()
    })
    | sort(customer => customer.total_spent)
    | reverse()
    | take(10)
"#, &context).await?;

// Null safety и error handling
let safe_access = engine.evaluate(r#"
    {
        user_name: $nodes.user_lookup.result?.name ?? "Anonymous",
        user_email: $nodes.user_lookup.result?.email ?? "no-email@example.com",
        address: {
            city: $nodes.user_lookup.result?.address?.city ?? "Unknown",
            country: $nodes.user_lookup.result?.address?.country ?? "Unknown"
        },
        is_premium: to_bool($nodes.user_lookup.result?.premium) ?? false
    }
"#, &context).await?;
```

---

## 6. nebula-eventbus

### Overview

**nebula-eventbus** предоставляет типобезопасную pub/sub систему для асинхронной коммуникации между компонентами Nebula. Поддерживает как локальные, так и распределенные события с гарантиями доставки и интеграцией с resource lifecycle.

### Architecture

```rust
// Основная шина событий с поддержкой scoped subscriptions
pub struct EventBus {
    local_bus: LocalEventBus,
    distributed_bus: Option<DistributedEventBus>,
    event_store: Arc<dyn EventStore>,
    subscription_manager: SubscriptionManager,
    metrics: EventMetrics,
}

// Локальная шина событий с resource scope awareness
pub struct LocalEventBus {
    subscribers: Arc<RwLock<HashMap<TypeId, Vec<ScopedSubscription>>>>,
    channels: HashMap<TypeId, mpsc::UnboundedSender<ScopedEvent>>,
    event_router: EventRouter,
}

// Subscription привязанная к resource scope
#[derive(Debug, Clone)]
pub struct ScopedSubscription {
    handler: Arc<dyn EventHandler>,
    scope: SubscriptionScope,
    filter: Option<EventFilter>,
    created_at: SystemTime,
}

// Scope для подписок на события
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionScope {
    Global,                           // Глобальные события
    Workflow(WorkflowId),            // События конкретного workflow
    Execution(ExecutionId),          // События конкретного execution
    Action(ExecutionId, NodeId),     // События конкретного action
}

// Event wrapper с scope информацией
#[derive(Debug, Clone)]
pub struct ScopedEvent {
    event: Box<dyn Event>,
    scope: EventScope,
    correlation_id: Option<CorrelationId>,
    timestamp: SystemTime,
    source: EventSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventScope {
    pub execution_id: Option<ExecutionId>,
    pub workflow_id: Option<WorkflowId>,
    pub action_id: Option<NodeId>,
    pub user_id: Option<UserId>,
    pub account_id: Option<String>,
}
```

### System Events для Workflow Engine

```rust
// События workflow lifecycle
#[derive(Debug, Clone, Event)]
pub enum WorkflowEvent {
    WorkflowDeployed { 
        workflow_id: WorkflowId,
        version: WorkflowVersion,
        deployed_by: UserId,
        deployment_time: SystemTime,
    },
    WorkflowUndeployed {
        workflow_id: WorkflowId,
        reason: String,
        undeployed_by: UserId,
    },
    WorkflowUpdated {
        workflow_id: WorkflowId,
        old_version: WorkflowVersion,
        new_version: WorkflowVersion,
        changes: Vec<WorkflowChange>,
    },
}

// События execution lifecycle  
#[derive(Debug, Clone, Event)]
pub enum ExecutionEvent {
    ExecutionStarted { 
        execution_id: ExecutionId,
        workflow_id: WorkflowId,
        triggered_by: TriggerSource,
        input_data: Value,
        start_time: SystemTime,
    },
    ExecutionCompleted { 
        execution_id: ExecutionId,
        workflow_id: WorkflowId,
        status: ExecutionStatus,
        result: Option<Value>,
        duration: Duration,
        metrics: ExecutionMetrics,
    },
    ExecutionFailed {
        execution_id: ExecutionId,
        workflow_id: WorkflowId,
        error: ExecutionError,
        failed_node: Option<NodeId>,
        retry_count: u32,
    },
    ExecutionPaused {
        execution_id: ExecutionId,
        workflow_id: WorkflowId,
        paused_at_node: NodeId,
        reason: String,
    },
    ExecutionResumed {
        execution_id: ExecutionId,
        workflow_id: WorkflowId,
        resumed_from_node: NodeId,
        resumed_by: UserId,
    },
}

// События node/action execution
#[derive(Debug, Clone, Event)]
pub enum NodeEvent {
    NodeStarted {
        execution_id: ExecutionId,
        node_id: NodeId,
        action_id: ActionId,
        input_data: Value,
        start_time: SystemTime,
    },
    NodeCompleted {
        execution_id: ExecutionId,
        node_id: NodeId,
        action_id: ActionId,
        result: ActionResult<Value>,
        duration: Duration,
        resource_usage: ResourceUsageMetrics,
    },
    NodeFailed {
        execution_id: ExecutionId,
        node_id: NodeId,
        action_id: ActionId,
        error: ActionError,
        retry_count: u32,
        will_retry: bool,
    },
    NodeSkipped {
        execution_id: ExecutionId,
        node_id: NodeId,
        reason: String,
        condition: Option<String>,
    },
}

// Events для resource management
#[derive(Debug, Clone, Event)]
pub enum ResourceEvent {
    ResourceCreated {
        resource_type: String,
        resource_id: ResourceInstanceId,
        scope: ResourceScope,
        creation_time: SystemTime,
    },
    ResourceDestroyed {
        resource_type: String,
        resource_id: ResourceInstanceId,
        scope: ResourceScope,
        lifetime: Duration,
    },
    ResourceHealthChanged {
        resource_type: String,
        resource_id: ResourceInstanceId,
        old_status: HealthStatus,
        new_status: HealthStatus,
        check_time: SystemTime,
    },
    CredentialRotated {
        credential_id: String,
        affected_resources: Vec<ResourceInstanceId>,
        rotation_time: SystemTime,
    },
}
```

### Scoped Event Handling

```rust
impl EventBus {
    // Подписка на события с scope filtering
    pub fn subscribe_scoped<T: Event, H: EventHandler<T> + 'static>(
        &self,
        handler: H,
        scope: SubscriptionScope,
        filter: Option<EventFilter>,
    ) -> SubscriptionId {
        let subscription = ScopedSubscription {
            handler: Arc::new(TypedEventHandler::new(handler)),
            scope,
            filter,
            created_at: SystemTime::now(),
        };
        
        let subscription_id = SubscriptionId::new();
        let type_id = TypeId::of::<T>();
        
        self.local_bus.subscribers
            .write()
            .unwrap()
            .entry(type_id)
            .or_insert_with(Vec::new)
            .push(subscription);
        
        // Регистрируем для cleanup при завершении scope
        self.subscription_manager.register_scoped_subscription(
            subscription_id,
            scope.clone(),
        );
        
        subscription_id
    }
    
    // Публикация события с автоматическим scope
    pub async fn publish_scoped<T: Event>(
        &self,
        event: T,
        scope: EventScope,
    ) -> Result<(), EventError> {
        let scoped_event = ScopedEvent {
            event: Box::new(event),
            scope,
            correlation_id: None, // Может быть установлен из context
            timestamp: SystemTime::now(),
            source: EventSource::Local,
        };
        
        // Отправляем в локальную шину
        self.local_bus.publish(scoped_event.clone()).await?;
        
        // Отправляем в распределенную шину если есть
        if let Some(distributed) = &self.distributed_bus {
            distributed.publish(scoped_event).await?;
        }
        
        // Сохраняем в event store
        self.event_store.store_event(&scoped_event).await?;
        
        Ok(())
    }
    
    // Cleanup subscriptions при завершении scope
    pub async fn cleanup_scope(&self, scope: &SubscriptionScope) -> Result<(), EventError> {
        let subscription_ids = self.subscription_manager.get_subscriptions_for_scope(scope);
        
        for subscription_id in subscription_ids {
            self.unsubscribe(subscription_id).await?;
        }
        
        // Уведомляем о cleanup scope
        self.publish_scoped(
            SystemEvent::ScopeCleanedUp {
                scope: scope.clone(),
                cleanup_time: SystemTime::now(),
            },
            EventScope::global(),
        ).await?;
        
        Ok(())
    }
}

// Integration с ExecutionContext
impl ExecutionContext {
    pub async fn emit_event<T: Event>(&self, event: T) -> Result<(), EventError> {
        let scope = EventScope {
            execution_id: Some(self.execution_id.clone()),
            workflow_id: Some(self.workflow_id.clone()),
            action_id: self.current_node_id.clone(),
            user_id: self.user_id.clone(),
            account_id: self.account_id.clone(),
        };
        
        self.event_bus.publish_scoped(event, scope).await
    }
    
    pub fn subscribe_to_execution_events<T: Event, H: EventHandler<T> + 'static>(
        &self,
        handler: H,
    ) -> SubscriptionId {
        self.event_bus.subscribe_scoped(
            handler,
            SubscriptionScope::Execution(self.execution_id.clone()),
            None,
        )
    }
}
```

### Event Filtering и Routing

```rust
// Фильтрация событий
#[derive(Debug, Clone)]
pub enum EventFilter {
    // По типу события
    EventType(String),
    
    // По scope
    Scope(EventScope),
    
    // По пользователю
    User(UserId),
    
    // По workflow
    Workflow(WorkflowId),
    
    // Комбинированные фильтры
    And(Vec<EventFilter>),
    Or(Vec<EventFilter>),
    Not(Box<EventFilter>),
    
    // Custom filter expression
    Expression(String),  // Expression для фильтрации событий
}

impl EventFilter {
    pub fn matches(&self, event: &ScopedEvent) -> bool {
        match self {
            EventFilter::EventType(event_type) => {
                event.event.event_type() == event_type
            }
            EventFilter::Scope(scope) => {
                self.scope_matches(scope, &event.scope)
            }
            EventFilter::User(user_id) => {
                event.scope.user_id.as_ref() == Some(user_id)
            }
            EventFilter::Workflow(workflow_id) => {
                event.scope.workflow_id.as_ref() == Some(workflow_id)
            }
            EventFilter::And(filters) => {
                filters.iter().all(|f| f.matches(event))
            }
            EventFilter::Or(filters) => {
                filters.iter().any(|f| f.matches(event))
            }
            EventFilter::Not(filter) => {
                !filter.matches(event)
            }
            EventFilter::Expression(expr) => {
                // Используем expression engine для фильтрации
                self.evaluate_filter_expression(expr, event)
            }
        }
    }
}
```

### Examples

```rust
use nebula_eventbus::*;

// Создание event bus
let event_bus = EventBus::builder()
    .with_distributed_transport(KafkaTransport::new(config))
    .with_event_store(PostgresEventStore::new(pool))
    .with_metrics(EventMetrics::new())
    .build();

// Подписка на события execution с scope filtering
let execution_handler = |event: &ExecutionEvent| async move {
    match event {
        ExecutionEvent::ExecutionStarted { execution_id, workflow_id, .. } => {
            println!("Execution {} started for workflow {}", execution_id, workflow_id);
            // Обновляем метрики, отправляем уведомления, etc.
        }
        ExecutionEvent::ExecutionCompleted { execution_id, duration, .. } => {
            println!("Execution {} completed in {:?}", execution_id, duration);
            // Записываем в audit log, отправляем отчеты, etc.
        }
        ExecutionEvent::ExecutionFailed { execution_id, error, .. } => {
            println!("Execution {} failed: {}", execution_id, error);
            // Отправляем alert, логируем ошибку, etc.
        }
        _ => {}
    }
};

// Глобальная подписка на все execution события
let global_sub = event_bus.subscribe_scoped(
    execution_handler,
    SubscriptionScope::Global,
    Some(EventFilter::EventType("execution".to_string())),
);

// Подписка только на события конкретного workflow  
let workflow_sub = event_bus.subscribe_scoped(
    |event: &NodeEvent| async move {
        println!("Node event in my workflow: {:?}", event);
    },
    SubscriptionScope::Workflow(WorkflowId::new("my-important-workflow").unwrap()),
    None,
);

// Публикация событий из ExecutionContext
context.emit_event(ExecutionEvent::ExecutionStarted {
    execution_id: context.execution_id.clone(),
    workflow_id: context.workflow_id.clone(), 
    triggered_by: TriggerSource::Manual,
    input_data: json!({"user_id": "123"}),
    start_time: SystemTime::now(),
}).await?;

context.emit_event(NodeEvent::NodeStarted {
    execution_id: context.execution_id.clone(),
    node_id: NodeId::new("validate_input").unwrap(),
    action_id: ActionId::new("validation.user_data").unwrap(),
    input_data: json!({"email": "user@example.com"}),
    start_time: SystemTime::now(),
}).await?;

// Resource events автоматически генерируются resource manager
resource_manager.on_resource_created(|resource_type, resource_id, scope| async move {
    event_bus.publish_scoped(
        ResourceEvent::ResourceCreated {
            resource_type: resource_type.to_string(),
            resource_id,
            scope,
            creation_time: SystemTime::now(),
        },
        EventScope::from_resource_scope(&scope),
    ).await
});

// Event replay для восстановления состояния
let events = event_bus.replay_events(
    EventFilter::And(vec![
        EventFilter::Execution(execution_id),
        EventFilter::EventType("node".to_string()),
    ]),
    TimeRange::last_hour(),
).await?;

// Автоматический cleanup subscriptions при завершении execution
context.on_execution_completed(|execution_id| async move {
    event_bus.cleanup_scope(&SubscriptionScope::Execution(execution_id)).await
});
```

---

## 7. nebula-action

### Overview

**nebula-action** определяет систему Actions - атомарных единиц работы в Nebula workflow. Поддерживает гибкий подход разработки: от простого программного кода до полноценной интеграции с derive макросами. Фокус на atomic actions для максимальной переиспользуемости.

### Architecture

```rust
// Основной трейт для всех действий с гибким подходом
#[async_trait]
pub trait Action: Send + Sync {
    // Метаданные действия (могут быть auto-generated)
    fn metadata(&self) -> &ActionMetadata;
    
    // Схема параметров (программно или через derive)
    fn parameter_schema(&self) -> ParameterCollection;
    fn output_schema(&self) -> OutputSchema;
    
    // Основной метод выполнения
    async fn execute(&self, context: &ActionContext) -> ActionResult;
    
    // Опциональные методы
    fn validate_parameters(&self, params: &Parameters) -> ValidationResult {
        self.parameter_schema().validate(params)
    }
    
    async fn pre_execute_check(&self, context: &ActionContext) -> Result<(), ActionError> {
        Ok(())
    }
}

// Метаданные действия (auto-generated или manual)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionMetadata {
    pub id: ActionId,
    pub name: String,
    pub description: String,
    pub category: ActionCategory,
    pub tags: Vec<String>,
    pub version: ActionVersion,
    pub author: Option<String>,
    pub documentation_url: Option<String>,
    pub examples: Vec<ActionExample>,
    pub stability: StabilityLevel,
}

// Контекст выполнения действия с resource integration
pub struct ActionContext {
    // Execution context integration
    pub execution_context: Arc<ExecutionContext>,
    
    // Action-specific data
    pub action_id: ActionId,
    pub node_id: NodeId,
    pub parameters: Parameters,
    pub input_data: Option<Value>,
    
    // Timeouts and retries
    pub timeout: Option<Duration>,
    pub retry_policy: Option<RetryPolicy>,
    pub attempt_number: u32,
}
```

### Flexible Development Approaches

```rust
// Подход 1: Простой программный код (быстро и просто)
pub struct SimpleSlackSendAction;

#[async_trait]
impl Action for SimpleSlackSendAction {
    fn metadata(&self) -> &ActionMetadata {
        static METADATA: Lazy<ActionMetadata> = Lazy::new(|| ActionMetadata {
            id: ActionId::new("slack.send_simple").unwrap(),
            name: "Simple Slack Send".to_string(),
            description: "Send message to Slack channel".to_string(),
            category: ActionCategory::Communication,
            tags: vec!["slack".to_string(), "messaging".to_string()],
            version: ActionVersion::new(1, 0, 0),
            author: Some("Developer".to_string()),
            documentation_url: None,
            examples: vec![],
            stability: StabilityLevel::Stable,
        });
        &METADATA
    }
    
    fn parameter_schema(&self) -> ParameterCollection {
        ParameterCollection::new()
            .add_required("channel", ParameterType::String)
            .add_required("message", ParameterType::String)
            .add_optional("thread_ts", ParameterType::String)
    }
    
    async fn execute(&self, context: &ActionContext) -> ActionResult {
        // Получаем параметры
        let channel = context.parameters.get_string("channel")?;
        let message = context.parameters.get_string("message")?;
        let thread_ts = context.parameters.get_optional_string("thread_ts");
        
        // Получаем credential простым способом
        let token = context.execution_context.get_credential("slack_token").await?;
        
        // Создаем простой HTTP клиент
        let client = reqwest::Client::new();
        let response = client
            .post("https://slack.com/api/chat.postMessage")
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .header("Content-Type", "application/json")
            .json(&json!({
                "channel": channel,
                "text": message,
                "thread_ts": thread_ts,
            }))
            .send()
            .await?;
        
        let result = response.json::<serde_json::Value>().await?;
        
        if result["ok"].as_bool().unwrap_or(false) {
            ActionResult::Success(json!({
                "message_ts": result["ts"],
                "channel": result["channel"],
            }))
        } else {
            ActionResult::Failure {
                error: ActionError::ExternalServiceError {
                    service: "slack".to_string(),
                    error: result["error"].as_str().unwrap_or("Unknown error").to_string(),
                },
                retry_info: Some(RetryInfo::exponential_backoff(3)),
            }
        }
    }
}

// Подход 2: Derive макросы для полноценной интеграции
#[derive(Action)]
#[action(
    id = "slack.send_advanced",
    name = "Advanced Slack Send",
    description = "Send message to Slack with full resource integration",
    category = "Communication",
    tags = ["slack", "messaging", "advanced"],
    version = "1.0.0",
    stability = "stable"
)]
#[resources([SlackClientResource, LoggerResource, MetricsCollectorResource])]
#[credentials(["slack_token"])]
pub struct AdvancedSlackSendAction;

#[derive(Parameters)]
pub struct AdvancedSlackSendInput {
    #[parameter(description = "Slack channel")]
    pub channel: String,
    
    #[parameter(description = "Message text")]
    pub message: String,
    
    #[parameter(description = "Thread timestamp", optional)]
    pub thread_ts: Option<String>,
    
    #[parameter(description = "Message blocks", optional)]
    pub blocks: Option<Vec<SlackBlock>>,
    
    #[parameter(description = "Attachments", optional)]
    pub attachments: Option<Vec<SlackAttachment>>,
}

#[derive(Serialize)]
pub struct AdvancedSlackSendOutput {
    pub message_ts: String,
    pub channel: String,
    pub permalink: String,
    pub sent_at: SystemTime,
}

// Derive автоматически генерирует Action impl с resource integration
#[async_trait]
impl ProcessAction for AdvancedSlackSendAction {
    type Input = AdvancedSlackSendInput;
    type Output = AdvancedSlackSendOutput;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // Resources доступны автоматически
        let slack = context.get_resource::<SlackClientResource>().await?;
        let logger = context.get_resource::<LoggerResource>().await?;
        let metrics = context.get_resource::<MetricsCollectorResource>().await?;
        
        logger.info(&format!("Sending Slack message to channel: {}", input.channel));
        
        let start_time = Instant::now();
        
        // Используем high-level SlackClient с circuit breaker, retry logic, etc.
        let result = slack.send_message(SlackMessage {
            channel: input.channel.clone(),
            text: input.message,
            thread_ts: input.thread_ts,
            blocks: input.blocks,
            attachments: input.attachments,
        }).await?;
        
        let duration = start_time.elapsed();
        
        // Автоматические метрики
        metrics.record_action_duration("slack.send", duration);
        metrics.increment_counter("slack.messages_sent", 1.0);
        
        logger.info(&format!("Message sent successfully: {}", result.message_ts));
        
        Ok(ActionResult::Success(AdvancedSlackSendOutput {
            message_ts: result.message_ts,
            channel: result.channel,
            permalink: result.permalink,
            sent_at: SystemTime::now(),
        }))
    }
}
```

### Action Types для разных use cases

```rust
// ProcessAction - стандартная обработка данных
#[async_trait]
pub trait ProcessAction: Action {
    type Input: DeserializeOwned + Send;
    type Output: Serialize + Send;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError>;
}

// StatefulAction - с состоянием между выполнениями  
#[async_trait]
pub trait StatefulAction: Action {
    type State: Serialize + DeserializeOwned + Send + Sync + Clone;
    type Input: DeserializeOwned + Send;
    type Output: Serialize + Send;
    
    async fn execute_with_state(
        &self,
        input: Self::Input,
        state: &mut Self::State,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError>;
    
    // Автоматическая state migration для версионирования
    async fn migrate_state(
        &self,
        old_state: serde_json::Value,
        old_version: semver::Version,
    ) -> Result<Self::State, ActionError>;
}

// TriggerAction - источники событий
#[async_trait]
pub trait TriggerAction: Action {
    type Config: DeserializeOwned + Send + Sync;
    type Event: Serialize + Send + Sync + Clone;
    
    async fn start(
        &self,
        config: Self::Config,
        context: &TriggerContext,
    ) -> Result<TriggerEventStream<Self::Event>, ActionError>;
    
    async fn stop(&self) -> Result<(), ActionError>;
}

// SupplyAction - поставщики ресурсов
#[async_trait]
pub trait SupplyAction: Action {
    type Config: DeserializeOwned + Send + Sync;
    type Resource: Send + Sync + 'static;
    
    async fn create(
        &self,
        config: Self::Config,
        context: &ActionContext,
    ) -> Result<Self::Resource, ActionError>;
    
    async fn destroy(&self, resource: Self::Resource) -> Result<(), ActionError>;
    
    async fn health_check(&self, resource: &Self::Resource) -> Result<HealthStatus, ActionError>;
}

// SimpleAction - упрощенный трейт для atomic actions
#[async_trait]
pub trait SimpleAction: Send + Sync {
    type Input: DeserializeOwned + Send;
    type Output: Serialize + Send;
    
    // Единственный метод для реализации
    async fn execute_simple(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<Self::Output, ActionError>;
    
    // Остальное генерируется автоматически
    fn action_id(&self) -> ActionId {
        ActionId::from_type_name::<Self>()
    }
    
    fn parameter_schema(&self) -> ParameterCollection {
        ParameterCollection::from_type::<Self::Input>()
    }
}

// Автоматическая реализация Action для SimpleAction
impl<T: SimpleAction> Action for T {
    fn metadata(&self) -> &ActionMetadata {
        static METADATA: Lazy<HashMap<TypeId, ActionMetadata>> = Lazy::new(HashMap::new);
        METADATA.entry(TypeId::of::<T>())
            .or_insert_with(|| ActionMetadata::from_simple_action::<T>())
    }
    
    fn parameter_schema(&self) -> ParameterCollection {
        <T as SimpleAction>::parameter_schema(self)
    }
    
    async fn execute(&self, context: &ActionContext) -> ActionResult {
        let input: T::Input = context.parameters.deserialize()?;
        let result = self.execute_simple(input, context).await?;
        ActionResult::Success(serde_json::to_value(result)?)
    }
}
```

### Integration с ExecutionContext

```rust
impl ActionContext {
    // Делегирование к ExecutionContext для resource access
    pub async fn get_resource<T: Resource + 'static>(&self) -> Result<Arc<T>, ResourceError> {
        self.execution_context.get_resource::<T>().await
    }
    
    pub async fn get_credential(&self, credential_id: &str) -> Result<Credential, CredentialError> {
        self.execution_context.get_credential(credential_id).await
    }
    
    pub async fn get_client<T: AuthenticatedClient>(&self, credential_type: &str) -> Result<T, ClientError> {
        self.execution_context.get_client::<T>(credential_type).await
    }
    
    // Expression evaluation в контексте action
    pub async fn evaluate_expression(&self, expression: &str) -> Result<Value, ExpressionError> {
        self.execution_context.evaluate_expression(expression).await
    }
    
    // Scoped logging с action context
    pub fn log_info(&self, message: &str) {
        self.execution_context.log_info(&format!("[{}:{}] {}", self.node_id, self.action_id, message));
    }
    
    pub fn log_error(&self, message: &str) {
        self.execution_context.log_error(&format!("[{}:{}] {}", self.node_id, self.action_id, message));
    }
    
    // Event emission с action scope
    pub async fn emit_event<T: Event>(&self, event: T) -> Result<(), EventError> {
        let mut scope = self.execution_context.get_event_scope();
        scope.action_id = Some(self.node_id.clone());
        self.execution_context.event_bus.publish_scoped(event, scope).await
    }
}
```

### Examples

```rust
use nebula_action::prelude::*;

// Пример 1: Простое действие для начинающих
pub struct EmailSendAction;

impl SimpleAction for EmailSendAction {
    type Input = EmailInput;
    type Output = EmailOutput;
    
    async fn execute_simple(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<Self::Output, ActionError> {
        let smtp_config = context.get_credential("smtp").await?;
        
        // Простая отправка email
        let email_client = EmailClient::new(&smtp_config);
        let message_id = email_client.send_email(&input.to, &input.subject, &input.body).await?;
        
        Ok(EmailOutput { message_id })
    }
}

#[derive(Deserialize)]
pub struct EmailInput {
    pub to: String,
    pub subject: String,
    pub body: String,
}

#[derive(Serialize)]
pub struct EmailOutput {
    pub message_id: String,
}

// Пример 2: Продвинутое действие с полной интеграцией
#[derive(Action)]
#[action(
    id = "database.user_lookup",
    name = "User Database Lookup",
    description = "Look up user information from database with caching"
)]
#[resources([DatabaseResource, CacheResource, LoggerResource])]
#[credentials(["database_connection"])]
pub struct UserLookupAction;

#[derive(Parameters)]
pub struct UserLookupInput {
    #[parameter(description = "User ID to lookup")]
    pub user_id: String,
    
    #[parameter(description = "Include user preferences", default = false)]
    pub include_preferences: bool,
    
    #[parameter(description = "Cache TTL in seconds", default = 300)]
    pub cache_ttl: u32,
}

#[derive(Serialize)]
pub struct UserLookupOutput {
    pub user: User,
    pub cached: bool,
    pub lookup_time: Duration,
}

impl ProcessAction for UserLookupAction {
    type Input = UserLookupInput;
    type Output = UserLookupOutput;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        let db = context.get_resource::<DatabaseResource>().await?;
        let cache = context.get_resource::<CacheResource>().await?;
        let logger = context.get_resource::<LoggerResource>().await?;
        
        let start_time = Instant::now();
        let cache_key = format!("user:{}", input.user_id);
        
        // Проверяем кэш
        if let Some(cached_user) = cache.get::<User>(&cache_key).await? {
            logger.info(&format!("User {} found in cache", input.user_id));
            return Ok(ActionResult::Success(UserLookupOutput {
                user: cached_user,
                cached: true,
                lookup_time: start_time.elapsed(),
            }));
        }
        
        // Загружаем из базы данных
        let query = if input.include_preferences {
            "SELECT u.*, p.preferences FROM users u LEFT JOIN user_preferences p ON u.id = p.user_id WHERE u.id = $1"
        } else {
            "SELECT * FROM users WHERE id = $1"
        };
        
        let user = db.query_one::<User>(query, &[&input.user_id]).await
            .map_err(|e| ActionError::ExternalServiceError {
                service: "database".to_string(),
                error: e.to_string(),
            })?;
        
        // Кэшируем результат
        cache.set(&cache_key, &user, Duration::from_secs(input.cache_ttl as u64)).await?;
        
        let lookup_time = start_time.elapsed();
        logger.info(&format!("User {} loaded from database in {:?}", input.user_id, lookup_time));
        
        Ok(ActionResult::Success(UserLookupOutput {
            user,
            cached: false,
            lookup_time,
        }))
    }
}

// Пример 3: Stateful action с автоматической state migration
#[derive(Action)]
#[action(id = "counter.increment")]
pub struct CounterAction;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct CounterState {
    pub count: u64,
    pub last_increment: Option<SystemTime>,
    pub increment_history: Vec<SystemTime>,
}

#[derive(Parameters)]
pub struct CounterInput {
    #[parameter(description = "Amount to increment")]
    pub increment: u64,
}

#[derive(Serialize)]
pub struct CounterOutput {
    pub previous_count: u64,
    pub new_count: u64,
    pub total_increments: usize,
}

impl StatefulAction for CounterAction {
    type State = CounterState;
    type Input = CounterInput;
    type Output = CounterOutput;
    
    async fn execute_with_state(
        &self,
        input: Self::Input,
        state: &mut Self::State,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        let previous_count = state.count;
        
        // Update state
        state.count += input.increment;
        state.last_increment = Some(SystemTime::now());
        state.increment_history.push(SystemTime::now());
        
        // Limit history size
        if state.increment_history.len() > 100 {
            state.increment_history.remove(0);
        }
        
        context.log_info(&format!("Counter incremented from {} to {}", previous_count, state.count));
        
        Ok(ActionResult::Success(CounterOutput {
            previous_count,
            new_count: state.count,
            total_increments: state.increment_history.len(),
        }))
    }
    
    async fn migrate_state(
        &self,
        old_state: serde_json::Value,
        old_version: semver::Version,
    ) -> Result<Self::State, ActionError> {
        // Пример миграции состояния между версиями
        if old_version.major < 2 {
            // Миграция с v1 на v2
            #[derive(Deserialize)]
            struct CounterStateV1 {
                count: u64,
                last_increment: Option<SystemTime>,
            }
            
            let v1_state: CounterStateV1 = serde_json::from_value(old_state)?;
            
            Ok(CounterState {
                count: v1_state.count,
                last_increment: v1_state.last_increment,
                increment_history: vec![], // Новое поле в v2
            })
        } else {
            Ok(serde_json::from_value(old_state)?)
        }
    }
}
```

Это обновленная вторая часть документации. Теперь создам третью часть.
