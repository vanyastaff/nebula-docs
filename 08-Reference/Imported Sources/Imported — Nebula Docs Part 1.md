---
title: Imported — Nebula Docs Part 1
tags: [nebula, imported]
created: 2025-08-17
---

# Imported — Nebula Docs Part 1

> Imported source from prior notes. Keep original structure; cross-link into sections as needed.

# Nebula Crates Documentation - Part 1 (Updated)

## Обзор архитектуры

Nebula - это высокопроизводительный workflow engine, построенный на Rust. Система состоит из 23 крейтов, каждый из которых выполняет определенную роль в экосистеме workflow engine.

```
┌─────────────────────────────────────────────────────────┐
│                 Presentation Layer                      │
│       (nebula-ui, nebula-api, nebula-cli, nebula-hub)   │
├─────────────────────────────────────────────────────────┤
│                 Developer Tools Layer                   │
│           (nebula-sdk, nebula-derive, nebula-testing)   │
├─────────────────────────────────────────────────────────┤
│                 Business Logic Layer                    │
│        (nebula-resource, nebula-registry)               │
├─────────────────────────────────────────────────────────┤
│                 Execution Layer                         │
│  (nebula-engine, nebula-runtime, nebula-worker)         │
├─────────────────────────────────────────────────────────┤
│                  Node Layer                             │
│ (nebula-node, nebula-action, nebula-parameter,          │
│           nebula-credential)                            │
├─────────────────────────────────────────────────────────┤
│                  Core Layer                             │
│ (nebula-workflow, nebula-execution, nebula-value,       │
│ nebula-memory, nebula-expression, nebula-eventbus,      │
│ nebula-idempotency)                                     │
├─────────────────────────────────────────────────────────┤
│               Infrastructure Layer                      │
│       (nebula-storage, nebula-binary)                   │
└─────────────────────────────────────────────────────────┘
```

### Основные принципы архитектуры:

1. **Типовая безопасность** - максимальное использование системы типов Rust
2. **Модульность** - четкое разделение обязанностей между компонентами  
3. **Гибкость разработки** - поддержка как программного подхода, так и derive макросов
4. **Atomic Actions** - фокус на простые, переиспользуемые блоки вместо монолитных решений
5. **Умное управление ресурсами** - различные lifecycle scopes для оптимальной производительности
6. **Expression-driven логика** - мощная система выражений для динамической обработки данных
7. **Event-Driven Architecture** - loose coupling через eventbus для масштабируемости

### Ключевые архитектурные решения:

**🎯 Node-Centric Discovery:**
- Node как каталог родственных Actions и Credentials
- UI показывает группировку по Node + прямой поиск по Actions
- Семантическое версионирование на уровне Node
- Package system для распространения узлов через nebula-hub

**🚀 Flexible Development Approach:**
- Простой программный подход для быстрых решений
- Derive макросы для полноценных интеграций с автогенерацией
- Разработчики выбирают подходящий уровень сложности

**⚡ Smart Resource Management:**
- Action-scoped resources (создаются для каждого действия)
- Execution-scoped resources (один на execution)  
- Workflow-scoped resources (один на весь workflow)
- Global resources (singleton для всего приложения)

**🔧 Expression-Powered Workflow Logic:**
- Динамические параметры через `$nodes.previous.result.field`
- Условная логика: `$user.premium && $order.amount > 1000`
- Cross-node data routing без жесткой связки в коде

---

## 1. nebula-workflow (ранее nebula-core)

### Overview

**nebula-workflow** содержит определения и структуры workflow - описывает "что нужно делать". Отвечает за схемы, валидацию, связи между узлами и workflow templates. Это декларативная часть системы.

### Architecture

```rust
// Основная структура workflow - описание процесса
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDefinition {
    pub id: WorkflowId,
    pub name: String,
    pub description: Option<String>,
    pub version: WorkflowVersion,
    pub nodes: Vec<NodeDefinition>,
    pub connections: Vec<Connection>,
    pub triggers: Vec<TriggerDefinition>,
    pub variables: HashMap<String, VariableDefinition>,
    pub metadata: WorkflowMetadata,
}

// Определение узла в workflow - статическое описание
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeDefinition {
    pub id: NodeId,
    pub action_id: ActionId,  // Какое действие выполнять
    pub parameters: ParameterValues,  // Статические и expression параметры
    pub position: Option<NodePosition>,  // Для UI
    pub enabled: bool,
    pub retry_policy: Option<RetryPolicy>,
    pub timeout: Option<Duration>,
}

// Связи между узлами
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub from_node: NodeId,
    pub to_node: NodeId,
    pub condition: Option<String>,  // Expression для условных переходов
    pub port: Option<String>,       // Для multi-output nodes
}

// Переменные workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableDefinition {
    pub name: String,
    pub value_type: ValueType,
    pub default_value: Option<Value>,
    pub description: Option<String>,
    pub expression: Option<String>,  // Динамические переменные
}
```

### Workflow Validation

```rust
// Валидация workflow на этапе развертывания
pub struct WorkflowValidator {
    action_registry: Arc<ActionRegistry>,
}

impl WorkflowValidator {
    pub fn validate(&self, workflow: &WorkflowDefinition) -> ValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // 1. Проверка существования всех actions
        for node in &workflow.nodes {
            if !self.action_registry.has_action(&node.action_id) {
                errors.push(ValidationError::ActionNotFound {
                    node_id: node.id.clone(),
                    action_id: node.action_id.clone(),
                });
            }
        }
        
        // 2. Проверка связей между узлами
        self.validate_connections(workflow, &mut errors, &mut warnings);
        
        // 3. Проверка циклических зависимостей
        self.validate_cycles(workflow, &mut errors);
        
        // 4. Проверка expression syntax
        self.validate_expressions(workflow, &mut errors, &mut warnings);
        
        ValidationResult { errors, warnings }
    }
    
    fn validate_expressions(&self, workflow: &WorkflowDefinition, errors: &mut Vec<ValidationError>, warnings: &mut Vec<ValidationWarning>) {
        for node in &workflow.nodes {
            for (param_name, param_value) in &node.parameters {
                if let ParameterValue::Expression(expr) = param_value {
                    // Проверяем синтаксис expression
                    if let Err(e) = self.parse_expression(expr) {
                        errors.push(ValidationError::InvalidExpression {
                            node_id: node.id.clone(),
                            parameter: param_name.clone(),
                            expression: expr.clone(),
                            error: e.to_string(),
                        });
                    }
                }
            }
        }
    }
}
```

### Examples

```rust
use nebula_workflow::*;

// Создание workflow определения
let workflow = WorkflowDefinition {
    id: WorkflowId::new("user-registration").unwrap(),
    name: "User Registration Process".to_string(),
    description: Some("Complete user registration with email verification".to_string()),
    nodes: vec![
        NodeDefinition {
            id: NodeId::new("validate_input").unwrap(),
            action_id: ActionId::new("validation.user_data").unwrap(),
            parameters: [
                ("email_pattern".to_string(), ParameterValue::String("^[^@]+@[^@]+$".to_string())),
                ("required_fields".to_string(), ParameterValue::Array(vec![
                    Value::String("email".to_string()),
                    Value::String("password".to_string()),
                    Value::String("name".to_string()),
                ])),
            ].into_iter().collect(),
            enabled: true,
            retry_policy: None,
            timeout: Some(Duration::from_secs(30)),
            position: Some(NodePosition { x: 100, y: 100 }),
        },
        NodeDefinition {
            id: NodeId::new("create_user").unwrap(),
            action_id: ActionId::new("database.insert_user").unwrap(),
            parameters: [
                ("table".to_string(), ParameterValue::String("users".to_string())),
                // Expression - берет данные из предыдущего узла
                ("user_data".to_string(), ParameterValue::Expression("$nodes.validate_input.result.validated_data".to_string())),
            ].into_iter().collect(),
            enabled: true,
            retry_policy: Some(RetryPolicy::exponential_backoff(3)),
            timeout: Some(Duration::from_secs(60)),
            position: Some(NodePosition { x: 300, y: 100 }),
        },
        NodeDefinition {
            id: NodeId::new("send_verification").unwrap(),
            action_id: ActionId::new("email.send_template").unwrap(),
            parameters: [
                // Expression - динамический email из результата создания пользователя
                ("to".to_string(), ParameterValue::Expression("$nodes.create_user.result.email".to_string())),
                ("template".to_string(), ParameterValue::String("email_verification".to_string())),
                ("data".to_string(), ParameterValue::Expression(r#"{
                    "user_name": $nodes.create_user.result.name,
                    "verification_link": "${workflow.variables.base_url}/verify/${nodes.create_user.result.verification_token}"
                }"#.to_string())),
            ].into_iter().collect(),
            enabled: true,
            retry_policy: Some(RetryPolicy::fixed_delay(2, Duration::from_secs(5))),
            timeout: Some(Duration::from_secs(30)),
            position: Some(NodePosition { x: 500, y: 100 }),
        },
    ],
    connections: vec![
        Connection {
            from_node: NodeId::new("validate_input").unwrap(),
            to_node: NodeId::new("create_user").unwrap(),
            condition: Some("$nodes.validate_input.success".to_string()),
            port: None,
        },
        Connection {
            from_node: NodeId::new("create_user").unwrap(),
            to_node: NodeId::new("send_verification").unwrap(),
            condition: Some("$nodes.create_user.success".to_string()),
            port: None,
        },
    ],
    variables: [
        ("base_url".to_string(), VariableDefinition {
            name: "base_url".to_string(),
            value_type: ValueType::String { max_length: None, min_length: None, pattern: None },
            default_value: Some(Value::String("https://api.example.com".to_string())),
            description: Some("Base URL for API endpoints".to_string()),
            expression: None,
        }),
        ("admin_email".to_string(), VariableDefinition {
            name: "admin_email".to_string(),
            value_type: ValueType::String { max_length: None, min_length: None, pattern: None },
            default_value: None,
            description: Some("Admin notification email".to_string()),
            // Expression - берется из переменных окружения
            expression: Some("$environment.ADMIN_EMAIL || 'admin@example.com'".to_string()),
        }),
    ].into_iter().collect(),
    triggers: vec![
        TriggerDefinition {
            id: TriggerId::new("api_endpoint").unwrap(),
            trigger_type: TriggerType::Webhook { 
                path: "/api/register".to_string(), 
                method: HttpMethod::Post,
                authentication: Some(AuthRequirement::ApiKey),
            },
            enabled: true,
            metadata: TriggerMetadata::default(),
        }
    ],
    metadata: WorkflowMetadata {
        created_at: SystemTime::now(),
        created_by: Some("developer@example.com".to_string()),
        tags: vec!["user-management".to_string(), "registration".to_string()],
        category: Some("Authentication".to_string()),
    },
};

// Валидация workflow
let validator = WorkflowValidator::new(action_registry);
let validation_result = validator.validate(&workflow);

if validation_result.is_valid() {
    println!("Workflow is valid and ready for deployment");
} else {
    println!("Validation errors: {:?}", validation_result.errors);
}
```

---

## 2. nebula-execution (ранее часть nebula-core)

### Overview

**nebula-execution** управляет "как выполняется" workflow. Содержит execution context, состояние выполнения, координацию между узлами и runtime данные. Это динамическая, исполняемая часть системы.

### Architecture

```rust
// Контекст выполнения - runtime информация
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub execution_id: ExecutionId,
    pub workflow_id: WorkflowId,
    pub workflow_definition: Arc<WorkflowDefinition>,
    pub current_node_id: Option<NodeId>,
    pub user_id: Option<UserId>,
    pub account_id: Option<String>,
    pub environment: ExecutionEnvironment,
    pub variables: Arc<RwLock<HashMap<String, Value>>>,
    pub node_outputs: Arc<RwLock<HashMap<NodeId, NodeOutput>>>,
    pub execution_metadata: ExecutionMetadata,
    pub resource_manager: Arc<ResourceManager>,
    pub credential_manager: Arc<CredentialManager>,
    pub expression_engine: Arc<ExpressionEngine>,
    pub event_bus: Arc<EventBus>,
}

// Состояние выполнения workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionState {
    pub execution_id: ExecutionId,
    pub workflow_id: WorkflowId,
    pub status: ExecutionStatus,
    pub current_step: Option<NodeId>,
    pub completed_nodes: HashSet<NodeId>,
    pub failed_nodes: HashSet<NodeId>,
    pub node_states: HashMap<NodeId, NodeExecutionState>,
    pub start_time: SystemTime,
    pub end_time: Option<SystemTime>,
    pub error: Option<ExecutionError>,
    pub retry_count: u32,
}

// Результат выполнения узла
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeOutput {
    pub node_id: NodeId,
    pub action_id: ActionId,
    pub result: ActionResult<Value>,
    pub execution_time: Duration,
    pub timestamp: SystemTime,
    pub retry_count: u32,
    pub error: Option<String>,
}

// Статусы выполнения
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExecutionStatus {
    Pending,
    Running,
    Paused,
    Completed { result: Value },
    Failed { error: ExecutionError },
    Cancelled { reason: String },
    TimedOut,
}
```

### Expression Integration

```rust
impl ExecutionContext {
    // Основной метод для вычисления expressions
    pub async fn evaluate_expression(&self, expression: &str) -> Result<Value, ExpressionError> {
        let mut context = ExpressionContext::new();
        
        // Добавляем доступные данные в контекст expression
        context.add_scope("nodes", self.get_node_results().await);
        context.add_scope("workflow", self.get_workflow_variables().await);
        context.add_scope("execution", self.get_execution_metadata());
        context.add_scope("user", self.get_user_context().await);
        context.add_scope("environment", self.get_environment_variables());
        
        self.expression_engine.evaluate(expression, &context).await
    }
    
    // Получение результатов других узлов для expressions
    async fn get_node_results(&self) -> Value {
        let outputs = self.node_outputs.read().await;
        let mut node_data = Map::new();
        
        for (node_id, output) in outputs.iter() {
            let node_result = match &output.result {
                ActionResult::Success(value) => json!({
                    "success": true,
                    "result": value,
                    "execution_time": output.execution_time.as_millis(),
                    "timestamp": output.timestamp,
                }),
                ActionResult::Skip { reason } => json!({
                    "success": false,
                    "skipped": true,
                    "reason": reason,
                }),
                ActionResult::Retry { after, reason } => json!({
                    "success": false,
                    "retry": true,
                    "reason": reason,
                    "retry_after": after.as_secs(),
                }),
                // ... другие варианты
            };
            node_data.insert(node_id.to_string(), node_result);
        }
        
        Value::Object(node_data)
    }
    
    // Получение переменных workflow
    async fn get_workflow_variables(&self) -> Value {
        let variables = self.variables.read().await;
        let mut var_data = Map::new();
        
        // Добавляем обычные переменные
        for (name, value) in variables.iter() {
            var_data.insert(name.clone(), value.clone());
        }
        
        // Добавляем метаданные workflow
        var_data.insert("id".to_string(), Value::String(self.workflow_id.to_string()));
        var_data.insert("name".to_string(), Value::String(self.workflow_definition.name.clone()));
        
        Value::Object(var_data)
    }
}
```

### Resource Integration

```rust
impl ExecutionContext {
    // Получение ресурсов с правильным scope
    pub async fn get_resource<T: Resource + 'static>(&self) -> Result<Arc<T>, ResourceError> {
        let resource_scope = ResourceScope {
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            action_id: self.current_node_id.clone(),
            account_id: self.account_id.clone(),
            user_id: self.user_id.clone(),
        };
        
        self.resource_manager.get_scoped_resource::<T>(resource_scope).await
    }
    
    // Получение credential через nebula-credential
    pub async fn get_credential(&self, credential_id: &str) -> Result<Credential, CredentialError> {
        let credential_context = CredentialContext {
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            user_id: self.user_id.clone(),
            account_id: self.account_id.clone(),
        };
        
        self.credential_manager.get_credential(credential_id, &credential_context).await
    }
    
    // Автоматический клиент с credential
    pub async fn get_client<T: AuthenticatedClient>(&self, credential_type: &str) -> Result<T, ClientError> {
        let credential = self.get_credential(credential_type).await?;
        T::from_credential(credential).await
    }
}
```

### Examples

```rust
use nebula_execution::*;

// Создание execution context
let execution_context = ExecutionContext::builder()
    .execution_id(ExecutionId::new())
    .workflow_id(workflow_id)
    .workflow_definition(Arc::new(workflow_definition))
    .user_id(Some(user_id))
    .account_id(Some("acme-corp".to_string()))
    .environment(ExecutionEnvironment::Production)
    .resource_manager(resource_manager)
    .credential_manager(credential_manager)
    .expression_engine(expression_engine)
    .build();

// Выполнение expression в контексте
let user_email = execution_context
    .evaluate_expression("$nodes.create_user.result.email")
    .await?;

let dynamic_endpoint = execution_context
    .evaluate_expression("${workflow.variables.base_url}/users/${nodes.create_user.result.id}")
    .await?;

let conditional_execution = execution_context
    .evaluate_expression("$user.premium && $nodes.validation.result.score > 80")
    .await?;

// Получение ресурсов с автоматическим scope
let logger = execution_context.get_resource::<LoggerResource>().await?;
let database = execution_context.get_resource::<DatabaseResource>().await?;

// Логирование с автоматическим контекстом
logger.info("Starting user creation process");

// Работа с базой данных
let user_data = database.query_one::<User>(
    "SELECT * FROM users WHERE email = $1",
    &[&user_email.as_str().unwrap()]
).await?;
```

---

## 3. nebula-value

### Overview

**nebula-value** предоставляет типобезопасную систему значений для передачи данных между узлами workflow. Поддерживает широкий спектр типов данных с zero-copy оптимизациями и строгой валидацией для Expression System.

### Architecture

```rust
// Основной тип значения с поддержкой zero-copy
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(StringValue),
    Array(Vec<Value>),
    Object(ObjectValue),
    Binary(BinaryValue),
    DateTime(DateTime<Utc>),
    Duration(Duration),
    Reference(ValueReference),  // Ссылка на другое значение для expression system
    Expression(String),         // Неразрешенное expression
}

// Оптимизированное представление строк
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StringValue {
    Inline(SmallString<[u8; 22]>),   // Малые строки без аллокации
    Heap(String),                    // Большие строки
    Interned(InternedString),        // Переиспользуемые строки
    Borrowed(&'static str),          // Статические строки
}

// Бинарные данные с различными стратегиями хранения
#[derive(Debug, Clone, PartialEq)]
pub enum BinaryValue {
    Inline(SmallVec<[u8; 64]>),     // Малые данные без аллокации
    Heap(Vec<u8>),                   // Средние данные в памяти
    MMap(MemoryMappedFile),          // Большие файлы
    Stream(Box<dyn AsyncRead>),      // Потоковые данные
}

// Ссылки на значения для expression system
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValueReference {
    NodeOutput { node_id: String, field_path: String },     // $nodes.create_user.result.email
    WorkflowVariable { variable_name: String },             // $workflow.variables.base_url
    ExecutionMetadata { field_name: String },               // $execution.start_time
    UserContext { field_name: String },                     // $user.id
    Environment { variable_name: String },                  // $environment.API_BASE_URL
}
```

### Type System для Expression Engine

```rust
// Схема типов для валидации и expression resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValueType {
    Null,
    Boolean,
    Integer { min: Option<i64>, max: Option<i64> },
    Float { min: Option<f64>, max: Option<f64> },
    String { 
        min_length: Option<usize>, 
        max_length: Option<usize>,
        pattern: Option<String>,
    },
    Array { 
        element_type: Box<ValueType>,
        min_items: Option<usize>,
        max_items: Option<usize>,
    },
    Object { 
        schema: ObjectSchema,
        additional_properties: bool,
    },
    Binary { 
        max_size: Option<usize>,
        allowed_types: Option<Vec<String>>,  // MIME types
    },
    DateTime,
    Duration,
    Union(Vec<ValueType>),
    Reference { target_type: Box<ValueType> },  // Для expression references
    Expression { expected_type: Box<ValueType> }, // Для неразрешенных expressions
}

// Схема объекта для сложных типов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectSchema {
    pub properties: HashMap<String, PropertySchema>,
    pub required: HashSet<String>,
    pub additional_properties: bool,
}

// Схема свойства
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertySchema {
    pub value_type: ValueType,
    pub description: Option<String>,
    pub default: Option<Value>,
    pub validation: Option<ValidationRules>,
    pub deprecated: bool,
}
```

### Expression Resolution

```rust
impl Value {
    // Разрешение expression values в runtime values
    pub async fn resolve_expressions(&self, context: &ExecutionContext) -> Result<Value, ExpressionError> {
        match self {
            Value::Expression(expr) => {
                // Разрешаем expression через execution context
                context.evaluate_expression(expr).await
            }
            Value::Reference(reference) => {
                // Разрешаем ссылку на другое значение
                self.resolve_reference(reference, context).await
            }
            Value::Object(obj) => {
                // Рекурсивно разрешаем expressions в объекте
                let mut resolved_obj = ObjectValue::new();
                for (key, value) in obj.iter() {
                    resolved_obj.insert(key.clone(), value.resolve_expressions(context).await?);
                }
                Ok(Value::Object(resolved_obj))
            }
            Value::Array(arr) => {
                // Рекурсивно разрешаем expressions в массиве
                let mut resolved_arr = Vec::new();
                for value in arr {
                    resolved_arr.push(value.resolve_expressions(context).await?);
                }
                Ok(Value::Array(resolved_arr))
            }
            // Остальные типы остаются как есть
            other => Ok(other.clone()),
        }
    }
    
    async fn resolve_reference(&self, reference: &ValueReference, context: &ExecutionContext) -> Result<Value, ExpressionError> {
        match reference {
            ValueReference::NodeOutput { node_id, field_path } => {
                let node_outputs = context.node_outputs.read().await;
                let output = node_outputs.get(&NodeId::new(node_id)?)
                    .ok_or_else(|| ExpressionError::NodeOutputNotFound(node_id.clone()))?;
                
                // Извлекаем значение по field_path
                self.extract_field_value(&output.result, field_path)
            }
            ValueReference::WorkflowVariable { variable_name } => {
                let variables = context.variables.read().await;
                variables.get(variable_name)
                    .cloned()
                    .ok_or_else(|| ExpressionError::VariableNotFound(variable_name.clone()))
            }
            ValueReference::ExecutionMetadata { field_name } => {
                match field_name.as_str() {
                    "execution_id" => Ok(Value::String(context.execution_id.to_string().into())),
                    "workflow_id" => Ok(Value::String(context.workflow_id.to_string().into())),
                    "start_time" => Ok(Value::DateTime(context.execution_metadata.start_time)),
                    "user_id" => Ok(context.user_id.as_ref()
                        .map(|id| Value::String(id.to_string().into()))
                        .unwrap_or(Value::Null)),
                    _ => Err(ExpressionError::UnknownMetadataField(field_name.clone())),
                }
            }
            ValueReference::UserContext { field_name } => {
                // Получаем пользовательский контекст
                context.get_user_context_field(field_name).await
            }
            ValueReference::Environment { variable_name } => {
                std::env::var(variable_name)
                    .map(|val| Value::String(val.into()))
                    .unwrap_or(Value::Null)
                    .into()
            }
        }
    }
}
```

### Performance Features

```rust
// Copy-on-write для больших объектов
#[derive(Debug, Clone)]
pub struct CowValue<'a> {
    inner: Cow<'a, Value>,
}

impl<'a> CowValue<'a> {
    pub fn borrowed(value: &'a Value) -> Self {
        Self { inner: Cow::Borrowed(value) }
    }
    
    pub fn owned(value: Value) -> Self {
        Self { inner: Cow::Owned(value) }
    }
    
    // Мутация с copy-on-write семантикой
    pub fn to_mut(&mut self) -> &mut Value {
        self.inner.to_mut()
    }
}

// Lazy evaluation для дорогих операций
pub struct LazyValue {
    generator: Box<dyn Fn(&ExecutionContext) -> BoxFuture<'_, Result<Value, ExpressionError>> + Send + Sync>,
    cached: OnceCell<Value>,
}

impl LazyValue {
    pub async fn resolve(&self, context: &ExecutionContext) -> Result<&Value, ExpressionError> {
        if let Some(cached) = self.cached.get() {
            return Ok(cached);
        }
        
        let value = (self.generator)(context).await?;
        Ok(self.cached.get_or_init(|| value))
    }
}

// Streaming для больших массивов
pub struct ValueStream {
    source: Box<dyn Stream<Item = Result<Value, StreamError>> + Send + Unpin>,
    chunk_size: usize,
}
```

### Examples

```rust
use nebula_value::*;

// Создание значений с автоматической оптимизацией
let small_string = Value::string("hello");  // Inline storage
let large_binary = Value::binary(vec![0u8; 1024 * 1024]);  // Heap storage

// Expression values для workflow parameters
let dynamic_email = Value::Expression("$nodes.create_user.result.email".to_string());
let conditional_value = Value::Expression(r#"
    if $user.premium then 
        $nodes.premium_processing.result 
    else 
        $nodes.standard_processing.result
"#.to_string());

// Reference values для прямых ссылок
let user_id_ref = Value::Reference(ValueReference::NodeOutput {
    node_id: "create_user".to_string(),
    field_path: "result.id".to_string(),
});

// Сложные объекты с expressions
let email_template_data = Value::Object([
    ("to".to_string(), Value::Expression("$nodes.user_lookup.result.email".to_string())),
    ("subject".to_string(), Value::String("Welcome to our service!".into())),
    ("user_name".to_string(), Value::Expression("$nodes.user_lookup.result.name".to_string())),
    ("verification_link".to_string(), Value::Expression(
        "${workflow.variables.base_url}/verify/${nodes.create_user.result.verification_token}".to_string()
    )),
    ("account_type".to_string(), Value::Expression(
        "if $user.premium then 'Premium' else 'Standard'".to_string()
    )),
].into_iter().collect());

// Разрешение expressions в runtime
let resolved_data = email_template_data.resolve_expressions(&execution_context).await?;

// Type-safe операции с валидацией
let email_schema = ValueType::String {
    min_length: Some(1),
    max_length: Some(255),
    pattern: Some(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
};

let user_schema = ValueType::Object {
    schema: ObjectSchema {
        properties: [
            ("id".to_string(), PropertySchema {
                value_type: ValueType::Integer { min: Some(1), max: None },
                description: Some("Unique user identifier".to_string()),
                default: None,
                validation: None,
                deprecated: false,
            }),
            ("email".to_string(), PropertySchema {
                value_type: email_schema,
                description: Some("User email address".to_string()),
                default: None,
                validation: Some(ValidationRules::Required),
                deprecated: false,
            }),
            ("name".to_string(), PropertySchema {
                value_type: ValueType::String {
                    min_length: Some(1),
                    max_length: Some(100),
                    pattern: None,
                },
                description: Some("User display name".to_string()),
                default: None,
                validation: Some(ValidationRules::Required),
                deprecated: false,
            }),
        ].into_iter().collect(),
        required: ["id", "email", "name"].into_iter().map(String::from).collect(),
        additional_properties: false,
    },
    additional_properties: false,
};

// Валидация значений против схемы
let user_value = Value::Object([
    ("id".to_string(), Value::Number(123.into())),
    ("email".to_string(), Value::String("user@example.com".into())),
    ("name".to_string(), Value::String("John Doe".into())),
].into_iter().collect());

let validation_result = user_schema.validate(&user_value)?;
assert!(validation_result.is_valid());

// Zero-copy операции где возможно
let borrowed_string = user_value
    .get_object()
    .and_then(|obj| obj.get("name"))
    .and_then(|v| v.as_str_borrowed())  // Без копирования строки
    .ok_or("Missing name field")?;
```

### Integration with Expression Engine

```rust
// Value types интегрируются с expression engine для type checking
impl ExpressionEngine {
    pub fn type_check_expression(&self, expr: &str, expected_type: &ValueType) -> Result<(), TypeError> {
        let inferred_type = self.infer_expression_type(expr)?;
        
        if !expected_type.is_compatible_with(&inferred_type) {
            return Err(TypeError::TypeMismatch {
                expected: expected_type.clone(),
                actual: inferred_type,
                expression: expr.to_string(),
            });
        }
        
        Ok(())
    }
    
    pub fn infer_expression_type(&self, expr: &str) -> Result<ValueType, TypeError> {
        // Парсинг expression и определение типа результата
        let ast = self.parse_expression(expr)?;
        self.infer_ast_type(&ast)
    }
}
```

Это обновленная первая часть документации, которая четко разделяет ответственности между крейтами, показывает гибкий подход к разработке и интеграцию с Expression System. В следующих частях я обновлю остальные крейты с учетом этих изменений.
