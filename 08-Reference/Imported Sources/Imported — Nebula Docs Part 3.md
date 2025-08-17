---
title: Imported — Nebula Docs Part 3
tags: [nebula, imported]
created: 2025-08-17
---

# Imported — Nebula Docs Part 3

> Imported source from prior notes. Keep original structure; cross-link into sections as needed.

# Nebula Crates Documentation - Part 3 (Updated)

## 8. nebula-parameter

### Overview

**nebula-parameter** предоставляет типобезопасную систему параметров для Actions и Nodes с поддержкой как программного подхода, так и derive макросов. Включает валидацию, expression integration, и динамическое разрешение параметров.

### Architecture

```rust
// Основная структура параметра с expression support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Parameter {
    pub name: String,
    pub parameter_type: ParameterType,
    pub required: bool,
    pub default_value: Option<ParameterValue>,
    pub description: Option<String>,
    pub validation_rules: Vec<ValidationRule>,
    pub metadata: ParameterMetadata,
}

// Значения параметров с поддержкой expressions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterValue {
    Static(Value),                    // Статическое значение
    Expression(String),               // Expression строка: "$nodes.create_user.result.email"
    Reference(ValueReference),        // Прямая ссылка на другое значение
    Template(String, Vec<String>),    // String template: "Hello ${user.name}!"
}

// Типы параметров с расширенной валидацией
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ParameterType {
    String { 
        min_length: Option<usize>, 
        max_length: Option<usize>,
        pattern: Option<String>,
        enum_values: Option<Vec<String>>,  // Enum constraint
    },
    Integer { 
        min: Option<i64>, 
        max: Option<i64>,
        multiple_of: Option<i64>,
    },
    Float { 
        min: Option<f64>, 
        max: Option<f64>,
        precision: Option<u8>,
    },
    Boolean,
    Array { 
        element_type: Box<ParameterType>,
        min_items: Option<usize>,
        max_items: Option<usize>,
        unique_items: bool,
    },
    Object { 
        schema: ObjectSchema,
        additional_properties: bool,
    },
    Enum { 
        variants: Vec<EnumVariant>,
        allow_custom: bool,
    },
    Union(Vec<ParameterType>),
    File {
        allowed_types: Option<Vec<String>>,  // MIME types
        max_size: Option<usize>,
    },
    Credential {
        credential_type: String,  // "api_key", "oauth2", etc.
    },
    Node {
        allowed_actions: Option<Vec<ActionId>>,  // Reference to other nodes
    },
    Expression {
        expected_type: Box<ParameterType>,  // Expected result type
    },
    Any,
}

// Коллекция параметров с группировкой
pub struct ParameterCollection {
    parameters: HashMap<String, Parameter>,
    groups: Vec<ParameterGroup>,
    conditional_parameters: Vec<ConditionalParameter>,
}

// Группировка параметров для UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterGroup {
    pub name: String,
    pub description: Option<String>,
    pub parameters: Vec<String>,
    pub collapsible: bool,
    pub collapsed_by_default: bool,
}

// Условные параметры (показываются только при определенных условиях)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionalParameter {
    pub parameter_name: String,
    pub condition: String,  // Expression: "method == 'POST'"
    pub show_when: bool,    // true = show when condition is true
}
```

### Flexible Parameter Declaration

```rust
// Подход 1: Программный (для простых случаев)
impl SimpleEmailAction {
    fn parameter_schema(&self) -> ParameterCollection {
        ParameterCollection::new()
            .add_required("to", ParameterType::String {
                min_length: Some(1),
                max_length: Some(255),
                pattern: Some(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
                enum_values: None,
            })
            .add_required("subject", ParameterType::String {
                min_length: Some(1),  
                max_length: Some(200),
                pattern: None,
                enum_values: None,
            })
            .add_required("body", ParameterType::String {
                min_length: None,
                max_length: Some(10000),
                pattern: None,
                enum_values: None,
            })
            .add_optional("priority", ParameterType::Enum {
                variants: vec![
                    EnumVariant::new("low", "Low Priority"),
                    EnumVariant::new("normal", "Normal Priority"),
                    EnumVariant::new("high", "High Priority"),
                ],
                allow_custom: false,
            })
            .with_default_value("priority", ParameterValue::Static(Value::String("normal".into())))
    }
}

// Подход 2: Derive макросы (для сложных случаев)
#[derive(Parameters)]
pub struct AdvancedEmailParameters {
    #[parameter(
        description = "Recipient email address",
        validation = "email"
    )]
    pub to: String,
    
    #[parameter(
        description = "Email subject",
        max_length = 200
    )]
    pub subject: String,
    
    #[parameter(
        description = "Email body content",
        max_length = 10000
    )]
    pub body: String,
    
    #[parameter(
        description = "Message priority",
        default = "normal",
        enum_values = ["low", "normal", "high"]
    )]
    pub priority: String,
    
    #[parameter(
        description = "Send as HTML",
        default = false,
        group = "formatting"
    )]
    pub html: bool,
    
    #[parameter(
        description = "HTML template name",
        optional,
        show_when = "html == true",  // Conditional parameter
        group = "formatting"
    )]
    pub template: Option<String>,
    
    #[parameter(
        description = "Template variables",
        optional,
        show_when = "html == true && template.is_some()",
        group = "formatting"
    )]
    pub template_vars: Option<HashMap<String, Value>>,
    
    #[parameter(
        description = "Attachments",
        optional,
        max_items = 10
    )]
    pub attachments: Option<Vec<FileAttachment>>,
    
    #[parameter(
        description = "SMTP credential",
        credential_type = "smtp"
    )]
    pub smtp_credential: String,
    
    #[parameter(
        description = "Send time (expression supported)",
        optional,
        expression_type = "DateTime"
    )]
    pub send_at: Option<String>,  // Может быть expression: "$nodes.scheduler.result.send_time"
}

// Группы автоматически генерируются из group атрибутов
// "formatting" группа будет содержать: html, template, template_vars
```

### Expression Integration в Parameters

```rust
impl ParameterCollection {
    // Разрешение dynamic parameters с expression support
    pub async fn resolve_parameters(
        &self,
        raw_parameters: &HashMap<String, ParameterValue>,
        context: &ExecutionContext,
    ) -> Result<ResolvedParameters, ParameterError> {
        let mut resolved = ResolvedParameters::new();
        
        for (name, param) in &self.parameters {
            let raw_value = raw_parameters.get(name);
            
            let resolved_value = match raw_value {
                Some(ParameterValue::Static(value)) => value.clone(),
                Some(ParameterValue::Expression(expr)) => {
                    // Разрешаем expression через ExecutionContext
                    context.evaluate_expression(expr).await
                        .map_err(|e| ParameterError::ExpressionError {
                            parameter: name.clone(),
                            expression: expr.clone(),
                            error: e,
                        })?
                }
                Some(ParameterValue::Reference(reference)) => {
                    // Разрешаем прямую ссылку
                    self.resolve_reference(reference, context).await?
                }
                Some(ParameterValue::Template(template, expressions)) => {
                    // Разрешаем string template
                    self.resolve_template(template, expressions, context).await?
                }
                None if param.required => {
                    return Err(ParameterError::RequiredParameterMissing(name.clone()));
                }
                None => {
                    // Используем default value или пропускаем
                    param.default_value.as_ref()
                        .map(|default| self.resolve_parameter_value(default, context))
                        .transpose()?.flatten()
                        .unwrap_or(Value::Null)
                }
            };
            
            // Валидируем разрешенное значение
            let validation_result = self.validate_parameter_value(name, &resolved_value, param)?;
            if !validation_result.is_valid {
                return Err(ParameterError::ValidationFailed {
                    parameter: name.clone(),
                    errors: validation_result.errors,
                });
            }
            
            resolved.insert(name.clone(), resolved_value);
        }
        
        // Проверяем conditional parameters
        self.resolve_conditional_parameters(&mut resolved, context).await?;
        
        Ok(resolved)
    }
    
    async fn resolve_template(
        &self,
        template: &str,
        expressions: &[String],
        context: &ExecutionContext,
    ) -> Result<Value, ParameterError> {
        let mut result = template.to_string();
        
        for (i, expr) in expressions.iter().enumerate() {
            let placeholder = format!("${{{}}}", i);
            let value = context.evaluate_expression(expr).await?;
            let value_str = self.value_to_string(&value);
            result = result.replace(&placeholder, &value_str);
        }
        
        Ok(Value::String(result.into()))
    }
    
    async fn resolve_conditional_parameters(
        &self,
        resolved: &mut ResolvedParameters,
        context: &ExecutionContext,
    ) -> Result<(), ParameterError> {
        for conditional in &self.conditional_parameters {
            let should_show = context.evaluate_expression(&conditional.condition).await?
                .as_bool().unwrap_or(false);
            
            if conditional.show_when != should_show {
                // Remove parameter if condition not met
                resolved.remove(&conditional.parameter_name);
            }
        }
        
        Ok(())
    }
}
```

### Advanced Validation System

```rust
// Правила валидации с expression support
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    Required,
    MinLength(usize),
    MaxLength(usize),
    Pattern(String),
    Range { min: Value, max: Value },
    OneOf(Vec<Value>),
    Email,
    Url,
    Json,
    UniqueItems,  // Для массивов
    Custom { 
        name: String, 
        expression: String,  // Expression для custom валидации
        error_message: String,
    },
    CrossField {
        other_field: String,
        relationship: FieldRelationship,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FieldRelationship {
    Equal,
    NotEqual,
    GreaterThan,
    LessThan,
    RequiredIf(String),  // Expression
    ExclusiveWith,       // Поля взаимоисключающие
}

// Результат валидации с подробной информацией
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub parameter: String,
    pub rule: ValidationRule,
    pub message: String,
    pub value: Option<Value>,
    pub suggestion: Option<String>,  // Предложение по исправлению
}

impl ParameterCollection {
    pub fn validate_parameter_value(
        &self, 
        name: &str, 
        value: &Value, 
        param: &Parameter
    ) -> Result<ValidationResult, ParameterError> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        
        // Type validation
        if !self.validate_type(value, &param.parameter_type) {
            errors.push(ValidationError {
                parameter: name.to_string(),
                rule: ValidationRule::Custom { 
                    name: "type_check".to_string(),
                    expression: "".to_string(),
                    error_message: format!("Expected type {:?}, got {:?}", param.parameter_type, value),
                },
                message: format!("Invalid type for parameter '{}'", name),
                value: Some(value.clone()),
                suggestion: Some(self.suggest_type_conversion(value, &param.parameter_type)),
            });
        }
        
        // Rule-based validation
        for rule in &param.validation_rules {
            match self.apply_validation_rule(value, rule) {
                Ok(()) => continue,
                Err(error) => errors.push(ValidationError {
                    parameter: name.to_string(),
                    rule: rule.clone(),
                    message: error,
                    value: Some(value.clone()),
                    suggestion: self.suggest_fix(value, rule),
                }),
            }
        }
        
        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
        })
    }
    
    fn suggest_type_conversion(&self, value: &Value, expected_type: &ParameterType) -> String {
        match (value, expected_type) {
            (Value::String(s), ParameterType::Integer { .. }) => {
                format!("Try converting '{}' to a number", s)
            }
            (Value::Number(_), ParameterType::String { .. }) => {
                "Try wrapping the number in quotes".to_string()
            }
            (Value::String(s), ParameterType::Boolean) => {
                format!("Try using 'true' or 'false' instead of '{}'", s)
            }
            _ => "Check the expected parameter type".to_string(),
        }
    }
}
```

### UI Integration

```rust
// Метаданные для UI генерации форм
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterUIMetadata {
    pub parameter_name: String,
    pub display_name: String,
    pub description: String,
    pub ui_type: UIParameterType,
    pub group: Option<String>,
    pub order: Option<u32>,
    pub placeholder: Option<String>,
    pub help_text: Option<String>,
    pub conditional_display: Option<ConditionalDisplay>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UIParameterType {
    TextInput { multiline: bool },
    NumberInput { step: Option<f64> },
    Select { options: Vec<SelectOption> },
    MultiSelect { options: Vec<SelectOption> },
    Checkbox,
    FileUpload { accept: Option<String> },
    DatePicker,
    TimePicker,
    DateTimePicker,
    CodeEditor { language: Option<String> },
    ExpressionEditor { expected_type: String },
    CredentialSelector { credential_type: String },
    NodeSelector { allowed_types: Vec<String> },
    JsonEditor,
    KeyValueEditor,
}

impl ParameterCollection {
    // Генерация UI метаданных для фронтенда
    pub fn generate_ui_metadata(&self) -> Vec<ParameterUIMetadata> {
        let mut ui_metadata = Vec::new();
        
        for (name, param) in &self.parameters {
            let ui_type = self.infer_ui_type(&param.parameter_type);
            
            ui_metadata.push(ParameterUIMetadata {
                parameter_name: name.clone(),
                display_name: self.humanize_parameter_name(name),
                description: param.description.clone().unwrap_or_default(),
                ui_type,
                group: self.find_parameter_group(name),
                order: param.metadata.ui_order,
                placeholder: param.metadata.placeholder.clone(),
                help_text: param.metadata.help_text.clone(),
                conditional_display: self.get_conditional_display(name),
            });
        }
        
        // Сортируем по группам и порядку
        ui_metadata.sort_by(|a, b| {
            match (&a.group, &b.group) {
                (Some(g1), Some(g2)) if g1 != g2 => g1.cmp(g2),
                (None, Some(_)) => std::cmp::Ordering::Less,
                (Some(_), None) => std::cmp::Ordering::Greater,
                _ => a.order.unwrap_or(0).cmp(&b.order.unwrap_or(0)),
            }
        });
        
        ui_metadata
    }
    
    fn infer_ui_type(&self, param_type: &ParameterType) -> UIParameterType {
        match param_type {
            ParameterType::String { max_length, .. } => {
                UIParameterType::TextInput { 
                    multiline: max_length.map_or(false, |len| len > 100) 
                }
            }
            ParameterType::Integer { .. } | ParameterType::Float { .. } => {
                UIParameterType::NumberInput { step: None }
            }
            ParameterType::Boolean => UIParameterType::Checkbox,
            ParameterType::Enum { variants, .. } => {
                UIParameterType::Select { 
                    options: variants.iter().map(|v| SelectOption {
                        value: v.value.clone(),
                        label: v.display_name.clone(),
                    }).collect()
                }
            }
            ParameterType::File { .. } => UIParameterType::FileUpload { accept: None },
            ParameterType::Credential { credential_type } => {
                UIParameterType::CredentialSelector { 
                    credential_type: credential_type.clone() 
                }
            }
            ParameterType::Expression { .. } => {
                UIParameterType::ExpressionEditor { expected_type: "any".to_string() }
            }
            ParameterType::Object { .. } => UIParameterType::JsonEditor,
            _ => UIParameterType::TextInput { multiline: false },
        }
    }
}
```

### Examples

```rust
use nebula_parameter::*;

// Пример 1: Программное создание параметров для HTTP Action
let http_parameters = ParameterCollection::new()
    .add_group(ParameterGroup {
        name: "Request".to_string(),
        description: Some("HTTP request configuration".to_string()),
        parameters: vec!["url".to_string(), "method".to_string(), "headers".to_string()],
        collapsible: false,
        collapsed_by_default: false,
    })
    .add_group(ParameterGroup {
        name: "Advanced".to_string(),
        description: Some("Advanced HTTP options".to_string()),
        parameters: vec!["timeout".to_string(), "follow_redirects".to_string()],
        collapsible: true,
        collapsed_by_default: true,
    })
    .add_required("url", ParameterType::String {
        min_length: Some(1),
        max_length: Some(2048),
        pattern: Some(r"^https?://.*".to_string()),
        enum_values: None,
    })
    .add_required("method", ParameterType::Enum {
        variants: vec![
            EnumVariant::new("GET", "GET Request"),
            EnumVariant::new("POST", "POST Request"),
            EnumVariant::new("PUT", "PUT Request"),
            EnumVariant::new("DELETE", "DELETE Request"),
            EnumVariant::new("PATCH", "PATCH Request"),
        ],
        allow_custom: false,
    })
    .add_optional("headers", ParameterType::Object {
        schema: ObjectSchema {
            properties: HashMap::new(),
            required: HashSet::new(),
            additional_properties: true,
        },
        additional_properties: true,
    })
    .add_optional("timeout", ParameterType::Integer {
        min: Some(1),
        max: Some(300),
        multiple_of: None,
    })
    .with_default_value("timeout", ParameterValue::Static(Value::Number(30.into())))
    .with_default_value("method", ParameterValue::Static(Value::String("GET".into())))
    .add_conditional_parameter(ConditionalParameter {
        parameter_name: "body".to_string(),
        condition: "method == 'POST' || method == 'PUT' || method == 'PATCH'".to_string(),
        show_when: true,
    });

// Пример 2: Derive макросы для сложного Action
#[derive(Parameters)]
pub struct DatabaseQueryParameters {
    #[parameter(
        description = "SQL query to execute",
        validation = "sql_syntax",
        group = "query"
    )]
    pub query: String,
    
    #[parameter(
        description = "Query parameters",
        optional,
        group = "query"
    )]
    pub params: Option<Vec<Value>>,
    
    #[parameter(
        description = "Maximum number of rows to fetch",
        default = 1000,
        min = 1,
        max = 10000,
        group = "limits"
    )]
    pub limit: u32,
    
    #[parameter(
        description = "Query timeout in seconds",
        default = 30,
        min = 1,
        max = 300,
        group = "limits"
    )]
    pub timeout: u32,
    
    #[parameter(
        description = "Cache results",
        default = false,
        group = "caching"
    )]
    pub cache_results: bool,
    
    #[parameter(
        description = "Cache TTL in seconds",
        default = 300,
        show_when = "cache_results == true",
        group = "caching"
    )]
    pub cache_ttl: u32,
    
    #[parameter(
        description = "Database connection credential",
        credential_type = "database"
    )]
    pub db_credential: String,
    
    #[parameter(
        description = "Execute at specific time (expression supported)",
        optional,
        expression_type = "DateTime"
    )]
    pub execute_at: Option<String>,  // Может быть: "$nodes.scheduler.result.execute_time"
}

// Пример 3: Использование expressions в параметрах
let email_params = hashmap! {
    "to".to_string() => ParameterValue::Expression("$nodes.user_lookup.result.email".to_string()),
    "subject".to_string() => ParameterValue::Template(
        "Order #{order_id} confirmation for {user_name}".to_string(),
        vec![
            "$nodes.create_order.result.id".to_string(),
            "$nodes.user_lookup.result.name".to_string(),
        ]
    ),
    "body".to_string() => ParameterValue::Template(
        "Hello {user_name}!\n\nYour order #{order_id} has been confirmed.\nTotal: ${total}\n\nThank you!".to_string(),
        vec![
            "$nodes.user_lookup.result.name".to_string(),
            "$nodes.create_order.result.id".to_string(), 
            "$nodes.create_order.result.total".to_string(),
        ]
    ),
    "priority".to_string() => ParameterValue::Expression(
        "if $nodes.create_order.result.total > 1000 then 'high' else 'normal'".to_string()
    ),
    "send_at".to_string() => ParameterValue::Expression(
        "add_minutes(now(), if $user.premium then 0 else 30)".to_string()
    ),
};

// Разрешение параметров в runtime
let resolved_params = parameter_collection
    .resolve_parameters(&email_params, &execution_context)
    .await?;

// Результат: все expressions разрешены в конкретные значения
assert_eq!(resolved_params.get("to").unwrap().as_str().unwrap(), "user@example.com");
assert_eq!(resolved_params.get("subject").unwrap().as_str().unwrap(), "Order #12345 confirmation for John Doe");
```

---

## 9. nebula-credential

### Overview

**nebula-credential** управляет безопасным хранением и использованием учетных данных для внешних сервисов. Поддерживает различные типы аутентификации, автоматическую ротацию, шифрование, и seamless интеграцию с Action system.

### Architecture

```rust
// Основной трейт для всех типов credentials с lifecycle support
#[async_trait]
pub trait Credential: Send + Sync {
    // Метаданные credential
    fn metadata(&self) -> &CredentialMetadata;
    
    // Тип аутентификации
    fn auth_type(&self) -> AuthenticationType;
    
    // Получение данных для аутентификации с context
    async fn get_auth_data(&self, context: &CredentialContext) -> Result<AuthData, CredentialError>;
    
    // Проверка валидности
    async fn validate(&self) -> Result<ValidationResult, CredentialError>;
    
    // Обновление данных (для токенов с expiration)
    async fn refresh(&mut self) -> Result<(), CredentialError>;
    
    // Поддержка ротации
    async fn rotate(&mut self, new_data: AuthData) -> Result<(), CredentialError>;
}

// Типы аутентификации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthenticationType {
    ApiKey,
    Bearer,
    Basic,
    OAuth2,
    Certificate,
    Signature,
    Custom(String),
}

// Данные аутентификации с secure handling
#[derive(Debug, Clone)]
pub enum AuthData {
    ApiKey { key: SecretString },
    Bearer { token: SecretString },
    Basic { username: String, password: SecretString },
    OAuth2 { 
        access_token: SecretString, 
        refresh_token: Option<SecretString>,
        expires_at: Option<SystemTime>,
        scopes: Vec<String>,
    },
    Certificate { cert: Vec<u8>, private_key: SecretBytes },
    Headers(HashMap<String, SecretString>),
    Custom(HashMap<String, SecretString>),
}

// Credential context для scoped access
#[derive(Debug, Clone)]
pub struct CredentialContext {
    pub execution_id: ExecutionId,
    pub workflow_id: WorkflowId,
    pub user_id: Option<UserId>,
    pub account_id: Option<String>,
    pub action_id: Option<ActionId>,
}
```

### Security Features

```rust
// Защищенное хранение секретов с encryption
pub struct SecretString {
    encrypted_data: Vec<u8>,
    key_id: KeyId,
    metadata: SecretMetadata,
}

impl SecretString {
    pub fn new(plaintext: &str, encryption_key: &EncryptionKey) -> Result<Self, CryptoError> {
        let encrypted_data = encryption_key.encrypt(plaintext.as_bytes())?;
        Ok(Self {
            encrypted_data,
            key_id: encryption_key.id(),
            metadata: SecretMetadata {
                created_at: SystemTime::now(),
                last_accessed: AtomicSystemTime::new(SystemTime::now()),
                access_count: AtomicU64::new(0),
            },
        })
    }
    
    pub fn expose_secret(&self) -> SecretGuard {
        self.metadata.access_count.fetch_add(1, Ordering::Relaxed);
        self.metadata.last_accessed.store(SystemTime::now(), Ordering::Relaxed);
        
        SecretGuard::new(self.reveal_internal())
    }
    
    fn reveal_internal(&self) -> String {
        // Decryption происходит только при необходимости
        let key_manager = KeyManager::instance();
        let key = key_manager.get_key(&self.key_id).expect("Encryption key not found");
        let plaintext = key.decrypt(&self.encrypted_data).expect("Decryption failed");
        String::from_utf8(plaintext).expect("Invalid UTF-8")
    }
}

// SecretGuard для автоматической очистки памяти
pub struct SecretGuard {
    secret: String,
}

impl SecretGuard {
    fn new(secret: String) -> Self {
        Self { secret }
    }
    
    pub fn as_str(&self) -> &str {
        &self.secret
    }
}

impl Drop for SecretGuard {
    fn drop(&mut self) {
        // Очищаем память от секрета
        unsafe {
            std::ptr::write_volatile(self.secret.as_mut_ptr(), 0);
        }
    }
}

// Audit trail для использования credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialUsageEvent {
    pub credential_id: CredentialId,
    pub used_by: UserId,
    pub action_id: Option<ActionId>,
    pub execution_id: Option<ExecutionId>,
    pub access_type: CredentialAccessType,
    pub timestamp: SystemTime,
    pub success: bool,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CredentialAccessType {
    Read,
    Refresh,
    Rotate,
    Validate,
}
```

### Credential Types Implementation

```rust
// OAuth2 Credential с автоматическим refresh
pub struct OAuth2Credential {
    metadata: CredentialMetadata,
    client_id: String,
    client_secret: SecretString,
    access_token: SecretString,
    refresh_token: Option<SecretString>,
    token_endpoint: String,
    expires_at: Option<SystemTime>,
    scopes: Vec<String>,
    auto_refresh: bool,
}

#[async_trait]
impl Credential for OAuth2Credential {
    async fn get_auth_data(&self, context: &CredentialContext) -> Result<AuthData, CredentialError> {
        // Проверяем истечение токена
        if let Some(expires_at) = self.expires_at {
            if SystemTime::now() > expires_at && self.auto_refresh {
                let mut mutable_self = self.clone();
                mutable_self.refresh().await?;
                return mutable_self.get_auth_data(context).await;
            }
        }
        
        // Записываем audit event
        self.record_usage_event(context, CredentialAccessType::Read).await?;
        
        Ok(AuthData::OAuth2 {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: self.expires_at,
            scopes: self.scopes.clone(),
        })
    }
    
    async fn refresh(&mut self) -> Result<(), CredentialError> {
        if let Some(refresh_token) = &self.refresh_token {
            let token_data = self.request_new_token(refresh_token).await?;
            
            // Обновляем токены
            self.access_token = SecretString::new(&token_data.access_token, &get_encryption_key())?;
            if let Some(new_refresh_token) = token_data.refresh_token {
                self.refresh_token = Some(SecretString::new(&new_refresh_token, &get_encryption_key())?);
            }
            self.expires_at = Some(SystemTime::now() + Duration::from_secs(token_data.expires_in));
            
            // Уведомляем об обновлении токена
            self.notify_token_refresh().await?;
        }
        Ok(())
    }
    
    async fn rotate(&mut self, new_data: AuthData) -> Result<(), CredentialError> {
        match new_data {
            AuthData::OAuth2 { access_token, refresh_token, expires_at, scopes } => {
                self.access_token = access_token;
                self.refresh_token = refresh_token;
                self.expires_at = expires_at;
                self.scopes = scopes;
                
                // Notify dependent resources about rotation
                self.notify_rotation().await?;
            }
            _ => return Err(CredentialError::InvalidAuthDataType),
        }
        Ok(())
    }
}

// API Key Credential (простой тип)
pub struct ApiKeyCredential {
    metadata: CredentialMetadata,
    api_key: SecretString,
    header_name: String,  // "Authorization", "X-API-Key", etc.
    prefix: Option<String>,  // "Bearer ", "Token ", etc.
}

#[async_trait]
impl Credential for ApiKeyCredential {
    async fn get_auth_data(&self, context: &CredentialContext) -> Result<AuthData, CredentialError> {
        self.record_usage_event(context, CredentialAccessType::Read).await?;
        Ok(AuthData::ApiKey { key: self.api_key.clone() })
    }
    
    async fn validate(&self) -> Result<ValidationResult, CredentialError> {
        // Простая валидация API ключа
        let key_value = self.api_key.expose_secret();
        
        if key_value.as_str().is_empty() {
            return Ok(ValidationResult::Invalid("API key is empty".to_string()));
        }
        
        if key_value.as_str().len() < 8 {
            return Ok(ValidationResult::Invalid("API key is too short".to_string()));
        }
        
        Ok(ValidationResult::Valid)
    }
}

// Database Connection Credential
pub struct DatabaseCredential {
    metadata: CredentialMetadata,
    connection_string: SecretString,
    username: String,
    password: SecretString,
    database_type: DatabaseType,
    ssl_config: Option<SslConfig>,
}

#[derive(Debug, Clone)]
pub enum DatabaseType {
    PostgreSQL,
    MySQL,
    SQLite,
    MongoDB,
    Redis,
}
```

### Integration с Action System

```rust
// ExecutionContext предоставляет seamless доступ к credentials
impl ExecutionContext {
    pub async fn get_credential(&self, credential_id: &str) -> Result<AuthData, CredentialError> {
        let context = CredentialContext {
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            user_id: self.user_id.clone(),
            account_id: self.account_id.clone(),
            action_id: self.current_node_id.clone(),
        };
        
        self.credential_manager.get_credential_auth_data(credential_id, &context).await
    }
    
    // Автоматическое создание authenticated clients
    pub async fn get_authenticated_client<T>(&self, credential_id: &str) -> Result<T, ClientError> 
    where T: AuthenticatedClient {
        let auth_data = self.get_credential(credential_id).await?;
        T::from_auth_data(auth_data).await
    }
}

// Trait для authenticated clients
#[async_trait]
pub trait AuthenticatedClient: Send + Sync + Sized {
    async fn from_auth_data(auth_data: AuthData) -> Result<Self, ClientError>;
}

// Реализации для популярных клиентов
#[async_trait]
impl AuthenticatedClient for reqwest::Client {
    async fn from_auth_data(auth_data: AuthData) -> Result<Self, ClientError> {
        let mut headers = reqwest::header::HeaderMap::new();
        
        match auth_data {
            AuthData::ApiKey { key } => {
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key.expose_secret().as_str()))?
                );
            }
            AuthData::Bearer { token } => {
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose_secret().as_str()))?
                );
            }
            AuthData::Basic { username, password } => {
                let encoded = base64::encode(format!("{}:{}", username, password.expose_secret().as_str()));
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Basic {}", encoded))?
                );
            }
            AuthData::Headers(header_map) => {
                for (name, value) in header_map {
                    headers.insert(
                        reqwest::header::HeaderName::from_str(&name)?,
                        reqwest::header::HeaderValue::from_str(value.expose_secret().as_str())?
                    );
                }
            }
            _ => return Err(ClientError::UnsupportedAuthType),
        }
        
        Ok(reqwest::Client::builder()
            .default_headers(headers)
            .build()?)
    }
}

// Slack client пример
pub struct SlackClient {
    client: reqwest::Client,
    base_url: String,
}

#[async_trait]
impl AuthenticatedClient for SlackClient {
    async fn from_auth_data(auth_data: AuthData) -> Result<Self, ClientError> {
        match auth_data {
            AuthData::Bearer { token } | AuthData::ApiKey { key: token } => {
                let mut headers = reqwest::header::HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.expose_secret().as_str()))?
                );
                
                let client = reqwest::Client::builder()
                    .default_headers(headers)
                    .build()?;
                
                Ok(SlackClient {
                    client,
                    base_url: "https://slack.com/api".to_string(),
                })
            }
            _ => Err(ClientError::UnsupportedAuthType),
        }
    }
}

impl SlackClient {
    pub async fn send_message(&self, channel: &str, text: &str) -> Result<SlackMessage, SlackError> {
        let response = self.client
            .post(&format!("{}/chat.postMessage", self.base_url))
            .json(&json!({
                "channel": channel,
                "text": text
            }))
            .send()
            .await?;
        
        let result: serde_json::Value = response.json().await?;
        
        if result["ok"].as_bool().unwrap_or(false) {
            Ok(SlackMessage {
                ts: result["ts"].as_str().unwrap_or_default().to_string(),
                channel: result["channel"].as_str().unwrap_or_default().to_string(),
            })
        } else {
            Err(SlackError::ApiError(result["error"].as_str().unwrap_or("Unknown error").to_string()))
        }
    }
}
```

### Credential Manager

```rust
// Менеджер credential с advanced features
pub struct CredentialManager {
    credentials: Arc<RwLock<HashMap<CredentialId, Box<dyn Credential>>>>,
    encryption_service: Arc<EncryptionService>,
    audit_logger: Arc<AuditLogger>,
    rotation_scheduler: Arc<RotationScheduler>,
    access_control: Arc<AccessControl>,
}

impl CredentialManager {
    pub async fn get_credential_auth_data(
        &self,
        credential_id: &str,
        context: &CredentialContext,
    ) -> Result<AuthData, CredentialError> {
        // Проверяем права доступа
        self.access_control.check_access(credential_id, context).await?;
        
        // Получаем credential
        let credentials = self.credentials.read().await;
        let credential = credentials.get(&CredentialId::new(credential_id)?)
            .ok_or_else(|| CredentialError::CredentialNotFound(credential_id.to_string()))?;
        
        // Получаем auth data
        let auth_data = credential.get_auth_data(context).await?;
        
        // Логируем использование
        self.audit_logger.log_credential_usage(CredentialUsageEvent {
            credential_id: CredentialId::new(credential_id)?,
            used_by: context.user_id.clone().unwrap_or_default(),
            action_id: context.action_id.clone(),
            execution_id: Some(context.execution_id.clone()),
            access_type: CredentialAccessType::Read,
            timestamp: SystemTime::now(),
            success: true,
            ip_address: None,
            user_agent: None,
        }).await?;
        
        Ok(auth_data)
    }
    
    pub async fn register_credential<C: Credential + 'static>(
        &self,
        credential_id: CredentialId,
        credential: C,
    ) -> Result<(), CredentialError> {
        // Валидируем credential
        let validation_result = credential.validate().await?;
        if !validation_result.is_valid() {
            return Err(CredentialError::ValidationFailed(validation_result.error_message()));
        }
        
        // Сохраняем credential
        self.credentials.write().await.insert(credential_id.clone(), Box::new(credential));
        
        // Планируем автоматическую ротацию если нужно
        if self.should_schedule_rotation(&credential_id) {
            self.rotation_scheduler.schedule_rotation(credential_id).await?;
        }
        
        Ok(())
    }
    
    // Автоматическая ротация credentials
    pub async fn rotate_credential(
        &self,
        credential_id: &CredentialId,
        new_auth_data: AuthData,
    ) -> Result<(), CredentialError> {
        let mut credentials = self.credentials.write().await;
        let credential = credentials.get_mut(credential_id)
            .ok_or_else(|| CredentialError::CredentialNotFound(credential_id.to_string()))?;
        
        // Выполняем ротацию
        credential.rotate(new_auth_data).await?;
        
        // Уведомляем зависимые ресурсы
        self.notify_dependent_resources(credential_id).await?;
        
        // Логируем ротацию
        self.audit_logger.log_credential_rotation(credential_id).await?;
        
        Ok(())
    }
}
```

### Examples

```rust
use nebula_credential::*;

// Создание credentials
let slack_credential = ApiKeyCredential::new(
    "slack-bot-token",
    "xoxb-your-token-here",
    "Authorization",
    Some("Bearer ")
)?;

let database_credential = DatabaseCredential::new(
    "main-database",
    DatabaseType::PostgreSQL,
    "postgresql://user:password@localhost/db",
)?;

let oauth_credential = OAuth2Credential::builder()
    .client_id("your-client-id")
    .client_secret("your-client-secret")
    .token_endpoint("https://oauth.example.com/token")
    .scopes(vec!["read", "write"])
    .auto_refresh(true)
    .build()?;

// Регистрация credentials
let credential_manager = CredentialManager::new();
credential_manager.register_credential("slack", slack_credential).await?;
credential_manager.register_credential("database", database_credential).await?;
credential_manager.register_credential("oauth", oauth_credential).await?;

// Использование в Action
#[derive(Action)]
#[action(id = "slack.send")]
#[credentials(["slack"])]
pub struct SlackSendAction;

impl ProcessAction for SlackSendAction {
    type Input = SlackSendInput;
    type Output = SlackSendOutput;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // Автоматически получаем authenticated Slack client
        let slack_client = context.execution_context
            .get_authenticated_client::<SlackClient>("slack")
            .await?;
        
        // Используем client
        let message = slack_client.send_message(&input.channel, &input.text).await?;
        
        Ok(ActionResult::Success(SlackSendOutput {
            message_ts: message.ts,
            channel: message.channel,
        }))
    }
}

// Использование в простом Action
pub struct SimpleEmailAction;

impl SimpleAction for SimpleEmailAction {
    type Input = EmailInput;
    type Output = EmailOutput;
    
    async fn execute_simple(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<Self::Output, ActionError> {
        // Получаем credential напрямую
        let auth_data = context.execution_context.get_credential("smtp").await?;
        
        match auth_data {
            AuthData::Basic { username, password } => {
                let email_client = SmtpClient::new(&username, password.expose_secret().as_str())?;
                let message_id = email_client.send(&input.to, &input.subject, &input.body).await?;
                Ok(EmailOutput { message_id })
            }
            _ => Err(ActionError::InvalidCredentialType),
        }
    }
}
```

---

## 10. nebula-resource

### Overview

**nebula-resource** управляет lifecycle долгоживущих ресурсов с поддержкой различных scopes (Global, Workflow, Execution, Action). Обеспечивает connection pooling, health monitoring, credential integration и context-aware operations для optimal performance.

### Architecture

```rust
// Основной trait для ресурсов с lifecycle awareness
#[async_trait]
pub trait Resource: Send + Sync + 'static {
    type Config: ResourceConfig;
    type Instance: ResourceInstance;
    
    // Metadata и capabilities
    fn metadata(&self) -> ResourceMetadata;
    fn lifecycle(&self) -> ResourceLifecycle;
    fn required_credentials() -> Vec<&'static str>;
    fn dependencies() -> Vec<&'static str>;
    
    // Создание экземпляра ресурса
    async fn create(
        &self,
        config: &Self::Config,
        context: &ResourceContext,
    ) -> Result<Self::Instance, ResourceError>;
    
    // Валидация конфигурации
    fn validate_config(&self, config: &Self::Config) -> Result<(), ResourceError>;
    
    // Capacity planning
    fn estimate_requirements(&self, config: &Self::Config) -> ResourceRequirements;
}

// Resource lifecycle scopes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ResourceLifecycle {
    Global,                           // Singleton для всего приложения
    Workflow(WorkflowId),            // Один экземпляр на workflow
    Execution(ExecutionId),          // Один экземпляр на execution
    Action(ExecutionId, NodeId),     // Новый экземпляр для каждого action
}

// Resource instance с health monitoring
#[async_trait]
pub trait ResourceInstance: Send + Sync + 'static {
    fn id(&self) -> &ResourceInstanceId;
    fn resource_type(&self) -> &str;
    
    // Health checking
    async fn health_check(&self) -> Result<HealthStatus, ResourceError>;
    
    // Cleanup
    async fn cleanup(&mut self) -> Result<(), ResourceError>;
    
    // Metrics
    fn metrics(&self) -> ResourceMetrics;
    
    // Reusability (для pooling)
    fn is_reusable(&self) -> bool { true }
    async fn reset(&mut self) -> Result<(), ResourceError> { Ok(()) }
}

// Resource Manager с intelligent scoping
pub struct ResourceManager {
    global_resources: Arc<DashMap<String, Arc<dyn ResourceInstance>>>,
    workflow_resources: Arc<DashMap<WorkflowId, HashMap<String, Arc<dyn ResourceInstance>>>>,
    execution_resources: Arc<DashMap<ExecutionId, HashMap<String, Arc<dyn ResourceInstance>>>>,
    action_resource_pools: Arc<DashMap<String, ResourcePool>>,
    
    health_monitor: Arc<HealthMonitor>,
    dependency_resolver: DependencyResolver,
    metrics_collector: Arc<ResourceMetrics>,
}
```

### Scoped Resource Management

```rust
impl ResourceManager {
    // Получение ресурса с правильным scope
    pub async fn get_scoped_resource<T: Resource + 'static>(
        &self,
        scope: ResourceScope,
    ) -> Result<Arc<T::Instance>, ResourceError> {
        let resource_key = std::any::type_name::<T>();
        
        match T::lifecycle() {
            ResourceLifecycle::Global => {
                self.get_or_create_global_resource::<T>(resource_key).await
            }
            ResourceLifecycle::Workflow(workflow_id) => {
                self.get_or_create_workflow_resource::<T>(workflow_id, resource_key).await
            }
            ResourceLifecycle::Execution(execution_id) => {
                self.get_or_create_execution_resource::<T>(execution_id, resource_key).await
            }
            ResourceLifecycle::Action(execution_id, node_id) => {
                self.create_action_resource::<T>(execution_id, node_id).await
            }
        }
    }
    
    async fn get_or_create_global_resource<T: Resource + 'static>(
        &self,
        resource_key: &str,
    ) -> Result<Arc<T::Instance>, ResourceError> {
        if let Some(existing) = self.global_resources.get(resource_key) {
            // Проверяем здоровье ресурса
            if existing.health_check().await?.is_healthy() {
                return Ok(existing.clone().downcast().unwrap());
            } else {
                // Удаляем нездоровый ресурс
                self.global_resources.remove(resource_key);
            }
        }
        
        // Создаем новый ресурс
        let resource = T::default();
        let config = self.get_resource_config::<T>()?;
        let context = ResourceContext::global();
        
        let instance = resource.create(&config, &context).await?;
        let instance_arc = Arc::new(instance);
        
        self.global_resources.insert(resource_key.to_string(), instance_arc.clone());
        
        // Запускаем health monitoring
        self.health_monitor.start_monitoring(instance_arc.clone()).await?;
        
        Ok(instance_arc.downcast().unwrap())
    }
    
    async fn get_or_create_workflow_resource<T: Resource + 'static>(
        &self,
        workflow_id: &WorkflowId,
        resource_key: &str,
    ) -> Result<Arc<T::Instance>, ResourceError> {
        let mut workflow_resources = self.workflow_resources
            .entry(workflow_id.clone())
            .or_insert_with(HashMap::new);
        
        if let Some(existing) = workflow_resources.get(resource_key) {
            if existing.health_check().await?.is_healthy() {
                return Ok(existing.clone().downcast().unwrap());
            } else {
                workflow_resources.remove(resource_key);
            }
        }
        
        let resource = T::default();
        let config = self.get_resource_config::<T>()?;
        let context = ResourceContext::workflow(workflow_id.clone());
        
        let instance = resource.create(&config, &context).await?;
        let instance_arc = Arc::new(instance);
        
        workflow_resources.insert(resource_key.to_string(), instance_arc.clone());
        
        Ok(instance_arc.downcast().unwrap())
    }
    
    // Cleanup ресурсов при завершении scopes
    pub async fn cleanup_workflow_resources(&self, workflow_id: &WorkflowId) -> Result<(), ResourceError> {
        if let Some((_, mut resources)) = self.workflow_resources.remove(workflow_id) {
            // Cleanup всех ресурсов workflow
            for (_, resource) in resources.drain() {
                if let Ok(mut resource) = Arc::try_unwrap(resource) {
                    resource.cleanup().await?;
                }
            }
        }
        Ok(())
    }
    
    pub async fn cleanup_execution_resources(&self, execution_id: &ExecutionId) -> Result<(), ResourceError> {
        if let Some((_, mut resources)) = self.execution_resources.remove(execution_id) {
            for (_, resource) in resources.drain() {
                if let Ok(mut resource) = Arc::try_unwrap(resource) {
                    resource.cleanup().await?;
                }
            }
        }
        Ok(())
    }
}
```

### Built-in Resource Types

```rust
// Database Connection Resource
#[derive(Resource)]
#[resource(
    id = "database_connection",
    name = "Database Connection Pool", 
    lifecycle = "global",
    credentials = ["database_connection"],
    health_checks = ["connectivity", "query_performance"]
)]
pub struct DatabaseResource;

#[derive(ResourceConfig)]
pub struct DatabaseConfig {
    #[validate(url)]
    pub connection_string: String,
    
    #[validate(range = "1..=100")]
    pub max_connections: u32,
    
    #[validate(range = "1..=300")]
    pub connection_timeout: u32,
    
    #[credential(id = "database_connection")]
    pub credential: String,
}

pub struct DatabaseInstance {
    id: ResourceInstanceId,
    pool: sqlx::Pool<sqlx::Postgres>,
    config: DatabaseConfig,
    metrics: DatabaseMetrics,
}

#[async_trait]
impl ResourceInstance for DatabaseInstance {
    fn id(&self) -> &ResourceInstanceId { &self.id }
    fn resource_type(&self) -> &str { "database" }
    
    async fn health_check(&self) -> Result<HealthStatus, ResourceError> {
        let start = Instant::now();
        
        match sqlx::query("SELECT 1").fetch_one(&self.pool).await {
            Ok(_) => Ok(HealthStatus::Healthy {
                latency: Some(start.elapsed()),
                metadata: json!({
                    "active_connections": self.pool.size(),
                    "idle_connections": self.pool.num_idle(),
                }),
            }),
            Err(e) => Ok(HealthStatus::Unhealthy {
                reason: e.to_string(),
                since: SystemTime::now(),
                recoverable: true,
            }),
        }
    }
}

impl DatabaseInstance {
    pub async fn query<T>(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<T>, DatabaseError>
    where T: for<'r> FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin {
        let start = Instant::now();
        
        let result = sqlx::query_as::<_, T>(query)
            .bind_all(params)
            .fetch_all(&self.pool)
            .await?;
        
        // Записываем метрики
        self.metrics.record_query_duration(start.elapsed());
        self.metrics.increment_query_count();
        
        Ok(result)
    }
}

// Logger Resource (execution-scoped)
#[derive(Resource)]
#[resource(
    id = "execution_logger",
    name = "Execution Context Logger",
    lifecycle = "execution"
)]
pub struct LoggerResource;

pub struct LoggerInstance {
    id: ResourceInstanceId,
    execution_id: ExecutionId,
    workflow_id: WorkflowId,
    writer: Arc<dyn LogWriter + Send + Sync>,
}

impl LoggerInstance {
    pub fn info(&self, message: &str) {
        let log_entry = LogEntry {
            level: LogLevel::Info,
            message: message.to_string(),
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            timestamp: SystemTime::now(),
            // Автоматический context
        };
        self.writer.write(log_entry);
    }
}

// Metrics Collector Resource (workflow-scoped)
#[derive(Resource)]
#[resource(
    id = "workflow_metrics",
    name = "Workflow Metrics Collector",
    lifecycle = "workflow"
)]
pub struct MetricsCollectorResource;

pub struct MetricsCollectorInstance {
    id: ResourceInstanceId,
    workflow_id: WorkflowId,
    metrics: Arc<RwLock<WorkflowMetrics>>,
    start_time: SystemTime,
}

impl MetricsCollectorInstance {
    pub fn record_action_duration(&self, action_id: &str, duration: Duration) {
        let mut metrics = self.metrics.write().unwrap();
        metrics.action_durations.insert(action_id.to_string(), duration);
        metrics.total_execution_time += duration;
    }
    
    pub fn increment_counter(&self, name: &str, value: f64) {
        let mut metrics = self.metrics.write().unwrap();
        *metrics.counters.entry(name.to_string()).or_insert(0.0) += value;
    }
    
    pub fn get_workflow_summary(&self) -> WorkflowMetrics {
        self.metrics.read().unwrap().clone()
    }
}

// HTTP Client Resource (global)
#[derive(Resource)]
#[resource(
    id = "http_client",
    name = "HTTP Client with Circuit Breaker",
    lifecycle = "global"
)]
pub struct HttpClientResource;

pub struct HttpClientInstance {
    id: ResourceInstanceId,
    client: reqwest::Client,
    circuit_breaker: CircuitBreaker,
    metrics: HttpMetrics,
}

impl HttpClientInstance {
    pub async fn request(&self, request: reqwest::Request) -> Result<reqwest::Response, HttpError> {
        if self.circuit_breaker.is_open() {
            return Err(HttpError::CircuitBreakerOpen);
        }
        
        let start = Instant::now();
        
        match self.client.execute(request).await {
            Ok(response) => {
                let duration = start.elapsed();
                self.circuit_breaker.record_success();
                self.metrics.record_request_duration(duration);
                Ok(response)
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                self.metrics.record_request_error();
                Err(HttpError::RequestFailed(e.to_string()))
            }
        }
    }
}
```

### Integration с ExecutionContext

```rust
impl ExecutionContext {
    pub async fn get_resource<T: Resource + 'static>(&self) -> Result<Arc<T::Instance>, ResourceError> {
        let scope = ResourceScope {
            execution_id: self.execution_id.clone(),
            workflow_id: self.workflow_id.clone(),
            action_id: self.current_node_id.clone(),
            user_id: self.user_id.clone(),
            account_id: self.account_id.clone(),
        };
        
        self.resource_manager.get_scoped_resource::<T>(scope).await
    }
}

// Action может объявлять необходимые ресурсы
#[derive(Action)]
#[action(id = "database.user_query")]
#[resources([DatabaseResource, LoggerResource, MetricsCollectorResource])]
#[credentials(["database_connection"])]
pub struct DatabaseUserQueryAction;

impl ProcessAction for DatabaseUserQueryAction {
    type Input = UserQueryInput;
    type Output = UserQueryOutput;
    
    async fn execute(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        // Resources автоматически доступны с правильным scope
        let db = context.get_resource::<DatabaseResource>().await?;          // Global
        let logger = context.get_resource::<LoggerResource>().await?;        // Execution-scoped
        let metrics = context.get_resource::<MetricsCollectorResource>().await?;  // Workflow-scoped
        
        logger.info(&format!("Querying users with filter: {:?}", input.filter));
        
        let start = Instant::now();
        let users = db.query::<User>(
            "SELECT * FROM users WHERE active = $1 AND created_at > $2",
            &[&true, &input.created_after]
        ).await?;
        
        let duration = start.elapsed();
        metrics.record_action_duration("database.user_query", duration);
        metrics.increment_counter("database.queries", 1.0);
        
        logger.info(&format!("Found {} users in {:?}", users.len(), duration));
        
        Ok(ActionResult::Success(UserQueryOutput {
            users,
            query_duration: duration,
            total_count: users.len(),
        }))
    }
}
```

### Examples

```rust
use nebula_resource::*;

// Создание resource manager
let resource_manager = ResourceManager::new();

// Resources регистрируются автоматически при первом использовании
// или можно зарегистрировать заранее

// Использование в простом Action
pub struct SimpleEmailAction;

impl SimpleAction for SimpleEmailAction {
    type Input = EmailInput;
    type Output = EmailOutput;
    
    async fn execute_simple(
        &self,
        input: Self::Input,
        context: &ActionContext,
    ) -> Result<Self::Output, ActionError> {
        // Получаем execution-scoped logger
        let logger = context.get_resource::<LoggerResource>().await?;
        logger.info("Sending email");
        
        // Получаем global HTTP client
        let http_client = context.get_resource::<HttpClientResource>().await?;
        
        // Отправляем email через HTTP API
        let response = http_client.post("https://api.emailservice.com/send")
            .json(&json!({
                "to": input.to,
                "subject": input.subject,
                "body": input.body
            }))
            .send()
            .await?;
        
        let result = response.json::<EmailApiResponse>().await?;
        
        logger.info(&format!("Email sent with ID: {}", result.message_id));
        
        Ok(EmailOutput {
            message_id: result.message_id,
            sent_at: SystemTime::now(),
        })
    }
}

// Workflow-scoped metrics пример
#[derive(Action)]
#[action(id = "workflow.metrics_summary")]  
#[resources([MetricsCollectorResource, LoggerResource])]
pub struct MetricsSummaryAction;

impl ProcessAction for MetricsSummaryAction {
    type Input = ();
    type Output = WorkflowMetricsSummary;
    
    async fn execute(
        &self,
        _input: Self::Input,
        context: &ActionContext,
    ) -> Result<ActionResult<Self::Output>, ActionError> {
        let metrics = context.get_resource::<MetricsCollectorResource>().await?;
        let logger = context.get_resource::<LoggerResource>().await?;
        
        let summary = metrics.get_workflow_summary();
        
        logger.info(&format!(
            "Workflow completed in {:?}. Total actions: {}, Total queries: {}",
            summary.total_execution_time,
            summary.action_durations.len(),
            summary.counters.get("database.queries").unwrap_or(&0.0)
        ));
        
        Ok(ActionResult::Success(WorkflowMetricsSummary {
            total_duration: summary.total_execution_time,
            actions_executed: summary.action_durations.len(),
            total_database_queries: summary.counters.get("database.queries").cloned().unwrap_or(0.0) as u64,
            average_action_duration: summary.total_execution_time / summary.action_durations.len() as u32,
        }))
    }
}

// Automatic cleanup при завершении workflow
impl WorkflowEngine {
    async fn complete_workflow_execution(&self, execution_id: &ExecutionId, workflow_id: &WorkflowId) -> Result<(), EngineError> {
        // ... завершение execution logic
        
        // Cleanup scoped resources
        self.resource_manager.cleanup_execution_resources(execution_id).await?;
        
        // Если это последний execution для workflow
        if self.is_last_execution_for_workflow(workflow_id).await? {
            self.resource_manager.cleanup_workflow_resources(workflow_id).await?;
        }
        
        Ok(())
    }
}
```

Эти обновленные документации теперь четко разделяют ответственности между крейтами, показывают гибкий подход к разработке (простой код vs derive макросы), объясняют интеграцию с Expression System, и демонстрируют умное управление ресурсами с различными lifecycle scopes. Больше не должно возникать вопросов о том, как всё работает вместе!
