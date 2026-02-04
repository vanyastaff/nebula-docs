---
title: Basic API Key Authentication
tags: [nebula, nebula-credential, docs, examples, api-key]
status: complete
created: 2025-08-24
updated: 2025-11-09
---

# Basic API Key Authentication

**API Key** — самый простой и распространенный тип аутентификации для API. API ключ - это уникальная строка, которая идентифицирует клиента и используется для авторизации запросов.

## Когда использовать API Keys

✅ **Используйте API Keys когда:**
- Нужна простая аутентификация server-to-server
- API не требует OAuth2/OIDC
- Нет необходимости в user context
- Ключи могут безопасно храниться на сервере

❌ **НЕ используйте API Keys когда:**
- Ключи хранятся на клиенте (browser, mobile app)
- Нужна аутентификация от имени пользователя
- Требуется fine-grained access control
- API требует OAuth2

## Структура API Key Credential

```rust
use nebula_credential::{Credential, CredentialManager};
use secrecy::SecretString;

/// API Key credential
#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKeyCredential {
    /// Уникальный ID ключа (можно показывать в UI)
    pub key_id: String,

    /// Сам API key (защищенный, никогда не логируется)
    #[serde(serialize_with = "serialize_secret")]
    #[serde(deserialize_with = "deserialize_secret")]
    pub api_key: SecretString,

    /// Опциональный secret (для HMAC signing)
    #[serde(serialize_with = "serialize_optional_secret")]
    #[serde(deserialize_with = "deserialize_optional_secret")]
    pub api_secret: Option<SecretString>,

    /// Metadata
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

impl ApiKeyCredential {
    /// Создать новый API key
    pub fn new(name: String, api_key: String) -> Self {
        Self {
            key_id: Uuid::new_v4().to_string(),
            api_key: SecretString::new(api_key),
            api_secret: None,
            name,
            created_at: Utc::now(),
            expires_at: None,
            scopes: Vec::new(),
        }
    }

    /// С expiration
    pub fn with_expiration(mut self, expires_in: Duration) -> Self {
        self.expires_at = Some(Utc::now() + expires_in);
        self
    }

    /// С scopes
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// Проверить, истек ли ключ
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }
}
```

## Базовое использование

### 1. Создание и хранение API Key

```rust
use nebula_credential::{CredentialManager, Credential};

async fn store_api_key_example() -> Result<()> {
    let credential_manager = CredentialManager::builder()
        .with_encryption_enabled(true)
        .build();

    // Создать API key credential
    let api_key = ApiKeyCredential::new(
        "GitHub API".to_string(),
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz".to_string(),
    )
    .with_expiration(Duration::days(90))
    .with_scopes(vec!["repo".to_string(), "user".to_string()]);

    // Сохранить (автоматически шифруется)
    let credential_id = credential_manager
        .store_credential(
            Credential::ApiKey(api_key),
            vec![Scope::Global],
        )
        .await?;

    info!("API key stored with ID: {}", credential_id);

    Ok(())
}
```

### 2. Использование API Key в HTTP запросах

```rust
use reqwest::Client;

async fn use_api_key_in_request(
    credential_manager: &CredentialManager,
    credential_id: &CredentialId,
) -> Result<serde_json::Value> {
    // Получить credential
    let credential = credential_manager
        .get_credential(credential_id, &Scope::Global)
        .await?;

    let api_key = match credential {
        Credential::ApiKey(key) => key,
        _ => return Err(Error::InvalidCredentialType),
    };

    // Проверить expiration
    if api_key.is_expired() {
        return Err(Error::CredentialExpired);
    }

    // Использовать в HTTP request
    let client = Client::new();
    let response = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", api_key.api_key.expose_secret()))
        .header("Accept", "application/vnd.github.v3+json")
        .send()
        .await?;

    let data: serde_json::Value = response.json().await?;

    Ok(data)
}
```

## Различные форматы API Keys

### Header-based Authentication

```rust
/// GitHub style: Authorization: Bearer TOKEN
async fn github_api_request(api_key: &ApiKeyCredential) -> Result<()> {
    let client = Client::new();

    let response = client
        .get("https://api.github.com/user/repos")
        .header(
            "Authorization",
            format!("Bearer {}", api_key.api_key.expose_secret())
        )
        .header("User-Agent", "Nebula-Workflow")
        .send()
        .await?;

    Ok(())
}

/// Custom header: X-API-Key: KEY
async fn custom_header_request(api_key: &ApiKeyCredential) -> Result<()> {
    let client = Client::new();

    let response = client
        .get("https://api.example.com/data")
        .header("X-API-Key", api_key.api_key.expose_secret())
        .send()
        .await?;

    Ok(())
}

/// Basic Auth: Authorization: Basic base64(key:secret)
async fn basic_auth_request(api_key: &ApiKeyCredential) -> Result<()> {
    let client = Client::new();

    let credentials = format!(
        "{}:{}",
        api_key.api_key.expose_secret(),
        api_key.api_secret.as_ref()
            .map(|s| s.expose_secret())
            .unwrap_or("")
    );
    let encoded = base64::encode(credentials);

    let response = client
        .get("https://api.example.com/data")
        .header("Authorization", format!("Basic {}", encoded))
        .send()
        .await?;

    Ok(())
}
```

### Query Parameter Authentication

```rust
/// API key в query string (менее безопасно, но иногда требуется)
async fn query_param_request(api_key: &ApiKeyCredential) -> Result<()> {
    let client = Client::new();

    let url = format!(
        "https://api.example.com/data?api_key={}",
        api_key.api_key.expose_secret()
    );

    // ⚠️ WARNING: URL может попасть в логи!
    let response = client.get(&url).send().await?;

    Ok(())
}
```

## Provider-specific Examples

### GitHub API

```rust
pub struct GitHubApiClient {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
    client: Client,
}

impl GitHubApiClient {
    pub async fn new(
        credential_manager: Arc<CredentialManager>,
        credential_id: CredentialId,
    ) -> Result<Self> {
        Ok(Self {
            credential_manager,
            credential_id,
            client: Client::builder()
                .user_agent("Nebula-Workflow/1.0")
                .build()?,
        })
    }

    /// Получить текущего пользователя
    pub async fn get_current_user(&self) -> Result<GitHubUser> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .get("https://api.github.com/user")
            .header(
                "Authorization",
                format!("Bearer {}", api_key.api_key.expose_secret())
            )
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::GitHubApiError(response.status()));
        }

        let user: GitHubUser = response.json().await?;
        Ok(user)
    }

    /// Список репозиториев
    pub async fn list_repositories(&self) -> Result<Vec<GitHubRepo>> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .get("https://api.github.com/user/repos")
            .header(
                "Authorization",
                format!("Bearer {}", api_key.api_key.expose_secret())
            )
            .header("Accept", "application/vnd.github.v3+json")
            .query(&[("per_page", "100"), ("sort", "updated")])
            .send()
            .await?;

        let repos: Vec<GitHubRepo> = response.json().await?;
        Ok(repos)
    }

    /// Создать issue
    pub async fn create_issue(
        &self,
        owner: &str,
        repo: &str,
        title: &str,
        body: &str,
    ) -> Result<GitHubIssue> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .post(&format!("https://api.github.com/repos/{}/{}/issues", owner, repo))
            .header(
                "Authorization",
                format!("Bearer {}", api_key.api_key.expose_secret())
            )
            .header("Accept", "application/vnd.github.v3+json")
            .json(&serde_json::json!({
                "title": title,
                "body": body,
            }))
            .send()
            .await?;

        let issue: GitHubIssue = response.json().await?;
        Ok(issue)
    }

    async fn get_api_key(&self) -> Result<ApiKeyCredential> {
        let credential = self.credential_manager
            .get_credential(&self.credential_id, &Scope::Global)
            .await?;

        match credential {
            Credential::ApiKey(key) => {
                if key.is_expired() {
                    return Err(Error::CredentialExpired);
                }
                Ok(key)
            }
            _ => Err(Error::InvalidCredentialType),
        }
    }
}
```

### Stripe API

```rust
pub struct StripeApiClient {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
    client: Client,
}

impl StripeApiClient {
    /// Создать customer
    pub async fn create_customer(
        &self,
        email: &str,
        name: &str,
    ) -> Result<StripeCustomer> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .post("https://api.stripe.com/v1/customers")
            .bearer_auth(api_key.api_key.expose_secret())
            .form(&[("email", email), ("name", name)])
            .send()
            .await?;

        let customer: StripeCustomer = response.json().await?;
        Ok(customer)
    }

    /// Создать payment intent
    pub async fn create_payment_intent(
        &self,
        amount: u64,
        currency: &str,
        customer_id: &str,
    ) -> Result<StripePaymentIntent> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .post("https://api.stripe.com/v1/payment_intents")
            .bearer_auth(api_key.api_key.expose_secret())
            .form(&[
                ("amount", amount.to_string().as_str()),
                ("currency", currency),
                ("customer", customer_id),
            ])
            .send()
            .await?;

        let payment_intent: StripePaymentIntent = response.json().await?;
        Ok(payment_intent)
    }

    /// Webhook signature verification (с api_secret)
    pub async fn verify_webhook_signature(
        &self,
        payload: &str,
        signature: &str,
        timestamp: i64,
    ) -> Result<bool> {
        let api_key = self.get_api_key().await?;

        let api_secret = api_key.api_secret
            .ok_or(Error::MissingApiSecret)?;

        // Stripe webhook signature format: t=timestamp,v1=signature
        let expected_signature = format!("{}.{}", timestamp, payload);
        let mut mac = Hmac::<Sha256>::new_from_slice(
            api_secret.expose_secret().as_bytes()
        )?;
        mac.update(expected_signature.as_bytes());
        let result = mac.finalize();
        let computed = hex::encode(result.into_bytes());

        Ok(computed == signature)
    }
}
```

### OpenAI API

```rust
pub struct OpenAIClient {
    credential_manager: Arc<CredentialManager>,
    credential_id: CredentialId,
    client: Client,
}

impl OpenAIClient {
    /// Chat completion
    pub async fn create_chat_completion(
        &self,
        messages: Vec<ChatMessage>,
        model: &str,
    ) -> Result<ChatCompletion> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(api_key.api_key.expose_secret())
            .json(&serde_json::json!({
                "model": model,
                "messages": messages,
            }))
            .send()
            .await?;

        let completion: ChatCompletion = response.json().await?;
        Ok(completion)
    }

    /// Stream completion
    pub async fn stream_chat_completion(
        &self,
        messages: Vec<ChatMessage>,
        model: &str,
    ) -> Result<impl Stream<Item = Result<ChatCompletionChunk>>> {
        let api_key = self.get_api_key().await?;

        let response = self.client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(api_key.api_key.expose_secret())
            .json(&serde_json::json!({
                "model": model,
                "messages": messages,
                "stream": true,
            }))
            .send()
            .await?;

        // Parse SSE stream
        let stream = response
            .bytes_stream()
            .map(|chunk| {
                // Parse SSE format: "data: {...}\n\n"
                // Implementation omitted for brevity
            });

        Ok(stream)
    }
}
```

## Ротация API Keys

```rust
pub struct ApiKeyRotationManager {
    credential_manager: Arc<CredentialManager>,
    api_provider: Arc<dyn ApiKeyProvider>,
}

#[async_trait]
pub trait ApiKeyProvider: Send + Sync {
    /// Создать новый API key через provider API
    async fn create_api_key(&self, name: &str) -> Result<String>;

    /// Удалить старый API key
    async fn revoke_api_key(&self, key_id: &str) -> Result<()>;
}

impl ApiKeyRotationManager {
    /// Multi-stage rotation (zero downtime)
    pub async fn rotate_api_key(&self, credential_id: &CredentialId) -> Result<()> {
        info!("Starting API key rotation for {}", credential_id);

        // STAGE 1: Получить текущий ключ
        let old_credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let old_key = match old_credential {
            Credential::ApiKey(key) => key,
            _ => return Err(Error::InvalidCredentialType),
        };

        // STAGE 2: Создать новый ключ
        let new_api_key_string = self.api_provider
            .create_api_key(&old_key.name)
            .await?;

        info!("Created new API key");

        // STAGE 3: Обновить credential в storage
        let new_key = ApiKeyCredential::new(
            old_key.name.clone(),
            new_api_key_string,
        )
        .with_scopes(old_key.scopes.clone());

        self.credential_manager
            .update_credential(
                credential_id,
                Credential::ApiKey(new_key),
            )
            .await?;

        info!("Updated credential with new API key");

        // STAGE 4: Подождать propagation (5-30 секунд)
        tokio::time::sleep(Duration::from_secs(30)).await;

        // STAGE 5: Проверить что новый ключ работает
        if let Err(e) = self.verify_api_key(credential_id).await {
            error!("New API key verification failed: {}", e);

            // Rollback к старому ключу
            self.credential_manager
                .update_credential(
                    credential_id,
                    Credential::ApiKey(old_key.clone()),
                )
                .await?;

            return Err(Error::RotationFailed(e.to_string()));
        }

        info!("New API key verified successfully");

        // STAGE 6: Удалить старый ключ
        if let Err(e) = self.api_provider.revoke_api_key(&old_key.key_id).await {
            warn!("Failed to revoke old API key (non-fatal): {}", e);
        }

        info!("API key rotation completed successfully");

        Ok(())
    }

    async fn verify_api_key(&self, credential_id: &CredentialId) -> Result<()> {
        let credential = self.credential_manager
            .get_credential(credential_id, &Scope::Global)
            .await?;

        let api_key = match credential {
            Credential::ApiKey(key) => key,
            _ => return Err(Error::InvalidCredentialType),
        };

        // Тестовый запрос
        let client = Client::new();
        let response = client
            .get("https://api.example.com/verify")
            .bearer_auth(api_key.api_key.expose_secret())
            .send()
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::ApiKeyVerificationFailed(response.status()))
        }
    }
}
```

## Security Best Practices

### 1. Никогда не логировать API keys

```rust
// ❌ НЕПРАВИЛЬНО: Ключ попадет в логи
info!("Using API key: {}", api_key.api_key.expose_secret());

// ✅ ПРАВИЛЬНО: Логировать только key_id
info!("Using API key ID: {}", api_key.key_id);

// ✅ ПРАВИЛЬНО: SecretString не выводится в Debug
#[derive(Debug)]
struct Request {
    api_key: SecretString, // <SecretString<[REDACTED]>>
}
```

### 2. Хранить ключи encrypted

```rust
let credential_manager = CredentialManager::builder()
    .with_encryption(EncryptionService::new(
        AwsKmsKeyManager::new(Region::UsEast1, "key-id").await?
    ))
    .build();

// Ключи автоматически шифруются при хранении
credential_manager.store_credential(
    Credential::ApiKey(api_key),
    vec![Scope::Global],
).await?;
```

### 3. Использовать expiration

```rust
// ✅ ПРАВИЛЬНО: Ключи с expiration
let api_key = ApiKeyCredential::new("Service A".to_string(), key)
    .with_expiration(Duration::days(90)); // Истекает через 90 дней

// Проверять перед использованием
if api_key.is_expired() {
    // Trigger rotation или alert
    return Err(Error::CredentialExpired);
}
```

### 4. Не передавать ключи в URL

```rust
// ❌ НЕПРАВИЛЬНО: Ключ в URL (попадает в логи, history)
let url = format!("https://api.example.com/data?api_key={}", api_key);

// ✅ ПРАВИЛЬНО: Ключ в header
let response = client.get("https://api.example.com/data")
    .header("Authorization", format!("Bearer {}", api_key.expose_secret()))
    .send().await?;
```

### 5. Scope isolation

```rust
// ✅ ПРАВИЛЬНО: Разные ключи для разных tenants
let tenant_a_key = ApiKeyCredential::new("Tenant A".to_string(), key_a);
credential_manager.store_credential(
    Credential::ApiKey(tenant_a_key),
    vec![Scope::Tenant(tenant_a_id)], // Только для Tenant A
).await?;

let tenant_b_key = ApiKeyCredential::new("Tenant B".to_string(), key_b);
credential_manager.store_credential(
    Credential::ApiKey(tenant_b_key),
    vec![Scope::Tenant(tenant_b_id)], // Только для Tenant B
).await?;
```

## Error Handling

```rust
async fn handle_api_key_errors(
    credential_manager: &CredentialManager,
    credential_id: &CredentialId,
) -> Result<Response> {
    let credential = credential_manager
        .get_credential(credential_id, &Scope::Global)
        .await?;

    let api_key = match credential {
        Credential::ApiKey(key) => key,
        _ => {
            error!("Expected ApiKey credential, got different type");
            return Err(Error::InvalidCredentialType);
        }
    };

    // Проверить expiration
    if api_key.is_expired() {
        error!("API key expired at {:?}", api_key.expires_at);

        // Trigger rotation
        trigger_key_rotation(credential_id).await?;

        return Err(Error::CredentialExpired);
    }

    // Использовать ключ
    let client = Client::new();
    let response = match client
        .get("https://api.example.com/data")
        .bearer_auth(api_key.api_key.expose_secret())
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => resp,
        Ok(resp) if resp.status() == StatusCode::UNAUTHORIZED => {
            error!("API key rejected (401 Unauthorized)");

            // Mark key as invalid
            mark_credential_invalid(credential_id).await?;

            return Err(Error::Unauthorized);
        }
        Ok(resp) if resp.status() == StatusCode::TOO_MANY_REQUESTS => {
            warn!("Rate limited, retrying after delay");

            // Implement exponential backoff
            tokio::time::sleep(Duration::from_secs(60)).await;

            return Err(Error::RateLimited);
        }
        Ok(resp) => {
            error!("API request failed with status: {}", resp.status());
            return Err(Error::ApiError(resp.status()));
        }
        Err(e) => {
            error!("Network error: {}", e);
            return Err(Error::NetworkError(e));
        }
    };

    Ok(response)
}
```

## Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    #[tokio::test]
    async fn test_api_key_usage() {
        let mut server = Server::new_async().await;

        // Mock API endpoint
        let mock = server.mock("GET", "/data")
            .match_header("authorization", "Bearer test-key-123")
            .with_status(200)
            .with_body(r#"{"result": "success"}"#)
            .create();

        let api_key = ApiKeyCredential::new(
            "Test API".to_string(),
            "test-key-123".to_string(),
        );

        let client = Client::new();
        let response = client
            .get(format!("{}/data", server.url()))
            .bearer_auth(api_key.api_key.expose_secret())
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        mock.assert();
    }

    #[tokio::test]
    async fn test_expired_key() {
        let api_key = ApiKeyCredential::new(
            "Test API".to_string(),
            "test-key-123".to_string(),
        )
        .with_expiration(Duration::seconds(-1)); // Already expired

        assert!(api_key.is_expired());
    }
}
```

## Complete Example: Multi-Service API Client

```rust
use nebula_credential::prelude::*;

pub struct MultiServiceClient {
    credential_manager: Arc<CredentialManager>,
}

impl MultiServiceClient {
    pub async fn new() -> Result<Self> {
        let credential_manager = CredentialManager::builder()
            .with_encryption_enabled(true)
            .build();

        Ok(Self {
            credential_manager: Arc::new(credential_manager),
        })
    }

    /// Setup API keys для разных сервисов
    pub async fn setup_api_keys(&self) -> Result<()> {
        // GitHub
        let github_key = ApiKeyCredential::new(
            "GitHub API".to_string(),
            std::env::var("GITHUB_TOKEN")?,
        );
        self.credential_manager.store_credential(
            Credential::ApiKey(github_key),
            vec![Scope::Global],
        ).await?;

        // Stripe
        let stripe_key = ApiKeyCredential::new(
            "Stripe API".to_string(),
            std::env::var("STRIPE_SECRET_KEY")?,
        );
        self.credential_manager.store_credential(
            Credential::ApiKey(stripe_key),
            vec![Scope::Global],
        ).await?;

        // OpenAI
        let openai_key = ApiKeyCredential::new(
            "OpenAI API".to_string(),
            std::env::var("OPENAI_API_KEY")?,
        )
        .with_expiration(Duration::days(90));
        self.credential_manager.store_credential(
            Credential::ApiKey(openai_key),
            vec![Scope::Global],
        ).await?;

        Ok(())
    }
}
```

## Links

- [[02-Crates/nebula-credential/Architecture|Credential Architecture]]
- [[02-Crates/nebula-credential/Security/Encryption|Encryption]]
- [[02-Crates/nebula-credential/How-To/RotateCredentials|Rotate Credentials]]
- [[02-Crates/nebula-credential/Examples/OAuth2Flow|OAuth2 Flow]]
