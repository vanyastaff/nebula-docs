---
title: Authentication
tags: [nebula, nebula-api, docs, authentication, jwt, oauth2, api-keys]
status: ready
created: 2025-08-17
---

# Authentication

Authentication в **nebula-api** — система аутентификации и авторизации для HTTP API, поддерживающая JWT tokens, API keys, OAuth2 и role-based access control (RBAC).

## Overview

nebula-api предоставляет multiple authentication methods:

1. **JWT (JSON Web Tokens)** — stateless authentication с access/refresh tokens
2. **API Keys** — long-lived tokens для service-to-service communication
3. **OAuth2** — third-party authentication (Google, GitHub, etc.)
4. **Session-Based** — traditional cookie-based sessions

## JWT Authentication

### Token Structure

```rust
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    // Subject (user ID)
    pub sub: String,

    // Expiration time (Unix timestamp)
    pub exp: i64,

    // Issued at (Unix timestamp)
    pub iat: i64,

    // User email
    pub email: String,

    // User roles
    pub roles: Vec<String>,

    // Permissions
    pub permissions: Vec<String>,
}

impl Claims {
    pub fn new(user_id: String, email: String, roles: Vec<String>, permissions: Vec<String>) -> Self {
        let now = Utc::now();
        let expiration = now + Duration::hours(1);  // 1 hour expiration

        Self {
            sub: user_id,
            exp: expiration.timestamp(),
            iat: now.timestamp(),
            email,
            roles,
            permissions,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.iter().any(|p| p == permission)
    }
}
```

### Login Flow

```rust
use axum::{
    Json,
    extract::State,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use argon2::{Argon2, PasswordHash, PasswordVerifier};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Find user by username
    let user = sqlx::query_as::<_, User>(
        "SELECT * FROM users WHERE username = $1"
    )
    .bind(&req.username)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|_| ApiError {
        code: "UNAUTHORIZED".to_string(),
        message: "Invalid username or password".to_string(),
        details: None,
    })?;

    // Verify password
    let argon2 = Argon2::default();
    let password_hash = PasswordHash::new(&user.password_hash)
        .map_err(|_| ApiError::internal_error("Invalid password hash"))?;

    argon2.verify_password(req.password.as_bytes(), &password_hash)
        .map_err(|_| ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Invalid username or password".to_string(),
            details: None,
        })?;

    // Get user roles and permissions
    let roles = get_user_roles(&state.db_pool, &user.id).await?;
    let permissions = get_user_permissions(&state.db_pool, &user.id).await?;

    // Create JWT claims
    let claims = Claims::new(
        user.id.clone(),
        user.email.clone(),
        roles,
        permissions,
    );

    // Generate access token
    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal_error(&format!("Failed to create token: {}", e)))?;

    // Generate refresh token
    let refresh_claims = Claims {
        exp: (Utc::now() + Duration::days(30)).timestamp(),  // 30 days
        ..claims
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal_error(&format!("Failed to create refresh token: {}", e)))?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,  // 1 hour
    }))
}
```

### Token Validation Middleware

```rust
use axum::{
    middleware::Next,
    http::{Request, header::AUTHORIZATION},
    response::Response,
};

pub async fn auth_middleware<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    // Extract Authorization header
    let auth_header = req.headers()
        .get(AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Missing Authorization header".to_string(),
            details: None,
        })?;

    // Extract token from "Bearer <token>"
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Invalid Authorization header format".to_string(),
            details: None,
        })?;

    // Get JWT secret from state
    let state = req.extensions().get::<Arc<AppState>>().unwrap();

    // Validate token
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| ApiError {
        code: "UNAUTHORIZED".to_string(),
        message: format!("Invalid token: {}", e),
        details: None,
    })?;

    // Check expiration
    if token_data.claims.is_expired() {
        return Err(ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Token expired".to_string(),
            details: None,
        });
    }

    // Insert claims into request extensions
    req.extensions_mut().insert(token_data.claims);

    Ok(next.run(req).await)
}
```

### Token Refresh

```rust
#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Validate refresh token
    let token_data = decode::<Claims>(
        &req.refresh_token,
        &DecodingKey::from_secret(state.config.jwt_secret.as_bytes()),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| ApiError {
        code: "UNAUTHORIZED".to_string(),
        message: format!("Invalid refresh token: {}", e),
        details: None,
    })?;

    // Check if expired
    if token_data.claims.is_expired() {
        return Err(ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Refresh token expired".to_string(),
            details: None,
        });
    }

    // Get fresh user data
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&token_data.claims.sub)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|_| ApiError::not_found("User not found"))?;

    // Get fresh roles and permissions
    let roles = get_user_roles(&state.db_pool, &user.id).await?;
    let permissions = get_user_permissions(&state.db_pool, &user.id).await?;

    // Create new tokens
    let new_claims = Claims::new(user.id, user.email, roles, permissions);

    let access_token = encode(
        &Header::default(),
        &new_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?;

    let refresh_claims = Claims {
        exp: (Utc::now() + Duration::days(30)).timestamp(),
        ..new_claims
    };

    let refresh_token = encode(
        &Header::default(),
        &refresh_claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    }))
}
```

## API Key Authentication

### API Key Structure

```rust
use secrecy::SecretString;

#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub name: String,

    #[serde(serialize_with = "serialize_secret")]
    pub key: SecretString,  // sk_live_1234567890abcdef

    pub user_id: String,
    pub scopes: Vec<String>,  // ["workflows:read", "workflows:write"]

    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

impl ApiKey {
    pub fn new(name: String, user_id: String, scopes: Vec<String>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            key: SecretString::new(Self::generate_key()),
            user_id,
            scopes,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        }
    }

    fn generate_key() -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

        let mut rng = rand::thread_rng();
        let random_part: String = (0..32)
            .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
            .collect();

        format!("sk_live_{}", random_part)
    }

    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope || s == "*")
    }
}
```

### API Key Middleware

```rust
pub async fn api_key_middleware<B>(
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, ApiError> {
    // Try to extract API key from header
    let api_key = req.headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "Missing X-API-Key header".to_string(),
            details: None,
        })?;

    // Get state
    let state = req.extensions().get::<Arc<AppState>>().unwrap();

    // Look up API key in database
    let key_record = sqlx::query_as::<_, ApiKey>(
        "SELECT * FROM api_keys WHERE key = $1"
    )
    .bind(api_key)
    .fetch_one(&state.db_pool)
    .await
    .map_err(|_| ApiError {
        code: "UNAUTHORIZED".to_string(),
        message: "Invalid API key".to_string(),
        details: None,
    })?;

    // Check expiration
    if key_record.is_expired() {
        return Err(ApiError {
            code: "UNAUTHORIZED".to_string(),
            message: "API key expired".to_string(),
            details: None,
        });
    }

    // Update last_used_at
    let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
        .bind(&key_record.id)
        .execute(&state.db_pool)
        .await;

    // Insert API key info into request extensions
    req.extensions_mut().insert(key_record);

    Ok(next.run(req).await)
}
```

### Creating API Keys

```rust
#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

pub async fn create_api_key(
    State(state): State<Arc<AppState>>,
    claims: Claims,  // From JWT middleware
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKey>, ApiError> {
    // Create API key
    let mut api_key = ApiKey::new(
        req.name,
        claims.sub.clone(),
        req.scopes,
    );

    // Set expiration if provided
    if let Some(days) = req.expires_in_days {
        api_key.expires_at = Some(Utc::now() + Duration::days(days));
    }

    // Store in database
    sqlx::query(
        r#"
        INSERT INTO api_keys (id, name, key, user_id, scopes, created_at, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        "#
    )
    .bind(&api_key.id)
    .bind(&api_key.name)
    .bind(api_key.key.expose_secret())
    .bind(&api_key.user_id)
    .bind(&api_key.scopes)
    .bind(api_key.created_at)
    .bind(api_key.expires_at)
    .execute(&state.db_pool)
    .await?;

    Ok(Json(api_key))
}
```

## OAuth2 Authentication

### OAuth2 Configuration

```rust
use oauth2::{
    AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
    basic::BasicClient,
    reqwest::async_http_client,
    AuthorizationCode, TokenResponse, CsrfToken, PkceCodeChallenge, Scope,
};

pub struct OAuth2Config {
    pub google: Option<OAuth2Provider>,
    pub github: Option<OAuth2Provider>,
}

pub struct OAuth2Provider {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
}

impl OAuth2Config {
    pub fn google_client(&self) -> Result<BasicClient> {
        let provider = self.google.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Google OAuth2 not configured"))?;

        Ok(BasicClient::new(
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(provider.client_secret.clone())),
            AuthUrl::new(provider.auth_url.clone())?,
            Some(TokenUrl::new(provider.token_url.clone())?),
        )
        .set_redirect_uri(RedirectUrl::new(provider.redirect_url.clone())?))
    }
}
```

### OAuth2 Authorization Flow

```rust
#[derive(Serialize)]
pub struct OAuth2AuthUrlResponse {
    pub auth_url: String,
    pub state: String,
}

pub async fn oauth2_authorize(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
) -> Result<Json<OAuth2AuthUrlResponse>, ApiError> {
    let client = match provider.as_str() {
        "google" => state.oauth2_config.google_client()?,
        "github" => state.oauth2_config.github_client()?,
        _ => return Err(ApiError::bad_request("Unknown OAuth2 provider")),
    };

    // Generate PKCE challenge
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate authorization URL
    let (auth_url, csrf_state) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Store PKCE verifier and CSRF state in session/cache
    // (Implementation depends on session storage)

    Ok(Json(OAuth2AuthUrlResponse {
        auth_url: auth_url.to_string(),
        state: csrf_state.secret().clone(),
    }))
}
```

### OAuth2 Callback

```rust
#[derive(Deserialize)]
pub struct OAuth2CallbackQuery {
    pub code: String,
    pub state: String,
}

pub async fn oauth2_callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(query): Query<OAuth2CallbackQuery>,
) -> Result<Json<LoginResponse>, ApiError> {
    // Verify CSRF state
    // (Implementation depends on session storage)

    let client = match provider.as_str() {
        "google" => state.oauth2_config.google_client()?,
        _ => return Err(ApiError::bad_request("Unknown OAuth2 provider")),
    };

    // Exchange authorization code for access token
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code))
        // .set_pkce_verifier(pkce_verifier)  // From session
        .request_async(async_http_client)
        .await
        .map_err(|e| ApiError::internal_error(&format!("Token exchange failed: {}", e)))?;

    // Get user info from OAuth2 provider
    let user_info = get_oauth2_user_info(&provider, token_result.access_token().secret()).await?;

    // Find or create user in database
    let user = find_or_create_oauth_user(&state.db_pool, &provider, &user_info).await?;

    // Create JWT tokens for the user
    let roles = get_user_roles(&state.db_pool, &user.id).await?;
    let permissions = get_user_permissions(&state.db_pool, &user.id).await?;

    let claims = Claims::new(user.id, user.email, roles, permissions);

    let access_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?;

    let refresh_token = encode(
        &Header::default(),
        &Claims {
            exp: (Utc::now() + Duration::days(30)).timestamp(),
            ..claims
        },
        &EncodingKey::from_secret(state.config.jwt_secret.as_bytes()),
    )?;

    Ok(Json(LoginResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600,
    }))
}
```

## Authorization (RBAC)

### Role-Based Access Control

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Role {
    Admin,
    Developer,
    Viewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Permission {
    // Workflows
    WorkflowsRead,
    WorkflowsWrite,
    WorkflowsExecute,
    WorkflowsDelete,

    // Credentials
    CredentialsRead,
    CredentialsWrite,
    CredentialsDelete,

    // Resources
    ResourcesRead,
    ResourcesWrite,
    ResourcesDelete,

    // Users
    UsersRead,
    UsersWrite,
    UsersDelete,
}

impl Role {
    pub fn permissions(&self) -> Vec<Permission> {
        match self {
            Role::Admin => vec![
                // All permissions
                Permission::WorkflowsRead,
                Permission::WorkflowsWrite,
                Permission::WorkflowsExecute,
                Permission::WorkflowsDelete,
                Permission::CredentialsRead,
                Permission::CredentialsWrite,
                Permission::CredentialsDelete,
                Permission::ResourcesRead,
                Permission::ResourcesWrite,
                Permission::ResourcesDelete,
                Permission::UsersRead,
                Permission::UsersWrite,
                Permission::UsersDelete,
            ],
            Role::Developer => vec![
                Permission::WorkflowsRead,
                Permission::WorkflowsWrite,
                Permission::WorkflowsExecute,
                Permission::CredentialsRead,
                Permission::ResourcesRead,
            ],
            Role::Viewer => vec![
                Permission::WorkflowsRead,
            ],
        }
    }
}
```

### Permission Middleware

```rust
use axum::middleware::from_fn_with_state;

pub fn require_permission(permission: Permission) -> impl Fn(Request<Body>, Next) -> Future<Output = Result<Response, ApiError>> {
    move |req, next| async move {
        // Extract claims from request
        let claims = req.extensions()
            .get::<Claims>()
            .ok_or_else(|| ApiError::unauthorized("Not authenticated"))?;

        // Check if user has permission
        let has_permission = claims.permissions.iter()
            .any(|p| p == &permission.to_string());

        if !has_permission {
            return Err(ApiError::forbidden("Insufficient permissions"));
        }

        Ok(next.run(req).await)
    }
}

// Usage in routes
let app = Router::new()
    .route("/workflows", post(create_workflow)
        .layer(from_fn(require_permission(Permission::WorkflowsWrite)))
    )
    .route("/workflows/:id", delete(delete_workflow)
        .layer(from_fn(require_permission(Permission::WorkflowsDelete)))
    );
```

## Security Best Practices

### ✅ Правильные практики

```rust
// ✅ ПРАВИЛЬНО: Use Argon2 для password hashing
use argon2::{
    password_hash::{PasswordHasher, SaltString, rand_core::OsRng},
    Argon2,
};

let salt = SaltString::generate(&mut OsRng);
let argon2 = Argon2::default();
let password_hash = argon2.hash_password(password.as_bytes(), &salt)?.to_string();

// ✅ ПРАВИЛЬНО: Short JWT expiration с refresh tokens
let access_token_exp = Duration::hours(1);  // 1 hour
let refresh_token_exp = Duration::days(30);  // 30 days

// ✅ ПРАВИЛЬНО: HTTPS required в production
if !req.uri().scheme().map(|s| s == &Scheme::HTTPS).unwrap_or(false) {
    return Err(ApiError::forbidden("HTTPS required"));
}

// ✅ ПРАВИЛЬНО: Rate limiting на login endpoint
let rate_limiter = RateLimiter::new(5, Duration::from_secs(60));  // 5 attempts per minute

// ✅ ПРАВИЛЬНО: CSRF protection для OAuth2
let csrf_token = CsrfToken::new_random();
store_csrf_token_in_session(csrf_token.secret());

// ✅ ПРАВИЛЬНО: Validate JWT algorithm
let mut validation = Validation::new(Algorithm::HS256);
validation.validate_exp = true;
validation.leeway = 0;

// ✅ ПРАВИЛЬНО: Secure cookie settings
Cookie::build("session_id", session_id)
    .secure(true)  // HTTPS only
    .http_only(true)  // Not accessible from JavaScript
    .same_site(SameSite::Strict)
    .max_age(Duration::days(7))
```

### ❌ Неправильные практики

```rust
// ❌ НЕПРАВИЛЬНО: Plain text passwords
let user = User {
    password: "password123",  // ОПАСНО!
};

// ❌ НЕПРАВИЛЬНО: Long JWT expiration без refresh
let exp = (Utc::now() + Duration::days(365)).timestamp();  // 1 year!

// ❌ НЕПРАВИЛЬНО: HTTP в production
// Credentials transmitted over plain text!

// ❌ НЕПРАВИЛЬНО: No rate limiting на login
// Открыто для brute force attacks!

// ❌ НЕПРАВИЛЬНО: Не проверять CSRF token
let code = query.code;  // No CSRF verification!

// ❌ НЕПРАВИЛЬНО: Accept any JWT algorithm
let validation = Validation::default();  // Accepts "none" algorithm!

// ❌ НЕПРАВИЛЬНО: Insecure cookies
Cookie::build("session", data)
    .secure(false)  // Can be sent over HTTP
    .http_only(false)  // Accessible from JS (XSS risk)
```

## Complete Example

```rust
use axum::{
    Router,
    routing::{get, post},
    middleware,
};

pub fn auth_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Public routes
        .route("/login", post(login))
        .route("/refresh", post(refresh_token))
        .route("/oauth/:provider", get(oauth2_authorize))
        .route("/oauth/callback/:provider", get(oauth2_callback))

        // Protected routes (require JWT)
        .route("/me", get(get_current_user))
        .route("/logout", post(logout))
        .route("/api-keys", get(list_api_keys).post(create_api_key))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
}

async fn get_current_user(
    claims: Claims,  // Extracted by auth_middleware
    State(state): State<Arc<AppState>>,
) -> Result<Json<User>, ApiError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(&claims.sub)
        .fetch_one(&state.db_pool)
        .await?;

    Ok(Json(user))
}
```

## Related Documentation

- [[02-Crates/nebula-api/README|nebula-api]] — API overview
- [[02-Crates/nebula-credential/README|nebula-credential]] — Credential management
- [[02-Crates/nebula-api/REST API|REST API]] — RESTful endpoints
- [[02-Crates/nebula-api/GraphQL API|GraphQL API]] — GraphQL API

## Links

- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [Argon2 Password Hashing](https://github.com/P-H-C/phc-winner-argon2)
