---
title: nebula-api
tags: [nebula, nebula-api, docs, rest, graphql, websocket, api]
status: ready
created: 2025-08-17
---

# nebula-api

**nebula-api** — HTTP API layer для Nebula workflow automation system, предоставляющий REST, GraphQL и WebSocket endpoints для управления workflows, credentials, resources и execution.

## Overview

nebula-api — это web API сервер, построенный на Axum framework, который обеспечивает:

- **REST API** — CRUD operations для workflows, actions, credentials
- **GraphQL API** — complex queries и mutations с flexible schema
- **WebSocket API** — real-time updates и workflow execution streaming
- **Authentication** — JWT tokens, API keys, OAuth2
- **Authorization** — role-based access control (RBAC)
- **Rate Limiting** — request throttling для защиты от abuse
- **OpenAPI/Swagger** — auto-generated API documentation

## Features

### Multi-Protocol Support

```rust
// REST endpoints
GET    /api/v1/workflows
POST   /api/v1/workflows
GET    /api/v1/workflows/{id}
PUT    /api/v1/workflows/{id}
DELETE /api/v1/workflows/{id}

// GraphQL endpoint
POST   /api/v1/graphql

// WebSocket endpoint
WS     /api/v1/ws

// Health check
GET    /health
GET    /metrics
```

### Authentication Methods

- **JWT (JSON Web Tokens)** — stateless authentication с expiration и refresh
- **API Keys** — long-lived tokens для service-to-service communication
- **OAuth2** — third-party authentication (Google, GitHub, etc.)
- **Session Cookies** — browser-based sessions

### Authorization

- **Role-Based Access Control (RBAC)** — admin, developer, viewer roles
- **Permission System** — granular permissions (read, write, execute, delete)
- **Scope Isolation** — tenant-based resource isolation
- **Audit Logging** — tracking всех API requests

### API Versioning

```rust
/api/v1/workflows  // Version 1 (stable)
/api/v2/workflows  // Version 2 (beta)
```

### Rate Limiting

```rust
// Per IP address
100 requests per minute

// Per API key
1000 requests per minute

// Per user
500 requests per minute
```

### CORS Configuration

```rust
// Allow specific origins
Access-Control-Allow-Origin: https://app.example.com

// Allow credentials
Access-Control-Allow-Credentials: true

// Allowed methods
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS

// Allowed headers
Access-Control-Allow-Headers: Authorization, Content-Type
```

## Architecture

### Server Structure

```rust
use axum::{
    Router,
    routing::{get, post, put, delete},
    middleware,
    extract::State,
};
use tower_http::cors::CorsLayer;
use std::sync::Arc;

pub struct ApiServer {
    // Application state
    state: Arc<AppState>,

    // Server configuration
    config: ApiConfig,
}

pub struct AppState {
    // Core services
    pub workflow_manager: Arc<WorkflowManager>,
    pub credential_manager: Arc<CredentialManager>,
    pub resource_manager: Arc<ResourceManager>,
    pub execution_engine: Arc<ExecutionEngine>,

    // Database connection
    pub db_pool: PgPool,

    // Authentication
    pub auth_service: Arc<AuthService>,
}

impl ApiServer {
    pub async fn start(config: ApiConfig) -> Result<()> {
        // Build application state
        let state = Arc::new(AppState::new(&config).await?);

        // Build router with all routes
        let app = Router::new()
            // Health endpoints
            .route("/health", get(health_check))
            .route("/metrics", get(metrics))

            // API v1 routes
            .nest("/api/v1", api_v1_routes())

            // Middleware
            .layer(middleware::from_fn_with_state(
                state.clone(),
                auth_middleware
            ))
            .layer(CorsLayer::permissive())
            .layer(middleware::from_fn(rate_limit_middleware))

            // Application state
            .with_state(state);

        // Start server
        let addr = format!("{}:{}", config.host, config.port).parse()?;

        info!("Starting API server on {}", addr);

        axum::Server::bind(&addr)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    }
}

fn api_v1_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Workflows
        .route("/workflows", get(list_workflows).post(create_workflow))
        .route("/workflows/:id", get(get_workflow).put(update_workflow).delete(delete_workflow))
        .route("/workflows/:id/execute", post(execute_workflow))

        // Executions
        .route("/executions", get(list_executions))
        .route("/executions/:id", get(get_execution).delete(cancel_execution))

        // Credentials
        .route("/credentials", get(list_credentials).post(create_credential))
        .route("/credentials/:id", get(get_credential).put(update_credential).delete(delete_credential))

        // Resources
        .route("/resources", get(list_resources).post(create_resource))
        .route("/resources/:id", get(get_resource).delete(delete_resource))

        // GraphQL
        .route("/graphql", post(graphql_handler))

        // WebSocket
        .route("/ws", get(websocket_handler))
}
```

### Request/Response Flow

```
Client Request
    ↓
CORS Middleware (validate origin)
    ↓
Rate Limit Middleware (check limits)
    ↓
Auth Middleware (validate token/API key)
    ↓
Router (match endpoint)
    ↓
Handler Function (business logic)
    ↓
Response (JSON/Error)
    ↓
Client
```

### Error Handling

```rust
use axum::{
    response::{IntoResponse, Response},
    http::StatusCode,
    Json,
};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
    pub details: Option<serde_json::Value>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.code.as_str() {
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "UNAUTHORIZED" => StatusCode::UNAUTHORIZED,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "BAD_REQUEST" => StatusCode::BAD_REQUEST,
            "CONFLICT" => StatusCode::CONFLICT,
            "INTERNAL_ERROR" => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(self)).into_response()
    }
}

// Usage in handlers
async fn get_workflow(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Workflow>, ApiError> {
    let workflow = state.workflow_manager
        .get_workflow(&id)
        .await
        .map_err(|e| ApiError {
            code: "NOT_FOUND".to_string(),
            message: format!("Workflow not found: {}", id),
            details: Some(json!({ "workflow_id": id })),
        })?;

    Ok(Json(workflow))
}
```

## API Protocols

### REST API

REST API предоставляет стандартные CRUD operations:

- **GET** — Read resources
- **POST** — Create resources
- **PUT** — Update resources
- **DELETE** — Delete resources
- **PATCH** — Partial update

Подробнее: [[02-Crates/nebula-api/REST API|REST API]]

### GraphQL API

GraphQL API для complex queries с:

- **Queries** — read operations с flexible schema
- **Mutations** — create/update/delete operations
- **Subscriptions** — real-time updates через WebSocket
- **Schema introspection** — self-documenting API

Подробнее: [[02-Crates/nebula-api/GraphQL API|GraphQL API]]

### WebSocket API

WebSocket API для real-time communication:

- **Workflow Execution Streaming** — real-time updates во время execution
- **Event Broadcasting** — workflow events, action results
- **Bi-directional Communication** — server ↔ client messages

Подробнее: [[02-Crates/nebula-api/WebSocket API|WebSocket API]]

## Authentication

nebula-api поддерживает multiple authentication methods:

### JWT Authentication

```rust
// Login endpoint
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "alice",
  "password": "secret"
}

// Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "expires_in": 3600
}

// Using token
GET /api/v1/workflows
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

### API Key Authentication

```rust
// Using API key
GET /api/v1/workflows
X-API-Key: sk_live_1234567890abcdef
```

### OAuth2 Authentication

```rust
// OAuth2 authorization
GET /api/v1/auth/oauth/google
→ Redirect to Google OAuth2 consent page

// Callback
GET /api/v1/auth/oauth/callback?code=xyz&state=abc
→ Exchange code for tokens

// Response
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "user-123",
    "email": "alice@example.com",
    "name": "Alice"
  }
}
```

Подробнее: [[02-Crates/nebula-api/Authentication|Authentication]]

## Getting Started

### Installation

```toml
# Cargo.toml
[dependencies]
nebula-api = "0.1.0"
```

### Configuration

```rust
use nebula_api::{ApiServer, ApiConfig};

let config = ApiConfig {
    host: "0.0.0.0".to_string(),
    port: 8080,

    // Database
    database_url: "postgresql://user:pass@localhost/nebula".to_string(),

    // Authentication
    jwt_secret: "your-secret-key".to_string(),
    jwt_expiration_seconds: 3600,

    // Rate limiting
    rate_limit_requests_per_minute: 100,

    // CORS
    cors_allowed_origins: vec!["https://app.example.com".to_string()],
};
```

### Running the Server

```rust
use nebula_api::ApiServer;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = ApiConfig::from_env()?;

    // Start API server
    ApiServer::start(config).await?;

    Ok(())
}
```

### Making Requests

```bash
# Create workflow
curl -X POST http://localhost:8080/api/v1/workflows \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "name": "My Workflow",
    "description": "Example workflow",
    "actions": [...]
  }'

# List workflows
curl http://localhost:8080/api/v1/workflows \
  -H "Authorization: Bearer <token>"

# Execute workflow
curl -X POST http://localhost:8080/api/v1/workflows/wf-123/execute \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "input": {
      "user_id": "123"
    }
  }'
```

## API Endpoints Overview

### Workflow Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/workflows` | List all workflows |
| POST | `/api/v1/workflows` | Create new workflow |
| GET | `/api/v1/workflows/:id` | Get workflow by ID |
| PUT | `/api/v1/workflows/:id` | Update workflow |
| DELETE | `/api/v1/workflows/:id` | Delete workflow |
| POST | `/api/v1/workflows/:id/execute` | Execute workflow |
| GET | `/api/v1/workflows/:id/versions` | List workflow versions |

### Execution Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/executions` | List executions |
| GET | `/api/v1/executions/:id` | Get execution details |
| DELETE | `/api/v1/executions/:id` | Cancel execution |
| GET | `/api/v1/executions/:id/logs` | Get execution logs |

### Credential Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/credentials` | List credentials |
| POST | `/api/v1/credentials` | Create credential |
| GET | `/api/v1/credentials/:id` | Get credential |
| PUT | `/api/v1/credentials/:id` | Update credential |
| DELETE | `/api/v1/credentials/:id` | Delete credential |
| POST | `/api/v1/credentials/:id/rotate` | Rotate credential |

### Resource Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/resources` | List resources |
| POST | `/api/v1/resources` | Create resource |
| GET | `/api/v1/resources/:id` | Get resource |
| DELETE | `/api/v1/resources/:id` | Delete resource |
| GET | `/api/v1/resources/:id/health` | Check resource health |

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/auth/login` | Login with username/password |
| POST | `/api/v1/auth/refresh` | Refresh access token |
| POST | `/api/v1/auth/logout` | Logout (invalidate token) |
| GET | `/api/v1/auth/oauth/:provider` | OAuth2 authorization |
| GET | `/api/v1/auth/oauth/callback` | OAuth2 callback |

## Example: Complete API Server

```rust
use nebula_api::{ApiServer, ApiConfig, AppState};
use nebula_workflow::WorkflowManager;
use nebula_credential::CredentialManager;
use nebula_resource::ResourceManager;
use nebula_execution::ExecutionEngine;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load configuration from environment
    let config = ApiConfig {
        host: std::env::var("API_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
        port: std::env::var("API_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080),
        database_url: std::env::var("DATABASE_URL")?,
        jwt_secret: std::env::var("JWT_SECRET")?,
        jwt_expiration_seconds: 3600,
        rate_limit_requests_per_minute: 100,
        cors_allowed_origins: vec![
            "https://app.example.com".to_string(),
            "http://localhost:3000".to_string(),
        ],
    };

    // Create database connection pool
    let db_pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;

    // Initialize core services
    let workflow_manager = Arc::new(WorkflowManager::new(db_pool.clone()));
    let credential_manager = Arc::new(CredentialManager::new(db_pool.clone()));
    let resource_manager = Arc::new(ResourceManager::new(db_pool.clone()));
    let execution_engine = Arc::new(ExecutionEngine::new(
        workflow_manager.clone(),
        resource_manager.clone(),
    ));

    // Build application state
    let state = Arc::new(AppState {
        workflow_manager,
        credential_manager,
        resource_manager,
        execution_engine,
        db_pool,
        auth_service: Arc::new(AuthService::new(&config)),
    });

    // Start API server
    info!("Starting Nebula API server on {}:{}", config.host, config.port);

    ApiServer::start_with_state(config, state).await?;

    Ok(())
}
```

## OpenAPI/Swagger Documentation

nebula-api автоматически генерирует OpenAPI 3.0 specification:

```rust
// Access Swagger UI
http://localhost:8080/api/docs

// OpenAPI JSON spec
http://localhost:8080/api/openapi.json
```

Swagger UI предоставляет:
- Interactive API documentation
- Try-it-out functionality для testing endpoints
- Request/response schemas
- Authentication configuration

## Health Check & Metrics

```rust
// Health check endpoint
GET /health

// Response
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 12345,
  "database": "connected",
  "services": {
    "workflow_manager": "healthy",
    "execution_engine": "healthy",
    "credential_manager": "healthy"
  }
}

// Prometheus metrics
GET /metrics

// Response (Prometheus format)
# HELP nebula_http_requests_total Total HTTP requests
# TYPE nebula_http_requests_total counter
nebula_http_requests_total{method="GET",path="/api/v1/workflows",status="200"} 1234

# HELP nebula_http_request_duration_seconds HTTP request duration
# TYPE nebula_http_request_duration_seconds histogram
nebula_http_request_duration_seconds_bucket{le="0.005"} 100
nebula_http_request_duration_seconds_bucket{le="0.01"} 150
...
```

## Security Best Practices

### ✅ Правильные практики

```rust
// ✅ ПРАВИЛЬНО: Use HTTPS в production
let config = ApiConfig {
    tls_cert_path: Some("/path/to/cert.pem".to_string()),
    tls_key_path: Some("/path/to/key.pem".to_string()),
    ...
};

// ✅ ПРАВИЛЬНО: Validate и sanitize user input
#[derive(Deserialize, Validate)]
pub struct CreateWorkflowRequest {
    #[validate(length(min = 1, max = 255))]
    pub name: String,

    #[validate(length(max = 1000))]
    pub description: Option<String>,
}

// ✅ ПРАВИЛЬНО: Rate limiting per user/IP
let rate_limiter = RateLimiter::new(100, Duration::from_secs(60));

// ✅ ПРАВИЛЬНО: JWT expiration и rotation
let jwt_config = JwtConfig {
    expiration_seconds: 3600,  // 1 hour
    refresh_token_expiration_days: 30,
};

// ✅ ПРАВИЛЬНО: CORS с specific origins
let cors = CorsLayer::new()
    .allow_origin("https://app.example.com".parse::<HeaderValue>()?)
    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
    .allow_credentials(true);

// ✅ ПРАВИЛЬНО: Audit logging всех API requests
middleware::from_fn(audit_log_middleware)
```

### ❌ Неправильные практики

```rust
// ❌ НЕПРАВИЛЬНО: HTTP без TLS в production
let config = ApiConfig {
    tls_cert_path: None,  // Небезопасно!
    ...
};

// ❌ НЕПРАВИЛЬНО: Не валидировать input
let workflow = create_workflow(request.name);  // Нет validation!

// ❌ НЕПРАВИЛЬНО: No rate limiting
// Открыто для DDoS атак!

// ❌ НЕПРАВИЛЬНО: JWT без expiration
let jwt_config = JwtConfig {
    expiration_seconds: None,  // Токен никогда не истекает!
};

// ❌ НЕПРАВИЛЬНО: Permissive CORS
let cors = CorsLayer::permissive();  // Любой origin!

// ❌ НЕПРАВИЛЬНО: Не логировать API requests
// Нет audit trail!
```

## Performance Tuning

```rust
// Connection pooling
let db_pool = PgPoolOptions::new()
    .max_connections(20)  // Увеличить для high load
    .min_connections(5)
    .acquire_timeout(Duration::from_secs(5))
    .connect(&database_url)
    .await?;

// Request timeout
let app = app.layer(
    TimeoutLayer::new(Duration::from_secs(30))
);

// Compression
let app = app.layer(
    CompressionLayer::new()
        .gzip(true)
        .br(true)
);

// Caching
let app = app.layer(
    CacheLayer::new()
        .max_age(Duration::from_secs(60))
);
```

## Deployment

### Docker

```dockerfile
FROM rust:1.75 as builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin nebula-api

FROM debian:bookworm-slim

COPY --from=builder /app/target/release/nebula-api /usr/local/bin/
EXPOSE 8080

CMD ["nebula-api"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nebula-api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nebula-api
  template:
    metadata:
      labels:
        app: nebula-api
    spec:
      containers:
      - name: api
        image: nebula-api:latest
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: nebula-secrets
              key: database-url
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: nebula-secrets
              key: jwt-secret
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Related Documentation

- [[02-Crates/nebula-api/Authentication|Authentication]] — JWT, API keys, OAuth2
- [[02-Crates/nebula-api/REST API|REST API]] — RESTful endpoints
- [[02-Crates/nebula-api/GraphQL API|GraphQL API]] — GraphQL schema и queries
- [[02-Crates/nebula-api/WebSocket API|WebSocket API]] — Real-time communication
- [[02-Crates/nebula-workflow/README|nebula-workflow]] — Workflow management
- [[02-Crates/nebula-execution/README|nebula-execution]] — Execution engine
- [[02-Crates/nebula-credential/README|nebula-credential]] — Credential management

## Links

- [Axum Documentation](https://docs.rs/axum/)
- [OpenAPI Specification](https://spec.openapis.org/oas/v3.1.0)
- [GraphQL Specification](https://spec.graphql.org/)
- [WebSocket Protocol](https://datatracker.ietf.org/doc/html/rfc6455)
