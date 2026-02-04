---
title: REST API
tags: [nebula, nebula-api, docs, rest, http, api]
status: ready
created: 2025-08-17
---

# REST API

REST API в **nebula-api** — RESTful HTTP API для управления workflows, executions, credentials и resources через стандартные HTTP methods (GET, POST, PUT, DELETE).

## Overview

nebula-api REST API следует RESTful principles:

- **Resource-Based URLs** — каждый endpoint представляет resource (/workflows, /executions)
- **HTTP Methods** — standard CRUD operations (GET, POST, PUT, DELETE)
- **Stateless** — каждый request содержит всю необходимую информацию
- **JSON Format** — request/response в JSON
- **Standard Status Codes** — HTTP status codes для result indication

## Base URL

```
Production:  https://api.nebula.example.com
Staging:     https://staging-api.nebula.example.com
Local:       http://localhost:8080
```

## API Versioning

```
/api/v1/*  - Version 1 (stable)
/api/v2/*  - Version 2 (beta)
```

## Authentication

Все REST API endpoints требуют authentication:

```bash
# JWT Token
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

# API Key
X-API-Key: sk_live_1234567890abcdef
```

См. [[02-Crates/nebula-api/Authentication|Authentication]]

## Common Headers

### Request Headers

```http
Content-Type: application/json
Authorization: Bearer <token>
X-Request-ID: <uuid>  # Optional for request tracking
```

### Response Headers

```http
Content-Type: application/json
X-Request-ID: <uuid>
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640000000
```

## HTTP Methods

| Method | Description | Idempotent |
|--------|-------------|------------|
| GET | Read resource(s) | Yes |
| POST | Create resource | No |
| PUT | Update/replace resource | Yes |
| PATCH | Partial update resource | No |
| DELETE | Delete resource | Yes |

## Workflow Endpoints

### List Workflows

Получить список всех workflows.

```http
GET /api/v1/workflows
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| limit | integer | Number of results (default: 20, max: 100) |
| offset | integer | Skip results for pagination |
| sort | string | Sort field (e.g., "created_at", "-name") |
| filter | string | Filter expression |

**Example Request:**

```bash
curl -X GET "https://api.nebula.example.com/api/v1/workflows?limit=10&sort=-created_at" \
  -H "Authorization: Bearer <token>"
```

**Example Response:**

```json
{
  "data": [
    {
      "id": "wf_1234567890",
      "name": "User Onboarding Workflow",
      "description": "Automated user onboarding process",
      "status": "active",
      "version": 1,
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-01-15T10:30:00Z",
      "actions": [
        {
          "id": "action_001",
          "type": "send_email",
          "name": "Send Welcome Email"
        }
      ]
    }
  ],
  "pagination": {
    "total": 42,
    "limit": 10,
    "offset": 0,
    "has_more": true
  }
}
```

### Create Workflow

Создать новый workflow.

```http
POST /api/v1/workflows
```

**Request Body:**

```json
{
  "name": "Order Processing Workflow",
  "description": "Process customer orders",
  "actions": [
    {
      "type": "validate_order",
      "name": "Validate Order",
      "config": {
        "rules": ["check_inventory", "verify_payment"]
      }
    },
    {
      "type": "send_notification",
      "name": "Notify Customer",
      "config": {
        "template": "order_confirmation"
      }
    }
  ],
  "triggers": [
    {
      "type": "webhook",
      "config": {
        "path": "/webhooks/new-order"
      }
    }
  ]
}
```

**Example Request:**

```bash
curl -X POST "https://api.nebula.example.com/api/v1/workflows" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Order Processing Workflow",
    "description": "Process customer orders",
    "actions": [...]
  }'
```

**Example Response:**

```json
{
  "id": "wf_9876543210",
  "name": "Order Processing Workflow",
  "description": "Process customer orders",
  "status": "draft",
  "version": 1,
  "created_at": "2025-01-16T14:20:00Z",
  "updated_at": "2025-01-16T14:20:00Z",
  "actions": [...],
  "triggers": [...]
}
```

**Status Codes:**

- `201 Created` — Workflow created successfully
- `400 Bad Request` — Invalid request body
- `401 Unauthorized` — Missing or invalid authentication
- `403 Forbidden` — Insufficient permissions
- `422 Unprocessable Entity` — Validation error

### Get Workflow

Получить workflow по ID.

```http
GET /api/v1/workflows/{workflow_id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| workflow_id | string | Workflow ID |

**Example Request:**

```bash
curl -X GET "https://api.nebula.example.com/api/v1/workflows/wf_1234567890" \
  -H "Authorization: Bearer <token>"
```

**Example Response:**

```json
{
  "id": "wf_1234567890",
  "name": "User Onboarding Workflow",
  "description": "Automated user onboarding process",
  "status": "active",
  "version": 2,
  "created_at": "2025-01-15T10:30:00Z",
  "updated_at": "2025-01-16T09:15:00Z",
  "actions": [...],
  "triggers": [...],
  "statistics": {
    "total_executions": 1234,
    "successful_executions": 1180,
    "failed_executions": 54,
    "avg_duration_ms": 2500
  }
}
```

**Status Codes:**

- `200 OK` — Workflow found
- `404 Not Found` — Workflow not found

### Update Workflow

Обновить существующий workflow.

```http
PUT /api/v1/workflows/{workflow_id}
```

**Request Body:**

```json
{
  "name": "Updated Workflow Name",
  "description": "Updated description",
  "actions": [...],
  "status": "active"
}
```

**Example Request:**

```bash
curl -X PUT "https://api.nebula.example.com/api/v1/workflows/wf_1234567890" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Workflow Name",
    "status": "active"
  }'
```

**Example Response:**

```json
{
  "id": "wf_1234567890",
  "name": "Updated Workflow Name",
  "description": "Updated description",
  "status": "active",
  "version": 3,
  "updated_at": "2025-01-16T15:00:00Z"
}
```

**Status Codes:**

- `200 OK` — Workflow updated
- `404 Not Found` — Workflow not found
- `409 Conflict` — Version conflict

### Delete Workflow

Удалить workflow.

```http
DELETE /api/v1/workflows/{workflow_id}
```

**Example Request:**

```bash
curl -X DELETE "https://api.nebula.example.com/api/v1/workflows/wf_1234567890" \
  -H "Authorization: Bearer <token>"
```

**Example Response:**

```json
{
  "id": "wf_1234567890",
  "deleted": true,
  "deleted_at": "2025-01-16T16:00:00Z"
}
```

**Status Codes:**

- `200 OK` — Workflow deleted
- `404 Not Found` — Workflow not found
- `409 Conflict` — Cannot delete active workflow

### Execute Workflow

Запустить execution workflow.

```http
POST /api/v1/workflows/{workflow_id}/execute
```

**Request Body:**

```json
{
  "input": {
    "user_id": "user_123",
    "email": "alice@example.com",
    "order_id": "ord_456"
  },
  "context": {
    "source": "api",
    "priority": "high"
  }
}
```

**Example Request:**

```bash
curl -X POST "https://api.nebula.example.com/api/v1/workflows/wf_1234567890/execute" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "user_id": "user_123"
    }
  }'
```

**Example Response:**

```json
{
  "execution_id": "exec_abc123def",
  "workflow_id": "wf_1234567890",
  "status": "running",
  "started_at": "2025-01-16T17:00:00Z",
  "input": {
    "user_id": "user_123"
  }
}
```

**Status Codes:**

- `202 Accepted` — Execution started
- `400 Bad Request` — Invalid input
- `404 Not Found` — Workflow not found

## Execution Endpoints

### List Executions

Получить список executions.

```http
GET /api/v1/executions
```

**Query Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| workflow_id | string | Filter by workflow ID |
| status | string | Filter by status (running, completed, failed) |
| limit | integer | Number of results |
| offset | integer | Pagination offset |

**Example Request:**

```bash
curl -X GET "https://api.nebula.example.com/api/v1/executions?workflow_id=wf_1234567890&status=completed&limit=10" \
  -H "Authorization: Bearer <token>"
```

**Example Response:**

```json
{
  "data": [
    {
      "id": "exec_abc123def",
      "workflow_id": "wf_1234567890",
      "status": "completed",
      "started_at": "2025-01-16T17:00:00Z",
      "completed_at": "2025-01-16T17:02:30Z",
      "duration_ms": 150000,
      "result": {
        "success": true,
        "output": {...}
      }
    }
  ],
  "pagination": {
    "total": 156,
    "limit": 10,
    "offset": 0
  }
}
```

### Get Execution

Получить детали execution.

```http
GET /api/v1/executions/{execution_id}
```

**Example Response:**

```json
{
  "id": "exec_abc123def",
  "workflow_id": "wf_1234567890",
  "status": "completed",
  "started_at": "2025-01-16T17:00:00Z",
  "completed_at": "2025-01-16T17:02:30Z",
  "duration_ms": 150000,
  "input": {
    "user_id": "user_123"
  },
  "output": {
    "email_sent": true,
    "notification_id": "notif_789"
  },
  "actions_executed": [
    {
      "action_id": "action_001",
      "name": "Send Welcome Email",
      "status": "completed",
      "started_at": "2025-01-16T17:00:05Z",
      "completed_at": "2025-01-16T17:02:00Z",
      "result": {
        "success": true
      }
    }
  ]
}
```

### Cancel Execution

Отменить running execution.

```http
DELETE /api/v1/executions/{execution_id}
```

**Example Request:**

```bash
curl -X DELETE "https://api.nebula.example.com/api/v1/executions/exec_abc123def" \
  -H "Authorization: Bearer <token>"
```

**Example Response:**

```json
{
  "id": "exec_abc123def",
  "status": "cancelled",
  "cancelled_at": "2025-01-16T17:05:00Z"
}
```

### Get Execution Logs

Получить logs execution.

```http
GET /api/v1/executions/{execution_id}/logs
```

**Example Response:**

```json
{
  "execution_id": "exec_abc123def",
  "logs": [
    {
      "timestamp": "2025-01-16T17:00:00Z",
      "level": "info",
      "message": "Execution started",
      "action_id": null
    },
    {
      "timestamp": "2025-01-16T17:00:05Z",
      "level": "info",
      "message": "Executing action: Send Welcome Email",
      "action_id": "action_001"
    },
    {
      "timestamp": "2025-01-16T17:02:00Z",
      "level": "info",
      "message": "Email sent successfully",
      "action_id": "action_001"
    }
  ]
}
```

## Credential Endpoints

### List Credentials

```http
GET /api/v1/credentials
```

### Create Credential

```http
POST /api/v1/credentials
```

**Request Body:**

```json
{
  "name": "GitHub API Key",
  "type": "api_key",
  "data": {
    "api_key": "ghp_1234567890abcdef"
  },
  "scopes": ["workflows:read"]
}
```

### Get Credential

```http
GET /api/v1/credentials/{credential_id}
```

### Update Credential

```http
PUT /api/v1/credentials/{credential_id}
```

### Delete Credential

```http
DELETE /api/v1/credentials/{credential_id}
```

### Rotate Credential

```http
POST /api/v1/credentials/{credential_id}/rotate
```

## Resource Endpoints

### List Resources

```http
GET /api/v1/resources
```

### Create Resource

```http
POST /api/v1/resources
```

**Request Body:**

```json
{
  "name": "PostgreSQL Production",
  "type": "database",
  "config": {
    "host": "db.example.com",
    "port": 5432,
    "database": "production",
    "max_connections": 10
  },
  "credential_id": "cred_123"
}
```

### Get Resource

```http
GET /api/v1/resources/{resource_id}
```

### Delete Resource

```http
DELETE /api/v1/resources/{resource_id}
```

### Resource Health Check

```http
GET /api/v1/resources/{resource_id}/health
```

**Example Response:**

```json
{
  "resource_id": "res_789",
  "status": "healthy",
  "checked_at": "2025-01-16T18:00:00Z",
  "details": {
    "connections_active": 3,
    "connections_idle": 7,
    "latency_ms": 15
  }
}
```

## Pagination

### Offset-Based Pagination

```http
GET /api/v1/workflows?limit=20&offset=40
```

**Response:**

```json
{
  "data": [...],
  "pagination": {
    "total": 100,
    "limit": 20,
    "offset": 40,
    "has_more": true
  }
}
```

### Cursor-Based Pagination

```http
GET /api/v1/executions?limit=20&cursor=eyJpZCI6ImV4ZWNfMTIzIn0=
```

**Response:**

```json
{
  "data": [...],
  "pagination": {
    "next_cursor": "eyJpZCI6ImV4ZWNfNDU2In0=",
    "has_more": true
  }
}
```

## Filtering

### Simple Filters

```http
GET /api/v1/workflows?status=active&name=onboarding
```

### Complex Filters

```http
GET /api/v1/executions?filter=status:completed,started_at>2025-01-01,duration_ms<5000
```

## Sorting

```http
# Ascending
GET /api/v1/workflows?sort=created_at

# Descending
GET /api/v1/workflows?sort=-created_at

# Multiple fields
GET /api/v1/workflows?sort=-status,created_at
```

## Error Response Format

Все errors возвращаются в consistent format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid workflow configuration",
    "details": {
      "field": "actions",
      "issue": "At least one action is required"
    },
    "request_id": "req_abc123"
  }
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| UNAUTHORIZED | 401 | Missing or invalid authentication |
| FORBIDDEN | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| VALIDATION_ERROR | 422 | Invalid request data |
| CONFLICT | 409 | Resource conflict |
| RATE_LIMIT_EXCEEDED | 429 | Too many requests |
| INTERNAL_ERROR | 500 | Server error |

## Rate Limiting

```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1640000000
```

При превышении rate limit:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1640000000
Retry-After: 60

{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Retry after 60 seconds."
  }
}
```

## Best Practices

### ✅ Правильные практики

```bash
# ✅ ПРАВИЛЬНО: Include request ID для debugging
curl -X GET "https://api.nebula.example.com/api/v1/workflows" \
  -H "Authorization: Bearer <token>" \
  -H "X-Request-ID: $(uuidgen)"

# ✅ ПРАВИЛЬНО: Use pagination для large datasets
curl -X GET "https://api.nebula.example.com/api/v1/executions?limit=100&offset=0"

# ✅ ПРАВИЛЬНО: Handle rate limits с exponential backoff
if [ $HTTP_STATUS -eq 429 ]; then
  sleep $((2 ** retry_count))
fi

# ✅ ПРАВИЛЬНО: Use proper Content-Type
curl -X POST "https://api.nebula.example.com/api/v1/workflows" \
  -H "Content-Type: application/json" \
  -d @workflow.json

# ✅ ПРАВИЛЬНО: Check response status codes
if [ $HTTP_STATUS -ge 200 ] && [ $HTTP_STATUS -lt 300 ]; then
  echo "Success"
fi
```

### ❌ Неправильные практики

```bash
# ❌ НЕПРАВИЛЬНО: Fetch all data без pagination
curl -X GET "https://api.nebula.example.com/api/v1/workflows"  # Может вернуть тысячи

# ❌ НЕПРАВИЛЬНО: Ignore rate limits
while true; do
  curl -X GET "https://api.nebula.example.com/api/v1/workflows"
done

# ❌ НЕПРАВИЛЬНО: Hardcode credentials
curl -X GET "https://api.nebula.example.com/api/v1/workflows" \
  -H "Authorization: Bearer hardcoded_token"

# ❌ НЕПРАВИЛЬНО: Не проверять HTTP status
result=$(curl -X POST "..." -d @data.json)
# Не проверили успешность!

# ❌ НЕПРАВИЛЬНО: Использовать GET для state-changing operations
curl -X GET "https://api.nebula.example.com/api/v1/workflows/wf_123/execute"  # Должен быть POST!
```

## Complete Example

### Creating and Executing Workflow

```bash
#!/bin/bash

API_BASE="https://api.nebula.example.com"
TOKEN="your_jwt_token"

# 1. Create workflow
WORKFLOW_ID=$(curl -X POST "$API_BASE/api/v1/workflows" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Order Processing",
    "actions": [
      {
        "type": "validate_order",
        "name": "Validate Order"
      },
      {
        "type": "send_email",
        "name": "Send Confirmation"
      }
    ]
  }' | jq -r '.id')

echo "Created workflow: $WORKFLOW_ID"

# 2. Execute workflow
EXECUTION_ID=$(curl -X POST "$API_BASE/api/v1/workflows/$WORKFLOW_ID/execute" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "order_id": "ord_123",
      "customer_email": "alice@example.com"
    }
  }' | jq -r '.execution_id')

echo "Started execution: $EXECUTION_ID"

# 3. Poll execution status
while true; do
  STATUS=$(curl -X GET "$API_BASE/api/v1/executions/$EXECUTION_ID" \
    -H "Authorization: Bearer $TOKEN" | jq -r '.status')

  echo "Execution status: $STATUS"

  if [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ]; then
    break
  fi

  sleep 2
done

# 4. Get execution logs
curl -X GET "$API_BASE/api/v1/executions/$EXECUTION_ID/logs" \
  -H "Authorization: Bearer $TOKEN" | jq '.logs'
```

## Related Documentation

- [[02-Crates/nebula-api/README|nebula-api]] — API overview
- [[02-Crates/nebula-api/Authentication|Authentication]] — JWT, API keys, OAuth2
- [[02-Crates/nebula-api/GraphQL API|GraphQL API]] — GraphQL API
- [[02-Crates/nebula-api/WebSocket API|WebSocket API]] — WebSocket API
- [[02-Crates/nebula-workflow/README|nebula-workflow]] — Workflow management

## Links

- [REST API Design Best Practices](https://restfulapi.net/)
- [HTTP Status Codes](https://httpstatuses.com/)
- [JSON API Specification](https://jsonapi.org/)
