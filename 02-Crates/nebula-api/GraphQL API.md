---
title: GraphQL API
tags: [nebula, nebula-api, docs, graphql, api, subscriptions]
status: ready
created: 2025-08-17
---

# GraphQL API

GraphQL API в **nebula-api** — flexible query language для получения данных о workflows, executions, credentials и resources с точным контролем над структурой response.

## Overview

nebula-api GraphQL API предоставляет:

- **Flexible Queries** — запрашивать только нужные поля
- **Strongly Typed Schema** — type safety с introspection
- **Single Endpoint** — один endpoint для всех операций
- **Mutations** — create, update, delete operations
- **Subscriptions** — real-time updates через WebSocket
- **Batching** — multiple queries в одном request

## Endpoint

```
POST https://api.nebula.example.com/api/v1/graphql
```

### GraphQL Playground

Interactive GraphQL IDE доступен по адресу:

```
GET https://api.nebula.example.com/api/v1/graphql/playground
```

## Authentication

GraphQL API требует authentication через HTTP header:

```http
Authorization: Bearer <jwt_token>
```

или

```http
X-API-Key: sk_live_1234567890abcdef
```

## Schema Overview

### Core Types

```graphql
type Workflow {
  id: ID!
  name: String!
  description: String
  status: WorkflowStatus!
  version: Int!
  createdAt: DateTime!
  updatedAt: DateTime!
  actions: [Action!]!
  triggers: [Trigger!]!
  executions(limit: Int, offset: Int): ExecutionConnection!
  statistics: WorkflowStatistics
}

type Action {
  id: ID!
  type: String!
  name: String!
  config: JSON!
  position: Int!
}

type Trigger {
  id: ID!
  type: TriggerType!
  config: JSON!
}

type Execution {
  id: ID!
  workflowId: ID!
  workflow: Workflow!
  status: ExecutionStatus!
  startedAt: DateTime!
  completedAt: DateTime
  duration: Int
  input: JSON!
  output: JSON
  actionsExecuted: [ActionExecution!]!
  logs: [ExecutionLog!]!
}

type ActionExecution {
  actionId: ID!
  action: Action!
  status: ExecutionStatus!
  startedAt: DateTime!
  completedAt: DateTime
  result: JSON
  error: String
}

type ExecutionLog {
  timestamp: DateTime!
  level: LogLevel!
  message: String!
  actionId: ID
}

type Credential {
  id: ID!
  name: String!
  type: CredentialType!
  scopes: [String!]!
  createdAt: DateTime!
  expiresAt: DateTime
  lastUsedAt: DateTime
}

type Resource {
  id: ID!
  name: String!
  type: ResourceType!
  status: ResourceStatus!
  createdAt: DateTime!
  health: ResourceHealth
}

enum WorkflowStatus {
  DRAFT
  ACTIVE
  PAUSED
  ARCHIVED
}

enum ExecutionStatus {
  RUNNING
  COMPLETED
  FAILED
  CANCELLED
}

enum TriggerType {
  WEBHOOK
  SCHEDULE
  EVENT
}

enum CredentialType {
  API_KEY
  OAUTH2
  DATABASE
  CERTIFICATE
}

enum ResourceType {
  DATABASE
  HTTP
  MESSAGE_QUEUE
  CACHE
}

enum LogLevel {
  DEBUG
  INFO
  WARN
  ERROR
}

scalar DateTime
scalar JSON
```

## Queries

### Get Workflow

Получить workflow по ID.

```graphql
query GetWorkflow($id: ID!) {
  workflow(id: $id) {
    id
    name
    description
    status
    version
    createdAt
    updatedAt
    actions {
      id
      type
      name
      config
    }
    triggers {
      id
      type
      config
    }
    statistics {
      totalExecutions
      successfulExecutions
      failedExecutions
      avgDurationMs
    }
  }
}
```

**Variables:**

```json
{
  "id": "wf_1234567890"
}
```

**Response:**

```json
{
  "data": {
    "workflow": {
      "id": "wf_1234567890",
      "name": "User Onboarding Workflow",
      "description": "Automated user onboarding process",
      "status": "ACTIVE",
      "version": 2,
      "createdAt": "2025-01-15T10:30:00Z",
      "updatedAt": "2025-01-16T09:15:00Z",
      "actions": [
        {
          "id": "action_001",
          "type": "send_email",
          "name": "Send Welcome Email",
          "config": {
            "template": "welcome",
            "to": "{{ user.email }}"
          }
        }
      ],
      "triggers": [
        {
          "id": "trigger_001",
          "type": "WEBHOOK",
          "config": {
            "path": "/webhooks/new-user"
          }
        }
      ],
      "statistics": {
        "totalExecutions": 1234,
        "successfulExecutions": 1180,
        "failedExecutions": 54,
        "avgDurationMs": 2500
      }
    }
  }
}
```

### List Workflows

Получить список workflows с фильтрацией и пагинацией.

```graphql
query ListWorkflows(
  $status: WorkflowStatus
  $limit: Int = 20
  $offset: Int = 0
  $orderBy: WorkflowOrderBy
) {
  workflows(
    filter: { status: $status }
    limit: $limit
    offset: $offset
    orderBy: $orderBy
  ) {
    edges {
      node {
        id
        name
        status
        version
        createdAt
      }
    }
    pageInfo {
      total
      hasNextPage
    }
  }
}
```

**Variables:**

```json
{
  "status": "ACTIVE",
  "limit": 10,
  "offset": 0,
  "orderBy": {
    "field": "CREATED_AT",
    "direction": "DESC"
  }
}
```

### Get Execution with Nested Data

Получить execution с вложенными данными workflow и action executions.

```graphql
query GetExecution($id: ID!) {
  execution(id: $id) {
    id
    status
    startedAt
    completedAt
    duration

    workflow {
      id
      name
      version
    }

    input
    output

    actionsExecuted {
      actionId
      action {
        name
        type
      }
      status
      startedAt
      completedAt
      result
      error
    }

    logs(limit: 100) {
      timestamp
      level
      message
      actionId
    }
  }
}
```

**Variables:**

```json
{
  "id": "exec_abc123def"
}
```

### Search Workflows

Поиск workflows по имени с частичным совпадением.

```graphql
query SearchWorkflows($query: String!, $limit: Int = 10) {
  searchWorkflows(query: $query, limit: $limit) {
    id
    name
    description
    status
    createdAt
  }
}
```

**Variables:**

```json
{
  "query": "onboarding",
  "limit": 10
}
```

### Complex Query with Fragments

Использование fragments для повторного использования полей.

```graphql
fragment WorkflowFields on Workflow {
  id
  name
  description
  status
  version
  createdAt
  updatedAt
}

fragment ActionFields on Action {
  id
  type
  name
  config
}

query GetWorkflowWithExecutions($workflowId: ID!, $executionLimit: Int = 10) {
  workflow(id: $workflowId) {
    ...WorkflowFields

    actions {
      ...ActionFields
    }

    executions(limit: $executionLimit) {
      edges {
        node {
          id
          status
          startedAt
          completedAt
          duration
        }
      }
    }
  }
}
```

## Mutations

### Create Workflow

Создать новый workflow.

```graphql
mutation CreateWorkflow($input: CreateWorkflowInput!) {
  createWorkflow(input: $input) {
    id
    name
    status
    version
    createdAt
    actions {
      id
      type
      name
    }
  }
}
```

**Variables:**

```json
{
  "input": {
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
        "type": "WEBHOOK",
        "config": {
          "path": "/webhooks/new-order"
        }
      }
    ]
  }
}
```

**Response:**

```json
{
  "data": {
    "createWorkflow": {
      "id": "wf_9876543210",
      "name": "Order Processing Workflow",
      "status": "DRAFT",
      "version": 1,
      "createdAt": "2025-01-16T14:20:00Z",
      "actions": [
        {
          "id": "action_new_001",
          "type": "validate_order",
          "name": "Validate Order"
        },
        {
          "id": "action_new_002",
          "type": "send_notification",
          "name": "Notify Customer"
        }
      ]
    }
  }
}
```

### Update Workflow

Обновить существующий workflow.

```graphql
mutation UpdateWorkflow($id: ID!, $input: UpdateWorkflowInput!) {
  updateWorkflow(id: $id, input: $input) {
    id
    name
    description
    status
    version
    updatedAt
  }
}
```

**Variables:**

```json
{
  "id": "wf_1234567890",
  "input": {
    "name": "Updated Workflow Name",
    "status": "ACTIVE"
  }
}
```

### Delete Workflow

Удалить workflow.

```graphql
mutation DeleteWorkflow($id: ID!) {
  deleteWorkflow(id: $id) {
    id
    deleted
    deletedAt
  }
}
```

**Variables:**

```json
{
  "id": "wf_1234567890"
}
```

### Execute Workflow

Запустить execution workflow.

```graphql
mutation ExecuteWorkflow($workflowId: ID!, $input: ExecutionInput!) {
  executeWorkflow(workflowId: $workflowId, input: $input) {
    id
    status
    startedAt
    workflow {
      id
      name
    }
  }
}
```

**Variables:**

```json
{
  "workflowId": "wf_1234567890",
  "input": {
    "data": {
      "user_id": "user_123",
      "email": "alice@example.com"
    },
    "context": {
      "source": "api",
      "priority": "high"
    }
  }
}
```

### Cancel Execution

Отменить running execution.

```graphql
mutation CancelExecution($id: ID!) {
  cancelExecution(id: $id) {
    id
    status
    cancelledAt
  }
}
```

**Variables:**

```json
{
  "id": "exec_abc123def"
}
```

### Create Credential

Создать новый credential.

```graphql
mutation CreateCredential($input: CreateCredentialInput!) {
  createCredential(input: $input) {
    id
    name
    type
    scopes
    createdAt
  }
}
```

**Variables:**

```json
{
  "input": {
    "name": "GitHub API Key",
    "type": "API_KEY",
    "data": {
      "api_key": "ghp_1234567890abcdef"
    },
    "scopes": ["workflows:read"]
  }
}
```

### Rotate Credential

Ротация credential.

```graphql
mutation RotateCredential($id: ID!) {
  rotateCredential(id: $id) {
    id
    name
    rotatedAt
  }
}
```

## Subscriptions

Subscriptions позволяют получать real-time updates через WebSocket.

### Subscribe to Execution Updates

Подписаться на updates execution.

```graphql
subscription OnExecutionUpdate($executionId: ID!) {
  executionUpdated(executionId: $executionId) {
    id
    status
    startedAt
    completedAt
    duration

    actionsExecuted {
      actionId
      status
      startedAt
      completedAt
    }

    logs {
      timestamp
      level
      message
    }
  }
}
```

**Variables:**

```json
{
  "executionId": "exec_abc123def"
}
```

**Streaming Updates:**

```json
{
  "data": {
    "executionUpdated": {
      "id": "exec_abc123def",
      "status": "RUNNING",
      "startedAt": "2025-01-16T17:00:00Z",
      "completedAt": null,
      "duration": null,
      "actionsExecuted": [
        {
          "actionId": "action_001",
          "status": "RUNNING",
          "startedAt": "2025-01-16T17:00:05Z",
          "completedAt": null
        }
      ],
      "logs": [
        {
          "timestamp": "2025-01-16T17:00:00Z",
          "level": "INFO",
          "message": "Execution started"
        }
      ]
    }
  }
}
```

### Subscribe to Workflow Events

Подписаться на события workflow.

```graphql
subscription OnWorkflowEvent($workflowId: ID!) {
  workflowEvent(workflowId: $workflowId) {
    event
    workflow {
      id
      name
      status
      version
    }
    timestamp
  }
}
```

**Event Types:**

- `CREATED` — workflow создан
- `UPDATED` — workflow обновлен
- `DELETED` — workflow удален
- `EXECUTED` — новый execution запущен

### Subscribe to All Executions

Подписаться на все новые executions.

```graphql
subscription OnNewExecution {
  executionCreated {
    id
    workflowId
    workflow {
      name
    }
    status
    startedAt
  }
}
```

## Batching

GraphQL позволяет выполнять multiple queries в одном request.

```graphql
query BatchQuery {
  workflow1: workflow(id: "wf_123") {
    id
    name
    status
  }

  workflow2: workflow(id: "wf_456") {
    id
    name
    status
  }

  recentExecutions: executions(limit: 10, orderBy: { field: STARTED_AT, direction: DESC }) {
    edges {
      node {
        id
        status
        startedAt
      }
    }
  }
}
```

## Pagination

### Cursor-Based Pagination

```graphql
query PaginatedWorkflows($first: Int!, $after: String) {
  workflows(first: $first, after: $after) {
    edges {
      cursor
      node {
        id
        name
        status
      }
    }
    pageInfo {
      hasNextPage
      hasPreviousPage
      startCursor
      endCursor
    }
  }
}
```

**First Page:**

```json
{
  "first": 10,
  "after": null
}
```

**Next Page:**

```json
{
  "first": 10,
  "after": "eyJpZCI6IndmXzEyMyJ9"
}
```

## Error Handling

GraphQL errors возвращаются в `errors` array:

```json
{
  "errors": [
    {
      "message": "Workflow not found",
      "locations": [
        {
          "line": 2,
          "column": 3
        }
      ],
      "path": ["workflow"],
      "extensions": {
        "code": "NOT_FOUND",
        "workflowId": "wf_invalid"
      }
    }
  ],
  "data": {
    "workflow": null
  }
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| UNAUTHENTICATED | Missing or invalid authentication |
| FORBIDDEN | Insufficient permissions |
| NOT_FOUND | Resource not found |
| VALIDATION_ERROR | Invalid input |
| CONFLICT | Resource conflict |
| INTERNAL_ERROR | Server error |

## Introspection

GraphQL schema introspection позволяет исследовать доступные types и fields.

```graphql
query IntrospectionQuery {
  __schema {
    types {
      name
      kind
      description
    }
  }
}
```

### Get Type Information

```graphql
query GetTypeInfo {
  __type(name: "Workflow") {
    name
    kind
    fields {
      name
      type {
        name
        kind
      }
      description
    }
  }
}
```

## Best Practices

### ✅ Правильные практики

```graphql
# ✅ ПРАВИЛЬНО: Request только нужные поля
query GetWorkflow($id: ID!) {
  workflow(id: $id) {
    id
    name
    status
  }
}

# ✅ ПРАВИЛЬНО: Use fragments для переиспользования
fragment WorkflowBasic on Workflow {
  id
  name
  status
  version
}

query GetMultipleWorkflows {
  workflow1: workflow(id: "wf_123") {
    ...WorkflowBasic
  }
  workflow2: workflow(id: "wf_456") {
    ...WorkflowBasic
  }
}

# ✅ ПРАВИЛЬНО: Use variables вместо hardcoding
query GetWorkflow($id: ID!) {
  workflow(id: $id) {
    name
  }
}

# ✅ ПРАВИЛЬНО: Pagination для больших datasets
query ListWorkflows($limit: Int = 20, $offset: Int = 0) {
  workflows(limit: $limit, offset: $offset) {
    edges {
      node {
        id
        name
      }
    }
  }
}

# ✅ ПРАВИЛЬНО: Named queries для debugging
query GetWorkflowDetails($id: ID!) {
  workflow(id: $id) {
    id
    name
  }
}
```

### ❌ Неправильные практики

```graphql
# ❌ НЕПРАВИЛЬНО: Request всех полей (overfetching)
query GetWorkflow($id: ID!) {
  workflow(id: $id) {
    id
    name
    description
    status
    version
    createdAt
    updatedAt
    actions {
      id
      type
      name
      config
      position
    }
    triggers {
      id
      type
      config
    }
    executions {
      edges {
        node {
          id
          status
          # ... и так далее
        }
      }
    }
  }
}

# ❌ НЕПРАВИЛЬНО: Hardcoded values вместо variables
query GetWorkflow {
  workflow(id: "wf_1234567890") {  # Hardcoded!
    name
  }
}

# ❌ НЕПРАВИЛЬНО: Anonymous queries (плохо для debugging)
{
  workflow(id: "wf_123") {
    name
  }
}

# ❌ НЕПРАВИЛЬНО: Не использовать pagination
query GetAllWorkflows {
  workflows {  # Может вернуть тысячи!
    edges {
      node {
        id
        name
      }
    }
  }
}

# ❌ НЕПРАВИЛЬНО: N+1 queries problem
query GetWorkflowsWithExecutions {
  workflows {
    edges {
      node {
        id
        name
        # Это вызывает отдельный query для каждого workflow!
        executions {
          edges {
            node {
              id
            }
          }
        }
      }
    }
  }
}
```

## Client Examples

### JavaScript (Apollo Client)

```javascript
import { ApolloClient, InMemoryCache, gql } from '@apollo/client';

const client = new ApolloClient({
  uri: 'https://api.nebula.example.com/api/v1/graphql',
  cache: new InMemoryCache(),
  headers: {
    authorization: `Bearer ${token}`,
  },
});

// Query
const GET_WORKFLOW = gql`
  query GetWorkflow($id: ID!) {
    workflow(id: $id) {
      id
      name
      status
      actions {
        id
        type
        name
      }
    }
  }
`;

const { data } = await client.query({
  query: GET_WORKFLOW,
  variables: { id: 'wf_1234567890' },
});

console.log(data.workflow);

// Mutation
const CREATE_WORKFLOW = gql`
  mutation CreateWorkflow($input: CreateWorkflowInput!) {
    createWorkflow(input: $input) {
      id
      name
      status
    }
  }
`;

const { data: mutationData } = await client.mutate({
  mutation: CREATE_WORKFLOW,
  variables: {
    input: {
      name: 'New Workflow',
      actions: [
        {
          type: 'send_email',
          name: 'Send Email',
          config: { template: 'welcome' },
        },
      ],
    },
  },
});

console.log(mutationData.createWorkflow);

// Subscription
const EXECUTION_SUBSCRIPTION = gql`
  subscription OnExecutionUpdate($executionId: ID!) {
    executionUpdated(executionId: $executionId) {
      id
      status
      completedAt
    }
  }
`;

client.subscribe({
  query: EXECUTION_SUBSCRIPTION,
  variables: { executionId: 'exec_abc123' },
}).subscribe({
  next: ({ data }) => {
    console.log('Execution update:', data.executionUpdated);
  },
});
```

### Python (gql)

```python
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

# Setup client
transport = RequestsHTTPTransport(
    url='https://api.nebula.example.com/api/v1/graphql',
    headers={'Authorization': f'Bearer {token}'}
)

client = Client(transport=transport, fetch_schema_from_transport=True)

# Query
query = gql('''
    query GetWorkflow($id: ID!) {
        workflow(id: $id) {
            id
            name
            status
        }
    }
''')

result = client.execute(query, variable_values={'id': 'wf_1234567890'})
print(result['workflow'])

# Mutation
mutation = gql('''
    mutation ExecuteWorkflow($workflowId: ID!, $input: ExecutionInput!) {
        executeWorkflow(workflowId: $workflowId, input: $input) {
            id
            status
            startedAt
        }
    }
''')

result = client.execute(
    mutation,
    variable_values={
        'workflowId': 'wf_1234567890',
        'input': {
            'data': {'user_id': 'user_123'}
        }
    }
)

print(result['executeWorkflow'])
```

### Rust (graphql-client)

```rust
use graphql_client::{GraphQLQuery, Response};
use reqwest::Client;

#[derive(GraphQLQuery)]
#[graphql(
    schema_path = "schema.graphql",
    query_path = "queries/get_workflow.graphql",
    response_derives = "Debug"
)]
pub struct GetWorkflow;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let variables = get_workflow::Variables {
        id: "wf_1234567890".to_string(),
    };

    let request_body = GetWorkflow::build_query(variables);

    let response = client
        .post("https://api.nebula.example.com/api/v1/graphql")
        .header("Authorization", format!("Bearer {}", token))
        .json(&request_body)
        .send()
        .await?;

    let response_body: Response<get_workflow::ResponseData> = response.json().await?;

    if let Some(data) = response_body.data {
        println!("Workflow: {:?}", data.workflow);
    }

    Ok(())
}
```

## Complete Example: Workflow Execution with Real-time Updates

```javascript
import { ApolloClient, InMemoryCache, gql, split, HttpLink } from '@apollo/client';
import { WebSocketLink } from '@apollo/client/link/ws';
import { getMainDefinition } from '@apollo/client/utilities';

// HTTP link for queries and mutations
const httpLink = new HttpLink({
  uri: 'https://api.nebula.example.com/api/v1/graphql',
  headers: {
    authorization: `Bearer ${token}`,
  },
});

// WebSocket link for subscriptions
const wsLink = new WebSocketLink({
  uri: 'wss://api.nebula.example.com/api/v1/graphql',
  options: {
    reconnect: true,
    connectionParams: {
      authorization: `Bearer ${token}`,
    },
  },
});

// Split based on operation type
const splitLink = split(
  ({ query }) => {
    const definition = getMainDefinition(query);
    return (
      definition.kind === 'OperationDefinition' &&
      definition.operation === 'subscription'
    );
  },
  wsLink,
  httpLink
);

const client = new ApolloClient({
  link: splitLink,
  cache: new InMemoryCache(),
});

// Execute workflow and subscribe to updates
async function executeAndMonitor(workflowId) {
  // 1. Execute workflow
  const EXECUTE_MUTATION = gql`
    mutation ExecuteWorkflow($workflowId: ID!, $input: ExecutionInput!) {
      executeWorkflow(workflowId: $workflowId, input: $input) {
        id
        status
        startedAt
      }
    }
  `;

  const { data } = await client.mutate({
    mutation: EXECUTE_MUTATION,
    variables: {
      workflowId,
      input: {
        data: { user_id: 'user_123' },
      },
    },
  });

  const executionId = data.executeWorkflow.id;
  console.log('Execution started:', executionId);

  // 2. Subscribe to execution updates
  const EXECUTION_SUBSCRIPTION = gql`
    subscription OnExecutionUpdate($executionId: ID!) {
      executionUpdated(executionId: $executionId) {
        id
        status
        completedAt
        actionsExecuted {
          actionId
          status
          completedAt
        }
        logs {
          timestamp
          level
          message
        }
      }
    }
  `;

  const subscription = client.subscribe({
    query: EXECUTION_SUBSCRIPTION,
    variables: { executionId },
  }).subscribe({
    next: ({ data }) => {
      const execution = data.executionUpdated;
      console.log(`Status: ${execution.status}`);

      if (execution.logs.length > 0) {
        const latestLog = execution.logs[execution.logs.length - 1];
        console.log(`Log: ${latestLog.message}`);
      }

      if (execution.status === 'COMPLETED' || execution.status === 'FAILED') {
        console.log('Execution finished:', execution);
        subscription.unsubscribe();
      }
    },
    error: (error) => {
      console.error('Subscription error:', error);
    },
  });
}

// Run
executeAndMonitor('wf_1234567890');
```

## Related Documentation

- [[02-Crates/nebula-api/README|nebula-api]] — API overview
- [[02-Crates/nebula-api/Authentication|Authentication]] — JWT, API keys, OAuth2
- [[02-Crates/nebula-api/REST API|REST API]] — RESTful endpoints
- [[02-Crates/nebula-api/WebSocket API|WebSocket API]] — WebSocket API
- [[02-Crates/nebula-workflow/README|nebula-workflow]] — Workflow management

## Links

- [GraphQL Specification](https://spec.graphql.org/)
- [Apollo GraphQL](https://www.apollographql.com/)
- [GraphQL Best Practices](https://graphql.org/learn/best-practices/)
- [Relay Cursor Connections](https://relay.dev/graphql/connections.htm)
