---
title: WebSocket API
tags: [nebula, docs]
status: draft
created: 2025-08-17
---

# WebSocket API

Documentation for **nebula-api** — WebSocket API.

## Overview

The **WebSocket API** provides real-time, bidirectional communication between clients and the Nebula server. Unlike REST and GraphQL APIs which use request-response patterns, WebSocket maintains a persistent connection that allows the server to push updates to clients instantly.

The WebSocket API is built on top of the Axum web framework using `axum::extract::ws` and follows a JSON-based message protocol for all communication.

**Key Features**:
- **Real-time Execution Streaming**: Receive live updates as workflows execute
- **Event Broadcasting**: Subscribe to workflow events, status changes, and logs
- **Bidirectional Communication**: Send commands and receive responses over the same connection
- **Multiplexing**: Subscribe to multiple workflows/executions on a single connection
- **Authentication**: JWT-based authentication with heartbeat verification
- **Automatic Reconnection**: Built-in reconnection logic with exponential backoff

## Why WebSocket API?

### Use Cases

1. **Live Workflow Execution Dashboard**
   - Stream execution status, progress, and logs in real-time
   - Display live metrics as workflows run
   - Show execution timeline with millisecond precision

2. **Interactive Workflow Builder**
   - Test workflow actions and see results immediately
   - Debug workflows with live log streaming
   - Validate configurations with instant feedback

3. **Monitoring and Alerting**
   - Subscribe to workflow failures or anomalies
   - Receive instant notifications for critical events
   - Monitor system health with live metrics

4. **Collaborative Features**
   - Multiple users editing workflows simultaneously
   - Real-time presence indication
   - Instant synchronization of changes

### Advantages Over HTTP Polling

| Feature | WebSocket | HTTP Polling |
|---------|-----------|--------------|
| Latency | < 50ms | 1-5 seconds |
| Server Load | Low (persistent connection) | High (repeated requests) |
| Bandwidth | Low (events only) | High (full response each time) |
| Bidirectional | Yes | No (separate requests) |
| Real-time | True real-time | Near real-time |

## Connection Establishment

### WebSocket Endpoint

```
ws://localhost:8000/api/v1/ws
wss://api.nebula.example.com/api/v1/ws  # Production (TLS)
```

### Authentication

WebSocket connections require authentication via JWT token passed as a query parameter or in the initial handshake message.

**Method 1: Query Parameter (Recommended)**

```javascript
const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...";
const ws = new WebSocket(`ws://localhost:8000/api/v1/ws?token=${token}`);
```

**Method 2: Initial Message**

```javascript
const ws = new WebSocket("ws://localhost:8000/api/v1/ws");

ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "authenticate",
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }));
};
```

### Rust Server Implementation

```rust
use axum::{
    extract::{
        ws::{WebSocket, WebSocketUpgrade, Message},
        State, Query,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub event_broadcaster: broadcast::Sender<WorkflowEvent>,
    pub jwt_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

pub fn websocket_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/ws", get(websocket_handler))
}

pub async fn websocket_handler(
    ws: WebSocketUpgrade,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Authenticate via query parameter
    if let Some(token) = query.token {
        match verify_jwt_token(&token, &state.jwt_secret) {
            Ok(claims) => {
                // Upgrade connection and handle WebSocket
                ws.on_upgrade(move |socket| {
                    handle_websocket(socket, state, claims)
                })
            }
            Err(_) => {
                // Return 401 Unauthorized before upgrade
                return axum::http::StatusCode::UNAUTHORIZED.into_response();
            }
        }
    } else {
        // No token provided
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }
}

async fn handle_websocket(
    socket: WebSocket,
    state: Arc<AppState>,
    claims: Claims,
) {
    let (mut sender, mut receiver) = socket.split();

    // Subscribe to event broadcaster
    let mut event_rx = state.event_broadcaster.subscribe();

    // Spawn task to send events to client
    let send_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let message = serde_json::to_string(&event).unwrap();
            if sender.send(Message::Text(message)).await.is_err() {
                break; // Connection closed
            }
        }
    });

    // Handle incoming messages from client
    while let Some(Ok(msg)) = receiver.next().await {
        if let Message::Text(text) = msg {
            match serde_json::from_str::<ClientMessage>(&text) {
                Ok(client_msg) => {
                    handle_client_message(client_msg, &state, &claims).await;
                }
                Err(e) => {
                    eprintln!("Failed to parse client message: {}", e);
                }
            }
        } else if let Message::Close(_) = msg {
            break;
        }
    }

    // Cleanup
    send_task.abort();
}
```

## Message Protocol

### Message Format

All messages use JSON format with a `type` field indicating the message type.

**Client → Server Messages**:

```typescript
type ClientMessage =
  | { type: "authenticate"; token: string }
  | { type: "subscribe"; resource: string; id: string }
  | { type: "unsubscribe"; resource: string; id: string }
  | { type: "execute_workflow"; workflow_id: string; input: any }
  | { type: "ping" };
```

**Server → Client Messages**:

```typescript
type ServerMessage =
  | { type: "authenticated"; user_id: string; roles: string[] }
  | { type: "subscribed"; resource: string; id: string }
  | { type: "unsubscribed"; resource: string; id: string }
  | { type: "execution_update"; execution: ExecutionUpdate }
  | { type: "workflow_event"; event: WorkflowEvent }
  | { type: "log"; log: LogEntry }
  | { type: "error"; code: string; message: string }
  | { type: "pong" };
```

### Subscription Model

Clients subscribe to specific resources to receive updates:

```javascript
// Subscribe to workflow execution updates
ws.send(JSON.stringify({
  type: "subscribe",
  resource: "execution",
  id: "exec_abc123"
}));

// Subscribe to all executions of a workflow
ws.send(JSON.stringify({
  type: "subscribe",
  resource: "workflow_executions",
  id: "wf_xyz789"
}));

// Subscribe to workflow events (created, updated, deleted)
ws.send(JSON.stringify({
  type: "subscribe",
  resource: "workflows",
  id: "all"  // or specific workflow ID
}));
```

## Event Types

### 1. Execution Updates

Sent when an execution status changes or progresses:

```json
{
  "type": "execution_update",
  "execution": {
    "id": "exec_abc123",
    "workflow_id": "wf_xyz789",
    "status": "running",
    "started_at": "2025-01-15T10:30:00Z",
    "progress": {
      "current_action": 3,
      "total_actions": 10,
      "percentage": 30
    },
    "actions_executed": [
      {
        "action_id": "act_001",
        "name": "Validate Order",
        "status": "completed",
        "started_at": "2025-01-15T10:30:01Z",
        "completed_at": "2025-01-15T10:30:02Z",
        "duration_ms": 1250,
        "result": { "valid": true }
      },
      {
        "action_id": "act_002",
        "name": "Check Inventory",
        "status": "completed",
        "started_at": "2025-01-15T10:30:02Z",
        "completed_at": "2025-01-15T10:30:04Z",
        "duration_ms": 2100,
        "result": { "in_stock": true, "quantity": 150 }
      },
      {
        "action_id": "act_003",
        "name": "Process Payment",
        "status": "running",
        "started_at": "2025-01-15T10:30:04Z"
      }
    ]
  }
}
```

### 2. Workflow Events

Sent when workflows are created, updated, or deleted:

```json
{
  "type": "workflow_event",
  "event": {
    "event_type": "updated",
    "workflow": {
      "id": "wf_xyz789",
      "name": "Order Processing",
      "status": "active",
      "version": 3,
      "updated_at": "2025-01-15T10:25:00Z",
      "updated_by": "user_123"
    }
  }
}
```

### 3. Log Entries

Real-time log streaming from workflow executions:

```json
{
  "type": "log",
  "log": {
    "execution_id": "exec_abc123",
    "action_id": "act_003",
    "timestamp": "2025-01-15T10:30:04.123Z",
    "level": "info",
    "message": "Initiating payment gateway connection",
    "metadata": {
      "payment_provider": "stripe",
      "amount": 99.99,
      "currency": "USD"
    }
  }
}
```

### 4. Error Messages

Sent when client requests fail or server errors occur:

```json
{
  "type": "error",
  "code": "SUBSCRIPTION_FAILED",
  "message": "Cannot subscribe to execution 'exec_invalid': not found",
  "request_id": "req_xyz123"
}
```

## Client Examples

### JavaScript (Browser)

```javascript
class NebulaWebSocketClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
    this.ws = null;
    this.subscriptions = new Map();
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 10;
  }

  connect() {
    return new Promise((resolve, reject) => {
      const wsUrl = `${this.baseUrl}/api/v1/ws?token=${this.token}`;
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log("WebSocket connected");
        this.reconnectAttempts = 0;
        this.startHeartbeat();
        resolve();
      };

      this.ws.onmessage = (event) => {
        const message = JSON.parse(event.data);
        this.handleMessage(message);
      };

      this.ws.onerror = (error) => {
        console.error("WebSocket error:", error);
        reject(error);
      };

      this.ws.onclose = () => {
        console.log("WebSocket closed");
        this.stopHeartbeat();
        this.attemptReconnect();
      };
    });
  }

  handleMessage(message) {
    switch (message.type) {
      case "execution_update":
        const handlers = this.subscriptions.get(`execution:${message.execution.id}`);
        handlers?.forEach(handler => handler(message.execution));
        break;

      case "workflow_event":
        const workflowHandlers = this.subscriptions.get(`workflow:${message.event.workflow.id}`);
        workflowHandlers?.forEach(handler => handler(message.event));
        break;

      case "log":
        const logHandlers = this.subscriptions.get(`logs:${message.log.execution_id}`);
        logHandlers?.forEach(handler => handler(message.log));
        break;

      case "error":
        console.error("Server error:", message);
        break;

      case "pong":
        // Heartbeat response
        break;

      default:
        console.warn("Unknown message type:", message.type);
    }
  }

  subscribeToExecution(executionId, callback) {
    const key = `execution:${executionId}`;

    if (!this.subscriptions.has(key)) {
      this.subscriptions.set(key, []);
      this.send({
        type: "subscribe",
        resource: "execution",
        id: executionId
      });
    }

    this.subscriptions.get(key).push(callback);

    // Return unsubscribe function
    return () => {
      const handlers = this.subscriptions.get(key);
      const index = handlers.indexOf(callback);
      if (index > -1) {
        handlers.splice(index, 1);
      }

      if (handlers.length === 0) {
        this.subscriptions.delete(key);
        this.send({
          type: "unsubscribe",
          resource: "execution",
          id: executionId
        });
      }
    };
  }

  subscribeToLogs(executionId, callback) {
    const key = `logs:${executionId}`;

    if (!this.subscriptions.has(key)) {
      this.subscriptions.set(key, []);
    }

    this.subscriptions.get(key).push(callback);

    return () => {
      const handlers = this.subscriptions.get(key);
      const index = handlers.indexOf(callback);
      if (index > -1) {
        handlers.splice(index, 1);
      }
      if (handlers.length === 0) {
        this.subscriptions.delete(key);
      }
    };
  }

  send(message) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.error("WebSocket not connected");
    }
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      this.send({ type: "ping" });
    }, 30000); // Every 30 seconds
  }

  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error("Max reconnection attempts reached");
      return;
    }

    this.reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);

    console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

    setTimeout(() => {
      this.connect().catch(err => {
        console.error("Reconnection failed:", err);
      });
    }, delay);
  }

  disconnect() {
    this.stopHeartbeat();
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.subscriptions.clear();
  }
}

// Usage Example
const client = new NebulaWebSocketClient("ws://localhost:8000", "your-jwt-token");

await client.connect();

// Subscribe to execution updates
const unsubscribe = client.subscribeToExecution("exec_abc123", (execution) => {
  console.log(`Execution status: ${execution.status}`);
  console.log(`Progress: ${execution.progress.percentage}%`);

  if (execution.status === "completed") {
    console.log("Execution completed!");
    unsubscribe(); // Stop receiving updates
  }
});

// Subscribe to logs
client.subscribeToLogs("exec_abc123", (log) => {
  console.log(`[${log.level.toUpperCase()}] ${log.message}`);
});
```

### Python (websockets library)

```python
import asyncio
import json
import websockets
from typing import Callable, Dict, List
from dataclasses import dataclass

@dataclass
class ExecutionUpdate:
    id: str
    workflow_id: str
    status: str
    progress: dict
    actions_executed: list

class NebulaWebSocketClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url
        self.token = token
        self.ws = None
        self.subscriptions: Dict[str, List[Callable]] = {}
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 10
        self.running = False

    async def connect(self):
        """Establish WebSocket connection with authentication."""
        ws_url = f"{self.base_url}/api/v1/ws?token={self.token}"

        try:
            self.ws = await websockets.connect(
                ws_url,
                ping_interval=30,  # Send ping every 30 seconds
                ping_timeout=10,
            )
            print("WebSocket connected")
            self.reconnect_attempts = 0
            self.running = True

            # Start message handler
            asyncio.create_task(self._message_handler())

        except Exception as e:
            print(f"Connection failed: {e}")
            await self._attempt_reconnect()

    async def _message_handler(self):
        """Handle incoming WebSocket messages."""
        try:
            async for message in self.ws:
                data = json.loads(message)
                await self._handle_message(data)
        except websockets.exceptions.ConnectionClosed:
            print("Connection closed")
            if self.running:
                await self._attempt_reconnect()

    async def _handle_message(self, message: dict):
        """Route messages to appropriate handlers."""
        msg_type = message.get("type")

        if msg_type == "execution_update":
            execution = message["execution"]
            key = f"execution:{execution['id']}"
            if key in self.subscriptions:
                for callback in self.subscriptions[key]:
                    await callback(execution)

        elif msg_type == "log":
            log = message["log"]
            key = f"logs:{log['execution_id']}"
            if key in self.subscriptions:
                for callback in self.subscriptions[key]:
                    await callback(log)

        elif msg_type == "workflow_event":
            event = message["event"]
            key = f"workflow:{event['workflow']['id']}"
            if key in self.subscriptions:
                for callback in self.subscriptions[key]:
                    await callback(event)

        elif msg_type == "error":
            print(f"Server error: {message.get('message')}")

        elif msg_type == "pong":
            pass  # Heartbeat response

    async def subscribe_to_execution(self, execution_id: str, callback: Callable):
        """Subscribe to execution updates."""
        key = f"execution:{execution_id}"

        if key not in self.subscriptions:
            self.subscriptions[key] = []
            await self._send({
                "type": "subscribe",
                "resource": "execution",
                "id": execution_id
            })

        self.subscriptions[key].append(callback)

    async def subscribe_to_logs(self, execution_id: str, callback: Callable):
        """Subscribe to execution log stream."""
        key = f"logs:{execution_id}"

        if key not in self.subscriptions:
            self.subscriptions[key] = []

        self.subscriptions[key].append(callback)

    async def unsubscribe_from_execution(self, execution_id: str):
        """Unsubscribe from execution updates."""
        key = f"execution:{execution_id}"

        if key in self.subscriptions:
            del self.subscriptions[key]
            await self._send({
                "type": "unsubscribe",
                "resource": "execution",
                "id": execution_id
            })

    async def _send(self, message: dict):
        """Send message to server."""
        if self.ws and not self.ws.closed:
            await self.ws.send(json.dumps(message))
        else:
            print("WebSocket not connected")

    async def _attempt_reconnect(self):
        """Attempt to reconnect with exponential backoff."""
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            print("Max reconnection attempts reached")
            return

        self.reconnect_attempts += 1
        delay = min(2 ** self.reconnect_attempts, 30)

        print(f"Reconnecting in {delay}s (attempt {self.reconnect_attempts})")
        await asyncio.sleep(delay)
        await self.connect()

    async def disconnect(self):
        """Close WebSocket connection."""
        self.running = False
        if self.ws:
            await self.ws.close()
        self.subscriptions.clear()

# Usage Example
async def main():
    client = NebulaWebSocketClient(
        base_url="ws://localhost:8000",
        token="your-jwt-token"
    )

    await client.connect()

    # Subscribe to execution updates
    async def on_execution_update(execution):
        print(f"Status: {execution['status']}")
        print(f"Progress: {execution['progress']['percentage']}%")

        if execution['status'] == 'completed':
            await client.unsubscribe_from_execution(execution['id'])

    await client.subscribe_to_execution("exec_abc123", on_execution_update)

    # Subscribe to logs
    async def on_log(log):
        print(f"[{log['level'].upper()}] {log['message']}")

    await client.subscribe_to_logs("exec_abc123", on_log)

    # Keep connection alive
    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### Rust (tokio-tungstenite)

```rust
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Subscribe {
        resource: String,
        id: String,
    },
    Unsubscribe {
        resource: String,
        id: String,
    },
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    ExecutionUpdate { execution: ExecutionUpdate },
    Log { log: LogEntry },
    WorkflowEvent { event: WorkflowEvent },
    Error { code: String, message: String },
    Pong,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExecutionUpdate {
    id: String,
    workflow_id: String,
    status: String,
    progress: Progress,
    actions_executed: Vec<ActionExecution>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Progress {
    current_action: usize,
    total_actions: usize,
    percentage: u8,
}

#[derive(Debug, Serialize, Deserialize)]
struct ActionExecution {
    action_id: String,
    name: String,
    status: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    duration_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LogEntry {
    execution_id: String,
    action_id: Option<String>,
    timestamp: String,
    level: String,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct WorkflowEvent {
    event_type: String,
    workflow: serde_json::Value,
}

pub struct NebulaWebSocketClient {
    base_url: String,
    token: String,
    tx: mpsc::UnboundedSender<ClientMessage>,
}

impl NebulaWebSocketClient {
    pub fn new(base_url: String, token: String) -> Self {
        let (tx, _rx) = mpsc::unbounded_channel();
        Self { base_url, token, tx }
    }

    pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let ws_url = format!("{}/api/v1/ws?token={}", self.base_url, self.token);

        let (ws_stream, _) = connect_async(&ws_url).await?;
        println!("WebSocket connected");

        let (mut write, mut read) = ws_stream.split();

        // Channel for sending messages
        let (tx, mut rx) = mpsc::unbounded_channel::<ClientMessage>();
        self.tx = tx;

        // Spawn task to send messages
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let json = serde_json::to_string(&msg).unwrap();
                if write.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        });

        // Handle incoming messages
        while let Some(Ok(msg)) = read.next().await {
            if let Message::Text(text) = msg {
                match serde_json::from_str::<ServerMessage>(&text) {
                    Ok(server_msg) => {
                        self.handle_message(server_msg);
                    }
                    Err(e) => {
                        eprintln!("Failed to parse message: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_message(&self, message: ServerMessage) {
        match message {
            ServerMessage::ExecutionUpdate { execution } => {
                println!("Execution {} status: {}", execution.id, execution.status);
                println!("Progress: {}%", execution.progress.percentage);

                for action in &execution.actions_executed {
                    println!("  Action {}: {}", action.name, action.status);
                }
            }
            ServerMessage::Log { log } => {
                println!("[{}] {}", log.level.to_uppercase(), log.message);
            }
            ServerMessage::WorkflowEvent { event } => {
                println!("Workflow event: {}", event.event_type);
            }
            ServerMessage::Error { code, message } => {
                eprintln!("Server error [{}]: {}", code, message);
            }
            ServerMessage::Pong => {
                // Heartbeat response
            }
        }
    }

    pub fn subscribe_to_execution(&self, execution_id: &str) {
        let _ = self.tx.send(ClientMessage::Subscribe {
            resource: "execution".to_string(),
            id: execution_id.to_string(),
        });
    }

    pub fn unsubscribe_from_execution(&self, execution_id: &str) {
        let _ = self.tx.send(ClientMessage::Unsubscribe {
            resource: "execution".to_string(),
            id: execution_id.to_string(),
        });
    }
}

// Usage Example
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut client = NebulaWebSocketClient::new(
        "ws://localhost:8000".to_string(),
        "your-jwt-token".to_string(),
    );

    // Connect and start receiving messages
    tokio::spawn(async move {
        if let Err(e) = client.connect().await {
            eprintln!("WebSocket error: {}", e);
        }
    });

    // Subscribe to execution
    client.subscribe_to_execution("exec_abc123");

    // Keep running
    tokio::signal::ctrl_c().await?;

    Ok(())
}
```

## Best Practices

### ✅ Correct Patterns

**1. Implement Automatic Reconnection**

```javascript
class ResilientWebSocketClient {
  async connect() {
    try {
      this.ws = new WebSocket(this.url);
      this.setupHandlers();
    } catch (error) {
      console.error("Connection failed, retrying...");
      await this.exponentialBackoff();
      return this.connect();
    }
  }

  exponentialBackoff() {
    const delay = Math.min(1000 * Math.pow(2, this.attempts), 30000);
    this.attempts++;
    return new Promise(resolve => setTimeout(resolve, delay));
  }
}
```

**2. Handle Connection State Properly**

```javascript
send(message) {
  if (this.ws.readyState === WebSocket.OPEN) {
    this.ws.send(JSON.stringify(message));
  } else if (this.ws.readyState === WebSocket.CONNECTING) {
    // Queue message for later
    this.messageQueue.push(message);
  } else {
    console.error("WebSocket not connected");
  }
}
```

**3. Implement Heartbeat/Ping-Pong**

```javascript
startHeartbeat() {
  this.heartbeatInterval = setInterval(() => {
    if (this.ws.readyState === WebSocket.OPEN) {
      this.send({ type: "ping" });

      // Set timeout to detect connection loss
      this.heartbeatTimeout = setTimeout(() => {
        console.warn("Heartbeat timeout, reconnecting...");
        this.ws.close();
      }, 10000);
    }
  }, 30000);
}

onPong() {
  clearTimeout(this.heartbeatTimeout);
}
```

**4. Clean Up Subscriptions on Disconnect**

```javascript
disconnect() {
  // Unsubscribe from all resources
  for (const [key, handlers] of this.subscriptions.entries()) {
    const [resource, id] = key.split(":");
    this.send({ type: "unsubscribe", resource, id });
  }

  this.subscriptions.clear();
  this.ws?.close();
}
```

**5. Use Message Buffering During Reconnection**

```python
async def _send(self, message: dict):
    if self.ws and not self.ws.closed:
        await self.ws.send(json.dumps(message))
    else:
        # Buffer messages during reconnection
        self.message_buffer.append(message)

async def connect(self):
    # ... connect logic ...

    # Flush buffered messages after reconnection
    for message in self.message_buffer:
        await self._send(message)
    self.message_buffer.clear()
```

### ❌ Wrong Patterns

**1. No Error Handling on Send**

```javascript
// ❌ BAD: No check for connection state
send(message) {
  this.ws.send(JSON.stringify(message));  // May throw if not connected
}

// ✅ GOOD: Check state before sending
send(message) {
  if (this.ws?.readyState === WebSocket.OPEN) {
    this.ws.send(JSON.stringify(message));
  } else {
    console.error("Cannot send: WebSocket not connected");
  }
}
```

**2. Not Cleaning Up Event Listeners**

```javascript
// ❌ BAD: Memory leak from event listeners
subscribeToExecution(executionId, callback) {
  this.ws.addEventListener("message", (event) => {
    const data = JSON.parse(event.data);
    if (data.execution?.id === executionId) {
      callback(data.execution);
    }
  });
}

// ✅ GOOD: Store reference and remove listener
subscribeToExecution(executionId, callback) {
  const handler = (event) => {
    const data = JSON.parse(event.data);
    if (data.execution?.id === executionId) {
      callback(data.execution);
    }
  };

  this.listeners.set(executionId, handler);
  this.ws.addEventListener("message", handler);

  return () => {
    this.ws.removeEventListener("message", this.listeners.get(executionId));
    this.listeners.delete(executionId);
  };
}
```

**3. Infinite Reconnection Loop**

```javascript
// ❌ BAD: No limit on reconnection attempts
async attemptReconnect() {
  await this.sleep(1000);
  await this.connect();  // Can loop forever
}

// ✅ GOOD: Limit reconnection attempts
async attemptReconnect() {
  if (this.reconnectAttempts >= this.maxReconnectAttempts) {
    throw new Error("Max reconnection attempts reached");
  }

  this.reconnectAttempts++;
  const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
  await this.sleep(delay);
  await this.connect();
}
```

**4. Blocking Main Thread with Large Messages**

```javascript
// ❌ BAD: Parse large JSON on main thread
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);  // Blocks for large payloads
  this.handleMessage(data);
};

// ✅ GOOD: Parse in Web Worker or use streaming
ws.onmessage = async (event) => {
  const data = await this.parseInWorker(event.data);
  this.handleMessage(data);
};
```

**5. Not Validating Server Messages**

```javascript
// ❌ BAD: Trust all incoming messages
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  this.handlers[data.type](data);  // May crash if data.type is undefined
};

// ✅ GOOD: Validate message structure
ws.onmessage = (event) => {
  try {
    const data = JSON.parse(event.data);

    if (!data.type || typeof data.type !== "string") {
      console.error("Invalid message format");
      return;
    }

    const handler = this.handlers[data.type];
    if (handler) {
      handler(data);
    } else {
      console.warn("Unknown message type:", data.type);
    }
  } catch (error) {
    console.error("Failed to parse message:", error);
  }
};
```

## Error Handling

### Client-Side Errors

**Connection Errors**:

```javascript
ws.onerror = (error) => {
  console.error("WebSocket error:", error);

  // Check error type
  if (error.type === "error" && ws.readyState === WebSocket.CLOSED) {
    // Connection refused or network error
    console.log("Connection failed, will retry");
  }
};

ws.onclose = (event) => {
  console.log(`Connection closed: ${event.code} - ${event.reason}`);

  // Standard close codes
  if (event.code === 1000) {
    // Normal closure
    console.log("Clean disconnect");
  } else if (event.code === 1006) {
    // Abnormal closure (no close frame)
    console.log("Connection lost unexpectedly");
    this.attemptReconnect();
  } else if (event.code === 4401) {
    // Custom code: Authentication failed
    console.error("Authentication failed, not reconnecting");
  }
};
```

**Message Parsing Errors**:

```javascript
handleMessage(event) {
  let data;

  try {
    data = JSON.parse(event.data);
  } catch (error) {
    console.error("Failed to parse JSON:", error);
    return;
  }

  if (!this.validateMessage(data)) {
    console.error("Invalid message structure:", data);
    return;
  }

  this.routeMessage(data);
}

validateMessage(data) {
  return data && typeof data === "object" && typeof data.type === "string";
}
```

### Server-Side Errors

**Handle Invalid Subscriptions**:

```rust
async fn handle_client_message(
    msg: ClientMessage,
    state: &Arc<AppState>,
    claims: &Claims,
) -> Result<(), Error> {
    match msg {
        ClientMessage::Subscribe { resource, id } => {
            // Verify user has permission to subscribe
            if !has_permission(claims, &resource, &id).await? {
                return Err(Error::Unauthorized(
                    format!("Cannot subscribe to {}:{}", resource, id)
                ));
            }

            // Verify resource exists
            match resource.as_str() {
                "execution" => {
                    if !execution_exists(&state.db, &id).await? {
                        return Err(Error::NotFound(
                            format!("Execution '{}' not found", id)
                        ));
                    }
                }
                "workflow" => {
                    if !workflow_exists(&state.db, &id).await? {
                        return Err(Error::NotFound(
                            format!("Workflow '{}' not found", id)
                        ));
                    }
                }
                _ => {
                    return Err(Error::InvalidResource(resource));
                }
            }

            // Add to subscription list
            add_subscription(claims.sub, &resource, &id).await?;

            Ok(())
        }
        // ... other message types ...
    }
}
```

**Rate Limiting**:

```rust
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

struct RateLimiter {
    requests: Mutex<HashMap<String, Vec<Instant>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    async fn check_rate_limit(&self, user_id: &str) -> Result<(), Error> {
        let mut requests = self.requests.lock().await;
        let now = Instant::now();

        let user_requests = requests.entry(user_id.to_string()).or_insert_with(Vec::new);

        // Remove old requests outside the time window
        user_requests.retain(|&time| now.duration_since(time) < self.window);

        if user_requests.len() >= self.max_requests {
            return Err(Error::RateLimitExceeded(
                format!("Max {} requests per {:?}", self.max_requests, self.window)
            ));
        }

        user_requests.push(now);
        Ok(())
    }
}

// Usage in WebSocket handler
async fn handle_client_message(
    msg: ClientMessage,
    state: &Arc<AppState>,
    claims: &Claims,
) -> Result<(), Error> {
    // Check rate limit (e.g., 100 messages per minute)
    state.rate_limiter.check_rate_limit(&claims.sub).await?;

    // Process message
    // ...
}
```

## Testing WebSocket Connections

### Manual Testing with wscat

```bash
# Install wscat
npm install -g wscat

# Connect to WebSocket endpoint
wscat -c "ws://localhost:8000/api/v1/ws?token=YOUR_JWT_TOKEN"

# Send subscribe message
> {"type":"subscribe","resource":"execution","id":"exec_abc123"}

# Receive messages
< {"type":"subscribed","resource":"execution","id":"exec_abc123"}
< {"type":"execution_update","execution":{"id":"exec_abc123","status":"running",...}}

# Send ping
> {"type":"ping"}
< {"type":"pong"}

# Disconnect
> ^C
```

### Automated Integration Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_tungstenite::connect_async;
    use futures_util::{SinkExt, StreamExt};

    #[tokio::test]
    async fn test_websocket_connection_and_subscription() {
        // Start test server
        let server_handle = tokio::spawn(async {
            start_test_server().await;
        });

        // Wait for server to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Connect to WebSocket
        let jwt_token = generate_test_jwt();
        let url = format!("ws://localhost:8000/api/v1/ws?token={}", jwt_token);

        let (ws_stream, _) = connect_async(&url).await.expect("Failed to connect");
        let (mut write, mut read) = ws_stream.split();

        // Subscribe to execution
        let subscribe_msg = serde_json::json!({
            "type": "subscribe",
            "resource": "execution",
            "id": "exec_test_123"
        });

        write.send(Message::Text(subscribe_msg.to_string()))
            .await
            .expect("Failed to send");

        // Verify subscription confirmation
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let response: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(response["type"], "subscribed");
            assert_eq!(response["resource"], "execution");
            assert_eq!(response["id"], "exec_test_123");
        }

        // Simulate execution update
        trigger_execution_update("exec_test_123").await;

        // Verify we receive the update
        if let Some(Ok(Message::Text(text))) = read.next().await {
            let response: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(response["type"], "execution_update");
            assert_eq!(response["execution"]["id"], "exec_test_123");
        }

        server_handle.abort();
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let url = "ws://localhost:8000/api/v1/ws?token=invalid_token";

        let result = connect_async(&url).await;
        assert!(result.is_err(), "Should fail with invalid token");
    }

    #[tokio::test]
    async fn test_heartbeat_mechanism() {
        // ... connect to WebSocket ...

        // Send ping
        let ping_msg = serde_json::json!({ "type": "ping" });
        write.send(Message::Text(ping_msg.to_string())).await.unwrap();

        // Expect pong response within 5 seconds
        let timeout = tokio::time::timeout(
            Duration::from_secs(5),
            read.next()
        ).await;

        assert!(timeout.is_ok(), "Should receive pong within timeout");

        if let Ok(Some(Ok(Message::Text(text)))) = timeout {
            let response: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(response["type"], "pong");
        }
    }
}
```

## Complete Example: Real-time Workflow Execution Dashboard

### HTML + JavaScript Frontend

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Workflow Execution Dashboard</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .execution-card {
      border: 1px solid #ccc;
      padding: 15px;
      margin: 10px 0;
      border-radius: 5px;
    }
    .status { font-weight: bold; }
    .status.running { color: #0066cc; }
    .status.completed { color: #00aa00; }
    .status.failed { color: #cc0000; }
    .progress-bar {
      width: 100%;
      height: 20px;
      background: #f0f0f0;
      border-radius: 10px;
      overflow: hidden;
    }
    .progress-fill {
      height: 100%;
      background: #0066cc;
      transition: width 0.3s ease;
    }
    .log-entry {
      font-family: monospace;
      font-size: 12px;
      margin: 2px 0;
      padding: 4px;
      background: #f5f5f5;
    }
    .log-entry.info { border-left: 3px solid #0066cc; }
    .log-entry.warn { border-left: 3px solid #ff9900; }
    .log-entry.error { border-left: 3px solid #cc0000; }
    #connection-status {
      padding: 10px;
      margin-bottom: 20px;
      border-radius: 5px;
    }
    #connection-status.connected { background: #e0ffe0; }
    #connection-status.disconnected { background: #ffe0e0; }
  </style>
</head>
<body>
  <h1>Workflow Execution Dashboard</h1>

  <div id="connection-status" class="disconnected">
    <strong>Status:</strong> <span id="status-text">Disconnected</span>
  </div>

  <button id="connect-btn">Connect</button>
  <button id="execute-workflow-btn" disabled>Execute Workflow</button>

  <h2>Active Executions</h2>
  <div id="executions-container"></div>

  <script src="nebula-ws-client.js"></script>
  <script>
    let wsClient = null;
    const activeExecutions = new Map();

    document.getElementById("connect-btn").addEventListener("click", async () => {
      const token = prompt("Enter JWT token:");
      if (!token) return;

      wsClient = new NebulaWebSocketClient("ws://localhost:8000", token);

      try {
        await wsClient.connect();
        updateConnectionStatus(true);
        document.getElementById("execute-workflow-btn").disabled = false;
      } catch (error) {
        alert("Connection failed: " + error.message);
      }
    });

    document.getElementById("execute-workflow-btn").addEventListener("click", async () => {
      const workflowId = prompt("Enter workflow ID:");
      if (!workflowId) return;

      // Execute workflow via REST API
      const response = await fetch(`http://localhost:8000/api/v1/workflows/${workflowId}/execute`, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${wsClient.token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ input: {} })
      });

      const data = await response.json();
      const executionId = data.execution_id;

      // Subscribe to execution updates via WebSocket
      const unsubscribe = wsClient.subscribeToExecution(executionId, (execution) => {
        updateExecutionCard(execution);
      });

      wsClient.subscribeToLogs(executionId, (log) => {
        appendLog(executionId, log);
      });

      activeExecutions.set(executionId, { unsubscribe });
      createExecutionCard(executionId);
    });

    function updateConnectionStatus(connected) {
      const statusDiv = document.getElementById("connection-status");
      const statusText = document.getElementById("status-text");

      if (connected) {
        statusDiv.className = "connected";
        statusText.textContent = "Connected";
      } else {
        statusDiv.className = "disconnected";
        statusText.textContent = "Disconnected";
      }
    }

    function createExecutionCard(executionId) {
      const container = document.getElementById("executions-container");

      const card = document.createElement("div");
      card.className = "execution-card";
      card.id = `execution-${executionId}`;
      card.innerHTML = `
        <h3>Execution: ${executionId}</h3>
        <div><span class="status running">Status: running</span></div>
        <div class="progress-bar">
          <div class="progress-fill" style="width: 0%"></div>
        </div>
        <div class="progress-text">0%</div>
        <h4>Actions:</h4>
        <div class="actions-list"></div>
        <h4>Logs:</h4>
        <div class="logs-container"></div>
      `;

      container.appendChild(card);
    }

    function updateExecutionCard(execution) {
      const card = document.getElementById(`execution-${execution.id}`);
      if (!card) return;

      // Update status
      const statusEl = card.querySelector(".status");
      statusEl.textContent = `Status: ${execution.status}`;
      statusEl.className = `status ${execution.status}`;

      // Update progress bar
      const progressFill = card.querySelector(".progress-fill");
      const progressText = card.querySelector(".progress-text");
      const percentage = execution.progress.percentage;

      progressFill.style.width = `${percentage}%`;
      progressText.textContent = `${percentage}%`;

      // Update actions list
      const actionsList = card.querySelector(".actions-list");
      actionsList.innerHTML = "";

      for (const action of execution.actions_executed) {
        const actionDiv = document.createElement("div");
        actionDiv.innerHTML = `
          <strong>${action.name}</strong>: ${action.status}
          ${action.duration_ms ? ` (${action.duration_ms}ms)` : ""}
        `;
        actionsList.appendChild(actionDiv);
      }

      // Clean up if completed
      if (execution.status === "completed" || execution.status === "failed") {
        const executionData = activeExecutions.get(execution.id);
        if (executionData) {
          executionData.unsubscribe();
          activeExecutions.delete(execution.id);
        }
      }
    }

    function appendLog(executionId, log) {
      const card = document.getElementById(`execution-${executionId}`);
      if (!card) return;

      const logsContainer = card.querySelector(".logs-container");

      const logEntry = document.createElement("div");
      logEntry.className = `log-entry ${log.level}`;
      logEntry.textContent = `[${log.timestamp}] ${log.message}`;

      logsContainer.appendChild(logEntry);

      // Auto-scroll to bottom
      logsContainer.scrollTop = logsContainer.scrollHeight;
    }
  </script>
</body>
</html>
```

## Performance Considerations

### Connection Pooling

For high-traffic applications, implement connection pooling on the server:

```rust
use std::sync::Arc;
use dashmap::DashMap;

pub struct WebSocketConnectionPool {
    connections: Arc<DashMap<String, Vec<WebSocketConnection>>>,
}

impl WebSocketConnectionPool {
    pub fn add_connection(&self, user_id: String, conn: WebSocketConnection) {
        self.connections
            .entry(user_id)
            .or_insert_with(Vec::new)
            .push(conn);
    }

    pub async fn broadcast_to_user(&self, user_id: &str, message: &ServerMessage) {
        if let Some(connections) = self.connections.get(user_id) {
            let json = serde_json::to_string(message).unwrap();

            for conn in connections.iter() {
                let _ = conn.send(Message::Text(json.clone())).await;
            }
        }
    }
}
```

### Message Batching

Batch multiple events to reduce network overhead:

```rust
pub struct MessageBatcher {
    pending: Mutex<Vec<ServerMessage>>,
    batch_size: usize,
    batch_interval: Duration,
}

impl MessageBatcher {
    pub async fn add_message(&self, message: ServerMessage) {
        let mut pending = self.pending.lock().await;
        pending.push(message);

        if pending.len() >= self.batch_size {
            self.flush_messages(&mut pending).await;
        }
    }

    async fn flush_messages(&self, messages: &mut Vec<ServerMessage>) {
        if messages.is_empty() {
            return;
        }

        let batch = ServerMessage::Batch {
            messages: messages.drain(..).collect(),
        };

        // Send batched message
        self.send_to_clients(batch).await;
    }

    pub async fn start_periodic_flush(&self) {
        loop {
            tokio::time::sleep(self.batch_interval).await;
            let mut pending = self.pending.lock().await;
            self.flush_messages(&mut pending).await;
        }
    }
}
```

### Compression

Enable per-message compression for large payloads:

```rust
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

let ws_config = WebSocketConfig {
    max_message_size: Some(64 << 20),  // 64 MB
    max_frame_size: Some(16 << 20),    // 16 MB
    accept_unmasked_frames: false,
    compression: Some(flate2::Compression::default()),  // Enable compression
    ..Default::default()
};
```

## Related Documentation

- [[02-Crates/nebula-api/README|API Overview]] - Main API documentation
- [[02-Crates/nebula-api/Authentication|Authentication]] - JWT and API key authentication
- [[02-Crates/nebula-api/REST API|REST API]] - RESTful API endpoints
- [[02-Crates/nebula-api/GraphQL API|GraphQL API]] - GraphQL queries and subscriptions
- [[02-Crates/nebula-execution/README|Execution Engine]] - Workflow execution system
- [[02-Crates/nebula-workflow/README|Workflow Engine]] - Workflow definition and management
