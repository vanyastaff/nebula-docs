---
title: Built-in Actions (Detailed)
tags: [nebula, nebula-action, crate, docs, deep]
status: draft
created: 2025-08-17
---

# Built-in Actions (Detailed)

This section documents **bundled** actions with full contracts.

## `http.request` — HTTP Request
**Purpose:** Perform HTTP call with timeout, headers, JSON body.  
**Type:** ProcessAction

### Parameters
| Field | Type | Default | Notes |
|---|---|---:|---|
| `url` | string | — | Absolute URL |
| `method` | enum(`GET`,`POST`,`PUT`,`DELETE`,`PATCH`) | `GET` | Uppercased |
| `headers` | map<string,string> | `{}` | No sensitive values in logs |
| `body` | any | `null` | JSON-serializable |
| `timeout_ms` | u32 | `10000` | Per-request timeout |

### Output (JSON)
```json
{ "status": 200, "headers": { "content-type": "application/json" }, "body": { }, "elapsed_ms": 12 }
```

### Errors
- `InvalidInput.method`
- `Timeout`
- `ExternalServiceError{ service:"http" }`

---

## `pg.supply` — PostgreSQL Supplier
**Purpose:** Provide a connection pool for downstream actions.  
**Type:** SupplyAction

### Parameters
| Field | Type | Default | Notes |
|---|---|---:|---|
| `dsn` | string | — | Postgres DSN |
| `max_connections` | u32 | 10 | Pool size |
| `idle_timeout_ms` | u32 | 30000 | Idle close |

### Resource
`PoolHandle` (opaque)

### Health
- `SELECT 1` within 500ms → Healthy

---

## `kafka.trigger` — Kafka Consumer Trigger
**Purpose:** Emit events from Kafka topic/group.  
**Type:** TriggerAction

### Parameters
| Field | Type | Notes |
|---|---|---|
| `brokers` | string[] | bootstrap servers |
| `topic` | string | topic name |
| `group_id` | string | consumer group |
| `offset_reset` | enum(`earliest`,`latest`) | on missing offset |

### Event
```json
{ "key": "abc", "payload": { "...": "..." }, "offset": 12345, "partition": 0 }
```

### Semantics
- At-least-once delivery with offsets in durable store
- Idempotency key: `${partition}:${offset}`
