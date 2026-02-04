---
title: Crates Overview
tags: [nebula, docs, crates]
status: published
created: 2025-08-17
last_updated: 2025-11-09
---

# Crates Overview

Nebula is built as a collection of focused Rust crates, each handling a specific aspect of the workflow automation system. This modular architecture allows you to use only what you need.

## Architecture Layers

Nebula's crates are organized into logical layers:

```
Application Layer
├── nebula-ui          (Web interface)
├── nebula-cli         (Command-line tool)
└── nebula-sdk         (Rust SDK)
         ↓
Workflow Layer
├── nebula-workflow    (Workflow definition and execution)
├── nebula-node        (Node management)
└── nebula-engine      (Execution engine)
         ↓
Action Layer
├── nebula-action      (Action framework)
├── nebula-hub         (Action registry)
└── nebula-registry    (Action catalog)
         ↓
Infrastructure Layer
├── nebula-credential  (Secret management)
├── nebula-parameter   (Parameter validation)
├── nebula-resource    (Resource pooling)
├── nebula-memory      (State management)
├── nebula-event       (Event bus)
└── nebula-expression  (Expression engine)
         ↓
Core Layer
├── nebula-core        (Core types and traits)
├── nebula-binary      (Serialization)
├── nebula-value       (Dynamic values)
└── nebula-derive      (Derive macros)
         ↓
Integration Layer
├── nebula-api         (REST/GraphQL/WebSocket)
├── nebula-runtime     (Runtime management)
├── nebula-worker      (Distributed workers)
├── nebula-storage     (Persistence)
└── nebula-idempotency (Idempotency tracking)
```

## Core Crates

These are the foundational crates used by most Nebula applications:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-core** | Core types, traits, and error handling | Stable | [[02-Crates/nebula-core/README\|README]] |
| **nebula-action** | Action trait and lifecycle management | Stable | [[02-Crates/nebula-action/README\|README]] |
| **nebula-workflow** | Workflow definition and execution | Stable | [[02-Crates/nebula-workflow/README\|README]] |
| **nebula-credential** | Credential storage and injection | Stable | [[02-Crates/nebula-credential/README\|README]] |
| **nebula-parameter** | Type-safe parameter validation | Stable | [[02-Crates/nebula-parameter/README\|README]] |

## Infrastructure Crates

Supporting services for action execution:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-resource** | Resource pooling (DB, HTTP clients) | Stable | [[02-Crates/nebula-resource/README\|README]] |
| **nebula-memory** | Workflow-scoped state management | Stable | [[02-Crates/nebula-memory/README\|README]] |
| **nebula-event** | Event bus for pub/sub | Beta | [[02-Crates/nebula-event/README\|README]] |
| **nebula-expression** | Expression language runtime | Stable | [[02-Crates/nebula-expression/README\|README]] |
| **nebula-idempotency** | Idempotency key tracking | Beta | [[02-Crates/nebula-idempotency/README\|README]] |

## Execution & Runtime Crates

Workflow execution and distributed processing:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-engine** | Workflow execution engine | Stable | [[02-Crates/nebula-engine/README\|README]] |
| **nebula-runtime** | Runtime environment management | Stable | [[02-Crates/nebula-runtime/README\|README]] |
| **nebula-worker** | Distributed worker nodes | Beta | [[02-Crates/nebula-worker/README\|README]] |
| **nebula-node** | Node lifecycle management | Stable | [[02-Crates/nebula-node/README\|README]] |

## API & Integration Crates

External interfaces and protocols:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-api** | REST, GraphQL, WebSocket APIs | Beta | [[02-Crates/nebula-api/README\|README]] |
| **nebula-storage** | Workflow and execution persistence | Beta | [[02-Crates/nebula-storage/README\|README]] |
| **nebula-cli** | Command-line interface | Stable | [[02-Crates/nebula-cli/README\|README]] |
| **nebula-sdk** | Rust SDK for building workflows | Stable | [[02-Crates/nebula-sdk/README\|README]] |

## Developer Tools

Utilities for action and workflow development:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-derive** | Derive macros for actions/parameters | Stable | [[02-Crates/nebula-derive/README\|README]] |
| **nebula-binary** | Efficient binary serialization | Stable | [[02-Crates/nebula-binary/README\|README]] |
| **nebula-value** | Dynamic value system | Stable | [[02-Crates/nebula-value/README\|README]] |
| **nebula-ui** | Web-based workflow editor | Alpha | [[02-Crates/nebula-ui/README\|README]] |

## Registry & Catalog

Action discovery and management:

| Crate | Purpose | Status | Documentation |
|-------|---------|--------|---------------|
| **nebula-hub** | Centralized action registry | Beta | [[02-Crates/nebula-hub/README\|README]] |
| **nebula-registry** | Action catalog and versioning | Beta | [[02-Crates/nebula-registry/README\|README]] |

## Quick Decision Guide

**Which crate do I need?**

| I want to... | Use this crate | Start here |
|-------------|----------------|------------|
| Build a custom action | `nebula-action` | [[Creating Actions]] |
| Manage credentials | `nebula-credential` | [[02-Crates/nebula-credential/README\|nebula-credential]] |
| Validate parameters | `nebula-parameter` | [[02-Crates/nebula-parameter/README\|nebula-parameter]] |
| Define workflows | `nebula-workflow` + `nebula-sdk` | [[Building Workflows]] |
| Store state between actions | `nebula-memory` | [[02-Crates/nebula-memory/README\|nebula-memory]] |
| Handle events | `nebula-event` | [[02-Crates/nebula-event/README\|nebula-event]] |
| Expose REST/GraphQL APIs | `nebula-api` | [[02-Crates/nebula-api/README\|nebula-api]] |
| Use workflow expressions | `nebula-expression` | [[Using Expressions]] |
| Pool resources (DB, HTTP) | `nebula-resource` | [[02-Crates/nebula-resource/README\|nebula-resource]] |
| Run workflows via CLI | `nebula-cli` | [[02-Crates/nebula-cli/README\|nebula-cli]] |

## Dependency Relationships

Some crates depend on others. Here's a simplified view:

```
nebula-action
  ├─ nebula-core (types, traits)
  ├─ nebula-parameter (input validation)
  ├─ nebula-credential (secret access)
  └─ nebula-derive (macros)

nebula-workflow
  ├─ nebula-action (action execution)
  ├─ nebula-memory (state)
  ├─ nebula-event (events)
  └─ nebula-expression (expressions)

nebula-api
  ├─ nebula-workflow (workflow execution)
  ├─ nebula-credential (auth)
  └─ nebula-storage (persistence)

nebula-sdk
  ├─ nebula-workflow (workflow building)
  └─ nebula-action (action registration)
```

See [[Dependencies Graph]] for the complete dependency tree.

## Status Definitions

- **Stable** — Production-ready, API stable, well-documented
- **Beta** — Functional but API may change, documentation in progress
- **Alpha** — Early development, expect breaking changes
- **Experimental** — Prototype, not recommended for production

## Getting Started with Crates

1. **New to Nebula?** Start with [[02-Crates/nebula-action/README|nebula-action]] to understand the action model
2. **Building workflows?** Explore [[02-Crates/nebula-workflow/README|nebula-workflow]] and [[02-Crates/nebula-sdk/README|nebula-sdk]]
3. **Need API access?** Check [[02-Crates/nebula-api/README|nebula-api]]
4. **Production deployment?** Review [[02-Crates/nebula-credential/README|nebula-credential]], [[02-Crates/nebula-storage/README|nebula-storage]], and [[07-Advanced/Deployment|Deployment]]

## See Also

- [[Dependencies Graph]] — Visual dependency tree
- [[Architecture Overview]] — High-level system design
- [[Getting Started]] — Build your first action
- [[04-Development/_Index|Development Guides]] — Development best practices
