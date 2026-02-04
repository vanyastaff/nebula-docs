# Feature Specification: Improve nebula-credential Documentation

**Feature Branch**: `001-credential-docs`  
**Created**: 2026-02-03  
**Status**: Draft  
**Input**: User description: "напиши документацию и поправь текущие в крейте nebula-credential изучив другие проекты"

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Getting Started with Credentials (Priority: P1)

A new Nebula user wants to understand how to securely store and use credentials (API keys, passwords, OAuth tokens) in their first workflow without exposing secrets in logs or code.

**Why this priority**: This is the entry point for all credential usage. Without a clear getting started guide, users will struggle with basic security or resort to insecure hardcoded credentials. This directly impacts security posture and user adoption.

**Independent Test**: User can read the "Getting Started" page, copy a simple code example, store their first credential (e.g., API key), and retrieve it in an action without seeing it in logs. Success = working code in under 10 minutes.

**Acceptance Scenarios**:

1. **Given** a user has never used nebula-credential before, **When** they read the Quick Start guide, **Then** they understand what credentials are, why they're needed, and see a complete minimal example
2. **Given** a user wants to store an API key, **When** they follow the "Store Your First Credential" tutorial, **Then** they successfully store it encrypted and can retrieve it in an action
3. **Given** a user accidentally logs a credential, **When** the credential is marked with `#[secret]`, **Then** it appears as `[REDACTED]` in logs instead of plaintext
4. **Given** a user has stored a credential, **When** they try to access it from a different scope (unauthorized workflow), **Then** they receive a clear error message explaining scope violations

---

### User Story 2 - Common Credential Patterns (Priority: P1)

A developer needs to implement OAuth2 authentication, database connections, or AWS service integration and wants to follow best practices with working examples.

**Why this priority**: These are the most common real-world use cases. Without clear examples, users will implement credentials incorrectly, leading to security vulnerabilities or brittle systems. OAuth2 and database credentials are particularly error-prone.

**Independent Test**: User can navigate to the "Examples" section, find OAuth2/Database/AWS credential examples, copy the code, adapt it to their provider, and have working credential management with automatic refresh.

**Acceptance Scenarios**:

1. **Given** a user needs OAuth2 integration (GitHub, Google, etc.), **When** they read the OAuth2 example, **Then** they understand the full flow: initial auth, token storage, automatic refresh, and scope management
2. **Given** a user connects to PostgreSQL/MySQL, **When** they follow the database credential example, **Then** they securely store connection strings, use connection pooling, and handle rotation
3. **Given** a user works with AWS services, **When** they use the AWS credential example, **Then** they store access keys securely, support AssumeRole, and handle temporary session tokens
4. **Given** a user's OAuth token is expiring, **When** the system detects expiration within 5 minutes, **Then** it automatically refreshes the token without workflow interruption

---

### User Story 3 - Credential Rotation (Priority: P2)

An operations engineer needs to rotate credentials (passwords, API keys, certificates) regularly for compliance without breaking running workflows.

**Why this priority**: Credential rotation is a compliance requirement (PCI DSS, SOC2, HIPAA) but complex to implement safely. This enables zero-downtime rotation which is critical for production systems.

**Independent Test**: User can follow the "Credential Rotation Guide," implement a rotation policy (periodic/before-expiry/scheduled), test rotation in staging, and verify no workflow downtime occurs.

**Acceptance Scenarios**:

1. **Given** a user wants to rotate credentials every 90 days, **When** they configure a periodic rotation policy, **Then** the system automatically rotates and workflows seamlessly transition to new credentials
2. **Given** an OAuth2 token expires in 10 minutes, **When** a before-expiry rotation policy is active, **Then** the system proactively refreshes the token before workflows fail
3. **Given** a user rotates a database password, **When** they use the blue-green rotation pattern, **Then** both old and new credentials work during a grace period, then old credentials are revoked
4. **Given** a rotation fails (network error, invalid new credentials), **When** the system detects failure, **Then** it rolls back to the previous credential and alerts the operator

---

### User Story 4 - Multi-Provider Storage (Priority: P2)

A platform engineer deploying Nebula in production needs to integrate with existing secret management infrastructure (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Kubernetes Secrets) instead of local storage.

**Why this priority**: Production deployments require enterprise secret management for compliance, audit trails, and centralized control. This enables Nebula to integrate with existing infrastructure.

**Independent Test**: User can read provider-specific integration guides (AWS/Vault/Azure/K8s), configure their provider, migrate credentials from local storage, and verify all workflows continue working.

**Acceptance Scenarios**:

1. **Given** a user has AWS Secrets Manager deployed, **When** they configure the AWS provider, **Then** Nebula stores and retrieves credentials via AWS without local storage
2. **Given** a user has HashiCorp Vault with Transit engine, **When** they configure the Vault provider, **Then** Vault handles all encryption/decryption operations
3. **Given** a user deploys on Kubernetes, **When** they configure the K8s Secrets provider, **Then** credentials are stored as Kubernetes secrets with RBAC enforcement
4. **Given** a user migrates from local to AWS KMS storage, **When** they run the migration command, **Then** all existing credentials are re-encrypted and moved without data loss

---

### User Story 5 - Security Hardening (Priority: P3)

A security engineer auditing Nebula needs to understand encryption mechanisms, key management, audit logging, and security best practices to ensure compliance with security standards (SOC2, ISO 27001, NIST).

**Why this priority**: Security audits require detailed technical documentation. While important for compliance, this is lower priority than getting basic credentials working. This enables passing security audits and certifications.

**Independent Test**: Security engineer can read the "Security Architecture" and "Encryption Deep Dive" documents, understand AES-256-GCM implementation, verify key management practices, and confirm compliance with security frameworks.

**Acceptance Scenarios**:

1. **Given** a security auditor asks "How are credentials encrypted?", **When** they read the encryption documentation, **Then** they understand AES-256-GCM with unique nonces, key derivation, and storage separation
2. **Given** an auditor asks "How is key rotation handled?", **When** they read the key management docs, **Then** they understand key versioning, automatic re-encryption, and HSM integration
3. **Given** an auditor needs an audit trail, **When** they review audit logging documentation, **Then** they find logs for all credential access with user ID, timestamp, and operation type
4. **Given** a security engineer wants to harden production, **When** they follow the security best practices guide, **Then** they configure HSM key storage, enable audit logging, and enforce scope isolation

---

### User Story 6 - Troubleshooting & Debugging (Priority: P3)

A developer encounters a credential-related error (decryption failure, expired token, scope violation, rotation failure) and needs to diagnose and fix the issue quickly.

**Why this priority**: Errors will happen in production. Clear troubleshooting documentation reduces mean time to recovery (MTTR). This is P3 because it's reactive (needed after problems occur) rather than proactive.

**Independent Test**: User encounters a common error, searches documentation or error message, finds relevant troubleshooting section, follows diagnostic steps, and resolves the issue.

**Acceptance Scenarios**:

1. **Given** a user sees "DecryptionFailed" error, **When** they check the troubleshooting guide, **Then** they understand possible causes (wrong key, corrupted data, key rotation) and resolution steps
2. **Given** a user's OAuth2 refresh fails with 401, **When** they follow the OAuth2 troubleshooting section, **Then** they implement retry logic with exponential backoff
3. **Given** a user gets "CredentialNotFound" error, **When** they use the debug checklist, **Then** they verify credential name, scope, and storage backend configuration
4. **Given** a user's credential rotation fails, **When** they read rotation troubleshooting, **Then** they enable detailed logging, identify the failure point, and apply fixes

---

### Edge Cases

- What happens when a credential provider (AWS KMS, Vault) is temporarily unavailable during credential access?
- How does the system handle credentials that have already expired when accessed?
- What occurs when storage backends contain credentials encrypted with old keys after multiple rotations?
- How are credentials handled when multiple workflows attempt to rotate the same credential simultaneously?
- What happens when a user tries to access a credential from a scope they don't have permission for?
- How does the system behave when decryption fails due to corrupted data or key mismatch?

## Clarifications

### Session 2026-02-03

- Q: What level of observability and monitoring is required for credential management in production deployments? → A: Comprehensive audit logging with metrics - Log all credential access (who, when, which credential, result), rotation events, and failures. Export metrics for latency, error rates, cache hit ratio. Structured logs with correlation IDs for tracing.

## Requirements *(mandatory)*

### Architectural Requirements

#### Core Type System

- **AR-001**: System MUST implement a trait hierarchy with base `Credential` trait providing `authenticate()`, `validate()`, and `refresh()` methods using async trait with Generic Associated Types (GATs)
- **AR-002**: System MUST support `InteractiveCredential` trait extending `Credential` for multi-step authentication flows (OAuth2, SAML) with `initialize()` and `resume()` methods
- **AR-003**: System MUST support `RotatableCredential` trait extending `Credential` for credentials requiring periodic rotation with configurable rotation policies
- **AR-004**: System MUST implement zero-copy `SecretString` type with `Zeroize` and `ZeroizeOnDrop` traits to prevent sensitive data from remaining in memory after use
- **AR-005**: System MUST use type-state pattern with `PhantomData<State>` for compile-time enforcement of credential lifecycle states (Uninitialized, PendingInteraction, Authenticating, Active, Expired, Rotating, GracePeriod, Revoked, Invalid)
- **AR-006**: System MUST provide builder patterns for all configuration types (CredentialConfig, StorageConfig, EncryptionConfig) with fluent APIs and compile-time validation

#### Authentication Protocol Support

- **AR-007**: System MUST support OAuth 2.0 with all grant types: Authorization Code + PKCE (RFC 7636), Client Credentials, Device Code (RFC 8628), and Refresh Token flows
- **AR-008**: System MUST support SAML 2.0 authentication with XML signature validation (RSA-SHA256, ECDSA-SHA256), assertion decryption, and attribute extraction
- **AR-009**: System MUST support LDAP/Active Directory authentication with connection pooling, TLS encryption (StartTLS/LDAPS), and LDAP injection prevention via DN/filter escaping
- **AR-010**: System MUST support mutual TLS (mTLS) authentication with X.509 certificate validation, CRL/OCSP checking, and client certificate presentation
- **AR-011**: System MUST support JWT (JSON Web Token) authentication with HS256/RS256/ES256 algorithms, claims validation (exp, nbf, aud, iss), and key rotation support
- **AR-012**: System MUST support API Key authentication with BLAKE3 hashing for storage, rate limiting per key, and key rotation without service interruption
- **AR-013**: System MUST support Kerberos authentication with TGT (Ticket Granting Ticket) acquisition, service ticket retrieval, and credential cache management

#### Cryptographic Security

- **AR-014**: System MUST use AES-256-GCM for symmetric encryption of credentials at rest with unique 96-bit nonces per encryption operation
- **AR-015**: System MUST use Argon2id for key derivation from master passwords with parameters: memory cost 19 MiB, time cost 2 iterations, parallelism 1 thread
- **AR-016**: System MUST use BLAKE3 for cryptographic hashing with keyed mode support and 32-byte output length
- **AR-017**: System MUST implement nonce generation with collision prevention: monotonic counter + random component + timestamp, checking last 1000 nonces
- **AR-018**: System MUST support key rotation with versioned keys: EncryptionKey contains version field, multiple key versions active simultaneously during rotation grace period
- **AR-019**: System MUST implement constant-time comparison for secrets using `subtle` crate to prevent timing attacks

#### Storage Architecture

- **AR-020**: System MUST implement `StorageProvider` trait supporting multiple backends: Local (SQLite), AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Kubernetes Secrets
- **AR-021**: System MUST encrypt credentials before storage using AES-256-GCM with metadata stored separately from encrypted payload
- **AR-022**: System MUST implement write-through caching with TTL-based expiration (default 5 minutes) and LRU eviction policy
- **AR-023**: System MUST support batch operations: `store_batch()`, `retrieve_batch()`, `delete_batch()` for efficient multi-credential operations
- **AR-024**: System MUST implement distributed locking using Redlock algorithm for concurrent credential rotation across multiple instances
- **AR-025**: System MUST support credential migration between storage providers with zero downtime and rollback capability

#### Access Control & Scoping

- **AR-026**: System MUST implement ownership model: every credential has single owner (user/service account) with non-transferable ownership
- **AR-027**: System MUST implement Access Control Lists (ACLs) with 6 permission types: Read, Write, Delete, Rotate, Grant (modify ACL), Execute (use credential)
- **AR-028**: System MUST enforce scope isolation: credentials scoped to workflow/organization/global with hierarchical access validation
- **AR-029**: System MUST implement privilege escalation prevention: operations requiring elevated privileges use separate authentication flow with audit logging
- **AR-030**: System MUST validate ACL consistency on every access: owner permissions cannot be revoked, Grant permission requires existing Grant permission

#### Credential Lifecycle Management

- **AR-031**: System MUST implement 11-state lifecycle state machine with validated transitions: Uninitialized → PendingInteraction → Authenticating → Active → {Expired, Rotating} → GracePeriod → {Active, Revoked}
- **AR-032**: System MUST support automatic credential refresh before expiration: configurable threshold (default 5 minutes before expiry) triggers proactive refresh
- **AR-033**: System MUST implement blue-green rotation pattern: both old and new credentials valid during grace period (configurable, default 24 hours), then old credential revoked
- **AR-034**: System MUST support rotation policies: periodic (fixed interval), before-expiry (based on TTL), scheduled (cron expression), manual (explicit trigger)
- **AR-035**: System MUST implement rotation failure handling: automatic rollback to previous credential, alerting, retry with exponential backoff (max 5 attempts)
- **AR-036**: System MUST provide credential testing capability: `CredentialTest` trait with `test()` method for on-demand validation like n8n

#### Observability & Audit

- **AR-037**: System MUST implement comprehensive audit logging with 10 event types: CredentialAccessed, CredentialCreated, CredentialUpdated, CredentialDeleted, CredentialRotated, CredentialRefreshed, AuthenticationAttempt, DecryptionFailed, ScopeViolation, PermissionDenied
- **AR-038**: System MUST log structured events with fields: event_id (UUID), timestamp (RFC3339), user_id, credential_id, operation, result (success/failure), duration_ms, metadata (JSON)
- **AR-039**: System MUST implement correlation IDs for distributed tracing: propagate trace_id and span_id across all credential operations
- **AR-040**: System MUST export Prometheus metrics: credential_access_duration_seconds (histogram, p50/p95/p99), credential_operations_total (counter by operation/result), credential_cache_hit_ratio (gauge), credential_rotation_failures_total (counter)
- **AR-041**: System MUST support OpenTelemetry integration for traces: span creation for authenticate/refresh/rotate operations with attributes (credential_type, provider, scope)

#### Error Handling & Resilience

- **AR-042**: System MUST implement comprehensive error hierarchy using `thiserror`: CredentialError (top-level), StorageError, CryptoError, OAuth2Error, SamlError, LdapError, MtlsError, JwtError, ApiKeyError, KerberosError
- **AR-043**: System MUST implement retry logic with exponential backoff for transient failures: network errors, provider timeouts, rate limiting (max 5 retries, initial delay 100ms, multiplier 2.0)
- **AR-044**: System MUST implement circuit breaker pattern for provider communication: open circuit after 5 consecutive failures, half-open after 30 seconds, close after 3 successful requests
- **AR-045**: System MUST provide detailed error context: error chain with causes, operation context (credential_id, operation type), retry information (attempt number, will_retry)
- **AR-046**: System MUST handle provider unavailability gracefully: fallback to cached credentials (if policy allows), queue operations for retry, emit degraded-service metrics

#### Security Requirements

- **AR-047**: System MUST implement threat mitigations for 10 identified threats: credential theft via storage (AES-256-GCM), key compromise (key rotation), MITM (TLS 1.3), replay attacks (nonce/timestamp), privilege escalation (ACL validation), timing attacks (constant-time comparison), DoS (rate limiting), log exposure (SecretString redaction), supply chain (dependency scanning), side-channel (cache-timing prevention)
- **AR-048**: System MUST enforce TLS 1.3 for all network communication with cipher suite restrictions: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 only
- **AR-049**: System MUST implement rate limiting per credential: max 100 requests/minute per credential_id, adaptive rate limiting based on failure rate
- **AR-050**: System MUST implement defense in depth: encryption at rest (AES-256-GCM), encryption in transit (TLS 1.3), memory protection (zeroization), access control (ACLs), audit logging (all operations)
- **AR-051**: System MUST support HSM integration for key storage: PKCS#11 interface for encryption keys, master key stored in HSM never exposed to application memory

#### Compliance & Standards

- **AR-052**: System MUST meet SOC 2 Type II requirements: access controls (AC-01 to AC-04), encryption (CC-01 to CC-03), audit logging (CC-04, CC-05), availability (CC-06)
- **AR-053**: System MUST meet ISO 27001:2013 requirements: encryption (A.10.1.1, A.10.1.2), access control (A.9.2.1 to A.9.2.6), audit (A.12.4.1 to A.12.4.3)
- **AR-054**: System MUST meet HIPAA requirements: encryption (164.312(a)(2)(iv)), access controls (164.312(a)(1)), audit (164.312(b)), integrity (164.312(c)(1))
- **AR-055**: System MUST meet GDPR requirements: encryption (Article 32), access logging (Article 30), breach notification (Article 33/34 within 72 hours)
- **AR-056**: System MUST implement credential retention policies: configurable retention period (default 90 days after revocation), automatic deletion after retention period, audit log retention (7 years)

#### Performance & Scalability

- **AR-057**: System MUST achieve latency targets: credential retrieval < 10ms (p95, cache hit), < 100ms (p95, cache miss), encryption/decryption < 5ms (p95)
- **AR-058**: System MUST support throughput targets: 10,000 credential operations/second per instance, linear scalability to 100,000 ops/sec with horizontal scaling
- **AR-059**: System MUST implement connection pooling: database connections (max 100 per instance), HTTP client connections (max 200 per provider), LDAP connections (max 50 per directory)
- **AR-060**: System MUST implement memory efficiency: credential cache max size 1GB, LRU eviction when limit reached, lazy deserialization for large credentials
- **AR-061**: System MUST support concurrent access: lock-free reads from cache, optimistic concurrency control for updates using CAS operations, distributed locking for rotation

#### Testing & Validation

- **AR-062**: System MUST implement `CredentialTest` trait for all credential types: test() method validates credential by making real authentication attempt to provider
- **AR-063**: System MUST support 4 testing strategies: on-save (validate before storing, n8n default), on-load (validate after retrieval), on-demand (manual test trigger), background (periodic health checks every 5 minutes)
- **AR-064**: System MUST provide test result types: TestResult enum with Success, Failure(error), PartialSuccess(warnings), including test duration and metadata
- **AR-065**: System MUST implement security testing: unit tests for constant-time comparison, OAuth2 PKCE validation, SAML signature verification, LDAP injection prevention, SQL injection prevention
- **AR-066**: System MUST support penetration testing scenarios: authentication bypass attempts, privilege escalation attempts, encryption breaking attempts, MITM simulation, DoS load testing

### Functional Requirements

#### Documentation Structure

- **FR-001**: Documentation MUST provide a "Quick Start" tutorial that takes a new user from zero to storing and retrieving their first credential in under 10 minutes
- **FR-002**: Documentation MUST include a "Core Concepts" section explaining what credentials are, why they're needed, and how Nebula's credential system differs from environment variables or hardcoded secrets
- **FR-003**: Documentation MUST provide complete working code examples for common credential types: API keys, OAuth2, database connections, AWS credentials, and certificates
- **FR-004**: Documentation MUST include a dedicated "How-To Guides" section covering: storing credentials, retrieving credentials, rotating credentials, configuring providers, and troubleshooting errors
- **FR-005**: Documentation MUST provide architecture documentation explaining: encryption (AES-256-GCM), key management, provider system, caching strategy, and rotation mechanism

#### Content Quality

- **FR-006**: All code examples MUST be complete, runnable, and tested (not pseudocode fragments)
- **FR-007**: Code examples MUST include prerequisites (dependencies, required imports, configuration), expected output, and common errors with solutions
- **FR-008**: Security-critical topics (encryption, key management, secrets handling) MUST include warnings about anti-patterns and common vulnerabilities
- **FR-009**: Documentation MUST use consistent terminology aligned with industry standards (OAuth2 RFC, NIST encryption guidelines, AWS/Vault/K8s terminology)
- **FR-010**: Documentation MUST follow the Nebula documentation constitution principles: Obsidian wikilinks, frontmatter metadata, progressive disclosure, bilingual RU/EN support

#### Integration Documentation

- **FR-011**: Documentation MUST provide setup guides for each storage provider: Local (development), AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Kubernetes Secrets
- **FR-012**: Each provider guide MUST include: installation/configuration steps, authentication setup, migration from other providers, and provider-specific best practices
- **FR-013**: Documentation MUST include OAuth2 flow examples for popular providers: GitHub, Google, Microsoft, generic OAuth2
- **FR-014**: Documentation MUST include database credential examples for: PostgreSQL, MySQL, MongoDB, Redis with connection pooling and rotation

#### Troubleshooting & Reference

- **FR-015**: Documentation MUST include a troubleshooting guide with common errors: DecryptionFailed, CredentialNotFound, RefreshFailed, ScopeViolation, RotationFailed
- **FR-016**: Each error scenario MUST include: error message, possible causes, diagnostic steps, and resolution procedures
- **FR-017**: Documentation MUST provide an API reference for all public types, traits, and functions with rustdoc comments and usage examples
- **FR-018**: Documentation MUST include a "Security Best Practices" guide covering: key storage (HSM vs file), rotation policies, audit logging, scope isolation, and compliance considerations

#### Learning Paths

- **FR-019**: Documentation MUST support multiple learning paths: beginner (getting started), intermediate (common patterns), advanced (security hardening, custom providers)
- **FR-020**: Documentation MUST use visual aids: architecture diagrams (Mermaid), sequence diagrams for OAuth2 flows, state machines for credential lifecycle
- **FR-021**: Documentation MUST include cross-references between related topics using Obsidian wikilinks (e.g., OAuth2 example links to rotation guide, encryption architecture, provider configuration)

#### Observability & Monitoring

- **FR-022**: Documentation MUST include a comprehensive observability guide covering audit logging, metrics collection, and tracing for credential operations
- **FR-023**: Audit logging documentation MUST specify what to log: credential access (user/workflow ID, credential name, timestamp, operation type, result success/failure), rotation events (start, completion, failure), and security violations (unauthorized access attempts, decryption failures)
- **FR-024**: Documentation MUST provide examples of structured logging formats with correlation IDs for distributed tracing across credential operations
- **FR-025**: Metrics documentation MUST cover key operational metrics: credential access latency (p50, p95, p99), error rates by operation type, cache hit ratio, rotation success/failure rates, and concurrent access patterns
- **FR-026**: Documentation MUST explain how to integrate credential metrics with standard observability platforms (Prometheus, Grafana, CloudWatch, Datadog) including example configuration and dashboard templates

### Key Entities

- **Documentation Page**: Represents a single documentation file (markdown) with frontmatter metadata, status, tags, language, and wikilinks to related pages
- **Code Example**: Complete, runnable code snippet demonstrating a specific credential pattern with prerequisites, imports, expected output, and error handling
- **Tutorial/Guide**: Step-by-step instructional content with numbered steps, screenshots/diagrams, and verification checkpoints
- **API Reference**: Technical reference documentation for Rust types, traits, functions with rustdoc comments, type signatures, and usage examples
- **Troubleshooting Entry**: Error scenario documentation with error message, root causes, diagnostic commands, and resolution steps

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: New users can store and retrieve their first credential in under 10 minutes following the Quick Start guide (measurable via user testing or support ticket analysis)
- **SC-002**: 90% of common credential use cases (API key, OAuth2, database, AWS) are covered by working code examples that users can copy-paste and adapt
- **SC-003**: Security documentation passes review by a qualified security engineer and addresses all requirements for SOC2/ISO 27001 compliance audits
- **SC-004**: Support tickets or community questions related to credential management decrease by 50% after documentation improvements (measured over 3 months)
- **SC-005**: All documentation pages follow Nebula constitution standards: 100% have valid frontmatter, wikilinks resolve correctly, no orphan pages exist
- **SC-006**: Documentation receives positive feedback from 5+ beta testers representing different user personas (beginners, developers, security engineers, platform engineers)
- **SC-007**: Average time to resolve credential-related issues decreases by 40% due to improved troubleshooting documentation (measured via support metrics)
- **SC-008**: Zero critical security vulnerabilities in documentation code examples (verified via security code review)
- **SC-009**: Documentation successfully guides users through zero-downtime credential rotation without requiring expert assistance
- **SC-010**: All provider integration guides (AWS, Vault, Azure, K8s) are validated by successfully deploying Nebula with each provider
- **SC-011**: Observability documentation enables users to set up comprehensive audit logging and metrics collection within 30 minutes (verified via user testing)
- **SC-012**: Production deployments following the observability guide successfully pass SOC2/ISO 27001 audit requirements for credential access logging (verified via compliance audit or security review)

---

## Assumptions

1. Users have basic Rust knowledge (can understand trait bounds, async/await, Result types)
2. Obsidian is the primary documentation platform (vault is already structured with wikilinks and frontmatter)
3. English technical terminology is preferred even in Russian documentation (e.g., "OAuth2" не translated as "OAuth2", "credentials" as "учётные данные (credentials)")
4. Code examples target the latest stable Rust version and nebula-credential API
5. Documentation follows existing Nebula crates' documentation patterns (similar structure to nebula-action, nebula-workflow docs)
6. Users deploying in production already have infrastructure for secret management (AWS KMS, Vault, etc.) or can deploy it
7. Mermaid diagram syntax is preferred for visual diagrams (architecture, flows, state machines) as it's text-based and version control friendly

---

## Out of Scope

- Implementation of new nebula-credential features (only documenting existing functionality)
- Translation of all documentation to English (only P1 pages will be bilingual)
- Video tutorials or interactive learning environments (text-based documentation only)
- Documentation for deprecated or experimental APIs
- Third-party credential provider implementations beyond the core five (AWS, Vault, Azure, K8s, Local)
