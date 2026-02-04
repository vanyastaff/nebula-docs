# Implementation Plan: Improve nebula-credential Documentation

**Branch**: `001-credential-docs` | **Date**: 2026-02-03 | **Spec**: [[spec.md|Feature Specification]]  
**Input**: Feature specification from `/specs/001-credential-docs/spec.md`

## Summary

Improve and expand documentation for the `nebula-credential` crate by creating comprehensive guides, working code examples, and troubleshooting resources. The primary requirements are:

1. **Quick Start Tutorial** (<10 minutes for new users to store/retrieve first credential)
2. **Common Patterns** (OAuth2, Database, AWS credentials with complete examples)
3. **How-To Guides** (credential rotation, provider configuration, troubleshooting)
4. **Security Documentation** (encryption, key management, audit logging, compliance)
5. **Provider Integration** (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Kubernetes Secrets)

Technical approach: Documentation-only feature (no code changes). Create structured Obsidian markdown files following Nebula documentation constitution. Research best practices from n8n, Temporal, and existing Rust credential libraries. Organize content by user journey (beginner → intermediate → advanced).

## Technical Context

**Language/Version**: Markdown (Obsidian-flavored) with embedded Rust code examples (targeting stable Rust 1.75+)  
**Primary Dependencies**: Obsidian (v1.5+), Dataview plugin (v0.5.64+), Mermaid (for diagrams), optionally Excalidraw  
**Storage**: File-based markdown in `02-Crates/nebula-credential/` directory with cross-references via wikilinks  
**Testing**: Manual validation of code examples, link checking, frontmatter validation, user testing with beta readers  
**Target Platform**: Obsidian vault consumed by developers/operators on Windows/macOS/Linux  
**Project Type**: Documentation (not software) - structure follows Nebula docs hierarchy  
**Performance Goals**: Users complete Quick Start in <10 minutes; find answers to common questions in <2 minutes via search/links  
**Constraints**: Must follow constitution principles (wikilinks, frontmatter, progressive disclosure, bilingual RU/EN support); code examples must be complete and runnable  
**Scale/Scope**: ~30-40 documentation pages covering 6 user stories (Getting Started, Common Patterns, Rotation, Multi-Provider, Security, Troubleshooting)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Verify compliance with Nebula Constitution (`.specify/memory/constitution.md`):

**I. Obsidian-Native Structure** ✅
- [x] All pages use wikilinks (`[[Page Name]]`) for internal references
- [x] Folder structure follows `02-Crates/nebula-credential/` hierarchy
- [x] Entry point is `README.md` with navigation to sub-sections
- [x] Use Obsidian callouts for warnings/tips/examples
- [x] Diagrams use Mermaid syntax (OAuth2 flows, architecture, state machines)
- [x] Tags in frontmatter for categorization
- [x] Backlinks intentional; no orphan pages

**II. Technical Accuracy & Research-Driven** ✅
- [x] Research n8n credential documentation patterns via deepwiki
- [x] Research Rust credential libraries (secrecy, aes-gcm) via context7
- [x] Include "Sources" section in research-heavy pages
- [x] Version numbers for APIs (e.g., "nebula-credential 0.1.0")

**III. Cross-Reference Network (Wikilinks)** ✅
- [x] Every concept page links to ≥3 related concepts
- [x] Code examples link to API reference pages
- [x] Guides link to prerequisite concepts
- [x] "See Also" sections with 5-7 related links
- [x] MOC page: `02-Crates/nebula-credential/README.md`

**IV. Multi-Language Support (RU/EN)** ✅
- [x] Frontmatter includes `lang: ru` or `lang: en`
- [x] P1 pages (Getting Started, Common Patterns) bilingual
- [x] Technical terms keep English equivalents in Russian text
- [x] Code examples always in English
- [x] File names in English

**V. Code Examples & Practical Guides** ✅
- [x] Code blocks specify language (` ```rust `)
- [x] Examples include prerequisites, expected output, common errors
- [x] Examples are complete and runnable (not pseudocode)
- [x] Minimal examples (one concept per example)
- [x] Comments explain non-obvious parts

**VI. Consistent Metadata & Frontmatter** ✅
- [x] Required fields: title, tags, status, lang, created, last_updated
- [x] Optional fields: audience, estimated_reading
- [x] Status values: draft → in-progress → published
- [x] Tags follow controlled vocabulary

**VII. Progressive Disclosure** ✅
- [x] Pages start with: TL;DR → Why it matters → Simple example → Link to details
- [x] Use collapsible Obsidian callouts for advanced content
- [x] Separate "Quick Start" from "Complete Guide"
- [x] Visual hierarchy with headers
- [x] Multiple entry points (beginner/intermediate/advanced paths)

**Additional: Tooling & Plugins Requirements** ✅
- [x] Dataview queries for Documentation Dashboard
- [x] Templates in `_templates/` for consistent page creation
- [x] Mermaid diagrams for architecture visualization
- [x] Frontmatter validation

**GATE RESULT**: ✅ **PASS** - All constitution requirements applicable to documentation work are met. No violations to justify.

## Project Structure

### Documentation (this feature)

```text
specs/001-credential-docs/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # ✅ Phase 0: Best practices (6 agents: Rust, OAuth2, Providers, SAML, LDAP, Auth0/SSE)
├── data-model.md        # ✅ Phase 1: Documentation page structure, frontmatter schema
├── quickstart.md        # ✅ Phase 1: Quick Start validation workflow
├── contracts/           # ✅ Phase 1: Documentation page templates and examples
│   ├── getting-started-template.md
│   ├── how-to-template.md
│   ├── example-template.md
│   └── troubleshooting-template.md
└── tasks.md             # Phase 2: NOT created by /speckit.plan (use /speckit.tasks)
```

### Source Code (Documentation Files)

This is a documentation feature, not code. The "source" is markdown files in the Obsidian vault:

```text
02-Crates/nebula-credential/
├── README.md                          # Main entry point (updated/enhanced)
├── Architecture.md                    # Already exists (minor updates)
├── Security/
│   └── Encryption.md                  # Already exists (minor updates)
├── Getting-Started/
│   ├── Quick-Start.md                 # NEW: P1 - 10-minute tutorial
│   ├── Core-Concepts.md               # NEW: P1 - What/Why credentials
│   └── Installation.md                # NEW: P1 - Setup guide
├── Examples/
│   ├── API-Key-Basic.md               # Already exists (enhance)
│   ├── OAuth2-Flow.md                 # Already exists (complete rewrite)
│   ├── OAuth2-GitHub.md               # NEW: P1 - Specific provider
│   ├── OAuth2-Google.md               # NEW: P1 - Specific provider
│   ├── Database-PostgreSQL.md         # NEW: P1 - Complete example
│   ├── Database-MySQL.md              # NEW: P1 - Complete example
│   ├── Database-Rotation.md           # Already exists (enhance)
│   ├── AWS-Credentials.md             # Already exists (enhance)
│   ├── AWS-AssumeRole.md              # NEW: P1 - Advanced AWS
│   └── Certificate-Auth.md            # Already exists (enhance)
├── How-To/
│   ├── Store-Credentials.md           # NEW: P2 - Step-by-step
│   ├── Retrieve-Credentials.md        # NEW: P2 - Step-by-step
│   ├── Rotate-Credentials.md          # Already exists (enhance)
│   ├── Configure-Caching.md           # NEW: P2 - Performance
│   └── Enable-Audit-Logging.md        # NEW: P3 - Security
├── Integrations/
│   ├── AWS-Secrets-Manager.md         # NEW: P2 - Provider setup
│   ├── HashiCorp-Vault.md             # NEW: P2 - Provider setup
│   ├── Azure-Key-Vault.md             # NEW: P2 - Provider setup
│   ├── Kubernetes-Secrets.md          # NEW: P2 - Provider setup
│   └── Migration-Guide.md             # NEW: P2 - Provider migration
├── Advanced/
│   ├── Security-Hardening.md          # NEW: P3 - Compliance
│   ├── Key-Management.md              # NEW: P3 - HSM, KMS
│   ├── Custom-Providers.md            # NEW: P3 - Extensibility
│   └── Performance-Tuning.md          # NEW: P3 - Optimization
├── Troubleshooting/
│   ├── Common-Errors.md               # NEW: P3 - Error catalog
│   ├── Decryption-Failures.md         # NEW: P3 - Specific issue
│   ├── OAuth2-Issues.md               # NEW: P3 - Specific issue
│   ├── Rotation-Failures.md           # NEW: P3 - Specific issue
│   └── Debugging-Checklist.md         # NEW: P3 - Diagnostic guide
└── Reference/
    ├── API-Reference.md               # NEW: P2 - Public API docs
    ├── Configuration-Options.md       # NEW: P2 - Config reference
    └── Glossary.md                    # NEW: P3 - Terms

_templates/
├── Credential-Example.md              # NEW: Template for examples
└── How-To-Guide.md                    # NEW: Template for guides
```

**Structure Decision**: Documentation follows existing `02-Crates/nebula-credential/` hierarchy. New sub-folders organize by content type (Getting-Started, Examples, How-To, Integrations, Advanced, Troubleshooting, Reference). This aligns with progressive disclosure principle: beginners start in Getting-Started, experts jump to Advanced/Reference.

## Complexity Tracking

**No violations** - This is a documentation feature that fully complies with the constitution. No complexity justifications needed.

---

## Phase 0: Outline & Research

**Goal**: Research best practices, resolve unknowns, establish documentation patterns.

### Research Tasks

1. **n8n Credential Documentation Patterns** ✅ COMPLETED
   - Researched via deepwiki
   - Found: `documentationUrl` patterns, ESLint rules for validation, sensitive field handling
   - Key insight: External documentation links for each credential type, no credential reuse security pattern

2. **Rust Credential Libraries Best Practices**
   - Research `secrecy` crate patterns (SecretString, zeroize on drop)
   - Research `aes-gcm` encryption patterns (nonce uniqueness, authenticated encryption)
   - Research `tokio` async patterns for credential refresh
   - Find examples from other Rust projects

3. **OAuth2 Documentation Standards**
   - Research OAuth2 RFC 6749 terminology
   - Find best practices for documenting token flows
   - Research common OAuth2 pitfalls and how to document them
   - Look at GitHub/Google/Microsoft OAuth2 documentation

4. **Database Credential Patterns**
   - Research connection string security (never log)
   - Research connection pooling best practices
   - Research credential rotation patterns (blue-green, rolling)
   - Find PostgreSQL/MySQL credential management examples

5. **Cloud Provider Integration**
   - Research AWS Secrets Manager documentation patterns
   - Research HashiCorp Vault Transit engine docs
   - Research Azure Key Vault documentation
   - Research Kubernetes Secrets best practices

6. **Security Documentation Standards**
   - Research SOC2/ISO 27001 documentation requirements
   - Research NIST encryption documentation guidelines
   - Find audit logging documentation examples
   - Research security compliance checklists

### Decisions to Make

**Decision 1: Documentation Organization**
- **Chosen**: Organize by user journey (Getting-Started → Examples → How-To → Advanced → Troubleshooting)
- **Rationale**: Supports progressive disclosure; beginners don't see advanced content
- **Alternatives considered**: 
  - Alphabetical (rejected: hard to navigate)
  - By credential type (rejected: doesn't match user mental model)
  - Flat structure (rejected: overwhelming for beginners)

**Decision 2: Code Example Format**
- **Chosen**: Complete, runnable examples with prerequisites, imports, error handling
- **Rationale**: Users can copy-paste and run; reduces support burden
- **Alternatives considered**:
  - Pseudocode (rejected: not runnable)
  - Minimal snippets (rejected: missing context)
  - Link to external repos (rejected: fragmentation)

**Decision 3: Diagram Style**
- **Chosen**: Mermaid syntax for all diagrams
- **Rationale**: Text-based, version control friendly, renders in Obsidian
- **Alternatives considered**:
  - Excalidraw (rejected for main docs: binary format, merge conflicts)
  - Draw.io exports (rejected: manual maintenance)
  - ASCII art (rejected: limited expressiveness)

**Decision 4: Bilingual Strategy**
- **Chosen**: P1 pages bilingual (RU primary, EN parallel), P2/P3 Russian only initially
- **Rationale**: Maximizes value for global users while managing translation effort
- **Alternatives considered**:
  - All English (rejected: team primarily Russian-speaking)
  - All Russian (rejected: limits global adoption)
  - Machine translation (rejected: poor quality for technical docs)

**Decision 5: Example Providers**
- **Chosen**: Focus on 5 core providers (Local, AWS, Vault, Azure, K8s)
- **Rationale**: Covers 95% of production deployments; extensibility documented for others
- **Alternatives considered**:
  - Only local storage (rejected: not production-ready)
  - More providers (rejected: maintenance burden)

**Output**: Research findings consolidated in `research.md` ✅ **COMPLETED** (2026-02-03)

---

## Phase 1: Design & Contracts ✅ **COMPLETED**

**Goal**: Define documentation structure, create page templates, establish validation workflow.

### Artifacts Created

#### 1. data-model.md ✅

**Purpose**: Canonical data model for all documentation pages

**Contents**:
- **Frontmatter Schema**: Required/optional fields with definitions
- **Controlled Tag Vocabulary**: 50+ tags organized by category (credential types, content types, topics, providers, skill levels)
- **Page Structure Template**: Universal template for all pages
- **Page Type Specifications**: Detailed specs for 7 page types:
  - Getting Started Pages
  - Concept Pages
  - How-To Guides
  - Example Pages
  - Troubleshooting Pages
  - Reference Pages
  - Integration Guides (Provider-Specific)
- **Cross-Reference Requirements**: Minimum links per page type, link types, orphan prevention
- **Mermaid Diagram Guidelines**: When to use, diagram types, best practices
- **Code Example Guidelines**: Complete example structure, requirements, output blocks
- **Special Callout Blocks**: Warning, Note, Tip, Example, Caution
- **Bilingual Content Strategy**: RU/EN translation priority, technical terms handling
- **Validation Checklist**: 25-point checklist before marking `published`

**Key Decisions**:
- All pages MUST have 2-7 tags from controlled vocabulary
- Every page (except entry points) MUST have incoming links
- Code examples MUST be complete and runnable
- P1 pages MUST be bilingual (RU + EN)
- Maximum 500 lines for Getting Started pages

#### 2. contracts/ Directory ✅

**Purpose**: Reusable page templates with placeholders

**Templates Created**:
1. **getting-started-template.md**
   - Structure: TL;DR, What You'll Learn, 5-minute Quick Start, FAQ
   - Target: <10 minutes completion time
   - Placeholders: {{PAGE_TITLE}}, {{CREDENTIAL_TYPE}}, {{STEP_N_CODE}}, etc.
   
2. **how-to-template.md**
   - Structure: Prerequisites, Step-by-Step, Verification, Troubleshooting
   - Target: 15 minutes
   - Emphasis: Actionable numbered steps
   
3. **example-template.md**
   - Structure: Use Case, Complete Code, Explanation, Variations
   - Target: 10 minutes
   - Emphasis: One example = one concept
   
4. **troubleshooting-template.md**
   - Structure: Quick Diagnosis Table, Issues with Symptoms/Causes/Solutions
   - Emphasis: Prioritized solutions, diagnostic commands, prevention

**Usage**: Authors copy template, fill placeholders, validate against checklist

#### 3. quickstart.md ✅

**Purpose**: Validation workflow for Quick Start guides

**Contents**:
- **4 Validation Phases**:
  1. Self-Review (Author): 15-point checklist
  2. Peer Review: Unbiased testing, timing, feedback form
  3. User Testing: 2-3 target users, screen recording, metrics
  4. Technical Review: SME approval, security/performance review
  
- **Validation Tools**: Automated checks for frontmatter, links, code compilation, timing estimation
- **Issue Categories**: Blocker (must fix), Major (should fix), Minor (nice to fix)
- **Approval Process**: Multi-reviewer sign-off with success criteria
- **Continuous Improvement**: Post-publication monitoring, update triggers
- **Templates for Common Scenarios**: OAuth2, Database, API Key quick starts
- **Success Metrics**: Completion time, success rate, user satisfaction targets

**Key Validations**:
- 2/3 testers must complete in <10 minutes
- 3/3 testers must complete without errors
- All code must compile and run
- Average confusion score <2

### Phase 1 Decisions

**Decision 1: Documentation Granularity**
- **Chosen**: 7 distinct page types with specific constraints
- **Rationale**: Clear expectations, easier to validate, better discoverability
- **Impact**: ~30-40 pages total vs potential 15-20 "kitchen sink" pages

**Decision 2: Tag Strategy**
- **Chosen**: Controlled vocabulary with 50+ predefined tags
- **Rationale**: Prevents tag sprawl, enables reliable Dataview queries, improves discoverability
- **Alternative**: Free-form tags (rejected: inconsistent, hard to query)

**Decision 3: Validation Rigor**
- **Chosen**: 4-phase validation with user testing requirement
- **Rationale**: Quick Start is critical entry point; worth extra effort to get right
- **Alternative**: Peer review only (rejected: misses real user confusion)

**Decision 4: Template Approach**
- **Chosen**: Explicit placeholders ({{VARIABLE}}) vs prose instructions
- **Rationale**: Unambiguous, easy to find/replace, prevents missed sections
- **Alternative**: Commented instructions (rejected: harder to track completion)

### Deliverables Summary

| Artifact | Status | Lines | Key Feature |
|----------|--------|-------|-------------|
| data-model.md | ✅ Complete | 850+ | Frontmatter schema, 7 page type specs |
| getting-started-template.md | ✅ Complete | 100+ | <10 min constraint, FAQ section |
| how-to-template.md | ✅ Complete | 120+ | Step-by-step, verification steps |
| example-template.md | ✅ Complete | 90+ | Use case driven, variations |
| troubleshooting-template.md | ✅ Complete | 130+ | Quick diagnosis table |
| quickstart.md | ✅ Complete | 550+ | 4-phase validation, user testing |

**Total Documentation**: ~1,850 lines of planning artifacts

---
