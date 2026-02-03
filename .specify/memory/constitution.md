<!--
SYNC IMPACT REPORT - Version Update
====================================
Version Change: 1.0.0 → 1.1.0
Amendment Date: 2026-02-03
Change Type: MINOR - New section added

Modified Sections:
- Added: "Tooling & Plugins Requirements" (new section after Documentation Standards)
  - Specifies mandatory and recommended Obsidian plugins
  - Establishes plugin configuration requirements
  - Defines fallback strategies for missing plugins

Rationale:
User requested clarification on whether plugin recommendations belong in constitution.
Added explicit tooling requirements to ensure consistent documentation experience across team.

Templates Requiring Updates:
- ✅ plan-template.md - Already aligned
- ✅ spec-template.md - Already aligned  
- ✅ tasks-template.md - Already aligned

Follow-up TODOs:
- None

Previous version summary:
v1.0.0 - Initial documentation constitution with 7 core principles
-->

# Nebula Documentation Constitution

**Project**: Nebula Workflow Automation Engine  
**Documentation Format**: Obsidian Vault  
**Primary Audience**: Rust developers, DevOps engineers, workflow automation users  
**Languages**: Russian (primary), English (secondary)

---

## Core Principles

### I. Obsidian-Native Structure

**Principle**: Documentation MUST leverage Obsidian's full feature set for maximum navigability and discoverability.

**Rules**:
- Every page MUST use wikilinks (`[[Page Name]]`) for internal references, NOT markdown links
- Folder structure MUST follow numbered prefix pattern: `00-Home`, `01-Overview`, `02-Crates`, etc.
- Every folder MUST contain `README.md` or `_Index.md` as entry point
- Use Obsidian callouts for important information: `> [!NOTE]`, `> [!WARNING]`, `> [!TIP]`
- Diagrams MUST use Mermaid syntax (natively rendered in Obsidian)
- Tags MUST be used in frontmatter for categorization: `tags: [nebula, workflow, api]`
- Backlinks MUST be intentional - avoid orphaned pages
- Use Dataview queries where beneficial for dynamic content aggregation

**Rationale**: Obsidian's power lies in networked thinking and bidirectional links. Generic markdown doesn't exploit these capabilities. The current vault structure (`00-Home/README.md`, `01-Overview/What is Nebula.md`) demonstrates this approach works well.

**Anti-patterns**: 
- Using `[text](./path/to/file.md)` instead of `[[Page Name]]`
- Creating pages without linking them from anywhere
- Ignoring folder hierarchy and dumping everything in root

---

### II. Technical Accuracy & Research-Driven

**Principle**: All technical content MUST be based on authoritative sources and verified through research tools.

**Rules**:
- When documenting external projects (n8n, Temporal, Tokio), use MCP tools: `deepwiki`, `context7`, `WebFetch`
- When describing Rust libraries, fetch documentation from official sources (docs.rs, GitHub repos)
- Include "Sources" section at the end of research-heavy pages with clickable links
- Mark unverified claims with `[NEEDS VERIFICATION]` and TODO comment
- Update pages when upstream projects release major changes
- Cross-reference multiple sources for architectural decisions
- Include version numbers when documenting APIs or libraries (e.g., "Tokio 1.35+")

**Rationale**: Workflow automation is a rapidly evolving field. Inaccurate documentation is worse than no documentation. The research phase identified best practices from n8n (security), ComfyUI (performance), Temporal (reliability) - these insights must be current.

**Research Workflow**:
1. Identify topic to document (e.g., "credential management patterns")
2. Use `deepwiki` to query similar projects (n8n-io/n8n, temporalio/temporal)
3. Use `context7` to get up-to-date library documentation
4. Use `WebSearch` for recent articles and best practices (2026 context)
5. Synthesize findings and cite sources
6. Mark areas requiring future updates

---

### III. Cross-Reference Network (Wikilinks)

**Principle**: Documentation MUST form a densely connected knowledge graph, enabling discovery through multiple paths.

**Rules**:
- Every concept page MUST link to related concepts (minimum 3 outgoing links)
- Every code example MUST link to relevant API reference pages
- Every guide MUST link to prerequisite concepts
- Use inline wikilinks for first mention of concepts: `Nebula uses [[Actions]] to execute tasks`
- Create "See Also" sections at the end of pages with 5-7 related links
- Avoid link overload - don't link same term multiple times on one page
- Use descriptive link text: `[[02-Crates/nebula-action/README|Action Framework]]` not `[[here]]`
- Create MOC (Map of Content) pages for major topics (`03-Concepts/_Index.md`)

**Rationale**: Users arrive at documentation from different contexts. A beginner needs path from "What is Nebula" → "Getting Started" → "Creating Actions". An experienced user needs direct access to "API Reference" → "Credential Management" → "Encryption Details". The graph structure supports both.

**Link Types**:
- **Hierarchical**: Parent section → Child topics (`Crates Overview` → `nebula-action`)
- **Conceptual**: Related ideas (`Actions` ↔ `Workflows` ↔ `Resources`)
- **Sequential**: Tutorial steps (`Step 1` → `Step 2` → `Step 3`)
- **Reference**: Examples → API docs (`OAuth2 Example` → `Credential API`)

---

### IV. Multi-Language Support (RU/EN)

**Principle**: Documentation MUST be accessible in both Russian (primary) and English (secondary), with clear language indicators.

**Rules**:
- Frontmatter MUST include `lang: ru` or `lang: en` field
- Russian is primary for initial drafts; English translations follow for major pages
- Technical terms SHOULD keep English equivalents in parentheses: `действие (action)`, `учётные данные (credentials)`
- Code examples, API references, and command outputs MUST remain in English (universal)
- File names MUST be in English for cross-platform compatibility
- Create parallel pages for key documentation: `Getting Started (RU).md` and `Getting Started (EN).md`
- Use language tags in Obsidian: `#ru`, `#en` for filtering

**Rationale**: Primary development team speaks Russian, but workflow automation is global domain with English-dominant technical vocabulary. Hybrid approach maximizes accessibility without duplication burden.

**Translation Priority**:
1. **High**: Overview, Getting Started, Key Features (frontpage content)
2. **Medium**: Core Concepts, API Reference, Common Examples
3. **Low**: Advanced topics, internal architecture details, changelog

---

### V. Code Examples & Practical Guides

**Principle**: Every concept MUST include executable code examples with clear explanations.

**Rules**:
- Code blocks MUST specify language: ` ```rust `, ` ```bash `, ` ```json `
- Every code example MUST include:
  - Brief description of what it demonstrates
  - Prerequisites (dependencies, environment setup)
  - Expected output or result
  - Link to full example in `06-Examples/` folder if longer than 20 lines
- Examples MUST be tested and working (even if not automated yet)
- Prefer minimal examples over comprehensive ones (show ONE concept clearly)
- Include common error cases and how to fix them
- Use comments in code to explain non-obvious parts
- Show both success and failure paths where relevant

**Rationale**: Workflow automation is learned by doing. Abstract descriptions of "actions" or "credentials" mean nothing without concrete examples. n8n's success comes from its 400+ pre-built nodes - documentation should show how to build similar functionality.

---

### VI. Consistent Metadata & Frontmatter

**Principle**: Every documentation page MUST include structured frontmatter for metadata tracking.

**Required Fields**:
```yaml
---
title: Human-Readable Page Title
tags: [primary-tag, secondary-tag, category]
status: draft | in-progress | published | outdated
lang: ru | en
created: YYYY-MM-DD
last_updated: YYYY-MM-DD
---
```

**Optional Fields**:
```yaml
author: Name (for contributed content)
related: [[Page1]], [[Page2]] (explicit relationships)
version: 0.1.0 (for versioned API docs)
audience: beginner | intermediate | advanced
estimated_reading: 5min | 15min | 30min
```

**Rules**:
- `status: published` pages are stable; `draft` pages may change significantly
- `tags` MUST follow controlled vocabulary (see `08-Reference/Tag Glossary.md`)
- `last_updated` MUST be updated when content changes significantly
- Use `status: outdated` for pages that need revision due to upstream changes
- Dataview queries can aggregate pages by status, tags, or dates

**Rationale**: Obsidian frontmatter enables powerful queries. We can generate:
- "All draft pages needing completion"
- "Pages tagged 'security' updated in last 30 days"
- "Beginner-friendly guides sorted by reading time"

---

### VII. Progressive Disclosure

**Principle**: Documentation MUST present information in layers, from simple to complex, allowing users to dive deeper as needed.

**Rules**:
- Every topic page MUST start with:
  1. One-sentence summary (what is this?)
  2. Why it matters (motivation)
  3. Simple example (show, don't tell)
  4. Link to detailed guide
- Use collapsible sections for advanced content: Obsidian callouts with fold syntax
- Separate "Quick Start" from "Complete Guide"
- Create visual hierarchy with headers: `#` → `##` → `###`
- Use "TL;DR" sections at the top of long pages
- Link to deep-dives instead of explaining everything inline
- Provide multiple entry points: tutorial path vs reference path

**Rationale**: Beginners are overwhelmed by comprehensive docs. Experts are frustrated by overly simple docs. Layered structure serves both: skim for quick answers, dig for complete understanding.

---

## Documentation Standards

### File Organization

**Folder Structure** (current and enforced):
```
00-Home/          # Landing page, navigation, project overview
01-Overview/      # What is Nebula, Key Features, Comparison with alternatives
02-Crates/        # Technical documentation per Rust crate
  ├── nebula-action/
  ├── nebula-credential/
  ├── nebula-resource/
  ├── nebula-workflow/
  └── nebula-api/
03-Concepts/      # Cross-cutting concepts: Actions, Workflows, Security Model
04-Development/   # How-to guides for developers
05-API-Reference/ # REST API, GraphQL, WebSocket, CLI reference
06-Examples/      # Complete working examples and patterns
07-Advanced/      # Deployment, monitoring, performance tuning
08-Reference/     # Glossary, FAQ, changelog, tag taxonomy
_templates/       # Reusable page templates (Crate, Concept, API)
```

**Naming Conventions**:
- Use Title Case for display names: `What is Nebula.md`
- Use hyphens for multi-word files: `Key-Features.md`
- Use `README.md` for folder entry points
- Prefix with numbers only at folder level, not files

### Visual Elements

**Diagrams**:
- Use Mermaid for architecture diagrams, flowcharts, sequence diagrams
- Use ASCII art for simple CLI output examples
- Use screenshots sparingly (hard to maintain)
- Always include alt text and diagram description

**Callouts**:
```markdown
> [!NOTE] General information or context
> [!TIP] Helpful suggestions or best practices
> [!WARNING] Important cautions or potential issues
> [!DANGER] Critical security or data loss warnings
> [!EXAMPLE] Inline code examples or use cases
```

**Tables**:
- Use for comparison matrices (Nebula vs competitors)
- Use for API parameter documentation
- Use for feature support matrices
- Keep tables under 6 columns for readability

---

## Tooling & Plugins Requirements

### Mandatory Plugins (REQUIRED)

These plugins are **essential** for documentation workflow and MUST be installed:

**Core Plugins** (built-in, enable in Settings → Core Plugins):
- ✅ **Quick Switcher** - Fast page navigation (`Ctrl+O`)
- ✅ **File Recovery** - Auto-backup for unsaved changes
- ✅ **Backlinks** - Track page connections
- ✅ **Command Palette** - Access all commands (`Ctrl+P`)
- ✅ **Page Preview on Hover** - Preview wikilinks without clicking
- ✅ **Templates** - Insert page templates (`_templates/` folder)

**Community Plugins** (install from Community Plugins):
- ✅ **Dataview** (MANDATORY) - SQL-like queries for dashboards
  - Used in: `Documentation Dashboard.md`, status tracking
  - Configuration: Enable JS queries, inline queries
  - Fallback: None - dashboard will not function without it

### Recommended Plugins (STRONGLY ENCOURAGED)

These plugins significantly improve workflow and SHOULD be installed:

- 📊 **Excalidraw** - Hand-drawn diagrams and sketches
  - Use for: Architecture diagrams, brainstorming, presentations
  - Fallback: Use Mermaid (text-based) for version control friendly diagrams

- 🗂️ **Kanban** - Visual task management boards
  - Use for: Tracking documentation progress, sprint planning
  - Fallback: Use markdown checklists in regular pages

- 🔄 **Obsidian Git** - Automated Git commits and sync
  - Configuration: Auto-commit every 10 min, auto-push every 30 min
  - Fallback: Manual Git commands via terminal

- 🎨 **Templater** - Advanced templating with JavaScript
  - Use for: Dynamic templates with prompts, date insertion
  - Fallback: Use built-in Templates plugin (limited functionality)

### Optional Plugins (NICE TO HAVE)

These plugins provide additional convenience:

- 🖼️ **Canvas** - Visual knowledge maps (built-in core plugin)
  - Use for: Concept relationship mapping, architecture overviews
  - Fallback: Text-based MOC (Map of Content) pages

- 📋 **Tasks** - Advanced task management with due dates
  - Use for: Deadline tracking, priority management
  - Fallback: Standard markdown checkboxes

- 📝 **Linter** - Auto-format markdown on save
  - Use for: Consistent formatting, YAML frontmatter validation
  - Fallback: Manual formatting following style guide

- 🔍 **Omnisearch** - Enhanced search across vault
  - Use for: Faster content discovery
  - Fallback: Built-in search (Ctrl+Shift+F)

### Plugin Configuration Requirements

**Dataview Configuration** (MANDATORY):
```
Settings → Dataview:
✅ Enable JavaScript Queries
✅ Enable Inline Queries
✅ Enable Inline JavaScript Queries
```

**Templates Configuration** (MANDATORY):
```
Settings → Templates:
Template folder location: _templates
Date format: YYYY-MM-DD
Time format: HH:mm
```

**Git Configuration** (if using Obsidian Git):
```
Settings → Obsidian Git:
✅ Auto commit: Every 10 minutes
✅ Auto push: Every 30 minutes
✅ Pull updates on startup
Commit message: "docs: auto backup {{date}}"
```

### Fallback Strategies

If a recommended plugin is unavailable:

**No Dataview**:
- Manually maintain status lists in `Documentation Dashboard.md`
- Use file explorer to navigate by folder structure
- Track progress in spreadsheet or issue tracker

**No Excalidraw**:
- Use Mermaid for all diagrams (text-based, version control friendly)
- Use external tools (draw.io, Lucidchart) and embed PNG images
- Favor ASCII art for simple diagrams

**No Git Plugin**:
- Use terminal Git commands manually
- Set up Git hooks for pre-commit checks
- Use external Git client (GitHub Desktop, GitKraken)

**No Kanban**:
- Use markdown checklists grouped by status
- Maintain task list in `08-Reference/Tasks.md`
- Use external project management tool (Notion, Trello)

### Plugin Compatibility

**Tested Configurations**:
- Obsidian v1.5+ (required for Canvas support)
- Dataview v0.5.64+
- Templater v1.16+
- Obsidian Git v2.20+

**Known Issues**:
- Dataview JS queries may slow down large vaults (>1000 pages)
- Git auto-commit can conflict with manual commits - coordinate with team
- Excalidraw files are binary - difficult to merge in Git conflicts

### Setup Instructions

**New Team Member Onboarding**:
1. Install Obsidian from https://obsidian.md/
2. Open `nebula-docs` vault
3. Settings → Core Plugins → Enable all mandatory core plugins
4. Settings → Community Plugins → Turn on Community Plugins
5. Browse Community Plugins → Install: Dataview, Excalidraw, Kanban, Obsidian Git
6. Configure Dataview: Enable JS queries
7. Configure Templates: Set folder to `_templates`
8. Read [[Quick Start]] and [[Obsidian Plugins Guide]] for detailed usage

**Verification Checklist**:
- [ ] Quick Switcher works (`Ctrl+O` opens search)
- [ ] Dataview renders queries in `Documentation Dashboard.md`
- [ ] Templates accessible via Command Palette (`Ctrl+P` → "Insert template")
- [ ] Backlinks panel visible in right sidebar
- [ ] Git status shows in status bar (if using Git plugin)

---

## Content Quality Gates

### Pre-Publish Checklist

Every page at `status: published` MUST pass:

- [ ] **Accuracy**: All technical claims verified with sources
- [ ] **Completeness**: Covers declared scope without major gaps
- [ ] **Examples**: Includes at least one working code example
- [ ] **Links**: All wikilinks resolve (no broken `[[references]]`)
- [ ] **Frontmatter**: Complete metadata with tags and dates
- [ ] **Readability**: Clear headers, short paragraphs (<5 sentences), bullet lists
- [ ] **Language**: Grammar checked (Grammarly or equivalent)
- [ ] **Cross-references**: Minimum 3 outgoing links to related pages
- [ ] **No orphans**: Page is linked from at least one other page

### Peer Review (Optional but Recommended)

For major pages (Getting Started, Architecture, API Reference):
- Request review from another technical writer or developer
- Verify examples compile and run
- Test navigation flow from entry page to target page
- Ensure prerequisites are clearly stated

---

## Maintenance Requirements

### Regular Updates

**Monthly**:
- Review `status: draft` pages and promote completed ones to `published`
- Check for new Rust library versions (Tokio, serde, etc.) and update version numbers
- Verify external links still work (n8n docs, Temporal blog, etc.)
- Update Dataview queries if frontmatter schema changes

**Quarterly**:
- Audit tag usage and consolidate similar tags (see `08-Reference/Tag Glossary.md`)
- Review backlinks for high-traffic pages and ensure they're intentional
- Update comparison tables with new workflow automation platforms
- Check for pages marked `status: outdated` and update or archive
- Test plugin compatibility with latest Obsidian version

**Annually**:
- Major documentation structure review
- Translation updates for English versions of key pages
- Archive deprecated features with clear deprecation notices
- Review and update plugin recommendations based on ecosystem changes

### Version Control

- Commit documentation changes with descriptive messages: `docs: add credential rotation guide`
- Use git tags for major documentation releases: `docs-v1.0.0`
- Track breaking changes in `CHANGELOG.md` at vault root
- Keep constitution version in sync with major doc releases

---

## Governance

**Authority**: This constitution governs all documentation within the `nebula-docs` Obsidian vault.

**Amendment Process**:
1. Propose change in issue with rationale
2. Discuss impact on existing documentation
3. Update constitution with version bump:
   - **MAJOR**: Structural changes (folder reorganization, mandatory plugin changes)
   - **MINOR**: New principles/sections added or existing principles expanded
   - **PATCH**: Clarifications, typo fixes, example improvements
4. Update affected documentation pages to comply

**Compliance**:
- New documentation pages MUST follow these principles
- Existing pages SHOULD be updated opportunistically (not required bulk update)
- Exceptions MUST be documented with justification
- Plugin requirements apply to all team members working on documentation

**Continuous Improvement**:
- Collect user feedback on documentation clarity
- Track most-visited pages (via analytics if available)
- Identify gaps in documentation coverage
- Learn from best-in-class documentation (Rust Book, n8n docs, Temporal docs)
- Evaluate new Obsidian plugins quarterly for potential inclusion

---

**Version**: 1.1.0  
**Ratified**: 2026-02-03  
**Last Amended**: 2026-02-03  
**Next Review**: 2026-05-03
