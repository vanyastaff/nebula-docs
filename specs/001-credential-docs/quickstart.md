# Quick Start Validation Workflow

**Date**: 2026-02-03  
**Feature**: [[spec.md|Improve nebula-credential Documentation]]  
**Purpose**: Define the validation workflow for ensuring Quick Start guides meet quality standards and can be completed in <10 minutes.

---

## Overview

Quick Start guides are the most critical entry point for new users. This document defines the validation process to ensure they are:
- **Fast**: Completable in <10 minutes
- **Clear**: No ambiguity or missing steps
- **Working**: All code examples run successfully
- **Complete**: No external prerequisites beyond listed items

---

## Validation Phases

### Phase 1: Self-Review (Author)

**Before submitting for review**, the author MUST complete:

#### Checklist 1: Structure

- [ ] Frontmatter complete with all required fields
- [ ] Tags include: `getting-started`, credential type, `beginner`
- [ ] TL;DR is exactly one sentence
- [ ] "What You'll Learn" section with 3-5 bullet points
- [ ] Prerequisites section explicitly lists requirements
- [ ] Steps are numbered (minimum 3, maximum 6)
- [ ] "What's Next" section with 3+ links
- [ ] See Also section with 3-5 related links

#### Checklist 2: Code Quality

- [ ] All code examples are complete (no `// ...` placeholders)
- [ ] All code examples have language specifiers (` ```rust `)
- [ ] Dependencies listed in Cargo.toml block
- [ ] Code includes error handling (no `.unwrap()` in main flow)
- [ ] Expected output shown for each step
- [ ] Complete example compiles without errors
- [ ] Complete example runs successfully

#### Checklist 3: Clarity

- [ ] Technical terms linked to concept pages on first mention
- [ ] No unexplained jargon
- [ ] Steps are actionable (start with verbs)
- [ ] No references to advanced concepts
- [ ] All wikilinks resolve to existing pages

#### Checklist 4: Timing

- [ ] Author completes guide in <8 minutes (allow 2min buffer)
- [ ] No external setup required beyond prerequisites
- [ ] Prerequisites completable in <5 minutes

---

### Phase 2: Peer Review

**Assign to someone unfamiliar with the topic** for unbiased feedback.

#### Reviewer Actions

1. **Read Prerequisites**:
   - [ ] All prerequisites clearly stated
   - [ ] Prerequisites link to relevant pages
   - [ ] Prerequisites are minimal (≤3 items)

2. **Follow Steps Exactly**:
   - [ ] Start timer when beginning Step 1
   - [ ] Copy-paste code exactly as shown
   - [ ] Verify expected output matches actual output
   - [ ] Note any confusion or missing information
   - [ ] Stop timer when guide completes

3. **Record Timing**:
   - Total time: ___ minutes
   - [ ] Completed in <10 minutes
   - If >10 minutes, identify slowest step: ___

4. **Test Variations**:
   - [ ] Test on clean system (no cached dependencies)
   - [ ] Test on different OS (if applicable)
   - [ ] Test with minimum Rust version specified

#### Reviewer Feedback Form

**Clarity** (1-5, 5=excellent):
- Steps are clear: __/5
- Code examples are complete: __/5
- Expected outputs match: __/5
- Prerequisites adequate: __/5

**Issues Found**:
```
- Step X: Missing Y
- Code example Z: Error W
- Unclear terminology: "foo" needs explanation
```

**Suggestions**:
```
- Add example output for Step X
- Link to [[Concept Page]] for term Y
- Simplify Step Z
```

---

### Phase 3: User Testing

**Test with 2-3 target users** (beginners) before marking `published`.

#### User Testing Protocol

1. **Recruit Testers**:
   - 1 complete beginner (never used Nebula)
   - 1 familiar with Rust but not Nebula
   - 1 familiar with similar tools (n8n, Zapier)

2. **Testing Environment**:
   - Clean system or VM
   - Only prerequisites installed
   - Screen recording + think-aloud protocol

3. **Testing Script**:
   ```
   "Please complete this Quick Start guide while thinking aloud. 
   Say what you're thinking, where you're confused, what you expect.
   I won't answer questions until the end."
   ```

4. **Record Metrics**:
   - Completion time: ___ minutes
   - Errors encountered: ___
   - Questions asked: ___
   - Steps where confused: ___
   - Success rate: ___/3 testers

#### Success Criteria

**Must Pass**:
- [ ] 2/3 testers complete in <10 minutes
- [ ] 3/3 testers complete without errors
- [ ] 0 critical issues (blocking errors)
- [ ] Average confusion score <2 per tester

**Confusion Score**:
- 0 = No confusion
- 1 = Minor hesitation (self-resolved)
- 2 = Moderate confusion (re-read section)
- 3 = Major confusion (stuck, needed help)

---

### Phase 4: Technical Review

**Final review by technical SME** (subject matter expert).

#### Technical Checklist

- [ ] Code follows Nebula coding standards
- [ ] Security best practices followed (no hardcoded secrets, proper error handling)
- [ ] No deprecated APIs used
- [ ] Example represents current best practices
- [ ] Idiomatic Rust (no anti-patterns)
- [ ] Proper async/await usage
- [ ] Resource cleanup (no leaks)
- [ ] Error types appropriate

#### Security Review

- [ ] No credentials in code
- [ ] No insecure defaults
- [ ] Security warnings present where needed
- [ ] Safe error messages (no info leakage)
- [ ] Input validation shown
- [ ] TLS/encryption used where appropriate

#### Performance Review

- [ ] No obvious performance issues
- [ ] Connection pooling used where appropriate
- [ ] Resources released properly
- [ ] No unnecessary allocations

---

## Validation Tools

### Automated Checks

Run before submitting for review:

#### 1. Frontmatter Validation

```bash
# Check all required fields present
python scripts/validate_frontmatter.py "02-Crates/nebula-credential/Getting-Started/*.md"
```

Expected output:
```
✓ Quick-Start.md: All required fields present
✓ Quick-Start.md: Tags valid
✓ Quick-Start.md: Status is 'draft' or 'in-progress'
```

#### 2. Link Validation

```bash
# Check all wikilinks resolve
python scripts/check_links.py "02-Crates/nebula-credential/Getting-Started/*.md"
```

Expected output:
```
✓ Quick-Start.md: All 8 wikilinks resolve
✗ Quick-Start.md: [[Non-Existent-Page]] not found (line 45)
```

#### 3. Code Compilation

```bash
# Extract and compile all code examples
python scripts/extract_and_test_code.py "02-Crates/nebula-credential/Getting-Started/Quick-Start.md"
```

Expected output:
```
Extracting code blocks...
✓ Example 1 (line 42): Compiles successfully
✓ Example 2 (line 67): Compiles successfully
✓ Complete example (line 95): Compiles and runs successfully
```

#### 4. Timing Estimation

```bash
# Estimate reading time
python scripts/estimate_reading_time.py "Quick-Start.md"
```

Expected output:
```
Estimated reading time: 6 minutes
Code typing time: 3 minutes
Total estimated time: 9 minutes
✓ Within 10-minute target
```

### Manual Checks

#### Readability Test

Use Hemingway Editor or similar:
- Target: Grade 8-10 reading level
- Avoid complex sentences (>20 words)
- Prefer active voice

#### Accessibility Check

- [ ] Code blocks have language specifiers
- [ ] Diagrams have alt text
- [ ] Links have descriptive text
- [ ] Headings are hierarchical (H2 → H3, no skips)

---

## Issue Categories

### Blocker Issues (Must Fix)

**Definition**: Prevents completion or causes errors

Examples:
- Missing step
- Code doesn't compile
- Expected output doesn't match
- Broken prerequisite link
- Missing dependency

**Action**: Return to author, mark `draft`

### Major Issues (Should Fix)

**Definition**: Causes significant confusion or takes >10 minutes

Examples:
- Unclear instruction
- Missing explanation of key concept
- Step takes >2 minutes
- Insufficient error handling shown

**Action**: Request revision

### Minor Issues (Nice to Fix)

**Definition**: Small improvements, doesn't block

Examples:
- Typo
- Could add helpful tip
- Alternative approach worth mentioning
- Minor formatting issue

**Action**: Note for future iteration

---

## Approval Process

### Approval Criteria

Guide can be marked `published` when:

1. **All Phases Complete**:
   - [ ] Self-review checklist: 100% pass
   - [ ] Peer review: Approved
   - [ ] User testing: 2/3 success in <10 min
   - [ ] Technical review: Approved

2. **All Blockers Resolved**:
   - [ ] 0 blocker issues
   - [ ] All major issues addressed
   - [ ] Minor issues documented for future

3. **Automated Checks Pass**:
   - [ ] Frontmatter valid
   - [ ] All links resolve
   - [ ] Code compiles
   - [ ] Timing <10 minutes

### Sign-Off

**Author**: __________ (Date: ______)
- I have completed self-review checklist
- All code examples tested
- Estimated time: ___ minutes

**Peer Reviewer**: __________ (Date: ______)
- Completed guide in ___ minutes
- Clarity rating: __/5
- Recommend: [ ] Approve [ ] Revise

**User Tester 1**: __________ (Date: ______)
- Completed: [ ] Yes [ ] No
- Time: ___ minutes
- Issues: ___

**User Tester 2**: __________ (Date: ______)
- Completed: [ ] Yes [ ] No
- Time: ___ minutes
- Issues: ___

**Technical Reviewer**: __________ (Date: ______)
- Security: [ ] Pass [ ] Issues found
- Best practices: [ ] Pass [ ] Issues found
- Recommend: [ ] Approve [ ] Revise

**Final Approval**: __________ (Date: ______)
- Status changed to: `published`

---

## Continuous Improvement

### Post-Publication Monitoring

After publication, track:

- **User feedback**: GitHub issues referencing this guide
- **Completion rate**: Analytics if available
- **Time to complete**: User-reported times
- **Common questions**: Support tickets related to guide

### Update Triggers

Mark guide as `outdated` and schedule update if:

- [ ] Referenced API changes
- [ ] Prerequisites change
- [ ] User completion rate <80%
- [ ] Average time >10 minutes
- [ ] 3+ user reports of confusion
- [ ] Security issue discovered

### Update Process

1. Change status: `published` → `in-progress`
2. Apply fixes
3. Re-run validation (Phases 2-4)
4. Change status: `in-progress` → `published`
5. Update `last_updated` date

---

## Templates for Common Scenarios

### Template: Quick Start for OAuth2 Credential

**Target Time**: 8 minutes
**Steps**: 5

1. Add dependencies (1 min)
2. Configure OAuth2 client (1 min)
3. Get authorization code (2 min)
4. Exchange for access token (2 min)
5. Use token to access API (2 min)

**Key Elements**:
- Complete `.env` file example
- Mock OAuth2 server for testing (optional)
- Common pitfall: callback URL mismatch

### Template: Quick Start for Database Credential

**Target Time**: 7 minutes
**Steps**: 4

1. Add dependencies (1 min)
2. Create connection pool (2 min)
3. Store/retrieve credentials (2 min)
4. Test connection (2 min)

**Key Elements**:
- Docker command for test database
- Complete connection string
- Common pitfall: connection pool exhaustion

### Template: Quick Start for API Key

**Target Time**: 5 minutes
**Steps**: 3

1. Add dependencies (1 min)
2. Generate API key (2 min)
3. Validate API key (2 min)

**Key Elements**:
- Secure key generation
- Storage format
- Common pitfall: plaintext storage

---

## Success Metrics

Track across all Quick Start guides:

| Metric | Target | Current |
|--------|--------|---------|
| Average completion time | <10 min | ___ |
| User success rate | >90% | ___ |
| Blocker issues per guide | 0 | ___ |
| User satisfaction | >4/5 | ___ |
| Update frequency | <1/quarter | ___ |

---

## Summary

This validation workflow ensures Quick Start guides are:

1. **Fast**: <10 minutes validated by real users
2. **Correct**: All code tested and working
3. **Clear**: Peer and user reviewed
4. **Secure**: Technical review for best practices
5. **Maintainable**: Continuous monitoring and updates

**Next Step**: Apply this workflow to validate each Quick Start guide before marking `published`.

---

**Validation Tools Location**: `scripts/validation/`
**Test Results**: Document in `specs/001-credential-docs/test-results/`
