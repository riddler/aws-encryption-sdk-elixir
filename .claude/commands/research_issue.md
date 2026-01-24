---
description: Research a GitHub issue using codebase and spec/test vector agents
model: opus
---

# Research Issue

Research a GitHub issue by analyzing the codebase, AWS Encryption SDK specification, and test vectors. Produces a research document in `thoughts/shared/research/`.

## Process

### Step 1: Get Issue Details

If an issue number was provided (e.g., `/research_issue #42` or `/research_issue 42`):

```bash
gh issue view 42 --json number,title,body,labels
```

If no issue number provided, ask the user for one.

### Step 2: Analyze Issue Requirements

Read and understand:
- What feature/fix is being requested
- What components are involved
- What the acceptance criteria are
- Any spec references mentioned

### Step 3: Spawn Parallel Research Agents

Launch these research tasks concurrently:

1. **codebase-locator**: Find all relevant existing code
   ```
   Prompt: Find all files related to [feature/component from issue].
   Look for existing implementations, tests, and related modules.
   ```

2. **codebase-analyzer**: Understand current implementation state
   ```
   Prompt: Analyze the current implementation of [related components].
   Document how they work and what interfaces exist.
   ```

3. **spec-researcher**: Find specification requirements
   ```
   Prompt: Find all specification requirements for [feature].
   Include MUST/SHOULD/MAY statements from relevant spec sections.
   Provide links to spec documents.
   ```

4. **test-vector-researcher**: Find applicable test vectors
   ```
   Prompt: Find test vectors applicable to [feature].
   List specific test vector IDs, organized by complexity.
   Note which vectors should be implemented first.
   ```

### Step 4: Synthesize Findings

Wait for all research tasks to complete, then synthesize into a research document.

### Step 5: Write Research Document

Write to `thoughts/shared/research/YYYY-MM-DD-GHXXX-description.md`:

```markdown
# Research: [Issue Title]

**Issue**: #XXX - [Title]
**Date**: YYYY-MM-DD
**Status**: Research complete

## Issue Summary

[Brief description of what needs to be implemented/fixed]

## Current Implementation State

### Existing Code
[From codebase-locator and codebase-analyzer]

- `lib/aws_encryption_sdk/...` - [description]
- `lib/aws_encryption_sdk/...` - [description]

### Relevant Patterns
[Existing patterns that should be followed]

### Dependencies
[What this feature depends on, what depends on it]

## Specification Requirements

### Source Documents
- [spec-name.md](link) - [description]

### MUST Requirements
1. **[Requirement name]** (spec-file.md#section)
   > Quoted requirement text

   Implementation notes: [how to implement]

2. **[Another requirement]** (spec-file.md#section)
   > Quoted requirement text

### SHOULD Requirements
[List SHOULD requirements]

### MAY Requirements
[List optional MAY requirements]

## Test Vectors

### Applicable Test Vector Sets
- **awses-decrypt**: [description]
- **awses-encrypt**: [description]

### Implementation Order

#### Phase 1: Basic Implementation
| Test ID | Algorithm | Description | Priority |
|---------|-----------|-------------|----------|
| `test-id-1` | 0x0478 | Simplest case | Start here |
| `test-id-2` | 0x0478 | Variation | Second |

#### Phase 2: Extended Coverage
| Test ID | Algorithm | Description | Priority |
|---------|-----------|-------------|----------|
| `test-id-3` | 0x0578 | With ECDSA | After basic |

#### Phase 3: Edge Cases
| Test ID | Description | Expected |
|---------|-------------|----------|
| `edge-1` | Empty plaintext | Success |
| `negative-1` | Wrong key | Error |

### Test Vector Details

**How to fetch**:
```bash
curl -O https://raw.githubusercontent.com/awslabs/aws-encryption-sdk-test-vectors/master/vectors/...
```

**Key material needed**:
[List keys from keys.json that are needed]

## Implementation Considerations

### Technical Approach
[Recommended approach based on research]

### Potential Challenges
- [Challenge 1]
- [Challenge 2]

### Open Questions
- [Any unresolved questions that need answers]

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/YYYY-MM-DD-GHXXX-description.md`
2. [Other recommendations]

## References

- Issue: https://github.com/owner/repo/issues/XXX
- Spec: [links]
- Test Vectors: [links]
```

### Step 6: Present Summary

After writing the research document:

```
Research complete for issue #42: "Implement Raw AES keyring"

**Document**: thoughts/shared/research/2026-01-24-GH42-raw-aes-keyring.md

**Summary**:
- Found 3 related existing files
- Identified 5 MUST requirements from spec
- Found 12 applicable test vectors
- Recommended starting with `test-id-001`

**Key Findings**:
- Keyring behaviour already exists
- Need to implement on_encrypt/on_decrypt callbacks
- Spec requires AES-GCM with 12-byte IV

**Next step**: `/create_plan thoughts/shared/research/2026-01-24-GH42-raw-aes-keyring.md`
```

## Important Guidelines

- Always spawn research agents in parallel for efficiency
- Wait for ALL agents to complete before synthesizing
- Include specific test vector IDs with implementation order
- Link to actual spec sections, not just repo
- Note any gaps or questions discovered during research
- Research document should be complete enough to create a plan from
