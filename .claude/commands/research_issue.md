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
   Use the test vector harness at test/support/test_vector_harness.ex.

   1. Check test/fixtures/test_vectors for available manifests
   2. Load manifests with TestVectorHarness.load_manifest/1
   3. Filter tests by algorithm suite or key type as needed
   4. List specific test vector IDs from the manifest, organized by complexity
   5. Note which vectors should be implemented first (prefer committed suites)
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

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets
- **awses-decrypt**: [description of decrypt vectors found]
- Manifest version: [version from harness.manifest_version]
- Total tests: [count from harness]

### Implementation Order

#### Phase 1: Basic Implementation
| Test ID | Algorithm | Key Type | Priority |
|---------|-----------|----------|----------|
| `[actual-test-id]` | 0x0478 | AES-256 | Start here |
| `[actual-test-id]` | 0x0478 | AES-256 | Second |

#### Phase 2: Extended Coverage
| Test ID | Algorithm | Key Type | Priority |
|---------|-----------|----------|----------|
| `[actual-test-id]` | 0x0578 | AES-256 + ECDSA | After basic |

#### Phase 3: Edge Cases
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `[actual-test-id]` | [from test.description] | Success/Error |

### Test Vector Setup

If test vectors are not present, run:

```elixir
TestVectorSetup.ensure_test_vectors()
```

This will print download instructions. Alternatively:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Get key metadata
{:ok, key_data} = TestVectorHarness.get_key(harness, "aes-256-key-id")

# Decode key material
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)
```

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
