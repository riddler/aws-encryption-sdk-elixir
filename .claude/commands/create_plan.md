---
description: Create detailed implementation plans through interactive research and iteration
model: opus
---

# Implementation Plan

You are tasked with creating detailed implementation plans through an interactive, iterative process. You should be skeptical, thorough, and work collaboratively with the user to produce high-quality technical specifications.

## Initial Response

When this command is invoked:

1. **Check if parameters were provided**:
   - If a file path was provided (research doc, ticket, or other), skip the default message
   - Immediately read any provided files FULLY
   - Begin the research process
   - **Supported input files**:
     - Research docs: `thoughts/shared/research/YYYY-MM-DD-GHXXX-topic.md`
     - Ticket files: `thoughts/shared/tickets/TICKET-123.md`
     - GitHub issue references: `#123` or issue URLs

2. **If no parameters provided**, respond with:

```
I'll help you create a detailed implementation plan. Let me start by understanding what we're building.

Please provide:
1. The task description, research document, or GitHub issue number
2. Any relevant context, constraints, or specific requirements
3. Links to related research or previous implementations

I'll analyze this information and work with you to create a comprehensive plan.

Examples:
- `/create_plan thoughts/shared/research/2026-01-24-GH42-raw-aes-keyring.md`
- `/create_plan #42` (GitHub issue number)
- `/create_plan Implement HKDF key derivation per RFC 5869`
```

Then wait for the user's input.

## Process Steps

### Step 1: Context Gathering & Initial Analysis

1. **Read all mentioned files immediately and FULLY**:
   - Research documents (e.g., `thoughts/shared/research/YYYY-MM-DD-topic.md`)
   - Ticket files
   - Related implementation plans
   - **IMPORTANT**: Use the Read tool WITHOUT limit/offset parameters to read entire files
   - **CRITICAL**: DO NOT spawn sub-tasks before reading these files yourself in the main context
   - **NEVER** read files partially - if a file is mentioned, read it completely

   **When starting from a research doc**:
   - Research docs contain analysis, discoveries, and recommendations
   - Use them as the foundation for the plan - they've already done the investigation
   - Focus on structuring the implementation rather than re-researching
   - Validate that recommendations are still current if the doc is old

2. **Spawn research tasks if starting from scratch**:
   If a research document was not provided with full details, spawn parallel agents:

   - Use **codebase-locator** to find all files related to the task
   - Use **codebase-analyzer** to understand current implementation
   - Use **spec-researcher** to find specification requirements
   - Use **test-vector-researcher** to find applicable test vectors

3. **Read all files identified by research tasks**:
   - After research tasks complete, read ALL files they identified as relevant
   - Read them FULLY into the main context
   - This ensures complete understanding before proceeding

4. **Present informed understanding and focused questions**:

   ```
   Based on the research and my analysis of the codebase, I understand we need to [accurate summary].

   I've found that:
   - [Current implementation detail with file:line reference]
   - [Relevant pattern or constraint discovered]
   - [Spec requirement identified]
   - [Test vectors to validate against]

   Questions that my research couldn't answer:
   - [Specific technical question that requires human judgment]
   - [Design preference that affects implementation]
   ```

   Only ask questions that you genuinely cannot answer through investigation.

### Step 2: Research & Discovery

After getting initial clarifications:

1. **If the user corrects any misunderstanding**:
   - DO NOT just accept the correction
   - Spawn new research tasks to verify the correct information
   - Read the specific files/directories they mention
   - Only proceed once you've verified the facts yourself

2. **Present findings and design options**:

   ```
   Based on my research, here's what I found:

   **Current State:**
   - [Key discovery about existing code]
   - [Pattern or convention to follow]

   **Spec Requirements:**
   - [MUST requirement from spec]
   - [SHOULD requirement from spec]

   **Test Vectors:**
   - Start with: [simplest test vector ID]
   - Then: [next complexity level]

   **Design Options:**
   1. [Option A] - [pros/cons]
   2. [Option B] - [pros/cons]

   Which approach aligns best with your vision?
   ```

### Step 3: Plan Structure Development

Once aligned on approach:

1. **Create initial plan outline**:

   ```
   Here's my proposed plan structure:

   ## Overview
   [1-2 sentence summary]

   ## Implementation Phases:
   1. [Phase name] - [what it accomplishes] - [test vectors to validate]
   2. [Phase name] - [what it accomplishes] - [test vectors to validate]
   3. [Phase name] - [what it accomplishes] - [test vectors to validate]

   Does this phasing make sense? Should I adjust the order or granularity?
   ```

2. **Get feedback on structure** before writing details

### Step 4: Detailed Plan Writing

After structure approval:

1. **Write the plan** to `thoughts/shared/plans/YYYY-MM-DD-GHXXX-description.md`
   - Format: `YYYY-MM-DD-GHXXX-description.md` where:
     - YYYY-MM-DD is today's date
     - GHXXX is the issue number (omit if no issue)
     - description is a brief kebab-case description
   - Examples:
     - With issue: `2026-01-24-GH42-raw-aes-keyring.md`
     - Without issue: `2026-01-24-hkdf-implementation.md`

2. **Use this template structure**:

````markdown
# [Feature/Task Name] Implementation Plan

## Overview

[Brief description of what we're implementing and why]

**Issue**: #XXX (if applicable)
**Research**: `thoughts/shared/research/...` (if applicable)

## Specification Requirements

### Source Documents
- [spec-document.md](link) - [description]

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| [Requirement 1] | spec.md#section | MUST |
| [Requirement 2] | spec.md#section | SHOULD |

## Test Vectors

### Validation Strategy
Each phase includes specific test vectors to validate the implementation.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary
| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | `[actual-ids-from-manifest]` | Basic functionality |
| 2 | `[actual-ids-from-manifest]` | Extended coverage |
| 3 | `[actual-ids-from-manifest]` | Edge cases and error conditions |

### Harness Setup Pattern

```elixir
# In test file setup_all
setup_all do
  case TestVectorSetup.find_manifest("**/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil}
  end
end
```

## Current State Analysis

[What exists now, what's missing, key constraints discovered]

### Key Discoveries:
- [Important finding with file:line reference]
- [Pattern to follow]
- [Constraint to work within]

## Desired End State

[A specification of the desired end state after this plan is complete, and how to verify it]

## What We're NOT Doing

[Explicitly list out-of-scope items to prevent scope creep]

## Implementation Approach

[High-level strategy and reasoning]

---

## Phase 1: [Descriptive Name]

### Overview
[What this phase accomplishes]

### Spec Requirements Addressed
- [Requirement from spec with link]

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `[actual-manifest-id]` | [from test.description] | Success |
| `[actual-manifest-id]` | [from test.description] | Success |

```elixir
# Load and validate these specific tests
for test_id <- ~w(actual-id-1 actual-id-2) do
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  {:ok, expected} = TestVectorHarness.load_expected_plaintext(harness, test_id)
  # ... validation logic
end
```

### Changes Required:

#### 1. [Component/File Group]
**File**: `path/to/file.ex`
**Changes**: [Summary of changes]

```elixir
# Specific code to add/modify
```

### Success Criteria:

#### Automated Verification:
- [ ] Tests pass: `mix quality --quick`
- [ ] Test vectors pass: `mix test --only test_vectors`
- [ ] Specific vectors validated: `[actual-test-id-1]`, `[actual-test-id-2]`

#### Manual Verification:
- [ ] Feature works as expected when tested in IEx
- [ ] No regressions in related functions

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: [Descriptive Name]

[Similar structure with spec requirements and test vectors...]

---

## Final Verification

After all phases complete:

### Automated:
- [ ] Full test suite: `mix quality`
- [ ] All test vectors pass

### Manual:
- [ ] End-to-end feature verification
- [ ] Edge case testing

## Testing Strategy

### Unit Tests:
- [What to test]
- [Key edge cases]

### Test Vector Integration:

Test vectors are integrated using the harness infrastructure:

```elixir
# Module setup
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()

# Load harness in setup_all
setup_all do
  case TestVectorSetup.find_manifest("**/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil}
  end
end

# Filter tests by criteria
success_tests =
  harness.tests
  |> Enum.filter(fn {_id, test} -> test.result == :success end)

# Load test data
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, expected} = TestVectorHarness.load_expected_plaintext(harness, test_id)
```

- Test vectors validate: [which features/requirements]
- Run with: `mix test --only test_vectors`

### Manual Testing Steps:
1. [Specific step to verify feature]
2. [Another verification step]

## References

- Issue: #XXX
- Research: `thoughts/shared/research/...`
- Spec: [links to spec sections]
- Test Vectors: [links to test vector files]
````

### Step 5: Review

1. **Present the draft plan location**:

   ```
   I've created the initial implementation plan at:
   `thoughts/shared/plans/YYYY-MM-DD-GH42-raw-aes-keyring.md`

   Please review it and let me know:
   - Are the phases properly scoped?
   - Are the test vectors appropriate for each phase?
   - Are the success criteria specific enough?
   - Any technical details that need adjustment?
   - Missing edge cases or considerations?
   ```

2. **Iterate based on feedback** - be ready to:
   - Add missing phases
   - Adjust technical approach
   - Add/remove test vectors per phase
   - Clarify success criteria

3. **Continue refining** until the user is satisfied

## Important Guidelines

1. **Be Skeptical**:
   - Question vague requirements
   - Identify potential issues early
   - Ask "why" and "what about"
   - Don't assume - verify with code

2. **Be Interactive**:
   - Don't write the full plan in one shot
   - Get buy-in at each major step
   - Allow course corrections
   - Work collaboratively

3. **Be Thorough**:
   - Read all context files COMPLETELY before planning
   - Research actual code patterns using parallel sub-tasks
   - Include specific file paths and line numbers
   - Include specific test vector IDs per phase
   - Write measurable success criteria with clear automated vs manual distinction

4. **Include Test Vectors**:
   - Every phase should have specific test vectors to validate
   - Use actual test IDs from the harness manifest (not placeholders)
   - Order test vectors by complexity (simple first)
   - Include both positive (`result: :success`) and negative (`result: :error`) test cases
   - Note which spec requirements each test vector validates
   - Reference `mix test --only test_vectors` for running test vector tests

5. **Be Practical**:
   - Focus on incremental, testable changes
   - Consider migration and rollback
   - Think about edge cases
   - Include "what we're NOT doing"

6. **No Open Questions in Final Plan**:
   - If you encounter open questions during planning, STOP
   - Research or ask for clarification immediately
   - Do NOT write the plan with unresolved questions
   - The implementation plan must be complete and actionable

## Success Criteria Guidelines

**Always separate success criteria into two categories:**

1. **Automated Verification** (can be run by execution agents):
   - `mix quality --quick` after each phase
   - `mix quality` after all phases
   - Specific test vectors that should pass
   - Code compilation

2. **Manual Verification** (requires human testing):
   - IEx interaction testing
   - Edge cases that are hard to automate
   - User acceptance criteria

## Example Interaction Flow

### From a research document:

```
User: /create_plan thoughts/shared/research/2026-01-24-GH42-raw-aes-keyring.md
Assistant: Let me read that research document completely first...

[Reads file fully]

Based on your research, I see you've already investigated the spec requirements and identified 12 applicable test vectors.
The research recommends starting with `aes-256-gcm-001`. Let me structure this into an implementation plan...

[Proceeds with planning using research findings]
```

### From a GitHub issue:

```
User: /create_plan #42
Assistant: Let me fetch the details for issue #42 and research the codebase...

[Fetches issue via gh issue view 42 --json title,body,labels]
[Spawns research agents for spec and test vectors]

Based on the issue and my research, I understand we need to [summary].

[Interactive process continues...]
```
