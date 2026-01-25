# Update Claude Commands for Test Vector Harness Implementation Plan

## Overview

Update the three Claude command files (`research_issue.md`, `create_plan.md`, `implement_plan.md`) to leverage the test vector harness infrastructure from PR #16. Replace abstract test vector references and manual file operations with concrete harness API patterns.

**Issue**: #17
**Research**: `thoughts/shared/research/2026-01-25-GH17-claude-commands-test-vector-harness.md`

## Current State Analysis

### Files to Update

| File | Current State | Key Issues |
|------|---------------|------------|
| `.claude/commands/research_issue.md` | Generic test-vector-researcher prompts, curl download commands | No harness awareness |
| `.claude/commands/create_plan.md` | Placeholder test IDs (`test-001`), abstract integration section | No concrete API examples |
| `.claude/commands/implement_plan.md` | `File.read!` for test vectors, no harness patterns | Outdated manual approach |

### Key Discoveries

- `test/support/test_vector_harness.ex:70-97` - `load_manifest/1` is the primary entry point
- `test/support/test_vector_setup.ex:19-23` - `vectors_available?/0` for conditional skipping
- `test/test_vectors/decrypt_test.exs:22-36` - Established `setup_all` pattern with harness loading
- `test/test_vectors/decrypt_test.exs:72-76` - Filtering pattern for test case selection

### Harness Public API Summary

**TestVectorHarness:**
- `load_manifest/1` - Load decrypt manifest and keys
- `list_test_ids/1` - Get all test IDs
- `get_test/2` - Get test case metadata
- `load_ciphertext/2` - Load ciphertext binary
- `load_expected_plaintext/2` - Load expected plaintext
- `parse_ciphertext/1` - Parse message structure
- `get_key/2` - Get key material
- `decode_key_material/1` - Decode key by encoding type

**TestVectorSetup:**
- `vectors_available?/0` - Check if vectors present
- `find_manifest/1` - Find manifest by pattern
- `ensure_test_vectors/0` - Check and print instructions

## Desired End State

After implementation:
1. All three command files reference the harness API consistently
2. Test vector examples use actual harness functions, not manual file operations
3. Success criteria reference `mix test --only test_vectors`
4. Setup instructions reference `TestVectorSetup.ensure_test_vectors()`

## What We're NOT Doing

- Changing the overall structure of the command files
- Adding new commands or capabilities
- Modifying the harness implementation itself
- Changing test file organization

## Implementation Approach

Update each file sequentially, ensuring consistent patterns across all three. Each phase is independent but sequential execution allows for pattern consistency verification.

---

## Phase 1: Update research_issue.md

### Overview
Replace the generic test-vector-researcher prompt and Test Vectors output template with harness-aware patterns.

### Changes Required

#### 1. Update test-vector-researcher agent prompt (lines 53-58)

**File**: `.claude/commands/research_issue.md`
**Current** (lines 53-58):
```markdown
4. **test-vector-researcher**: Find applicable test vectors
   ```
   Prompt: Find test vectors applicable to [feature].
   List specific test vector IDs, organized by complexity.
   Note which vectors should be implemented first.
   ```
```

**New**:
```markdown
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
```

#### 2. Update Test Vectors output template (lines 113-147)

**File**: `.claude/commands/research_issue.md`
**Current** (lines 113-147):
```markdown
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
```

**New**:
```markdown
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
```

### Success Criteria

#### Automated Verification:
- [x] File saves without syntax errors
- [x] Markdown renders correctly (no broken code blocks)

#### Manual Verification:
- [x] Test vector harness patterns match actual API in `test/support/test_vector_harness.ex`
- [x] Setup instructions match `test/support/test_vector_setup.ex`

---

## Phase 2: Update create_plan.md

### Overview
Add harness setup code to test vector template sections and update success criteria to reference harness-based testing.

### Changes Required

#### 1. Update Test Vector Summary table (lines 184-195)

**File**: `.claude/commands/create_plan.md`
**Current** (lines 184-195):
```markdown
## Test Vectors

### Validation Strategy
Each phase includes specific test vectors to validate the implementation.

### Test Vector Summary
| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | `test-001`, `test-002` | Basic functionality |
| 2 | `test-003`, `test-004` | Extended coverage |
| 3 | `edge-001`, `negative-001` | Edge cases |
```

**New**:
```markdown
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
```

#### 2. Update per-phase test vector table (lines 227-232)

**File**: `.claude/commands/create_plan.md`
**Current** (lines 227-232):
```markdown
### Test Vectors for This Phase
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `test-001` | Basic encrypt/decrypt | Success |
| `test-002` | Different key size | Success |
```

**New**:
```markdown
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
```

#### 3. Update success criteria template (lines 243-254)

**File**: `.claude/commands/create_plan.md`
**Current** (lines 245-248):
```markdown
#### Automated Verification:
- [ ] Tests pass: `mix quality --quick`
- [ ] Test vector `test-001` passes
- [ ] Test vector `test-002` passes
```

**New**:
```markdown
#### Automated Verification:
- [ ] Tests pass: `mix quality --quick`
- [ ] Test vectors pass: `mix test --only test_vectors`
- [ ] Specific vectors validated: `[actual-test-id-1]`, `[actual-test-id-2]`
```

#### 4. Update Test Vector Integration section (lines 282-284)

**File**: `.claude/commands/create_plan.md`
**Current** (lines 282-284):
```markdown
### Test Vector Integration:
- [How test vectors will be used]
- [Which vectors validate which features]
```

**New**:
```markdown
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
```

#### 5. Update guidelines about test vectors (lines 343-347)

**File**: `.claude/commands/create_plan.md`
**Current** (lines 343-347):
```markdown
4. **Include Test Vectors**:
   - Every phase should have specific test vectors to validate
   - Order test vectors by complexity (simple first)
   - Include both positive and negative test cases
   - Note which spec requirements each test vector validates
```

**New**:
```markdown
4. **Include Test Vectors**:
   - Every phase should have specific test vectors to validate
   - Use actual test IDs from the harness manifest (not placeholders)
   - Order test vectors by complexity (simple first)
   - Include both positive (`result: :success`) and negative (`result: :error`) test cases
   - Note which spec requirements each test vector validates
   - Reference `mix test --only test_vectors` for running test vector tests
```

### Success Criteria

#### Automated Verification:
- [x] File saves without syntax errors
- [x] Markdown renders correctly

#### Manual Verification:
- [x] Harness patterns are consistent with Phase 1 updates
- [x] Code examples compile conceptually (correct function calls)

---

## Phase 3: Update implement_plan.md

### Overview
Replace the `File.read!` example with harness API calls, add harness debugging patterns, and update verification output format.

### Changes Required

#### 1. Replace File.read! test vector example (lines 129-145)

**File**: `.claude/commands/implement_plan.md`
**Current** (lines 129-145):
```markdown
## Test Vector Integration

Plans include specific test vectors for each phase. Use them to:

1. **Validate correctness**: Test vectors ensure interoperability with other SDKs
2. **Guide implementation**: If a test vector fails, it points to what needs fixing
3. **Track progress**: Each passing test vector is concrete progress

When implementing:

```elixir
# Example: Running a specific test vector
test "passes test vector aes-256-gcm-001" do
  # Load test vector data
  ciphertext = File.read!("test/vectors/ciphertext-001")
  expected_plaintext = File.read!("test/vectors/plaintext-001")
  key = Base.decode64!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")

  # Run decryption
  {:ok, plaintext} = AwsEncryptionSdk.decrypt(ciphertext, keyring: keyring)

  # Verify
  assert plaintext == expected_plaintext
end
```
```

**New**:
```markdown
## Test Vector Integration

Plans include specific test vectors for each phase. Use them to:

1. **Validate correctness**: Test vectors ensure interoperability with other SDKs
2. **Guide implementation**: If a test vector fails, it points to what needs fixing
3. **Track progress**: Each passing test vector is concrete progress

### Test Vector Harness Usage

Test vectors are accessed through the harness API:

```elixir
alias AwsEncryptionSdk.TestSupport.TestVectorHarness
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

# Module setup for test vector tests
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()

setup_all do
  case TestVectorSetup.find_manifest("**/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil}
  end
end

# Example: Running a specific test vector
test "passes test vector", %{harness: harness} do
  test_id = "specific-test-id-from-manifest"

  # Load test vector data via harness
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  {:ok, expected_plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)

  # Get key material if needed
  {:ok, test_case} = TestVectorHarness.get_test(harness, test_id)
  [master_key | _] = test_case.master_keys
  {:ok, key_data} = TestVectorHarness.get_key(harness, master_key["key"])
  {:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)

  # Run decryption (when implemented)
  {:ok, plaintext} = AwsEncryptionSdk.decrypt(ciphertext, keyring: keyring)

  # Verify
  assert plaintext == expected_plaintext
end
```

### Running Test Vector Tests

```bash
# Run all test vector tests
mix test --only test_vectors

# Run with verbose output
mix test --only test_vectors --trace
```
```

#### 2. Update verification output format (lines 63-66)

**File**: `.claude/commands/implement_plan.md`
**Current** (lines 63-66):
```markdown
   Automated verification passed:
   - mix quality --quick: OK
   - Test vector `test-001`: PASS
   - Test vector `test-002`: PASS
```

**New**:
```markdown
   Automated verification passed:
   - mix quality --quick: OK
   - Test vectors: `mix test --only test_vectors` PASS
   - Specific vectors validated: [list actual test IDs from plan]
```

#### 3. Update debugging mention (line 106)

**File**: `.claude/commands/implement_plan.md`
**Current** (line 106):
```markdown
- Check if test vectors are providing useful debugging information
```

**New**:
```markdown
- Check if test vectors are providing useful debugging information:
  - Use `TestVectorHarness.parse_ciphertext/1` to inspect message structure
  - Use `TestVectorHarness.get_test/2` to see test case details and expected results
```

### Success Criteria

#### Automated Verification:
- [x] File saves without syntax errors
- [x] Markdown renders correctly

#### Manual Verification:
- [x] Harness patterns are consistent with Phases 1 and 2
- [x] All three files use identical harness setup patterns
- [x] Code examples match actual harness API signatures

---

## Final Verification

After all phases complete:

### Automated:
- [x] All three files save without errors
- [x] `mix quality --quick` passes (no impact on code)

### Manual:
- [x] Patterns are consistent across all three command files
- [x] Harness API usage matches `test/support/test_vector_harness.ex`
- [x] Setup patterns match `test/test_vectors/decrypt_test.exs`
- [x] No references to old patterns (`File.read!`, curl commands, placeholder IDs) remain

## Testing Strategy

### Validation Approach:
Since these are markdown documentation files, testing is manual:

1. Review each file for markdown syntax errors
2. Verify code blocks are properly formatted
3. Check that API function names match actual implementation
4. Ensure consistency across all three files

### Consistency Checklist:
- [x] All files use `TestVectorSetup.vectors_available?()` for availability check
- [x] All files use `TestVectorSetup.find_manifest/1` for manifest discovery
- [x] All files use `TestVectorHarness.load_manifest/1` for loading
- [x] All files reference `mix test --only test_vectors` for running tests

## References

- Issue: #17
- Research: `thoughts/shared/research/2026-01-25-GH17-claude-commands-test-vector-harness.md`
- Test Vector Harness: `test/support/test_vector_harness.ex`
- Test Vector Setup: `test/support/test_vector_setup.ex`
- Usage Example: `test/test_vectors/decrypt_test.exs`
