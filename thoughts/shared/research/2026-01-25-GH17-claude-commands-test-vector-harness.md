# Research: Update Claude commands to incorporate test vector harness

**Issue**: #17 - Update Claude commands to incorporate test vector harness
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Update the `/research_issue`, `/create_plan`, and `/implement_plan` Claude commands to leverage the new test vector harness infrastructure implemented in PR #16. The current commands reference test vectors abstractly with placeholder IDs and manual file operations, while a comprehensive harness API now exists.

## Current Implementation State

### Existing Code

The three command files that need updating:

- `.claude/commands/research_issue.md` - References test-vector-researcher agent and includes test vector output template
- `.claude/commands/create_plan.md` - Includes test vector sections in plan templates with placeholder examples
- `.claude/commands/implement_plan.md` - Shows manual file reading for test vector execution

### Test Vector Harness Implementation

The harness implementation from PR #16:

- `test/support/test_vector_harness.ex:1-286` - Main harness module with complete API
- `test/support/test_vector_setup.ex:1-79` - Setup utilities and availability checking
- `test/test_vectors/decrypt_test.exs:1-226` - Example usage patterns

### Current Test Vector References

**research_issue.md**:
- Lines 53-58: test-vector-researcher agent prompt (generic)
- Lines 113-147: Test Vectors output template with placeholder test IDs
- Lines 140-143: Curl commands for manual download

**create_plan.md**:
- Lines 184-195: Test vector summary table template
- Lines 227-232: Per-phase test vector table
- Lines 247-248: Success criteria with generic "test-001" references
- Lines 282-284: Test Vector Integration section (abstract)
- Lines 343-347: Guidelines about test vectors

**implement_plan.md**:
- Lines 131-145: Code example showing `File.read!("test/vectors/ciphertext-001")`
- Lines 54, 65-66: Verification checkboxes with generic test vector references
- Line 106: Debugging mention of test vectors

### Relevant Patterns

From `test/test_vectors/decrypt_test.exs`, the established patterns are:

1. **Module tags for conditional skipping**:
```elixir
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()
```

2. **setup_all with harness loading**:
```elixir
setup_all do
  case TestVectorSetup.find_manifest("**/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil, load_error: :manifest_not_found}
  end
end
```

3. **Iterating test cases with filtering**:
```elixir
success_tests =
  harness.tests
  |> Enum.filter(fn {_id, test} -> test.result == :success end)
  |> Enum.take(10)
```

### Dependencies

- PR #16 (merged) - Test vector harness implementation
- `AwsEncryptionSdk.Format.Message` - Used by `TestVectorHarness.parse_ciphertext/1`
- `AwsEncryptionSdk.AlgorithmSuite` - Used for filtering by algorithm properties

## Test Vector Harness Public API

### TestVectorHarness Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `load_manifest/1` | `(String.t()) :: {:ok, t()} \| {:error, term()}` | Load decrypt manifest and keys |
| `list_test_ids/1` | `(t()) :: [String.t()]` | List all test IDs |
| `get_test/2` | `(t(), String.t()) :: {:ok, test_case()} \| :not_found` | Get test case metadata |
| `load_ciphertext/2` | `(t(), String.t()) :: {:ok, binary()} \| {:error, term()}` | Load ciphertext binary |
| `load_expected_plaintext/2` | `(t(), String.t()) :: {:ok, binary()} \| {:error, term()}` | Load expected plaintext |
| `parse_ciphertext/1` | `(binary()) :: {:ok, map()} \| {:error, term()}` | Parse message structure |
| `get_key/2` | `(t(), String.t()) :: {:ok, map()} \| :not_found` | Get key material metadata |
| `decode_key_material/1` | `(map()) :: {:ok, binary()} \| {:error, term()}` | Decode key by encoding type |
| `resolve_uri/2` | `(String.t(), String.t()) :: String.t()` | Resolve file:// URIs |

### TestVectorSetup Functions

| Function | Signature | Purpose |
|----------|-----------|---------|
| `test_vectors_path/0` | `() :: String.t()` | Returns base path for test vectors |
| `vectors_available?/0` | `() :: boolean()` | Check if vectors are present |
| `find_manifest/1` | `(String.t()) :: {:ok, String.t()} \| :not_found` | Find manifest by pattern |
| `print_setup_instructions/0` | `() :: :ok` | Print download instructions |
| `ensure_test_vectors/0` | `() :: :available \| :not_available` | Check and print instructions if missing |

### Data Structures

**Harness Struct**:
```elixir
%TestVectorHarness{
  manifest_path: String.t(),
  base_dir: String.t(),
  manifest_type: "awses-decrypt",
  manifest_version: 2 | 3 | 4,
  client_info: map() | nil,
  keys: %{key_id => key_data},
  tests: %{test_id => test_case}
}
```

**Test Case**:
```elixir
%{
  description: String.t(),
  ciphertext_path: String.t(),
  master_keys: [map()],
  result: :success | :error,
  expected_plaintext_path: String.t() | nil,
  error_description: String.t() | nil
}
```

## Implementation Considerations

### Technical Approach

Each command file needs specific updates:

**research_issue.md**:
1. Update test-vector-researcher agent prompt to use harness API
2. Replace Test Vectors template section with harness-based examples
3. Replace curl commands with `TestVectorSetup` references

**create_plan.md**:
1. Add harness setup code to Test Vectors template section
2. Update per-phase test vector tables to show harness usage
3. Update success criteria to reference `mix test --only test_vectors`
4. Replace Test Vector Integration section with concrete API examples
5. Update guidelines to mention harness discovery

**implement_plan.md**:
1. Replace `File.read!` example with harness API calls
2. Update verification output format to show harness test results
3. Add harness debugging patterns
4. Add new "Test Vector Harness Setup" section with complete patterns

### Key Changes Summary

| Current Pattern | New Pattern |
|-----------------|-------------|
| `File.read!("test/vectors/ciphertext-001")` | `TestVectorHarness.load_ciphertext(harness, test_id)` |
| `Base.decode64!("...")` | `TestVectorHarness.decode_key_material(key_data)` |
| Placeholder `test-001`, `test-id-1` | Actual test IDs from manifest |
| Curl download commands | `TestVectorSetup.ensure_test_vectors()` |
| Generic "test vectors pass" | `mix test --only test_vectors` |

### Potential Challenges

1. **Documentation length**: Adding concrete examples may significantly increase file sizes
2. **Consistency**: Need to ensure all three files use identical patterns for harness usage
3. **Example maintenance**: Code examples must match actual harness implementation

### Open Questions

None - the harness API is well-documented and usage patterns are established in `decrypt_test.exs`.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-25-GH17-claude-commands-test-vector-harness.md`
2. Update each command file in sequence, validating consistency

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/17
- Test Vector Harness: `test/support/test_vector_harness.ex`
- Test Vector Setup: `test/support/test_vector_setup.ex`
- Usage Example: `test/test_vectors/decrypt_test.exs`
- PR #16: Test vector harness implementation
