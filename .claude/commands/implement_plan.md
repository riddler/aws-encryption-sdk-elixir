---
description: Implement technical plans from thoughts/shared/plans with verification
model: sonnet
---

# Implement Plan

You are tasked with implementing an approved technical plan from `thoughts/shared/plans/`. These plans contain phases with specific changes, spec requirements, test vectors, and success criteria.

## Getting Started

When given a plan path:

- Read the plan completely and check for any existing checkmarks (- [x])
- Read the original issue (if referenced) and all files mentioned in the plan
- **Read files fully** - never use limit/offset parameters, you need complete context
- Think deeply about how the pieces fit together
- Start implementing if you understand what needs to be done

If no plan path provided, ask for one.

## Implementation Philosophy

Plans are carefully designed, but reality can be messy. Your job is to:

- Follow the plan's intent while adapting to what you find
- Implement each phase fully before moving to the next
- Verify your work makes sense in the broader codebase context
- Update checkboxes in the plan as you complete sections
- **Validate against test vectors** specified for each phase
- **Write doctests** for new public functions to provide usage examples

When things don't match the plan exactly, think about why and communicate clearly. The plan is your guide, but your judgment matters too.

If you encounter a mismatch:

- STOP and think deeply about why the plan can't be followed
- Present the issue clearly:

  ```
  Issue in Phase [N]:
  Expected: [what the plan says]
  Found: [actual situation]
  Why this matters: [explanation]

  How should I proceed?
  ```

## Verification Approach

### After Each Phase

1. Run `mix quality --quick` for fast feedback
2. Verify test vectors specified for this phase pass (if applicable)
3. Fix any issues before proceeding
4. Update your progress in both the plan and your todos
5. Check off completed items in the plan file itself using Edit
6. **Pause for human verification**: After completing all automated verification for a phase, pause and inform the human:

   ```
   Phase [N] Complete - Ready for Manual Verification

   Automated verification passed:
   - mix quality --quick: OK
   - Test vectors: `mix test --only test_vectors` PASS
   - Specific vectors validated: [list actual test IDs from plan]

   Please perform the manual verification steps listed in the plan:
   - [List manual verification items from the plan]

   Let me know when manual testing is complete so I can proceed to Phase [N+1].
   ```

If instructed to execute multiple phases consecutively, skip the pause until the last phase. Otherwise, assume you are just doing one phase.

Do not check off items in the manual testing steps until confirmed by the user.

### After All Phases Complete

1. Run `mix quality` for full verification
2. Verify ALL test vectors from the plan pass
3. Present final summary:

   ```
   Implementation Complete

   All phases completed:
   - Phase 1: [description] - DONE
   - Phase 2: [description] - DONE
   - Phase 3: [description] - DONE

   Final verification:
   - mix quality: PASS
   - All test vectors: PASS

   Manual verification needed:
   - [List final manual verification items]
   ```

## If You Get Stuck

When something isn't working as expected:

- First, make sure you've read and understood all the relevant code
- Consider if the codebase has evolved since the plan was written
- Check if test vectors are providing useful debugging information:
  - Use `TestVectorHarness.parse_ciphertext/1` to inspect message structure
  - Use `TestVectorHarness.get_test/2` to see test case details and expected results
- Present the mismatch clearly and ask for guidance

Use sub-tasks sparingly - mainly for targeted debugging or exploring unfamiliar territory.

## Resuming Work

If the plan has existing checkmarks:

- Trust that completed work is done
- Pick up from the first unchecked item
- Verify previous work only if something seems off

Remember: You're implementing a solution, not just checking boxes. Keep the end goal in mind and maintain forward momentum.

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

## Doctest Guidelines

When implementing new public functions, add doctests in the `@doc` block:

```elixir
@doc """
Encrypts plaintext using the provided keyring.

## Examples

    iex> keyring = AwsEncryptionSdk.Keyring.RawAes.new(key: key, namespace: "test", name: "key1")
    iex> {:ok, ciphertext} = AwsEncryptionSdk.encrypt("hello", keyring: keyring)
    iex> is_binary(ciphertext)
    true

"""
```

**Doctest benefits:**
- Examples serve as both documentation AND tests
- Ensures documentation stays accurate
- Run automatically with `mix test`

**When to use doctests vs separate tests:**
- **Doctests**: Simple examples, happy paths, basic usage
- **Separate tests**: Complex scenarios, test vectors, edge cases, mocking required

## Spec Compliance

Plans reference spec requirements. As you implement:

1. Keep the spec requirement in mind
2. Note any deviations and why
3. Update the plan with any spec clarifications discovered

## Quality Commands

| When | Command | Purpose |
|------|---------|---------|
| After each phase | `mix quality --quick` | Fast feedback |
| After all phases | `mix quality` | Full verification |

## Important Notes

- NEVER skip test vector validation if specified in the plan
- ALWAYS update checkboxes as you complete items
- ALWAYS pause for manual verification between phases (unless told otherwise)
- Keep the spec requirements in mind while implementing
- Write clean, idiomatic Elixir code
- Add doctests for new public functions
