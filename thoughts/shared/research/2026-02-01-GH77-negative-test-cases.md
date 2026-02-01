# Research: Implement Negative Test Case Validation (Error Vectors)

**Issue**: #77 - Implement Negative Test Case Validation (Error Vectors)
**Date**: 2026-02-01
**Status**: Research complete

## Issue Summary

Implement validation for all ~4,903 error test vectors to ensure the SDK correctly rejects invalid ciphertexts, tampered data, and other error scenarios. Currently **zero error test vectors are executed**. For a production-ready v1.0.0, we must validate that the SDK fails safely and correctly on all known bad inputs.

### Error Vector Distribution
| Category | Approx Count | Description |
|----------|--------------|-------------|
| Bit flip errors | 3,768 | Single bit flips in ciphertext (76.9%) |
| Incorrect KMS ARN | 639 | Malformed AWS KMS ARN (13.0%) |
| Truncation errors | 470 | Message truncated at various byte positions (9.6%) |
| API mismatch | 1 | Signed message to unsigned-only API (<0.1%) |
| Other | ~25 | Miscellaneous edge cases (0.5%) |

## Current Implementation State

### Existing Code

#### Test Vector Infrastructure
- `test/support/test_vector_harness.ex` - Main test vector harness module
- `test/support/test_vector_setup.ex` - Setup and path utilities
- `test/test_vectors/full_decrypt_test.exs` - Full decrypt test suite (**success cases only**)
- `test/test_vectors/decrypt_test.exs` - Basic decrypt test vectors

#### Decrypt Implementation
- `lib/aws_encryption_sdk/decrypt.ex` - Core decrypt with error handling
- `lib/aws_encryption_sdk/client.ex` - Client-level decrypt API with validation

#### Test Vector Data
- `test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json` - Test vector manifest
- `test/fixtures/test_vectors/vectors/awses-decrypt/keys.json` - Test vector keys
- `test/fixtures/test_vectors/vectors/awses-decrypt/ciphertexts/` - 100+ ciphertext files

### Relevant Patterns

#### Test Vector Harness Filtering (test/support/test_vector_harness.ex)

The harness already provides filtering helpers for error tests:

```elixir
# Line 302 - Filter to error tests only
def error_tests(%__MODULE__{tests: tests}) do
  Enum.filter(tests, fn {_id, test} -> test.result == :error end)
end

# Line 294 - Filter to success tests only
def success_tests(%__MODULE__{tests: tests}) do
  Enum.filter(tests, fn {_id, test} -> test.result == :success end)
end

# Line 310 - Filter to non-KMS keys
def raw_key_tests(tests) do
  Enum.filter(tests, fn {_id, test} ->
    Enum.all?(test.master_keys, fn mk -> mk["type"] != "aws-kms" end)
  end)
end
```

#### Error Test Case Structure

Error tests are identified in manifest by `result.error` instead of `result.output`:

```json
{
  "test-id": {
    "ciphertext": "file://ciphertexts/061f37ec-2433-4ff8-9fbb-4ab98ee100ef",
    "master-keys": [...],
    "result": {
      "error": {
        "error-description": "Bit 0 flipped"
      }
    }
  }
}
```

#### Full Decrypt Test Pattern (test/test_vectors/full_decrypt_test.exs)

```elixir
def run_full_decrypt_test(harness, test_id) do
  {:ok, test} = TestVectorHarness.get_test(harness, test_id)
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  {:ok, message} = Message.deserialize(ciphertext)

  keyring = build_keyring_from_master_keys(harness, test.master_keys, message.header.encrypted_data_keys)

  result = Client.decrypt_with_keyring(keyring, ciphertext,
    commitment_policy: :require_encrypt_allow_decrypt
  )

  # For success tests: assert {:ok, %{plaintext: expected}}
  # For error tests: assert {:error, _reason} = result
end
```

### Dependencies

- Test vectors must be downloaded to `test/fixtures/test_vectors/`
- Uses existing keyring builders (`build_keyring_from_master_keys/3`)
- Depends on `Client.decrypt_with_keyring/3` for execution

## Specification Requirements

### Source Documents
- [client-apis/decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Primary decrypt operation
- [client-apis/client.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md) - Client configuration, commitment policy
- [framework/keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring error conditions
- [framework/cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - CMM error conditions
- [data-format/message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md) - Header validation
- [data-format/message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md) - Body authentication
- [data-format/message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md) - Signature verification

### MUST Requirements

1. **Unauthenticated Data Protection** (decrypt.md)
   > "This operation MUST NOT release any unauthenticated plaintext or unauthenticated associated data."

   Implementation: Never return plaintext before all authentication checks pass.

2. **Immediate Halt on Tag Verification Failure** (decrypt.md)
   > "If this tag verification fails, this operation MUST immediately halt and fail."

   Implementation: Return error immediately when any authentication tag fails.

3. **Immediate Halt on Signature Verification Failure** (decrypt.md)
   > "If this verification is not successful, this operation MUST immediately halt and fail."

   Implementation: For signed suites, halt immediately if signature verification fails.

4. **Commitment Key Validation** (decrypt.md)
   > "If the algorithm suite supports key commitment, the derived commit key MUST equal the commit key stored in the message header."

   Implementation: Fail if derived commitment key doesn't match stored value.

5. **Commitment Policy Enforcement** (client.md, decrypt.md)
   > "decrypt MUST yield an error" if algorithm suite doesn't satisfy commitment policy.

   Implementation: Reject non-committed suites when policy is `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`.

6. **EDK Count Limit** (decrypt.md)
   > "MUST process no more bytes and yield an error" if EDK count exceeds configured maximum.

   Implementation: Fail before attempting to process EDKs if limit exceeded.

7. **Keyring Decryption Failure** (keyring-interface.md)
   > "If the keyring is unable to get any plaintext data key using the input encrypted data keys, the keyring MUST NOT update the decryption materials and MUST return failure."

   Implementation: Return error if no keyring can decrypt any EDK.

### SHOULD Requirements

1. **Base64 Detection** (decrypt.md)
   > "Implementations SHOULD detect base64-encoded messages and fail with specific error messages."

   Implementation: Detect "AQ" or "Ag" prefixes (base64 of version bytes).

2. **Descriptive Errors** (keyring-interface.md)
   > "Keyrings SHOULD return descriptive error information when operations fail."

   Implementation: Provide specific error messages for debugging.

### Error Types Returned by Current Implementation

From `lib/aws_encryption_sdk/decrypt.ex`:
- `:base64_encoded_message` - Message appears Base64 encoded
- `:header_authentication_failed` - Header auth tag invalid
- `:commitment_mismatch` - Key commitment verification failed
- `:body_authentication_failed` - Frame/body auth tag invalid
- `:signature_verification_failed` - Footer signature invalid
- `:missing_verification_key` - Signed suite but no verification key

From `lib/aws_encryption_sdk/client.ex`:
- `:commitment_policy_requires_committed_suite` - Algorithm suite validation
- `:too_many_encrypted_data_keys` - EDK count limit exceeded

## Test Vectors

### Harness Setup

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Load manifest
manifest_path = "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# Get error tests
error_tests = TestVectorHarness.error_tests(harness)
# => [{test_id, %{result: :error, error_description: "...", ...}}]

# Filter to raw key tests (exclude KMS)
raw_error_tests = TestVectorHarness.raw_key_tests(error_tests)
```

### Applicable Test Vector Sets

**Total Error Tests**: ~4,903 vectors

| Category | Count | Description |
|----------|-------|-------------|
| Bit flip errors | 3,768 | Tests every bit position 0-3767 for authentication validation |
| Incorrect KMS ARN | 639 | Malformed ARNs in EDK provider info |
| Truncation errors | 470 | Message truncated at bytes 1-470 |
| API mismatch | 1 | Signed message to unsigned-only API |

### Implementation Order

#### Phase 1: Core Error Handling (Start Here)

| Test ID | Category | Description | Priority |
|---------|----------|-------------|----------|
| `b2510a07-dc9e-48e0-ba2c-12d2c27af7ff` | Truncation | Truncated at byte 1 | First - tests parser |
| `87e90659-908b-4802-97fd-9b7581ba2131` | Truncation | Truncated at byte 2 | Parser robustness |
| `061f37ec-2433-4ff8-9fbb-4ab98ee100ef` | Bit flip | Bit 0 flipped | Tests authentication |
| `42db66aa-92dc-47c0-a916-8c59b098181a` | Bit flip | Bit 1 flipped | Authentication tag |
| `3e49cfb0-1348-448a-ba09-7f4d0c34289c` | Bit flip | Bit 2 flipped | Authentication tag |
| `b3514aca-0eeb-45ea-b120-c29958a5fa4b` | Bit flip | Bit 3 flipped | Authentication tag |

#### Phase 2: Comprehensive Bit Flip Coverage

Run sample of bit flip tests (e.g., every 100th bit):
- Bits 0, 100, 200, 300, ... 3700

Then optionally run full 3,768 bit flip suite.

#### Phase 3: KMS-Specific (if applicable)

| Category | Count | When to Test |
|----------|-------|--------------|
| Incorrect KMS ARN | 639 | When testing KMS keyring |

#### Phase 4: Edge Cases

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `fe0a0327-a701-47f9-a42e-8ec7744161ab` | Signed message to unsigned-only API | Error |

### Test Vector Setup

If test vectors are not present, run:

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

#### 1. Create New Error Test File

Create `test/test_vectors/error_decrypt_test.exs` following the pattern from `full_decrypt_test.exs`:

```elixir
defmodule AwsEncryptionSdk.TestVectors.ErrorDecryptTest do
  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.TestVectors.TestVectorHarness

  @moduletag :test_vectors
  @moduletag :error_vectors

  setup_all do
    case TestVectorHarness.load_manifest(manifest_path()) do
      {:ok, harness} -> {:ok, harness: harness}
      {:error, reason} -> {:ok, harness: nil, load_error: reason}
    end
  end

  describe "error test vectors" do
    @tag timeout: 600_000
    test "all raw key error tests", %{harness: harness} do
      error_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()

      results = for {test_id, test} <- error_tests do
        result = run_error_decrypt_test(harness, test_id)

        case result do
          {:error, _reason} -> {:pass, test_id}
          {:ok, _} -> {:fail_unexpected_success, test_id, test.error_description}
          other -> {:fail_crash, test_id, other}
        end
      end

      # Assert all tests returned errors (not successes)
      failures = Enum.reject(results, fn {status, _} -> status == :pass end)
      assert failures == [], "Expected all error tests to fail, got: #{inspect(failures)}"
    end
  end

  defp run_error_decrypt_test(harness, test_id) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

    case build_keyring(harness, test) do
      {:ok, keyring} ->
        Client.decrypt_with_keyring(keyring, ciphertext,
          commitment_policy: :require_encrypt_allow_decrypt
        )
      {:error, reason} ->
        # Some errors occur before keyring can be built
        {:error, reason}
    end
  end
end
```

#### 2. Reuse Existing Helpers

From `full_decrypt_test.exs`:
- `build_keyring_from_master_keys/3` - Builds keyrings from test vector specs
- `build_single_keyring/3` - Builds individual AES/RSA keyrings
- `extract_aes_key_name/2` - Extracts key name from EDK
- `extract_rsa_key_name/2` - Extracts RSA key name from EDK
- `parse_rsa_padding/1` - Parses RSA padding algorithm

#### 3. Error Categorization

Track errors by category for reporting:

```elixir
defp categorize_error_test(test) do
  cond do
    String.match?(test.error_description || "", ~r/^Bit \d+ flipped$/) -> :bit_flip
    String.match?(test.error_description || "", ~r/Truncated/) -> :truncation
    String.contains?(test.error_description || "", "ARN") -> :kms_arn
    String.contains?(test.error_description || "", "streaming unsigned") -> :api_mismatch
    true -> :other
  end
end
```

### Potential Challenges

1. **Performance**: 4,903 tests will take significant time. Consider:
   - Running in phases with `@tag :slow`
   - Parallel execution with `async: true` where possible
   - Sample-based testing for CI, full suite for releases

2. **KMS Tests**: 639 KMS ARN tests require AWS KMS integration. May need to:
   - Skip for Raw AES/RSA-only runs
   - Use mock KMS client for ARN validation testing

3. **Error Reason Matching**: Test vectors describe errors generically ("Bit 0 flipped"). We should:
   - Assert `{:error, _reason}` rather than matching specific atoms
   - Ensure no plaintext is ever returned
   - Focus on "fails correctly" not "fails with exact error"

4. **Crash vs Error**: Ensure tampering causes graceful `{:error, reason}` not crashes:
   - Wrap decrypt in try/catch for crash detection
   - Report crashes separately from error returns

### Open Questions

1. **Should we match specific error reasons to categories?**
   - e.g., bit flip -> `:body_authentication_failed` or `:header_authentication_failed`
   - Trade-off: More validation vs. more brittle tests

2. **How to handle tests that require AWS KMS?**
   - Skip 639 KMS tests when not testing KMS keyring?
   - Use mock KMS client that validates ARN format?

3. **Performance optimization for CI?**
   - Run all 4,903 tests on every push?
   - Use sample-based testing for PRs, full suite for main?

## Recommended Next Steps

1. **Create implementation plan**: `/create_plan thoughts/shared/research/2026-02-01-GH77-negative-test-cases.md`

2. **Start with truncation tests** - Simplest category, tests parser robustness

3. **Add bit flip sample** - 20-50 representative bit positions

4. **Expand to full suite** - All 3,768 bit flip tests

5. **Add category tracking** - Report pass/fail by error category

6. **Performance optimization** - Add tags for CI vs. release testing

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/77
- Decrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- Test Vector Framework: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
