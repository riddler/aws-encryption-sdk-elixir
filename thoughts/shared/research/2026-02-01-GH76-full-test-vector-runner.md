# Research: Implement Full Test Vector Runner for Success Cases

**Issue**: #76 - Implement Full Test Vector Runner for Success Cases
**Date**: 2026-02-01
**Status**: Research complete

## Issue Summary

Implement a comprehensive test vector runner that executes all ~4,186 success test vectors from the AWS Encryption SDK test vector suite. Currently only 16 hardcoded test cases are executed (0.2% coverage), testing only keyring unwrap operations rather than full end-to-end decryption.

**Key Requirements**:
- Execute full `AwsEncryptionSdk.decrypt/3` flow (not just keyring unwrap)
- Validate plaintext matches expected output
- Validate encryption context is preserved
- Support all non-KMS key types (Raw AES, Raw RSA, Multi-keyring)
- Skip gracefully when vectors not downloaded
- Add algorithm suite coverage matrix

## Current Implementation State

### Existing Code

| File | Purpose | Status |
|------|---------|--------|
| `test/support/test_vector_harness.ex` | Manifest loading, test data access, key decoding | Complete |
| `test/support/test_vector_setup.ex` | Vector availability checking, setup instructions | Complete |
| `test/test_vectors/decrypt_test.exs` | Structure validation tests | Partial |
| `test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs` | 4 hardcoded AES tests | Keyring-only |
| `test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs` | 5 hardcoded RSA tests | Keyring-only |
| `test/aws_encryption_sdk/keyring/multi_test_vectors_test.exs` | 7 hardcoded multi tests | Keyring-only |
| `test/aws_encryption_sdk/cmm/default_test_vectors_test.exs` | 3 CMM tests | CMM-only |

**Total currently tested**: 16 hardcoded test vectors (keyring/CMM layer only)

### Relevant Patterns

#### Harness API (test_vector_harness.ex)

```elixir
# Load manifest
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List all test IDs
test_ids = TestVectorHarness.list_test_ids(harness)

# Get test case details
{:ok, test_case} = TestVectorHarness.get_test(harness, test_id)
# Returns: %{result: :success | :error, master_keys: [...], ciphertext_path: "...", ...}

# Load test data
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, expected_plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)

# Get and decode key material
{:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
{:ok, raw_bytes} = TestVectorHarness.decode_key_material(key_data)
```

#### Keyring Creation Pattern (from default_test_vectors_test.exs:121-149)

```elixir
defp create_keyring_from_test(harness, %{"type" => "raw"} = master_key) do
  key_id = master_key["key"]
  {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)

  case master_key["encryption-algorithm"] do
    "aes" ->
      {:ok, key_bytes} = TestVectorHarness.decode_key_material(key_data)
      wrapping_alg = case byte_size(key_bytes) do
        16 -> :aes_128
        24 -> :aes_192
        32 -> :aes_256
      end
      RawAes.new(
        master_key["provider-id"],
        master_key["key"],
        key_bytes,
        wrapping_alg
      )

    "rsa" ->
      {:ok, pem} = TestVectorHarness.decode_key_material(key_data)
      padding = parse_rsa_padding(master_key)
      RawRsa.new(
        master_key["provider-id"],
        master_key["key"],
        pem,
        padding
      )
  end
end
```

#### RSA Padding Mapping

```elixir
defp parse_rsa_padding(%{"padding-algorithm" => "pkcs1"}), do: :pkcs1_v1_5
defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha256"}), do: {:oaep, :sha256}
defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha1"}), do: {:oaep, :sha1}
defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha384"}), do: {:oaep, :sha384}
defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha512"}), do: {:oaep, :sha512}
```

### Dependencies

| Component | Required For | Status |
|-----------|--------------|--------|
| TestVectorHarness | Loading manifests/test data | Complete |
| RawAes keyring | AES key unwrapping | Complete |
| RawRsa keyring | RSA key unwrapping | Complete |
| Multi keyring | Multi-key scenarios | Complete |
| Default CMM | Materials management | Complete |
| Client.decrypt/3 | Full decrypt flow | Complete |
| Decrypt.decrypt/2 | Materials-based decrypt | Complete |

## Specification Requirements

### Source Documents
- [0004-awses-message-decryption.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md) - Decrypt manifest format
- [0002-keys.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0002-keys.md) - Keys manifest format
- [client-apis/decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Decrypt operation

### MUST Requirements

1. **Manifest Version Support** (0004-awses-message-decryption.md)
   > Implementations MUST identify which manifest versions they support.

   Implementation: Support decrypt manifest versions 2, 3, 4 and keys manifest version 3.

2. **URI Resolution** (Framework spec)
   > Implementations MUST resolve `file://` URIs relative to the parent directory of the manifest file.

   Implementation: Already handled by `TestVectorHarness.resolve_uri/2`.

3. **Success Test Validation** (0004-awses-message-decryption.md)
   > For success cases: MUST validate that decryption produces the expected plaintext.

   Implementation: Compare `result.plaintext` with loaded expected plaintext byte-for-byte.

4. **Failure Test Validation** (0004-awses-message-decryption.md)
   > For error cases: MUST verify that decryption fails (exact error message is NOT validated).

   Implementation: Assert `{:error, _reason}` is returned; error description is informational only.

5. **No Unauthenticated Plaintext** (decrypt.md)
   > This operation MUST NOT release any unauthenticated plaintext or unauthenticated associated data.

   Implementation: Full decrypt verifies header auth tag, frame auth tags, and signature before returning plaintext.

6. **Commitment Policy Enforcement** (client.md)
   > Default commitment policy MUST be REQUIRE_ENCRYPT_REQUIRE_DECRYPT.

   Implementation: Use `:require_encrypt_allow_decrypt` for test vectors (allows decryption of non-committed legacy messages).

### SHOULD Requirements

1. **Graceful Degradation**
   > Implementations SHOULD skip tests gracefully when dependencies are unavailable.

   Implementation: Skip when vectors not downloaded; skip AWS KMS tests without credentials.

### MAY Requirements

1. **Error Descriptions**
   > Error descriptions in failure test cases MAY be used for documentation but implementations MAY NOT require specific error types.

   Implementation: Log error descriptions for debugging but don't validate error text.

## Test Vectors

### Harness Setup

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Test Vector Location

**Manifest**: `test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json`
- Type: `awses-decrypt`
- Version: 2
- Client: `aws/aws-encryption-sdk-python` version `2.2.0`

### Vector Statistics

| Category | Total | Success | Error |
|----------|-------|---------|-------|
| All Tests | ~9,089 | ~4,186 | ~4,903 |
| Raw AES | ~4,901 | ~2,450 | ~2,451 |
| Raw RSA | ~3,300 | ~1,650 | ~1,650 |
| Multi-keyring | ~336 | ~168 | ~168 |
| AWS KMS | ~1,981 | ~varies | ~varies |

### Implementation Order

#### Phase 1: Raw AES Success Tests (~2,450 tests)
Lowest complexity, no external dependencies.

| Priority | Key Size | Example Test ID | Description |
|----------|----------|-----------------|-------------|
| 1 | AES-256 | `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Most common |
| 2 | AES-128 | `4be2393c-2916-4668-ae7a-d26ddb8de593` | Baseline |
| 3 | AES-192 | `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | Complete coverage |

**Filtering Strategy**:
```elixir
raw_aes_success = Enum.filter(harness.tests, fn {_id, test} ->
  test.result == :success and
  Enum.all?(test.master_keys, fn key ->
    key["type"] == "raw" and key["encryption-algorithm"] == "aes"
  end)
end)
```

#### Phase 2: Raw RSA Success Tests (~1,650 tests)
Medium complexity, tests RSA padding schemes.

| Priority | Padding | Example Test ID | Description |
|----------|---------|-----------------|-------------|
| 1 | OAEP-SHA256 | (filter by padding) | Most secure |
| 2 | OAEP-SHA1 | (filter by padding) | Legacy OAEP |
| 3 | PKCS1 | `d20b31a6-200d-4fdb-819d-7ded46c99d10` | Legacy padding |

**Filtering Strategy**:
```elixir
raw_rsa_success = Enum.filter(harness.tests, fn {_id, test} ->
  test.result == :success and
  Enum.all?(test.master_keys, fn key ->
    key["type"] == "raw" and key["encryption-algorithm"] == "rsa"
  end)
end)
```

#### Phase 3: Multi-Keyring Success Tests (~168 tests)
Higher complexity, tests keyring composition.

| Priority | Scenario | Example Test ID | Description |
|----------|----------|-----------------|-------------|
| 1 | AES + AES | (filter by keys) | Same type multi |
| 2 | RSA + RSA | `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` | Private + public |
| 3 | Mixed | (filter by keys) | AES + RSA combo |

**Filtering Strategy**:
```elixir
multi_keyring_success = Enum.filter(harness.tests, fn {_id, test} ->
  test.result == :success and
  length(test.master_keys) > 1 and
  Enum.all?(test.master_keys, fn key -> key["type"] == "raw" end)
end)
```

#### Phase 4: Error Tests (~4,903 tests, separate issue?)
Critical for security validation.

| Priority | Error Type | Example | Description |
|----------|------------|---------|-------------|
| 1 | Bit flip | `061f37ec-2433-4ff8-9fbb-4ab98ee100ef` | Tamper detection |
| 2 | Wrong method | `fe0a0327-a701-47f9-a42e-8ec7744161ab` | Algorithm mismatch |
| 3 | Auth failure | (various) | Wrong key errors |

#### Phase 5: AWS KMS Tests (Separate Issue)
Requires AWS credentials, network access.

### Test Vector Setup

If test vectors are not present:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

Or run:
```elixir
TestVectorSetup.ensure_test_vectors()
# Prints download instructions
```

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Available key types
%{
  "aes-128" => %{type: "symmetric", bits: 128, encoding: "base64"},
  "aes-192" => %{type: "symmetric", bits: 192, encoding: "base64"},
  "aes-256" => %{type: "symmetric", bits: 256, encoding: "base64"},
  "rsa-4096-private" => %{type: "private", bits: 4096, encoding: "pem"},
  "rsa-4096-public" => %{type: "public", bits: 4096, encoding: "pem"},
  # AWS KMS keys reference ARNs, not local material
}
```

## Implementation Considerations

### Technical Approach

#### 1. Create Filtering Helpers

Add to `test_vector_harness.ex` or new module:

```elixir
defmodule TestVectorHarness.Filters do
  def success_tests(harness) do
    Enum.filter(harness.tests, fn {_id, test} -> test.result == :success end)
  end

  def by_key_type(tests, type) do
    Enum.filter(tests, fn {_id, test} ->
      Enum.any?(test.master_keys, fn key ->
        key["encryption-algorithm"] == type
      end)
    end)
  end

  def exclude_kms(tests) do
    Enum.filter(tests, fn {_id, test} ->
      Enum.all?(test.master_keys, fn key -> key["type"] == "raw" end)
    end)
  end
end
```

#### 2. Full Decrypt Flow

```elixir
def run_full_decrypt_test(harness, test_id) do
  # 1. Load test case
  {:ok, test_case} = TestVectorHarness.get_test(harness, test_id)
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

  # 2. Build keyring(s) from master-keys
  keyring = build_keyring_from_master_keys(harness, test_case.master_keys)

  # 3. Create client with appropriate commitment policy
  # Use :require_encrypt_allow_decrypt to allow decryption of legacy non-committed messages
  cmm = Default.new(keyring)
  client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

  # 4. Execute full decrypt
  result = Client.decrypt(client, ciphertext)

  # 5. Validate based on expected result
  case test_case.result do
    :success ->
      {:ok, expected} = TestVectorHarness.load_expected_plaintext(harness, test_id)
      assert {:ok, %{plaintext: ^expected}} = result

    :error ->
      assert {:error, _reason} = result
  end
end
```

#### 3. Parameterized Test Generation

```elixir
defmodule AwsEncryptionSdk.TestVectors.FullDecryptTest do
  use ExUnit.Case, async: true

  @moduletag :test_vectors
  @moduletag :full_test_vectors
  @moduletag skip: not TestVectorSetup.vectors_available?()

  setup_all do
    case TestVectorSetup.find_manifest("**/manifest.json") do
      {:ok, manifest_path} ->
        {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

        # Pre-filter to raw key success tests only
        success_tests = harness.tests
          |> Enum.filter(fn {_id, test} -> test.result == :success end)
          |> Enum.filter(fn {_id, test} ->
            Enum.all?(test.master_keys, fn key -> key["type"] == "raw" end)
          end)
          |> Map.new()

        {:ok, harness: harness, success_tests: success_tests}

      :not_found ->
        {:ok, harness: nil, success_tests: %{}}
    end
  end

  # Dynamic test generation at compile time not possible due to setup_all
  # Use runtime iteration instead:

  @tag timeout: 300_000  # 5 minutes for all tests
  test "all raw key success tests", %{harness: harness, success_tests: tests} do
    if harness == nil do
      IO.puts("Skipping: test vectors not available")
    else
      failed = Enum.reduce(tests, [], fn {test_id, _test}, acc ->
        case run_full_decrypt_test(harness, test_id) do
          :ok -> acc
          {:error, reason} -> [{test_id, reason} | acc]
        end
      end)

      assert failed == [], "Failed tests: #{inspect(failed)}"
    end
  end
end
```

### Performance Considerations

| Approach | Tests | Expected Time | Use Case |
|----------|-------|---------------|----------|
| Smoke | 10-20 | <5 seconds | Pre-commit |
| Integration | 100-200 | <30 seconds | PR validation |
| Full | 4,186+ | 5-15 minutes | Nightly/release |

**Recommendations**:
- Use `async: true` for parallel execution
- Cache harness in `setup_all` (already done)
- Consider `@tag :slow` for CI exclusion
- Add progress reporting for long runs

### Potential Challenges

1. **Test Runtime**: 4,186 tests may take 5-15 minutes
   - Mitigation: Use parallel execution, tiered test suites

2. **Memory Usage**: Loading all test data simultaneously
   - Mitigation: Stream test execution, don't preload all ciphertexts

3. **Commitment Policy**: Legacy vectors may use non-committed suites
   - Mitigation: Use `:require_encrypt_allow_decrypt` policy

4. **Algorithm Suite Coverage**: Need to verify all suites are tested
   - Mitigation: Add coverage matrix reporting

### Open Questions

1. Should error tests (negative cases) be in this issue or separate?
   - Recommendation: Separate issue for clarity, but include framework support

2. Should AWS KMS tests be skipped entirely or conditionally run?
   - Recommendation: Skip by default, enable via environment variable

3. How to report algorithm suite coverage?
   - Option A: Test tags per suite
   - Option B: Post-test coverage report
   - Option C: Matrix in test output

## Recommended Next Steps

1. **Create implementation plan**:
   ```
   /create_plan thoughts/shared/research/2026-02-01-GH76-full-test-vector-runner.md
   ```

2. **Implementation order**:
   - Add filtering helpers to test harness
   - Create full decrypt test helper function
   - Implement Raw AES tests first (simplest)
   - Add Raw RSA tests
   - Add Multi-keyring tests
   - Add coverage reporting

3. **Acceptance criteria checklist**:
   - [ ] Create `test/test_vectors/full_decrypt_test.exs`
   - [ ] Execute all Raw AES success vectors (~2,450 tests)
   - [ ] Execute all Raw RSA success vectors (~1,650 tests)
   - [ ] Execute all Multi-keyring success vectors (~168 tests)
   - [ ] Test full `AwsEncryptionSdk.decrypt/3` flow
   - [ ] Validate plaintext matches expected output
   - [ ] Validate encryption context is preserved
   - [ ] Add algorithm suite coverage report
   - [ ] Tests skip gracefully if vectors not downloaded
   - [ ] Add CI configuration (optional/scheduled)

## References

- Issue: https://github.com/owner/repo/issues/76
- Spec - Test Vector Framework: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
- Spec - Decrypt: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
