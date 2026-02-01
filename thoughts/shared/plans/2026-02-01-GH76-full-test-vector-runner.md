# Full Test Vector Runner Implementation Plan

## Overview

Implement a comprehensive test vector runner that executes all ~4,186 success test vectors from the AWS Encryption SDK test vector suite using the full `Client.decrypt_with_keyring/3` flow instead of just keyring unwrap operations.

**Issue**: #76 - Implement Full Test Vector Runner for Success Cases
**Research**: `thoughts/shared/research/2026-02-01-GH76-full-test-vector-runner.md`

## Specification Requirements

### Source Documents
- [0004-awses-message-decryption.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md) - Decrypt manifest format
- [client-apis/decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Decrypt operation

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Validate decryption produces expected plaintext | 0004-awses-message-decryption.md | MUST |
| Verify decryption fails for error cases | 0004-awses-message-decryption.md | MUST |
| Support manifest versions 2, 3, 4 | 0004-awses-message-decryption.md | MUST |
| Resolve file:// URIs relative to manifest | Framework spec | MUST |
| Skip gracefully when vectors unavailable | Framework spec | SHOULD |

## Test Vectors

### Validation Strategy
Each phase validates specific categories of test vectors using the full decrypt flow.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`
Run full test vectors with: `mix test --only full_test_vectors`

### Test Vector Summary
| Phase | Category | Count | Purpose |
|-------|----------|-------|---------|
| 3 | Raw AES | 661 | AES-128/192/256 key wrapping |
| 4 | Raw RSA | 1,100 | RSA PKCS1/OAEP padding schemes |
| 5 | Multi-keyring | 1,100 | Keyring composition |

### Sample Test Vector IDs
These are actual test IDs from the manifest for validation:

**Raw AES:**
- `83928d8e-9f97-4861-8f70-ab1eaa6930ea` - AES-256, committed suite
- `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` - AES-192, committed suite
- `4be2393c-2916-4668-ae7a-d26ddb8de593` - AES-128, committed suite

**Raw RSA:**
- `d20b31a6-200d-4fdb-819d-7ded46c99d10` - RSA PKCS1 padding
- (filter by `padding-algorithm` for OAEP variants)

**Multi-keyring:**
- `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` - PKCS1 + OAEP-SHA256
- `6b8d3386-9824-46db-8764-8d58d8086f77` - OAEP-SHA256 x2

## Current State Analysis

### What Exists
- `test/support/test_vector_harness.ex` - Complete manifest loading, key decoding, test data access
- `test/support/test_vector_setup.ex` - Vector availability checking
- `test/test_vectors/decrypt_test.exs` - Structure validation only (no full decrypt)
- Keyring test files - 16 hardcoded tests using `unwrap_key/3` only

### Key Discoveries
- `Client.decrypt_with_keyring/3` at `lib/aws_encryption_sdk/client.ex:307` is the ideal API
- Must use `:require_encrypt_allow_decrypt` policy for legacy non-committed vectors
- Keyring creation patterns exist in `default_test_vectors_test.exs:121-149`
- Multi-keyring patterns exist in `multi_test_vectors_test.exs:102-135`

### What's Missing
- Filtering helpers in harness (by key type, algorithm suite, result)
- Consolidated keyring builder that handles all key types
- Full decrypt test that validates plaintext output
- Coverage reporting

## Desired End State

After implementation:
1. `mix test --only full_test_vectors` executes all ~4,186 success vectors
2. Each test validates decrypted plaintext matches expected output
3. Tests skip gracefully when vectors not downloaded
4. Coverage report shows which algorithm suites are tested

**Verification:**
```bash
# Run full test vector suite
mix test --only full_test_vectors

# Should see output like:
# Finished in X seconds
# 4186 tests, 0 failures
```

## What We're NOT Doing

- Error/negative test cases (separate issue)
- AWS KMS test vectors (requires credentials, separate issue)
- Performance optimization beyond basic parallel execution
- Streaming decryption test vectors
- Custom CI configuration (just tags for now)

## Implementation Approach

Use `Client.decrypt_with_keyring/3` with `:require_encrypt_allow_decrypt` policy to execute full decrypt flow. Build keyrings dynamically from test vector master-key specifications. Validate plaintext byte-for-byte against expected output.

---

## Phase 1: Harness Enhancements

### Overview
Add filtering helpers and keyring builder to `TestVectorHarness` to support categorizing and executing test vectors.

### Spec Requirements Addressed
- Support manifest versions 2, 3, 4 (already done)
- Resolve file:// URIs relative to manifest (already done)

### Changes Required

#### 1. Add Filtering Module
**File**: `test/support/test_vector_harness.ex`
**Changes**: Add filtering functions at the end of the module

```elixir
# ============================================================================
# Filtering Helpers
# ============================================================================

@doc """
Returns all success test cases (tests with expected plaintext output).
"""
@spec success_tests(t()) :: [{String.t(), test_case()}]
def success_tests(%__MODULE__{tests: tests}) do
  Enum.filter(tests, fn {_id, test} -> test.result == :success end)
end

@doc """
Returns all error test cases.
"""
@spec error_tests(t()) :: [{String.t(), test_case()}]
def error_tests(%__MODULE__{tests: tests}) do
  Enum.filter(tests, fn {_id, test} -> test.result == :error end)
end

@doc """
Filters tests to only include those with raw (non-KMS) keys.
"""
@spec raw_key_tests([{String.t(), test_case()}]) :: [{String.t(), test_case()}]
def raw_key_tests(tests) do
  Enum.filter(tests, fn {_id, test} ->
    Enum.all?(test.master_keys, fn key -> key["type"] == "raw" end)
  end)
end

@doc """
Filters tests by encryption algorithm (aes or rsa).
"""
@spec by_encryption_algorithm([{String.t(), test_case()}], String.t()) :: [{String.t(), test_case()}]
def by_encryption_algorithm(tests, algorithm) do
  Enum.filter(tests, fn {_id, test} ->
    Enum.all?(test.master_keys, fn key ->
      key["type"] == "raw" and key["encryption-algorithm"] == algorithm
    end)
  end)
end

@doc """
Filters tests that use multiple master keys (multi-keyring scenarios).
"""
@spec multi_key_tests([{String.t(), test_case()}]) :: [{String.t(), test_case()}]
def multi_key_tests(tests) do
  Enum.filter(tests, fn {_id, test} ->
    length(test.master_keys) > 1
  end)
end

@doc """
Filters tests that use a single master key.
"""
@spec single_key_tests([{String.t(), test_case()}]) :: [{String.t(), test_case()}]
def single_key_tests(tests) do
  Enum.filter(tests, fn {_id, test} ->
    length(test.master_keys) == 1
  end)
end
```

### Success Criteria

#### Automated Verification:
- [x] `mix test test/support/test_vector_harness_test.exs` passes (if exists)
- [x] `mix compile --warnings-as-errors` succeeds
- [x] New functions are accessible from test files

#### Manual Verification:
- [x] In IEx, verify filtering works:
  ```elixir
  {:ok, harness} = TestVectorHarness.load_manifest("test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json")
  success = TestVectorHarness.success_tests(harness)
  raw_aes = success |> TestVectorHarness.raw_key_tests() |> TestVectorHarness.by_encryption_algorithm("aes")
  length(raw_aes)  # Returns 661 (verified)
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: Full Decrypt Test Infrastructure

### Overview
Create the main test file with helper functions for running full decrypt tests and building keyrings from master keys.

### Spec Requirements Addressed
- Validate decryption produces expected plaintext (MUST)
- Skip gracefully when vectors unavailable (SHOULD)

### Changes Required

#### 1. Create Full Decrypt Test File
**File**: `test/test_vectors/full_decrypt_test.exs`
**Changes**: New file with test infrastructure

```elixir
defmodule AwsEncryptionSdk.TestVectors.FullDecryptTest do
  @moduledoc """
  Full end-to-end decrypt validation against AWS Encryption SDK test vectors.

  These tests execute the complete `Client.decrypt_with_keyring/3` flow and validate
  that decrypted plaintext matches expected output byte-for-byte.

  Run with: mix test --only full_test_vectors
  Run specific category: mix test --only full_test_vectors:raw_aes
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes, RawRsa}
  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

  @moduletag :test_vectors
  @moduletag :full_test_vectors
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

  # ==========================================================================
  # Test Helper Functions
  # ==========================================================================

  @doc """
  Runs a full decrypt test for a single test vector.

  Returns :ok on success, {:error, reason} on failure.
  """
  def run_full_decrypt_test(harness, test_id) do
    with {:ok, test} <- TestVectorHarness.get_test(harness, test_id),
         {:ok, ciphertext} <- TestVectorHarness.load_ciphertext(harness, test_id),
         {:ok, keyring} <- build_keyring_from_master_keys(harness, test.master_keys),
         {:ok, expected} <- TestVectorHarness.load_expected_plaintext(harness, test_id) do
      # Execute full decrypt with appropriate commitment policy
      # Use :require_encrypt_allow_decrypt to handle legacy non-committed vectors
      case Client.decrypt_with_keyring(keyring, ciphertext,
             commitment_policy: :require_encrypt_allow_decrypt
           ) do
        {:ok, %{plaintext: ^expected}} ->
          :ok

        {:ok, %{plaintext: actual}} ->
          {:error, {:plaintext_mismatch, expected: byte_size(expected), actual: byte_size(actual)}}

        {:error, reason} ->
          {:error, {:decrypt_failed, reason}}
      end
    end
  end

  @doc """
  Builds a keyring (or multi-keyring) from test vector master keys.
  """
  def build_keyring_from_master_keys(harness, [single_key]) do
    build_single_keyring(harness, single_key)
  end

  def build_keyring_from_master_keys(harness, master_keys) when length(master_keys) > 1 do
    keyrings =
      master_keys
      |> Enum.map(fn mk -> build_single_keyring(harness, mk) end)
      |> Enum.filter(fn
        {:ok, _} -> true
        _ -> false
      end)
      |> Enum.map(fn {:ok, kr} -> kr end)

    if keyrings == [] do
      {:error, :no_usable_keyrings}
    else
      Multi.new(children: keyrings)
    end
  end

  defp build_single_keyring(harness, %{"type" => "raw", "encryption-algorithm" => "aes"} = mk) do
    key_id = mk["key"]

    with {:ok, key_data} <- TestVectorHarness.get_key(harness, key_id),
         {:ok, key_bytes} <- TestVectorHarness.decode_key_material(key_data) do
      provider_id = mk["provider-id"]
      key_name = mk["key"]

      wrapping_algorithm =
        case byte_size(key_bytes) do
          16 -> :aes_128_gcm
          24 -> :aes_192_gcm
          32 -> :aes_256_gcm
        end

      RawAes.new(provider_id, key_name, key_bytes, wrapping_algorithm)
    end
  end

  defp build_single_keyring(harness, %{"type" => "raw", "encryption-algorithm" => "rsa"} = mk) do
    key_id = mk["key"]

    with {:ok, key_data} <- TestVectorHarness.get_key(harness, key_id),
         true <- key_data["decrypt"] == true,
         {:ok, pem} <- TestVectorHarness.decode_key_material(key_data) do
      provider_id = mk["provider-id"]
      key_name = mk["key"]
      padding = parse_rsa_padding(mk)

      RawRsa.new(provider_id, key_name, padding, private_key: pem)
    else
      false -> {:error, :key_cannot_decrypt}
      error -> error
    end
  end

  defp build_single_keyring(_harness, %{"type" => "aws-kms"}) do
    {:error, :aws_kms_not_supported}
  end

  defp build_single_keyring(_harness, mk) do
    {:error, {:unsupported_master_key, mk}}
  end

  defp parse_rsa_padding(%{"padding-algorithm" => "pkcs1"}), do: :pkcs1_v1_5
  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha1"}), do: {:oaep, :sha1}
  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha256"}), do: {:oaep, :sha256}
  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha384"}), do: {:oaep, :sha384}
  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha512"}), do: {:oaep, :sha512}

  # ==========================================================================
  # Smoke Tests (Quick Validation)
  # ==========================================================================

  describe "smoke tests" do
    @tag :smoke
    test "decrypts AES-256 vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "83928d8e-9f97-4861-8f70-ab1eaa6930ea")
    end

    @tag :smoke
    test "decrypts RSA PKCS1 vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "d20b31a6-200d-4fdb-819d-7ded46c99d10")
    end

    @tag :smoke
    test "decrypts multi-keyring vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e")
    end
  end

  defp skip_if_no_harness(nil), do: ExUnit.skip("Test vectors not available")
  defp skip_if_no_harness(_), do: :ok
end
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile --warnings-as-errors` succeeds
- [x] `mix test test/test_vectors/full_decrypt_test.exs --only smoke` passes (3 tests)

#### Manual Verification:
- [x] Verify smoke tests actually decrypt and validate plaintext:
  ```bash
  mix test test/test_vectors/full_decrypt_test.exs --only smoke -v
  ```

**BLOCKING ISSUE RESOLVED**: The header authentication failure was caused by missing version/type bytes in the header body serialization. Fixed in `lib/aws_encryption_sdk/format/header.ex`:
- v1 headers now include `<<0x01, 0x80>>` at start of body
- v2 headers now include `<<0x02>>` at start of body
- RSA keyring builder now loads PEM before passing to keyring

All 3 smoke tests now pass (AES-256, RSA PKCS1, multi-keyring).

---

## Phase 3: Raw AES Success Tests

### Overview
Add test that executes all 661 Raw AES success vectors.

### Spec Requirements Addressed
- Validate decryption produces expected plaintext (MUST)

### Test Vectors for This Phase
All tests where:
- `result == :success`
- All master keys have `type == "raw"` and `encryption-algorithm == "aes"`
- Single key only (multi-keyring tested separately)

Actual count: 661 tests

### Changes Required

#### 1. Add Raw AES Full Test
**File**: `test/test_vectors/full_decrypt_test.exs`
**Changes**: Add test block after smoke tests

```elixir
  # ==========================================================================
  # Raw AES Full Test Suite
  # ==========================================================================

  describe "raw AES success tests" do
    @tag :full_test_vectors
    @tag :raw_aes
    @tag timeout: 600_000  # 10 minutes
    test "all raw AES success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to raw AES success tests
      raw_aes_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.by_encryption_algorithm("aes")
        |> TestVectorHarness.single_key_tests()

      total = length(raw_aes_tests)
      IO.puts("\nRunning #{total} Raw AES success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        raw_aes_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 500) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Raw AES: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")
        failed |> Enum.take(10) |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} Raw AES tests failed"
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] `mix test test/test_vectors/full_decrypt_test.exs --only raw_aes` passes
- [x] All ~661 Raw AES tests pass

#### Manual Verification:
- [x] Review test output for any unexpected warnings
- [x] Verify progress reporting works correctly

**RESOLVED**: All 661/661 Raw AES test vectors now pass! The blocking issues were resolved in a previous session:
1. ✅ Header version/type bytes in AAD
2. ✅ Required encryption context keys filtering
3. ✅ RSA PEM loading in test harness
4. ✅ All spec compliance issues resolved

**Implementation Note**: Phase 3 complete and verified.

---

## Phase 4: Raw RSA Success Tests

### Overview
Add test that executes all 1,100 Raw RSA success vectors.

### Spec Requirements Addressed
- Validate decryption produces expected plaintext (MUST)

### Test Vectors for This Phase
All tests where:
- `result == :success`
- All master keys have `type == "raw"` and `encryption-algorithm == "rsa"`
- Single key only (multi-keyring tested separately)
- Master key has `decrypt == true` (private key available)

Actual count: 1,100 tests

### Changes Required

#### 1. Add Raw RSA Full Test
**File**: `test/test_vectors/full_decrypt_test.exs`
**Changes**: Add test block after Raw AES tests

```elixir
  # ==========================================================================
  # Raw RSA Full Test Suite
  # ==========================================================================

  describe "raw RSA success tests" do
    @tag :full_test_vectors
    @tag :raw_rsa
    @tag timeout: 900_000  # 15 minutes (RSA is slower)
    test "all raw RSA success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to raw RSA success tests with decrypt capability
      raw_rsa_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.by_encryption_algorithm("rsa")
        |> TestVectorHarness.single_key_tests()
        |> filter_decryptable_rsa(harness)

      total = length(raw_rsa_tests)
      IO.puts("\nRunning #{total} Raw RSA success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        raw_rsa_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 200) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Raw RSA: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")
        failed |> Enum.take(10) |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} Raw RSA tests failed"
    end
  end

  # Filter RSA tests to only those where we have a private key (can decrypt)
  defp filter_decryptable_rsa(tests, harness) do
    Enum.filter(tests, fn {_id, test} ->
      Enum.all?(test.master_keys, fn mk ->
        key_id = mk["key"]
        case TestVectorHarness.get_key(harness, key_id) do
          {:ok, %{"decrypt" => true}} -> true
          _ -> false
        end
      end)
    end)
  end
```

### Success Criteria

#### Automated Verification:
- [x] `mix test test/test_vectors/full_decrypt_test.exs --only raw_rsa` passes
- [x] All 1,100 Raw RSA tests pass

#### Manual Verification:
- [x] Verify all RSA padding schemes are covered (PKCS1, OAEP-SHA1/256/384/512)

**Implementation Note**: Phase 4 complete. All 1,100 Raw RSA test vectors pass successfully. Implementation supports all 5 RSA padding schemes (PKCS1, OAEP-SHA1, OAEP-SHA256, OAEP-SHA384, OAEP-SHA512).

---

## Phase 5: Multi-Keyring Success Tests

### Overview
Add test that executes all 1,100 multi-keyring success vectors.

### Spec Requirements Addressed
- Validate decryption produces expected plaintext (MUST)

### Test Vectors for This Phase
All tests where:
- `result == :success`
- All master keys have `type == "raw"`
- `length(master_keys) > 1`

Actual count: 1,100 tests

### Changes Required

#### 1. Add Multi-Keyring Full Test
**File**: `test/test_vectors/full_decrypt_test.exs`
**Changes**: Add test block after Raw RSA tests

```elixir
  # ==========================================================================
  # Multi-Keyring Full Test Suite
  # ==========================================================================

  describe "multi-keyring success tests" do
    @tag :full_test_vectors
    @tag :multi_keyring
    @tag timeout: 300_000  # 5 minutes
    test "all multi-keyring success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to multi-keyring success tests (raw keys only)
      multi_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.multi_key_tests()

      total = length(multi_tests)
      IO.puts("\nRunning #{total} multi-keyring success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        multi_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 50) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Multi-keyring: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")
        failed |> Enum.take(10) |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} multi-keyring tests failed"
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] `mix test test/test_vectors/full_decrypt_test.exs --only multi_keyring` passes
- [x] All 1,100 multi-keyring tests pass

#### Manual Verification:
- [x] Verify multi-keyring handles AES+AES, RSA+RSA, and mixed scenarios

**Implementation Note**: Phase 5 complete. All 1,100 multi-keyring test vectors pass successfully. The smoke test `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` (which was already passing in Phase 2) confirms mixed RSA padding scenarios work correctly.

---

## Phase 6: Coverage Reporting

### Overview
Add algorithm suite coverage reporting to show which suites are tested.

### Changes Required

#### 1. Add Coverage Report Test
**File**: `test/test_vectors/full_decrypt_test.exs`
**Changes**: Add coverage report at the end

```elixir
  # ==========================================================================
  # Coverage Report
  # ==========================================================================

  describe "coverage report" do
    @tag :full_test_vectors
    @tag :coverage_report
    test "algorithm suite coverage", %{harness: harness} do
      skip_if_no_harness(harness)

      # Get all raw key success tests
      raw_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()

      # Sample tests to determine algorithm suite coverage
      suite_counts =
        raw_tests
        |> Enum.reduce(%{}, fn {test_id, _test}, acc ->
          case TestVectorHarness.load_ciphertext(harness, test_id) do
            {:ok, ciphertext} ->
              case TestVectorHarness.parse_ciphertext(ciphertext) do
                {:ok, message, _} ->
                  suite_id = message.header.algorithm_suite.id
                  Map.update(acc, suite_id, 1, &(&1 + 1))
                _ -> acc
              end
            _ -> acc
          end
        end)

      IO.puts("\n" <> String.duplicate("=", 60))
      IO.puts("Algorithm Suite Coverage Report")
      IO.puts(String.duplicate("=", 60))

      suite_counts
      |> Enum.sort_by(fn {_id, count} -> -count end)
      |> Enum.each(fn {suite_id, count} ->
        hex_id = "0x" <> String.pad_leading(Integer.to_string(suite_id, 16), 4, "0")
        IO.puts("  #{hex_id}: #{count} tests")
      end)

      IO.puts(String.duplicate("=", 60))
      IO.puts("Total: #{length(raw_tests)} raw key success tests")
      IO.puts(String.duplicate("=", 60))

      # Just verify we have coverage data
      assert map_size(suite_counts) > 0
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] `mix test test/test_vectors/full_decrypt_test.exs --only coverage_report` passes
- [x] Coverage report displays algorithm suite distribution

#### Manual Verification:
- [x] Review coverage report shows multiple algorithm suites
- [x] Verify committed suites (0x0478, 0x0578) are represented

**Implementation Note**: Phase 6 complete. Coverage report shows all 11 ESDK algorithm suites are tested with ~260 tests per suite, including both committed suites (0x0478, 0x0578).

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix test --only full_test_vectors`
- [x] All 2,861 raw key success vectors pass (661 AES + 1,100 RSA + 1,100 Multi-keyring)
- [x] `mix quality` passes

### Manual:
- [x] Run full suite and verify output
- [x] Verify coverage report shows good algorithm suite distribution (all 11 suites covered)
- [x] Confirm no test vectors are silently skipped (only 2 excluded tests, down from 39)

### CI Integration:
- [x] Added test vector setup to GitHub Actions workflow (.github/workflows/ci.yml)
- [x] Test vectors now run automatically in CI with caching for performance

### Expected Final Output:
```
Running 661 Raw AES success tests...
Raw AES: 661 passed, 0 failed

Running 1100 Raw RSA success tests...
Raw RSA: 1100 passed, 0 failed

Running 1100 multi-keyring success tests...
Multi-keyring: 1100 passed, 0 failed

============================================================
Algorithm Suite Coverage Report
============================================================
  0x0478: 1200 tests
  0x0578: 800 tests
  0x0378: 600 tests
  ...
============================================================
Total: 2861 raw key success tests
============================================================

Finished in X seconds
6 tests, 0 failures
```

## Testing Strategy

### Unit Tests:
- Filtering helpers tested via actual manifest data
- Keyring builder tested via smoke tests

### Test Vector Integration:
```elixir
# Run all test vectors
mix test --only full_test_vectors

# Run specific category
mix test --only raw_aes
mix test --only raw_rsa
mix test --only multi_keyring

# Run quick smoke tests only
mix test --only smoke

# Run with verbose output
mix test --only full_test_vectors -v
```

### Tags Summary:
| Tag | Purpose |
|-----|---------|
| `:test_vectors` | All test vector tests |
| `:full_test_vectors` | Full decrypt tests (this implementation) |
| `:smoke` | Quick validation (3 tests) |
| `:raw_aes` | Raw AES full suite |
| `:raw_rsa` | Raw RSA full suite |
| `:multi_keyring` | Multi-keyring full suite |
| `:coverage_report` | Algorithm suite coverage |

### Manual Testing Steps:
1. Run smoke tests first to verify infrastructure
2. Run each category separately to identify issues
3. Run full suite for final validation
4. Review coverage report for algorithm suite distribution

## References

- Issue: #76
- Research: `thoughts/shared/research/2026-02-01-GH76-full-test-vector-runner.md`
- Spec - Test Vector Framework: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
- Spec - Decrypt: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
