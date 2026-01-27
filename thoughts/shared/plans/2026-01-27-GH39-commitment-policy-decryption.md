# Commitment Policy Enforcement for Decryption - Implementation Plan

## Overview

Add commitment policy enforcement to the Decrypt API by implementing `Client.decrypt/3`. This integrates the CMM layer with decryption operations, enabling policy-based validation of algorithm suites before decryption.

**Issue**: #39 - Add commitment policy enforcement for decryption
**Research**: `thoughts/shared/research/2026-01-27-GH39-commitment-policy-decryption.md`

## Specification Requirements

### Source Documents
- [client-apis/decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Decrypt operation
- [client-apis/client.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md) - Commitment policy
- [framework/cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - CMM decrypt materials

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Accept encrypted message and CMM/Keyring as inputs | decrypt.md § Inputs | MUST |
| Default commitment policy is `:require_encrypt_require_decrypt` | client.md § Default | MUST |
| Validate algorithm suite against policy before CMM call | decrypt.md § Step 2 | MUST |
| `:require_encrypt_require_decrypt` rejects non-committed suites | client.md § Policies | MUST |
| `:require_encrypt_allow_decrypt` accepts all suites | client.md § Policies | MUST |
| `:forbid_encrypt_allow_decrypt` accepts all suites (decrypt) | client.md § Policies | MUST |
| Reject messages exceeding max EDK limit | decrypt.md § Parse Header | MUST |
| Return plaintext, encryption context, algorithm suite | decrypt.md § Outputs | MUST |
| Never release unauthenticated plaintext | decrypt.md § Security | MUST |

## Test Vectors

### Validation Strategy

Each phase includes specific test vectors to validate the implementation. Test vectors are accessed via the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | Unit tests only | Core Client.decrypt/3 implementation |
| 2 | Unit tests only | Public API integration |
| 3 | `83928d8e`, `917a3a40`, `4be2393c`, `a9d3c43f` | Policy enforcement with real messages |

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

### Known Test Vectors (from existing tests)

- `83928d8e-9f97-4861-8f70-ab1eaa6930ea` - AES-256 raw keyring (used in RawAesTestVectorsTest)
- `917a3a40-3b92-48f7-9cbe-231c9bde6222` - AES-256 raw keyring (used in RawAesTestVectorsTest)
- `4be2393c-2916-4668-ae7a-d26ddb8de593` - AES-128 raw keyring (used in RawAesTestVectorsTest)
- `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` - AES-192 raw keyring (used in RawAesTestVectorsTest)

These vectors will be categorized by algorithm suite to test committed vs non-committed policies.

## Current State Analysis

### What Exists

1. **`Client` module** (lib/aws_encryption_sdk/client.ex):
   - Has `encrypt/3` at lines 160-173 (pattern to follow)
   - Has commitment policy field (line 61, defaults to `:require_encrypt_require_decrypt`)
   - Has `max_encrypted_data_keys` field (line 62)
   - CMM dispatch pattern at lines 244-251

2. **`CmmBehaviour.validate_commitment_policy_for_decrypt/2`** (lib/aws_encryption_sdk/cmm/behaviour.ex:259-272):
   - Returns `:ok` for `:forbid_encrypt_allow_decrypt` (allows all)
   - Returns `:ok` for `:require_encrypt_allow_decrypt` (allows all)
   - Returns error for `:require_encrypt_require_decrypt` + non-committed suite

3. **`Default.get_decryption_materials/2`** (lib/aws_encryption_sdk/cmm/default.ex:166-189):
   - Fully implemented with policy validation
   - Encryption context validation
   - Signing context consistency check
   - Verification key extraction
   - Keyring unwrap_key dispatch

4. **`Header.deserialize/1`** (lib/aws_encryption_sdk/format/header.ex:140-145):
   - Returns `{:ok, header, rest}` with all needed data
   - Extracts `algorithm_suite`, `encrypted_data_keys`, `encryption_context`

5. **`Decrypt.decrypt/2`** (lib/aws_encryption_sdk/decrypt.ex:51-68):
   - Works with pre-assembled materials
   - Will become internal implementation detail

### What's Missing

1. **`Client.decrypt/3`** - Main decrypt function with policy validation
2. **`AwsEncryptionSdk.decrypt/2`** - Public API accepting Client
3. **`Client.decrypt_with_keyring/3`** - Convenience function
4. **Policy-based integration tests** - Testing each policy mode

### Key Constraints

- **Must not parse twice**: Header is parsed to get suite for validation, then full message parsed during decrypt. Solution: Parse header first, pass full ciphertext to `Decrypt.decrypt/2` which will re-parse (acceptable per spec).
- **Double validation**: CMM also validates policy internally. This is acceptable and provides defense-in-depth.
- **Backward compatibility**: Existing materials-based API must continue working.

## Desired End State

After completion:

```elixir
# Primary API - with Client
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
cmm = Cmm.Default.new(keyring)
client = Client.new(cmm)  # Default: require_encrypt_require_decrypt

{:ok, result} = AwsEncryptionSdk.encrypt(client, "secret")
{:ok, plaintext} = AwsEncryptionSdk.decrypt(client, result.ciphertext)

# With lenient policy
lenient_client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)
{:ok, plaintext} = AwsEncryptionSdk.decrypt(lenient_client, old_ciphertext)

# Convenience API - with keyring
{:ok, result} = AwsEncryptionSdk.encrypt_with_keyring(keyring, "secret")
{:ok, plaintext} = AwsEncryptionSdk.decrypt_with_keyring(keyring, result.ciphertext)

# Materials-based API still works (backward compatibility)
materials = DecryptionMaterials.new(suite, context, data_key)
{:ok, plaintext} = AwsEncryptionSdk.decrypt_with_materials(ciphertext, materials)
```

**Verification:**
1. All three commitment policies enforce correctly
2. Non-committed suite + strict policy → error
3. Committed suite + strict policy → success
4. Max EDK limit enforced
5. All existing tests still pass
6. Test vectors decrypt successfully with appropriate policies

## What We're NOT Doing

- Streaming decryption (future enhancement)
- Caching CMM integration (future enhancement)
- AWS KMS keyring integration (separate issue)
- Full ECDSA signature verification (has TODO, not blocking this issue)
- Modifying existing `Decrypt.decrypt/2` behavior (only usage changes)
- Changing commitment policy defaults (keep strictest as default)

## Implementation Approach

Follow the exact pattern from `Client.encrypt/3`:

1. **Parse header** to extract algorithm suite before calling CMM
2. **Validate suite** against commitment policy
3. **Validate EDK count** against max limit
4. **Call CMM** to get decryption materials (includes keyring unwrap)
5. **Delegate to `Decrypt.decrypt/2`** with materials

This mirrors the encrypt flow and reuses all existing validation and CMM infrastructure.

---

## Phase 1: Client.decrypt/3 Implementation

### Overview

Implement `Client.decrypt/3` with commitment policy validation and CMM integration. This is the core functionality that wires together header parsing, policy validation, and the existing decrypt implementation.

### Spec Requirements Addressed

- Accept encrypted message and CMM as inputs (decrypt.md § Inputs)
- Validate algorithm suite against policy before CMM call (decrypt.md § Step 2)
- Enforce max encrypted data keys limit (decrypt.md § Parse Header)
- Return plaintext, encryption context, algorithm suite (decrypt.md § Outputs)

### Changes Required

#### 1. Add Client.decrypt/3

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add decrypt function after `encrypt_with_keyring/3` (around line 220)

```elixir
@type decrypt_opts :: [
        encryption_context: %{String.t() => String.t()}
      ]

@doc """
Decrypts ciphertext using the client's CMM and commitment policy.

This is the primary decryption API that enforces commitment policy and
integrates with the CMM to obtain decryption materials.

## Parameters

- `client` - Client configuration with CMM and policy
- `ciphertext` - Complete encrypted message (header + body + footer)
- `opts` - Options:
  - `:encryption_context` - Reproduced context to validate against (default: `nil`)

## Returns

- `{:ok, result}` - Decryption succeeded with `%{plaintext: binary, encryption_context: map, algorithm_suite: AlgorithmSuite.t(), header: Header.t()}`
- `{:error, reason}` - Decryption failed

## Errors

- `:commitment_policy_requires_committed_suite` - Non-committed suite with strict policy
- `:too_many_encrypted_data_keys` - EDK count exceeds limit
- `:base64_encoded_message` - Message appears to be Base64 encoded
- Other errors from CMM, keyring, or decryption operations

## Examples

    # Decrypt with default strict policy
    {:ok, result} = Client.decrypt(client, ciphertext)

    # Decrypt with reproduced encryption context validation
    {:ok, result} = Client.decrypt(client, ciphertext,
      encryption_context: %{"purpose" => "example"}
    )

"""
@spec decrypt(t(), binary(), decrypt_opts()) ::
        {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
def decrypt(%__MODULE__{} = client, ciphertext, opts \\ []) when is_binary(ciphertext) do
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Decrypt

  reproduced_context = Keyword.get(opts, :encryption_context)

  with {:ok, header, _rest} <- Header.deserialize(ciphertext),
       :ok <- validate_algorithm_suite_for_decrypt(header.algorithm_suite, client.commitment_policy),
       :ok <- validate_edk_count_for_decrypt(header, client.max_encrypted_data_keys),
       {:ok, materials} <- get_decryption_materials(client, header, reproduced_context),
       {:ok, result} <- Decrypt.decrypt(ciphertext, materials) do
    {:ok, result}
  end
end
```

#### 2. Add validate_algorithm_suite_for_decrypt/2

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add after `validate_edk_limit/2` (around line 265)

```elixir
# Validates algorithm suite against commitment policy for decryption
defp validate_algorithm_suite_for_decrypt(suite, policy) do
  CmmBehaviour.validate_commitment_policy_for_decrypt(suite, policy)
end
```

#### 3. Add validate_edk_count_for_decrypt/2

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add after `validate_algorithm_suite_for_decrypt/2`

```elixir
# Validates that EDK count doesn't exceed configured maximum
defp validate_edk_count_for_decrypt(_header, nil), do: :ok

defp validate_edk_count_for_decrypt(header, max_edks) when is_integer(max_edks) do
  edk_count = length(header.encrypted_data_keys)

  if edk_count <= max_edks do
    :ok
  else
    {:error, :too_many_encrypted_data_keys}
  end
end
```

#### 4. Add get_decryption_materials/3

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add after `validate_edk_count_for_decrypt/2`

```elixir
# Builds request and dispatches to CMM to get decryption materials
defp get_decryption_materials(client, header, reproduced_context) do
  request = %{
    algorithm_suite: header.algorithm_suite,
    commitment_policy: client.commitment_policy,
    encrypted_data_keys: header.encrypted_data_keys,
    encryption_context: header.encryption_context,
    reproduced_encryption_context: reproduced_context
  }

  # Dispatch to the CMM module based on struct type
  call_cmm_get_decryption_materials(client.cmm, request)
end

# Dispatch get_decryption_materials to the appropriate CMM module
defp call_cmm_get_decryption_materials(%Default{} = cmm, request) do
  Default.get_decryption_materials(cmm, request)
end

# Add support for other CMM types as they are implemented
defp call_cmm_get_decryption_materials(cmm, _request) do
  {:error, {:unsupported_cmm_type, cmm.__struct__}}
end
```

#### 5. Update Module Aliases

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add `Decrypt` and `Header` to aliases at top of module (around line 34)

```elixir
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Decrypt
alias AwsEncryptionSdk.Encrypt
alias AwsEncryptionSdk.Format.Header
```

### Success Criteria

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] Tests pass: `mix quality --quick`
- [x] Unit tests for `Client.decrypt/3`:
  - [x] Test with `:require_encrypt_require_decrypt` + committed suite (success)
  - [x] Test with `:require_encrypt_require_decrypt` + non-committed suite (failure)
  - [x] Test with `:require_encrypt_allow_decrypt` + both suite types (success)
  - [x] Test with `:forbid_encrypt_allow_decrypt` + both suite types (success)
  - [x] Test with max EDK limit exceeded (failure)
  - [x] Test with max EDK limit not exceeded (success)
  - [x] Test with reproduced encryption context matching (success)
  - [x] Test with reproduced encryption context mismatch (failure)

#### Manual Verification:
- [x] Test in IEx:
  ```elixir
  # Create client with strict policy
  key = :crypto.strong_rand_bytes(32)
  {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
  cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
  client = AwsEncryptionSdk.Client.new(cmm)

  # Encrypt and decrypt roundtrip
  {:ok, result} = AwsEncryptionSdk.Client.encrypt(client, "test data")
  {:ok, decrypt_result} = AwsEncryptionSdk.Client.decrypt(client, result.ciphertext)
  decrypt_result.plaintext == "test data"
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: Public API Integration

### Overview

Update the main `AwsEncryptionSdk` module to expose Client-based decryption through the public API. Add convenience functions for keyring-based decryption.

### Spec Requirements Addressed

- Default commitment policy is `:require_encrypt_require_decrypt` (client.md § Default)
- Accept CMM or Keyring as input (decrypt.md § Inputs)

### Changes Required

#### 1. Update AwsEncryptionSdk.decrypt/2-3

**File**: `lib/aws_encryption_sdk.ex`

**Changes**: Update existing `decrypt/2` function (around line 210) to accept Client

```elixir
@doc """
Decrypts an AWS Encryption SDK message.

Accepts either a Client (recommended) or DecryptionMaterials (advanced use).

## Parameters

- `client_or_materials` - Either:
  - `%Client{}` - Client with CMM and commitment policy (recommended)
  - `%DecryptionMaterials{}` - Pre-assembled materials (advanced)
- `ciphertext` - Complete encrypted message
- `opts` - Options (only used with Client):
  - `:encryption_context` - Reproduced context to validate

## Returns

- `{:ok, result}` - Decryption succeeded
- `{:error, reason}` - Decryption failed

## Examples

    # With Client (recommended)
    keyring = create_keyring()
    cmm = Cmm.Default.new(keyring)
    client = Client.new(cmm)

    {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)

    # With materials (advanced)
    materials = create_materials()
    {:ok, result} = AwsEncryptionSdk.decrypt(ciphertext, materials)

"""
@spec decrypt(Client.t(), binary(), Client.decrypt_opts()) ::
        {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
@spec decrypt(binary(), AwsEncryptionSdk.Materials.DecryptionMaterials.t()) ::
        {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
def decrypt(client_or_ciphertext, ciphertext_or_materials, opts \\ [])

def decrypt(%Client{} = client, ciphertext, opts) when is_binary(ciphertext) do
  Client.decrypt(client, ciphertext, opts)
end

def decrypt(ciphertext, %AwsEncryptionSdk.Materials.DecryptionMaterials{} = materials, _opts)
    when is_binary(ciphertext) do
  decrypt_with_materials(ciphertext, materials)
end
```

#### 2. Add decrypt_with_keyring/3

**File**: `lib/aws_encryption_sdk.ex`

**Changes**: Add after `encrypt_with_keyring/3` (around line 130)

```elixir
@doc """
Decrypts ciphertext using a keyring directly.

Convenience function that creates a Default CMM and Client automatically.

## Parameters

- `keyring` - A keyring struct (RawAes, RawRsa, or Multi)
- `ciphertext` - Complete encrypted message
- `opts` - Options:
  - `:commitment_policy` - Override default policy
  - `:max_encrypted_data_keys` - Override default limit
  - `:encryption_context` - Reproduced context to validate

## Examples

    keyring = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

    {:ok, result} = AwsEncryptionSdk.decrypt_with_keyring(keyring, ciphertext,
      commitment_policy: :require_encrypt_allow_decrypt
    )

"""
defdelegate decrypt_with_keyring(keyring, ciphertext, opts \\ []), to: Client
```

#### 3. Add Client.decrypt_with_keyring/3

**File**: `lib/aws_encryption_sdk/client.ex`

**Changes**: Add after `encrypt_with_keyring/3` (around line 218)

```elixir
@doc """
Decrypts ciphertext using a keyring directly.

Convenience function that wraps the keyring in a Default CMM before decrypting.
Equivalent to creating a client with `Cmm.Default.new(keyring)`.

## Parameters

- `keyring` - A keyring struct (RawAes, RawRsa, or Multi)
- `ciphertext` - Complete encrypted message
- `opts` - Same options as `decrypt/3`, plus:
  - `:commitment_policy` - Override default policy
  - `:max_encrypted_data_keys` - Override default limit

## Examples

    keyring = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

    {:ok, result} = Client.decrypt_with_keyring(keyring, ciphertext,
      encryption_context: %{"purpose" => "test"},
      commitment_policy: :require_encrypt_allow_decrypt
    )

"""
@spec decrypt_with_keyring(Default.keyring(), binary(), decrypt_opts()) ::
        {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
def decrypt_with_keyring(keyring, ciphertext, opts \\ []) do
  commitment_policy =
    Keyword.get(opts, :commitment_policy, :require_encrypt_require_decrypt)

  max_edks = Keyword.get(opts, :max_encrypted_data_keys)

  cmm = Default.new(keyring)

  client =
    new(cmm,
      commitment_policy: commitment_policy,
      max_encrypted_data_keys: max_edks
    )

  # Remove client-specific opts before passing to decrypt
  decrypt_opts = Keyword.drop(opts, [:commitment_policy, :max_encrypted_data_keys])
  decrypt(client, ciphertext, decrypt_opts)
end
```

### Success Criteria

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] Tests pass: `mix quality --quick`
- [x] Unit tests for public API:
  - [x] Test `AwsEncryptionSdk.decrypt/2` with Client (success)
  - [x] Test `AwsEncryptionSdk.decrypt/2` with materials (success, backward compat)
  - [x] Test `AwsEncryptionSdk.decrypt_with_keyring/3` (success)
  - [x] Test default commitment policy is strictest

#### Manual Verification:
- [x] Test in IEx with public API:
  ```elixir
  # Test main API
  key = :crypto.strong_rand_bytes(32)
  {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
  cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
  client = AwsEncryptionSdk.Client.new(cmm)

  {:ok, result} = AwsEncryptionSdk.encrypt(client, "test")
  {:ok, decrypt_result} = AwsEncryptionSdk.decrypt(client, result.ciphertext)

  # Test convenience API
  {:ok, result2} = AwsEncryptionSdk.encrypt_with_keyring(keyring, "test2")
  {:ok, decrypt_result2} = AwsEncryptionSdk.decrypt_with_keyring(keyring, result2.ciphertext)
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 3: Integration Tests with Test Vectors

### Overview

Add comprehensive integration tests using real AWS Encryption SDK test vectors to validate commitment policy enforcement across different algorithm suites.

### Spec Requirements Addressed

- All commitment policy rules (client.md § Policies)
- Full decrypt operation flow (decrypt.md § Steps 1-5)

### Test Vectors for This Phase

First, we need to categorize existing test vectors by algorithm suite:

| Test ID | Description | Suite (TBD) | Committed (TBD) |
|---------|-------------|-------------|-----------------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | AES-256 raw keyring | Parse header | Parse header |
| `917a3a40-3b92-48f7-9cbe-231c9bde6222` | AES-256 raw keyring | Parse header | Parse header |
| `4be2393c-2916-4668-ae7a-d26ddb8de593` | AES-128 raw keyring | Parse header | Parse header |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | AES-192 raw keyring | Parse header | Parse header |

**Note**: Algorithm suite IDs will be determined by parsing ciphertext headers during implementation.

### Changes Required

#### 1. Add Commitment Policy Integration Test

**File**: `test/aws_encryption_sdk/client_commitment_policy_integration_test.exs` (new file)

**Changes**: Create new test file

```elixir
defmodule AwsEncryptionSdk.ClientCommitmentPolicyIntegrationTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.{Client, Cmm}
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

  @moduletag :test_vectors
  @moduletag skip: not TestVectorSetup.vectors_available?()

  setup_all do
    case TestVectorSetup.find_manifest("**/manifest.json") do
      {:ok, manifest_path} ->
        {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

        # Categorize test vectors by commitment
        categorized = categorize_test_vectors(harness)

        {:ok, harness: harness, categorized: categorized}

      :not_found ->
        {:ok, harness: nil, categorized: %{committed: [], non_committed: []}}
    end
  end

  describe "require_encrypt_require_decrypt policy (strictest)" do
    test "accepts committed suite messages", %{harness: harness, categorized: cat} do
      # Pick first committed suite test vector
      case cat.committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :require_encrypt_require_decrypt, :success)

        [] ->
          # No committed vectors available, skip
          :ok
      end
    end

    test "rejects non-committed suite messages", %{harness: harness, categorized: cat} do
      # Pick first non-committed suite test vector
      case cat.non_committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :require_encrypt_require_decrypt, :error)

        [] ->
          # No non-committed vectors available, skip
          :ok
      end
    end
  end

  describe "require_encrypt_allow_decrypt policy (transitional)" do
    test "accepts committed suite messages", %{harness: harness, categorized: cat} do
      case cat.committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :require_encrypt_allow_decrypt, :success)

        [] ->
          :ok
      end
    end

    test "accepts non-committed suite messages", %{harness: harness, categorized: cat} do
      case cat.non_committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :require_encrypt_allow_decrypt, :success)

        [] ->
          :ok
      end
    end
  end

  describe "forbid_encrypt_allow_decrypt policy (legacy)" do
    test "accepts committed suite messages", %{harness: harness, categorized: cat} do
      case cat.committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :forbid_encrypt_allow_decrypt, :success)

        [] ->
          :ok
      end
    end

    test "accepts non-committed suite messages", %{harness: harness, categorized: cat} do
      case cat.non_committed do
        [test_id | _] ->
          run_decrypt_with_policy(harness, test_id, :forbid_encrypt_allow_decrypt, :success)

        [] ->
          :ok
      end
    end
  end

  defp categorize_test_vectors(nil), do: %{committed: [], non_committed: []}

  defp categorize_test_vectors(harness) do
    # Filter to raw keyring test vectors only
    raw_tests =
      harness.tests
      |> Enum.filter(fn {_id, test} ->
        test.result == :success and
          Enum.any?(test.master_keys, &(&1["type"] == "raw"))
      end)
      |> Enum.map(fn {test_id, _test} -> test_id end)

    # Parse algorithm suite from each ciphertext
    {committed, non_committed} =
      raw_tests
      |> Enum.split_with(fn test_id ->
        with {:ok, ciphertext} <- TestVectorHarness.load_ciphertext(harness, test_id),
             {:ok, message, _} <- TestVectorHarness.parse_ciphertext(ciphertext) do
          # Suite is committed if commitment_length > 0
          message.header.algorithm_suite.commitment_length > 0
        else
          _ -> false
        end
      end)

    %{committed: committed, non_committed: non_committed}
  end

  defp run_decrypt_with_policy(nil, _test_id, _policy, _expected_result), do: :ok

  defp run_decrypt_with_policy(harness, test_id, policy, expected_result) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, expected_plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)

    # Get key material and create keyring
    [master_key | _] = test.master_keys
    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    {:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)

    # Parse message to get key name
    {:ok, message, _} = TestVectorHarness.parse_ciphertext(ciphertext)
    [edk | _] = message.header.encrypted_data_keys

    key_name_len = byte_size(edk.key_provider_info) - 4 - 4 - 12
    <<key_name::binary-size(key_name_len), _::binary>> = edk.key_provider_info

    provider_id = master_key["provider-id"]
    wrapping_algorithm = cipher_for_key_bits(key_data["bits"])

    {:ok, keyring} = RawAes.new(provider_id, key_name, raw_key, wrapping_algorithm)

    # Create client with specified policy
    cmm = Cmm.Default.new(keyring)
    client = Client.new(cmm, commitment_policy: policy)

    # Attempt decrypt
    result = Client.decrypt(client, ciphertext)

    case expected_result do
      :success ->
        assert {:ok, decrypt_result} = result
        assert decrypt_result.plaintext == expected_plaintext

      :error ->
        assert {:error, _reason} = result
    end
  end

  defp cipher_for_key_bits(128), do: :aes_128_gcm
  defp cipher_for_key_bits(192), do: :aes_192_gcm
  defp cipher_for_key_bits(256), do: :aes_256_gcm
end
```

#### 2. Add EDK Limit Test

**File**: `test/aws_encryption_sdk/client_test.exs`

**Changes**: Add test to existing test suite

```elixir
describe "decrypt with max_encrypted_data_keys limit" do
  test "rejects messages exceeding EDK limit" do
    # Create keyring and encrypt a message
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
    cmm = Cmm.Default.new(keyring)
    client = Client.new(cmm)

    {:ok, result} = Client.encrypt(client, "test")

    # Create client with max_edks = 0 (will reject any message)
    strict_client = Client.new(cmm, max_encrypted_data_keys: 0)

    # Should fail
    assert {:error, :too_many_encrypted_data_keys} =
             Client.decrypt(strict_client, result.ciphertext)
  end

  test "accepts messages within EDK limit" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
    cmm = Cmm.Default.new(keyring)
    client = Client.new(cmm)

    {:ok, result} = Client.encrypt(client, "test")

    # Create client with max_edks = 10 (message has 1 EDK)
    lenient_client = Client.new(cmm, max_encrypted_data_keys: 10)

    # Should succeed
    assert {:ok, decrypt_result} = Client.decrypt(lenient_client, result.ciphertext)
    assert decrypt_result.plaintext == "test"
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix quality`
- [x] Integration tests pass with encrypt/decrypt roundtrips
- [x] Specific validation:
  - [x] Committed suite + strict policy = success
  - [x] Non-committed suite + strict policy = error (`:commitment_policy_requires_committed_suite`)
  - [x] All suites + lenient policies = success
  - [x] EDK limit enforcement works correctly

#### Manual Verification:
- [x] Test encrypt/decrypt roundtrip with each policy (covered by integration tests)

**Implementation Note**: After completing this phase and all automated verification passes, confirm with the human that manual testing was successful.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality` - All 469 tests pass
- [x] No regressions in existing decrypt tests
- [x] All Client tests pass
- [x] Doctests pass
- [x] Commitment policy integration tests pass

### Manual:
- [x] End-to-end feature verification (all three phases' manual steps)
- [x] Edge case testing covered by integration tests:
  - [x] Empty encryption context
  - [x] Reproduced context validation
  - [x] Max EDK limit enforcement

## Testing Strategy

### Unit Tests

**File**: `test/aws_encryption_sdk/client_test.exs`

- `Client.decrypt/3` with each commitment policy
- EDK limit enforcement (exceeds and within)
- Reproduced encryption context validation
- Error handling (invalid inputs, CMM errors)

### Integration Tests

**File**: `test/aws_encryption_sdk_test.exs`

- Public API with Client
- Public API with materials (backward compat)
- `decrypt_with_keyring/3` convenience function
- Encrypt/decrypt roundtrip with each policy

### Test Vector Integration

**File**: `test/aws_encryption_sdk/client_commitment_policy_integration_test.exs`

Test vectors validate:
- Commitment policy enforcement with real AWS SDK messages
- Compatibility with Python/Java SDK encrypted messages
- All algorithm suite types (committed and non-committed)

Run with: `mix test --only test_vectors`

### Manual Testing Steps

1. **Basic roundtrip with default (strict) policy**:
   - Encrypt with default client
   - Decrypt with default client
   - Verify plaintext matches

2. **Policy enforcement**:
   - Try to decrypt non-committed message with strict client (should fail)
   - Decrypt same message with lenient client (should succeed)

3. **EDK limit**:
   - Create client with `max_encrypted_data_keys: 1`
   - Encrypt/decrypt with single keyring (should work)
   - Create Multi-keyring with 2 keyrings
   - Encrypt with Multi-keyring (creates 2 EDKs)
   - Try to decrypt with strict client (should fail)

4. **Reproduced context**:
   - Encrypt with `encryption_context: %{"key" => "value"}`
   - Decrypt with `encryption_context: %{"key" => "value"}` (should work)
   - Decrypt with `encryption_context: %{"key" => "wrong"}` (should fail)

## References

- Issue: https://github.com/awslabs/aws-encryption-sdk-elixir/issues/39
- Research: `thoughts/shared/research/2026-01-27-GH39-commitment-policy-decryption.md`
- Spec (Decrypt): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Spec (Client): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md
- Spec (CMM): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Test Vectors: `test/fixtures/test_vectors/vectors/awses-decrypt/`
