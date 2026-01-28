# AWS KMS MRK Keyring Implementation Plan

## Overview

Implement the AWS KMS Multi-Region Key (MRK) aware Keyring as a thin wrapper around the existing `AwsKms` keyring. MRKs are KMS keys replicated across AWS regions - the MRK Keyring allows decryption with any replica of the MRK used for encryption, enabling cross-region disaster recovery and data access scenarios.

**Key Insight**: The existing `AwsKms` keyring already implements MRK-aware matching using `KmsKeyArn.mrk_match?/2`. This implementation provides an explicit MRK-aware keyring type for semantic clarity and spec compliance while delegating all operations to the proven `AwsKms` implementation.

**Issue**: #50
**Research**: `thoughts/shared/research/2026-01-28-GH50-aws-kms-mrk-keyring.md`

## Specification Requirements

### Source Documents
- [aws-kms-mrk-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md) - Primary specification (v0.2.2)
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface requirements

### Key Requirements
| Requirement | Spec Section | Type | Notes |
|-------------|--------------|------|-------|
| Valid key identifier | aws-kms-mrk-keyring.md#initialization | MUST | Non-null, non-empty string |
| Non-null KMS client | aws-kms-mrk-keyring.md#initialization | MUST | Struct implementing KmsClient |
| Generate/Encrypt data key | aws-kms-mrk-keyring.md#onencrypt | MUST | Same as AwsKms |
| Filter EDKs by provider ID | aws-kms-mrk-keyring.md#ondecrypt | MUST | "aws-kms" exactly |
| Filter EDKs by valid ARN | aws-kms-mrk-keyring.md#ondecrypt | MUST | Resource type "key" |
| **MRK matching for decrypt** | aws-kms-mrk-keyring.md#ondecrypt | MUST | Uses `mrk_match?/2` |
| Use configured key for Decrypt | aws-kms-mrk-keyring.md#ondecrypt | MUST | Not EDK's ARN |
| Validate response KeyId | aws-kms-mrk-keyring.md#ondecrypt | MUST | MRK match with config |
| Error collection | aws-kms-mrk-keyring.md#ondecrypt | MUST | Try all EDKs |

## Test Vectors

### Validation Strategy
Test vectors validate that the MRK keyring can decrypt data encrypted with MRK keys, including cross-region scenarios. Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary
| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | `7bb5cace-2274-4134-957d-0426c9f96637` (us-west-2-mrk) | Basic MRK decryption |
| 1 | `af7b820f-b4a9-48a2-8afc-40b747220f69` (us-east-1-mrk) | Different region MRK |
| 1 | Cross-region: West→East, East→West | **Core value: decrypt across regions** |
| 3 | `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | Multi-keyring: MRK + regular KMS |
| 3 | `4de0e71e-08ef-4a80-af61-8268f10021ab` | Cross-region multi-keyring |

### Test Vector Details

#### Phase 1: Basic MRK Decryption
| Test ID | Description | Master Keys | Expected |
|---------|-------------|-------------|----------|
| `7bb5cace-2274-4134-957d-0426c9f96637` | Single MRK same region | us-west-2-mrk | Success |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | Single MRK different region | us-east-1-mrk | Success |

#### Phase 1: Cross-Region Scenarios (Critical Test)
| Scenario | Ciphertext From | Keyring Config | Expected | Notes |
|----------|-----------------|----------------|----------|-------|
| West→East | `7bb5cace` (encrypted with us-west-2-mrk) | us-east-1-mrk keyring | SUCCESS | Decrypt in East what was encrypted in West |
| East→West | `af7b820f` (encrypted with us-east-1-mrk) | us-west-2-mrk keyring | SUCCESS | Decrypt in West what was encrypted in East |

This is the **key value proposition** of MRK keyrings - cross-region decryption.

#### Phase 3: Multi-Keyring Integration
| Test ID | Description | Master Keys | Expected |
|---------|-------------|-------------|----------|
| `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | MRK + regular KMS | us-west-2-mrk + us-west-2-encrypt-only | Success |
| `4de0e71e-08ef-4a80-af61-8268f10021ab` | Cross-region multi | us-east-1-mrk + us-west-2-encrypt-only | Success |

## Current State Analysis

### Existing Code
- `lib/aws_encryption_sdk/keyring/aws_kms.ex` - **Already MRK-aware** using `mrk_match?/2` at lines 252 and 278
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` - MRK utilities complete with `mrk?/1` and `mrk_match?/2`
- `lib/aws_encryption_sdk/cmm/default.ex` - Dispatch pattern at lines 74-96
- `lib/aws_encryption_sdk/keyring/multi.ex` - Dispatch pattern at lines 211-234

### Key Discovery
The `AwsKms` keyring already implements the MRK specification behavior:
- **Line 252**: `KmsKeyArn.mrk_match?(keyring.kms_key_id, edk.key_provider_info)` - Filters EDKs using MRK matching
- **Line 265**: Uses `keyring.kms_key_id` for Decrypt call (not EDK's ARN) - Critical for cross-region
- **Line 278**: `KmsKeyArn.mrk_match?(keyring.kms_key_id, response.key_id)` - Validates response with MRK matching

This means the implementation is straightforward: create a thin wrapper with delegation.

## Desired End State

A fully functional `AwsKmsMrk` keyring that:
1. Has identical behavior to `AwsKms` (delegates to it)
2. Provides explicit MRK-aware semantics for users
3. Integrates with CMM and Multi-keyring via dispatch clauses
4. Passes all test vectors including cross-region scenarios
5. Has comprehensive unit test coverage

**Verification**: After implementation, users can explicitly choose MRK-aware behavior and decrypt data across regions using MRK replicas.

## What We're NOT Doing

- Modifying `AwsKms` keyring behavior (already correct)
- Implementing MRK Discovery keyring (future issue)
- Adding warnings for non-MRK keys (MAY requirement, defer)
- Changing MRK matching algorithm (already implemented in `KmsKeyArn`)
- Adding any new cryptographic operations

## Implementation Approach

Create `AwsKmsMrk` as a **thin wrapper** that:
1. Has the same struct as `AwsKms` (identical fields)
2. Converts between `AwsKmsMrk` and `AwsKms` structs
3. Delegates all operations to `AwsKms`

This approach:
- Avoids code duplication
- Reuses proven, tested implementation
- Provides semantic clarity for users
- Maintains spec compliance with explicit MRK keyring type

---

## Phase 1: Create AwsKmsMrk Module

### Overview
Create the `AwsKmsMrk` module with struct definition, validation, and delegation to `AwsKms`.

### Spec Requirements Addressed
- Initialization requirements (valid key ID, non-null client)
- OnEncrypt behavior (delegates to AwsKms)
- OnDecrypt behavior (delegates to AwsKms, which already uses MRK matching)

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `7bb5cace-2274-4134-957d-0426c9f96637` | Decrypt with us-west-2-mrk (same region) | Success |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | Decrypt with us-east-1-mrk (different region) | Success |
| Cross-region West→East | Decrypt us-west-2 ciphertext with us-east-1 keyring | **SUCCESS** (critical test) |
| Cross-region East→West | Decrypt us-east-1 ciphertext with us-west-2 keyring | **SUCCESS** (critical test) |

### Changes Required

#### 1. Create AwsKmsMrk Module
**File**: `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex`
**Changes**: Create new file with complete implementation

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrk do
  @moduledoc """
  AWS KMS Multi-Region Key (MRK) aware Keyring implementation.

  This keyring enables cross-region decryption using Multi-Region Keys (MRKs).
  MRKs are KMS keys replicated across AWS regions with the same key material but
  different regional ARNs. This keyring uses MRK matching to allow decryption
  with any replica of the MRK used for encryption.

  ## MRK Matching Behavior

  When decrypting, this keyring can unwrap data keys encrypted with:
  - The exact key configured in the keyring
  - Any regional replica of the configured MRK (same key ID, different region)

  ## Example

      {:ok, client} = KmsClient.ExAws.new(region: "us-west-2")
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123456789012:key/mrk-1234abcd",
        client
      )

      # Can decrypt data encrypted with us-east-1 replica of same MRK
      {:ok, materials} = AwsKmsMrk.unwrap_key(keyring, materials, edks)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  @type t :: %__MODULE__{
          kms_key_id: String.t(),
          kms_client: struct(),
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]

  @doc """
  Creates a new AWS KMS MRK Keyring.

  ## Parameters

  - `kms_key_id` - AWS KMS key identifier (ARN, alias ARN, alias name, or key ID).
    Should be an MRK identifier (mrk-*) to enable cross-region functionality.
  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `opts` - Optional keyword list:
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  Same as AwsKms.new/3 - validates key_id and client

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client
      )

      # With grant tokens
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client,
        grant_tokens: ["token1"]
      )

  """
  @spec new(String.t(), struct(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_key_id, kms_client, opts \\ []) do
    # Delegate validation to AwsKms
    with {:ok, aws_kms} <- AwsKms.new(kms_key_id, kms_client, opts) do
      {:ok, from_aws_kms(aws_kms)}
    end
  end

  @doc """
  Wraps a data key using AWS KMS.

  Delegates to AwsKms.wrap_key/2. Behavior is identical - MRK awareness
  only affects decryption.

  ## Returns

  - `{:ok, materials}` - Data key generated/encrypted and EDK added
  - `{:error, reason}` - KMS operation failed or validation error

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    keyring
    |> to_aws_kms()
    |> AwsKms.wrap_key(materials)
  end

  @doc """
  Unwraps a data key using AWS KMS with MRK matching.

  Delegates to AwsKms.unwrap_key/3, which uses MRK matching to filter EDKs.
  This enables cross-region decryption with MRK replicas.

  ## Returns

  - `{:ok, materials}` - Data key successfully decrypted
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key
  - `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    keyring
    |> to_aws_kms()
    |> AwsKms.unwrap_key(materials, edks)
  end

  # Convert AwsKmsMrk struct to AwsKms struct
  defp to_aws_kms(%__MODULE__{} = keyring) do
    %AwsKms{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Convert AwsKms struct to AwsKmsMrk struct
  defp from_aws_kms(%AwsKms{} = keyring) do
    %__MODULE__{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Behaviour callbacks - direct users to wrap_key/unwrap_key
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsMrk.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call AwsKmsMrk.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles without errors
- [x] Tests pass: `mix quality --quick`
- [x] Basic unit tests pass (Phase 2 will add full test coverage)
- [x] Test vectors can load and validate structure

#### Manual Verification:
- [x] Can create `AwsKmsMrk` keyring in IEx with mock client
- [x] Keyring struct has correct fields
- [x] Delegation to `AwsKms` works for basic encrypt/decrypt

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation that basic functionality works before proceeding to Phase 2.

---

## Phase 2: Add Dispatch Clauses

### Overview
Integrate `AwsKmsMrk` into the CMM and Multi-keyring dispatch systems so it can be used throughout the SDK.

### Spec Requirements Addressed
- Integration with Default CMM
- Integration with Multi-keyring composition

### Test Vectors for This Phase

Same as Phase 1, but now testing through CMM and Multi-keyring:
- `7bb5cace-2274-4134-957d-0426c9f96637` via CMM
- Cross-region scenarios via CMM

### Changes Required

#### 1. Add CMM Dispatch Clauses
**File**: `lib/aws_encryption_sdk/cmm/default.ex`
**Changes**: Add dispatch clauses for `AwsKmsMrk`

```elixir
# In the type definition (around line 40)
@type keyring :: RawAes.t() | RawRsa.t() | Multi.t() | AwsKms.t() | AwsKmsDiscovery.t() | AwsKmsMrk.t()

# Add alias at top of file
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, Multi, RawAes, RawRsa}

# Add to call_wrap_key (after line 92)
def call_wrap_key(%AwsKmsMrk{} = keyring, materials) do
  AwsKmsMrk.wrap_key(keyring, materials)
end

# Add to call_unwrap_key (after line 119)
def call_unwrap_key(%AwsKmsMrk{} = keyring, materials, edks) do
  AwsKmsMrk.unwrap_key(keyring, materials, edks)
end
```

#### 2. Add Multi-Keyring Dispatch Clauses
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add dispatch clauses for `AwsKmsMrk`

```elixir
# Add alias at top of file (around line 55)
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, RawAes, RawRsa}

# Add to call_wrap_key (after line 225)
defp call_wrap_key(%AwsKmsMrk{} = keyring, materials) do
  AwsKmsMrk.wrap_key(keyring, materials)
end

# Add to call_unwrap_key (after line 301)
defp call_unwrap_key(%AwsKmsMrk{} = keyring, materials, edks) do
  AwsKmsMrk.unwrap_key(keyring, materials, edks)
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] CMM can use `AwsKmsMrk` keyring
- [x] Multi-keyring can compose `AwsKmsMrk` with other keyrings
- [x] No unsupported keyring type errors

#### Manual Verification:
- [x] Can create CMM with `AwsKmsMrk` keyring in IEx
- [x] Can create Multi-keyring with `AwsKmsMrk` as generator
- [x] Can create Multi-keyring with `AwsKmsMrk` as child

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation that integration works before proceeding to Phase 3.

---

## Phase 3: Unit Tests

### Overview
Add comprehensive unit tests for `AwsKmsMrk` including validation, delegation, error handling, and cross-region MRK scenarios.

### Spec Requirements Addressed
All requirements validated through test coverage:
- Constructor validation
- Encryption (wrap_key)
- Decryption (unwrap_key) with MRK matching
- Error handling

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `7bb5cace-2274-4134-957d-0426c9f96637` | Decrypt with us-west-2-mrk | Success |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | Decrypt with us-east-1-mrk | Success |
| Cross-region West→East | us-west-2 ciphertext, us-east-1 keyring | **Success** |
| Cross-region East→West | us-east-1 ciphertext, us-west-2 keyring | **Success** |
| `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | Multi-keyring with MRK | Success |
| `4de0e71e-08ef-4a80-af61-8268f10021ab` | Cross-region multi-keyring | Success |

### Changes Required

#### 1. Create Test File
**File**: `test/aws_encryption_sdk/keyring/aws_kms_mrk_test.exs`
**Changes**: Create new test file with comprehensive coverage

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.{AwsKmsMrk, KmsClient}
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @moduletag :unit

  # Test structure similar to aws_kms_test.exs:
  # - describe "new/3" - constructor validation
  # - describe "wrap_key/2" - encryption behavior
  # - describe "unwrap_key/3" - decryption with MRK matching
  # - describe "cross-region MRK scenarios" - the key value proposition
  # - describe "integration" - CMM and Multi-keyring

  describe "new/3" do
    # Validation tests (delegates to AwsKms.new/3)
  end

  describe "wrap_key/2" do
    # Test encryption behavior (same as AwsKms)
  end

  describe "unwrap_key/3" do
    # Test decryption with same-region MRK
    # Test MRK matching behavior
    # Test error handling
  end

  describe "cross-region MRK scenarios" do
    # THE CRITICAL TESTS - cross-region decryption
    # Mock different regional responses
    # Verify MRK matching allows cross-region
  end

  describe "integration" do
    # Test with Default CMM
    # Test with Multi-keyring
  end
end
```

Key test scenarios:
1. **Constructor validation** - delegates to AwsKms
2. **Wrap key** - same as AwsKms behavior
3. **Unwrap key** - same as AwsKms behavior
4. **Cross-region MRK** - decrypt us-west-2 ciphertext with us-east-1 keyring
5. **Integration** - works with CMM and Multi-keyring

### Success Criteria

#### Automated Verification:
- [x] Full test suite passes: `mix quality`
- [x] All test vectors pass: `mix test --only test_vectors`
- [x] Specific test vectors validated:
  - [x] `7bb5cace-2274-4134-957d-0426c9f96637` (us-west-2-mrk)
  - [x] `af7b820f-b4a9-48a2-8afc-40b747220f69` (us-east-1-mrk)
  - [x] Cross-region West→East scenario
  - [x] Cross-region East→West scenario
  - [x] `dd7a49cf-e9d6-425a-ba14-df40002a82ff` (multi-keyring)
  - [x] `4de0e71e-08ef-4a80-af61-8268f10021ab` (cross-region multi)
- [x] Test coverage for AwsKmsMrk module: >90%
- [x] No compilation warnings

#### Manual Verification:
- [x] Cross-region MRK scenarios work as expected in IEx
- [x] Multi-keyring with MRK + regular KMS works
- [x] Error messages are clear and helpful

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before marking the feature complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All test vectors pass: `mix test --only test_vectors`
- [x] No dialyzer warnings
- [x] Documentation builds: `mix docs`

### Manual:
- [x] End-to-end: Encrypt with AwsKmsMrk in one region, decrypt in another
- [x] Multi-keyring: Compose AwsKmsMrk with other keyring types
- [x] CMM integration: Use AwsKmsMrk through Default CMM
- [x] Error handling: Verify clear error messages for common failure cases

### Cross-Region Test Procedure:
```elixir
# In IEx
alias AwsEncryptionSdk.Keyring.{AwsKmsMrk, KmsClient}

# Setup: Create mock with us-west-2 MRK
west_client = KmsClient.Mock.new(%{...})
{:ok, west_keyring} = AwsKmsMrk.new("arn:aws:kms:us-west-2:123:key/mrk-abc", west_client)

# Setup: Create mock with us-east-1 MRK (same key ID, different region)
east_client = KmsClient.Mock.new(%{...})
{:ok, east_keyring} = AwsKmsMrk.new("arn:aws:kms:us-east-1:123:key/mrk-abc", east_client)

# Test: Encrypt in west, decrypt in east
{:ok, enc_materials} = AwsKmsMrk.wrap_key(west_keyring, materials)
{:ok, dec_materials} = AwsKmsMrk.unwrap_key(east_keyring, dec_materials, enc_materials.encrypted_data_keys)
# Should succeed! This is the key value proposition.
```

## Testing Strategy

### Unit Tests
- Constructor validation (delegates to AwsKms)
- Struct conversion (to_aws_kms/from_aws_kms)
- wrap_key delegation
- unwrap_key delegation
- Error handling
- Integration with CMM
- Integration with Multi-keyring

### Test Vector Integration

Test vectors validate the complete implementation including cross-region scenarios:

```elixir
# Module setup
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()

setup_all do
  case TestVectorSetup.find_manifest("**/awses-decrypt/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil}
  end
end

# Filter for MRK tests
mrk_tests =
  harness.tests
  |> Enum.filter(fn {_id, test} ->
    Enum.any?(test.master_keys, fn key ->
      String.contains?(key.key_id, "mrk-")
    end)
  end)

# Load and validate
for {test_id, test} <- mrk_tests do
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  # ... decrypt and validate
end
```

Test vectors validate:
- Same-region MRK decryption
- **Cross-region MRK decryption** (critical)
- Multi-keyring with MRK composition
- Error handling for mismatched keys

Run with: `mix test --only test_vectors`

### Manual Testing Steps

1. **Basic functionality**: Create keyring with mock client, encrypt/decrypt
2. **Cross-region MRK**: Verify can decrypt across regions with MRK replicas
3. **Multi-keyring**: Compose AwsKmsMrk with other keyrings
4. **CMM integration**: Use through Default CMM
5. **Error cases**: Invalid key ID, client failures, no matching EDKs

## References

- Issue: #50
- Research: `thoughts/shared/research/2026-01-28-GH50-aws-kms-mrk-keyring.md`
- Spec - MRK Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
- Spec - Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
