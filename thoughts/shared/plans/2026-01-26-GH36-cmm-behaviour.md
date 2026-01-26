# CMM Behaviour Implementation Plan

## Overview

Implement the Cryptographic Materials Manager (CMM) behaviour module that defines the interface all CMM implementations must follow. The CMM sits between encrypt/decrypt APIs and keyrings, managing algorithm suite selection, encryption context handling, and orchestrating keyring operations.

**Issue**: #36
**Research**: `thoughts/shared/research/2026-01-26-GH36-cmm-behaviour.md`

## Specification Requirements

### Source Documents
- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - Core CMM behaviour definition
- [default-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md) - Default CMM implementation (future issue #37)
- [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Material structure definitions

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Return valid encryption materials | cmm-interface.md | MUST |
| Plaintext data key must be non-NULL | cmm-interface.md | MUST |
| Plaintext data key length must equal KDF input length | cmm-interface.md | MUST |
| At least one encrypted data key | cmm-interface.md | MUST |
| Include signing key if algorithm suite has signing | cmm-interface.md | MUST |
| Required encryption context keys must be superset of request | cmm-interface.md | MUST |
| Add `aws-crypto-public-key` to context for signed suites | cmm-interface.md | SHOULD |
| Validate encryption context against reproduced context | cmm-interface.md | MUST |
| Include verification key if algorithm suite has signing | cmm-interface.md | MUST |
| Fail if signing present but `aws-crypto-public-key` missing | cmm-interface.md | SHOULD |
| Fail if no signing but `aws-crypto-public-key` present | cmm-interface.md | SHOULD |

## Test Vectors

### Note on CMM Testing

The CMM behaviour is an interface definition. Test vectors do not directly test CMM implementations - instead, they test the complete encrypt/decrypt flow which implicitly validates CMM behavior through keyring interactions. Unit tests will validate the helper functions directly.

### Validation Strategy

Helper functions will be tested with unit tests covering:
- Commitment policy validation against algorithm suites
- Encryption materials completeness validation
- Decryption materials completeness validation
- Encryption context validation (reserved key handling)
- Required encryption context keys validation

## Current State Analysis

### Existing Code

- `lib/aws_encryption_sdk/keyring/behaviour.ex` - **Pattern to follow** - Keyring behaviour with callbacks and helper functions
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - EncryptionMaterials struct
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - DecryptionMaterials struct
- `lib/aws_encryption_sdk/algorithm_suite.ex` - Algorithm suite definitions with `committed?/1` and `signed?/1` helpers

### Key Discoveries

- Keyring behaviour pattern at `lib/aws_encryption_sdk/keyring/behaviour.ex:1-164`:
  - Uses `@callback` for interface definition
  - Includes helper functions (not just callbacks)
  - Uses `term()` for generic struct types
  - Does NOT use `__using__` macro
- AlgorithmSuite already has `committed?/1` and `signed?/1` helpers at lines 497-509
- Materials structs have `new_for_encrypt/3` and `new_for_decrypt/3` constructors

### CMM Directory

Does not exist yet - will create `lib/aws_encryption_sdk/cmm/behaviour.ex`

## Desired End State

After this plan is complete:

1. `lib/aws_encryption_sdk/cmm/behaviour.ex` exists with:
   - Two callbacks: `get_encryption_materials/2` and `get_decryption_materials/2`
   - Type definitions for request maps and commitment policy
   - Helper functions for validation and context handling

2. Comprehensive unit tests at `test/aws_encryption_sdk/cmm/behaviour_test.exs`

3. All tests pass: `mix quality`

### Verification

```bash
# Compile without warnings
mix compile --warnings-as-errors

# Run tests
mix test test/aws_encryption_sdk/cmm/behaviour_test.exs

# Full quality check
mix quality
```

## What We're NOT Doing

- **Default CMM implementation** - That's issue #37, a separate effort
- **Caching CMM** - Future milestone
- **Required Encryption Context CMM** - Future milestone
- **ECDSA key generation/parsing** - The behaviour defines the interface; implementations handle crypto
- **Integration with encrypt/decrypt modules** - Will be done when Default CMM is implemented

## Implementation Approach

Follow the established keyring behaviour pattern:
1. Define callbacks with clear typespecs
2. Include helper functions for common operations
3. Comprehensive documentation with spec references
4. Unit tests for all helper functions

---

## Phase 1: Core Behaviour Module Structure

### Overview

Create the behaviour module with callbacks, type definitions, and module documentation.

### Spec Requirements Addressed

- Define `get_encryption_materials/2` callback (cmm-interface.md)
- Define `get_decryption_materials/2` callback (cmm-interface.md)
- Define commitment policy type (cmm-interface.md)

### Changes Required

#### 1. Create CMM Behaviour Module

**File**: `lib/aws_encryption_sdk/cmm/behaviour.ex`
**Changes**: Create new file with behaviour definition

```elixir
defmodule AwsEncryptionSdk.Cmm.Behaviour do
  @moduledoc """
  Behaviour for Cryptographic Materials Manager (CMM) implementations.

  The CMM is responsible for assembling cryptographic materials for encryption
  and decryption operations. It sits between the encrypt/decrypt APIs and keyrings,
  managing algorithm suite selection, encryption context handling, and orchestrating
  keyring operations.

  ## Callbacks

  - `get_encryption_materials/2` - Obtain materials for encryption
  - `decrypt_materials/2` - Obtain materials for decryption

  ## Commitment Policy

  The commitment policy controls which algorithm suites can be used:

  - `:forbid_encrypt_allow_decrypt` - Forbid committed suites for encrypt, allow all for decrypt
  - `:require_encrypt_allow_decrypt` - Require committed suites for encrypt, allow all for decrypt
  - `:require_encrypt_require_decrypt` - Require committed suites for both (strictest, recommended)

  ## Reserved Encryption Context Key

  The key `"aws-crypto-public-key"` is reserved for storing the signature verification
  key in the encryption context. CMMs MUST:

  - Add this key when the algorithm suite includes signing
  - Fail if the caller already provided this key
  - Extract the verification key from this key during decryption

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @typedoc "CMM implementation struct (opaque to the behaviour)"
  @type t :: term()

  @typedoc """
  Commitment policy for algorithm suite selection.

  - `:forbid_encrypt_allow_decrypt` - Non-committed suites only for encrypt
  - `:require_encrypt_allow_decrypt` - Committed suites required for encrypt
  - `:require_encrypt_require_decrypt` - Committed suites required for both (default)
  """
  @type commitment_policy ::
          :forbid_encrypt_allow_decrypt
          | :require_encrypt_allow_decrypt
          | :require_encrypt_require_decrypt

  @typedoc """
  Request for encryption materials.

  ## Required Fields

  - `:encryption_context` - Key-value pairs for AAD (may be empty map)
  - `:commitment_policy` - Policy controlling algorithm suite selection

  ## Optional Fields

  - `:algorithm_suite` - Requested algorithm suite (CMM may use default)
  - `:required_encryption_context_keys` - Keys that must be in final context
  - `:max_plaintext_length` - Maximum plaintext length hint
  """
  @type encryption_materials_request :: %{
          required(:encryption_context) => %{String.t() => String.t()},
          required(:commitment_policy) => commitment_policy(),
          optional(:algorithm_suite) => AlgorithmSuite.t() | nil,
          optional(:required_encryption_context_keys) => [String.t()],
          optional(:max_plaintext_length) => non_neg_integer() | nil
        }

  @typedoc """
  Request for decryption materials.

  ## Required Fields

  - `:algorithm_suite` - Algorithm suite from message header
  - `:commitment_policy` - Policy controlling algorithm suite selection
  - `:encrypted_data_keys` - EDKs from message header
  - `:encryption_context` - Encryption context from message header

  ## Optional Fields

  - `:reproduced_encryption_context` - Context to validate against
  """
  @type decrypt_materials_request :: %{
          required(:algorithm_suite) => AlgorithmSuite.t(),
          required(:commitment_policy) => commitment_policy(),
          required(:encrypted_data_keys) => [EncryptedDataKey.t()],
          required(:encryption_context) => %{String.t() => String.t()},
          optional(:reproduced_encryption_context) => %{String.t() => String.t()} | nil
        }

  @doc """
  Obtains encryption materials for an encryption operation.

  The CMM assembles encryption materials by:
  1. Selecting an algorithm suite (using requested or default)
  2. Validating the algorithm suite against commitment policy
  3. Delegating to keyring(s) to generate/encrypt data key
  4. Adding signing key if algorithm suite requires signing
  5. Validating the assembled materials

  ## Parameters

  - `cmm` - CMM implementation struct
  - `request` - Encryption materials request

  ## Returns

  - `{:ok, %EncryptionMaterials{}}` - Valid encryption materials
  - `{:error, term()}` - Failed to assemble materials

  ## Spec Requirements

  The returned materials MUST:
  - Include a non-NULL plaintext data key
  - Include at least one encrypted data key
  - Include signing key if algorithm suite has signing algorithm
  - Have required_encryption_context_keys as superset of request
  """
  @callback get_encryption_materials(cmm :: t(), request :: encryption_materials_request()) ::
              {:ok, EncryptionMaterials.t()} | {:error, term()}

  @doc """
  Obtains decryption materials for a decryption operation.

  The CMM assembles decryption materials by:
  1. Validating the algorithm suite against commitment policy
  2. Validating encryption context against reproduced context (if provided)
  3. Delegating to keyring(s) to decrypt a data key
  4. Extracting verification key if algorithm suite requires signing
  5. Validating the assembled materials

  ## Parameters

  - `cmm` - CMM implementation struct
  - `request` - Decryption materials request

  ## Returns

  - `{:ok, %DecryptionMaterials{}}` - Valid decryption materials
  - `{:error, term()}` - Failed to assemble materials

  ## Spec Requirements

  The returned materials MUST:
  - Include a non-NULL plaintext data key
  - Include verification key if algorithm suite has signing algorithm
  - Have all required_encryption_context_keys present in encryption context
  """
  @callback decrypt_materials(cmm :: t(), request :: decrypt_materials_request()) ::
              {:ok, DecryptionMaterials.t()} | {:error, term()}
end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles: `mix compile --warnings-as-errors`
- [x] No dialyzer errors: `mix dialyzer` (if configured)

#### Manual Verification:
- [x] Module loads in IEx: `alias AwsEncryptionSdk.Cmm.Behaviour`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 2: Commitment Policy Helpers

### Overview

Add helper functions for validating commitment policy against algorithm suites.

### Spec Requirements Addressed

- Commitment policy must match algorithm suite (cmm-interface.md)
- Default suite selection based on commitment policy

### Changes Required

#### 1. Add Commitment Policy Helpers

**File**: `lib/aws_encryption_sdk/cmm/behaviour.ex`
**Changes**: Add helper functions after callbacks

```elixir
  # Reserved encryption context key for signature verification
  @reserved_ec_key "aws-crypto-public-key"

  @doc """
  Returns the reserved encryption context key for signature verification.

  This key is used to store the base64-encoded public key in the encryption
  context for signed algorithm suites.
  """
  @spec reserved_encryption_context_key() :: String.t()
  def reserved_encryption_context_key, do: @reserved_ec_key

  @doc """
  Returns the default algorithm suite for a commitment policy.

  ## Examples

      iex> AwsEncryptionSdk.Cmm.Behaviour.default_algorithm_suite(:require_encrypt_require_decrypt)
      %AwsEncryptionSdk.AlgorithmSuite{id: 0x0578}

      iex> AwsEncryptionSdk.Cmm.Behaviour.default_algorithm_suite(:forbid_encrypt_allow_decrypt)
      %AwsEncryptionSdk.AlgorithmSuite{id: 0x0378}

  """
  @spec default_algorithm_suite(commitment_policy()) :: AlgorithmSuite.t()
  def default_algorithm_suite(:forbid_encrypt_allow_decrypt) do
    # Non-committed suite with signing
    AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()
  end

  def default_algorithm_suite(_policy) do
    # Committed suite (default for require_* policies)
    AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
  end

  @doc """
  Validates an algorithm suite against a commitment policy for encryption.

  ## Rules

  - `:forbid_encrypt_allow_decrypt` - Suite MUST NOT be committed
  - `:require_encrypt_allow_decrypt` - Suite MUST be committed
  - `:require_encrypt_require_decrypt` - Suite MUST be committed

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
      {:error, :commitment_policy_requires_committed_suite}

  """
  @spec validate_commitment_policy_for_encrypt(AlgorithmSuite.t(), commitment_policy()) ::
          :ok | {:error, :commitment_policy_requires_committed_suite | :commitment_policy_forbids_committed_suite}
  def validate_commitment_policy_for_encrypt(suite, :forbid_encrypt_allow_decrypt) do
    if AlgorithmSuite.committed?(suite) do
      {:error, :commitment_policy_forbids_committed_suite}
    else
      :ok
    end
  end

  def validate_commitment_policy_for_encrypt(suite, policy)
      when policy in [:require_encrypt_allow_decrypt, :require_encrypt_require_decrypt] do
    if AlgorithmSuite.committed?(suite) do
      :ok
    else
      {:error, :commitment_policy_requires_committed_suite}
    end
  end

  @doc """
  Validates an algorithm suite against a commitment policy for decryption.

  ## Rules

  - `:forbid_encrypt_allow_decrypt` - Any suite allowed
  - `:require_encrypt_allow_decrypt` - Any suite allowed
  - `:require_encrypt_require_decrypt` - Suite MUST be committed

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_decrypt(suite, :require_encrypt_allow_decrypt)
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_decrypt(suite, :require_encrypt_require_decrypt)
      {:error, :commitment_policy_requires_committed_suite}

  """
  @spec validate_commitment_policy_for_decrypt(AlgorithmSuite.t(), commitment_policy()) ::
          :ok | {:error, :commitment_policy_requires_committed_suite}
  def validate_commitment_policy_for_decrypt(_suite, policy)
      when policy in [:forbid_encrypt_allow_decrypt, :require_encrypt_allow_decrypt] do
    :ok
  end

  def validate_commitment_policy_for_decrypt(suite, :require_encrypt_require_decrypt) do
    if AlgorithmSuite.committed?(suite) do
      :ok
    else
      {:error, :commitment_policy_requires_committed_suite}
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles: `mix compile --warnings-as-errors`
- [x] Doctests pass: `mix test --only doctest`

#### Manual Verification:
- [x] Test in IEx:
  ```elixir
  alias AwsEncryptionSdk.Cmm.Behaviour
  alias AwsEncryptionSdk.AlgorithmSuite

  # Should return :ok
  Behaviour.validate_commitment_policy_for_encrypt(
    AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
    :require_encrypt_require_decrypt
  )

  # Should return {:error, :commitment_policy_requires_committed_suite}
  Behaviour.validate_commitment_policy_for_encrypt(
    AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256(),
    :require_encrypt_require_decrypt
  )
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 3: Materials Validation Helpers

### Overview

Add helper functions for validating encryption and decryption materials completeness.

### Spec Requirements Addressed

- Plaintext data key must be non-NULL (cmm-interface.md)
- Plaintext data key length must equal KDF input length (cmm-interface.md)
- At least one encrypted data key (cmm-interface.md)
- Signing key required for signed suites (cmm-interface.md)
- Verification key required for signed suites (cmm-interface.md)

### Changes Required

#### 1. Add Materials Validation Helpers

**File**: `lib/aws_encryption_sdk/cmm/behaviour.ex`
**Changes**: Add validation helper functions

```elixir
  @doc """
  Validates that encryption materials are complete and valid.

  Checks:
  1. Plaintext data key is present and correct length
  2. At least one encrypted data key exists
  3. Signing key present if algorithm suite has signing
  4. Required encryption context keys are present in context

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new(suite, %{}, [edk], key)
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_materials(materials)
      :ok

  """
  @spec validate_encryption_materials(EncryptionMaterials.t()) ::
          :ok
          | {:error,
             :missing_plaintext_data_key
             | :invalid_plaintext_data_key_length
             | :missing_encrypted_data_keys
             | :missing_signing_key
             | :missing_required_encryption_context_key}
  def validate_encryption_materials(%EncryptionMaterials{} = materials) do
    with :ok <- validate_plaintext_data_key(materials),
         :ok <- validate_encrypted_data_keys(materials),
         :ok <- validate_signing_key(materials),
         :ok <- validate_required_context_keys(materials) do
      :ok
    end
  end

  defp validate_plaintext_data_key(%{plaintext_data_key: nil}) do
    {:error, :missing_plaintext_data_key}
  end

  defp validate_plaintext_data_key(%{plaintext_data_key: key, algorithm_suite: suite})
       when is_binary(key) do
    expected_length = suite.kdf_input_length

    if byte_size(key) == expected_length do
      :ok
    else
      {:error, :invalid_plaintext_data_key_length}
    end
  end

  defp validate_encrypted_data_keys(%{encrypted_data_keys: []}) do
    {:error, :missing_encrypted_data_keys}
  end

  defp validate_encrypted_data_keys(%{encrypted_data_keys: edks}) when is_list(edks) do
    :ok
  end

  defp validate_signing_key(%{algorithm_suite: suite, signing_key: signing_key}) do
    if AlgorithmSuite.signed?(suite) and is_nil(signing_key) do
      {:error, :missing_signing_key}
    else
      :ok
    end
  end

  defp validate_required_context_keys(%{
         encryption_context: context,
         required_encryption_context_keys: required_keys
       }) do
    missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, :missing_required_encryption_context_key}
    end
  end

  @doc """
  Validates that decryption materials are complete and valid.

  Checks:
  1. Plaintext data key is present and correct length
  2. Verification key present if algorithm suite has signing
  3. Required encryption context keys are present in context

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new(suite, %{}, key)
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_decryption_materials(materials)
      :ok

  """
  @spec validate_decryption_materials(DecryptionMaterials.t()) ::
          :ok
          | {:error,
             :missing_plaintext_data_key
             | :invalid_plaintext_data_key_length
             | :missing_verification_key
             | :missing_required_encryption_context_key}
  def validate_decryption_materials(%DecryptionMaterials{} = materials) do
    with :ok <- validate_decryption_plaintext_key(materials),
         :ok <- validate_verification_key(materials),
         :ok <- validate_decryption_required_context_keys(materials) do
      :ok
    end
  end

  defp validate_decryption_plaintext_key(%{plaintext_data_key: nil}) do
    {:error, :missing_plaintext_data_key}
  end

  defp validate_decryption_plaintext_key(%{plaintext_data_key: key, algorithm_suite: suite})
       when is_binary(key) do
    expected_length = suite.kdf_input_length

    if byte_size(key) == expected_length do
      :ok
    else
      {:error, :invalid_plaintext_data_key_length}
    end
  end

  defp validate_verification_key(%{algorithm_suite: suite, verification_key: verification_key}) do
    if AlgorithmSuite.signed?(suite) and is_nil(verification_key) do
      {:error, :missing_verification_key}
    else
      :ok
    end
  end

  defp validate_decryption_required_context_keys(%{
         encryption_context: context,
         required_encryption_context_keys: required_keys
       }) do
    missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, :missing_required_encryption_context_key}
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles: `mix compile --warnings-as-errors`
- [x] Doctests pass: `mix test --only doctest` (will be verified in Phase 5)

#### Manual Verification:
- [x] Test in IEx with missing plaintext data key
- [x] Test in IEx with wrong key length
- [x] Test in IEx with missing EDKs

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 4: Encryption Context Helpers

### Overview

Add helper functions for encryption context validation, including reserved key handling and reproduced context comparison.

### Spec Requirements Addressed

- CMM MUST fail if caller provides reserved `aws-crypto-public-key` (cmm-interface.md)
- SHOULD fail if signing present but `aws-crypto-public-key` missing in context (cmm-interface.md)
- SHOULD fail if no signing but `aws-crypto-public-key` present (cmm-interface.md)
- Validate encryption context against reproduced context (cmm-interface.md)

### Changes Required

#### 1. Add Encryption Context Helpers

**File**: `lib/aws_encryption_sdk/cmm/behaviour.ex`
**Changes**: Add context validation helper functions

```elixir
  @doc """
  Validates that encryption context does not contain reserved keys.

  The caller MUST NOT provide the reserved key `aws-crypto-public-key`.
  This key is reserved for the CMM to store the signature verification key.

  ## Examples

      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_context_for_encrypt(%{"key" => "value"})
      :ok

      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_context_for_encrypt(%{"aws-crypto-public-key" => "value"})
      {:error, :reserved_encryption_context_key}

  """
  @spec validate_encryption_context_for_encrypt(%{String.t() => String.t()}) ::
          :ok | {:error, :reserved_encryption_context_key}
  def validate_encryption_context_for_encrypt(context) when is_map(context) do
    if Map.has_key?(context, @reserved_ec_key) do
      {:error, :reserved_encryption_context_key}
    else
      :ok
    end
  end

  @doc """
  Validates encryption context consistency with algorithm suite signing requirement.

  For decryption, validates that:
  - If algorithm suite has signing, `aws-crypto-public-key` SHOULD be present
  - If algorithm suite has no signing, `aws-crypto-public-key` SHOULD NOT be present

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_signing_context_consistency(suite, %{})
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_signing_context_consistency(suite, %{})
      {:error, :missing_public_key_in_context}

  """
  @spec validate_signing_context_consistency(AlgorithmSuite.t(), %{String.t() => String.t()}) ::
          :ok | {:error, :missing_public_key_in_context | :unexpected_public_key_in_context}
  def validate_signing_context_consistency(suite, context) do
    is_signed = AlgorithmSuite.signed?(suite)
    has_public_key = Map.has_key?(context, @reserved_ec_key)

    cond do
      is_signed and not has_public_key ->
        {:error, :missing_public_key_in_context}

      not is_signed and has_public_key ->
        {:error, :unexpected_public_key_in_context}

      true ->
        :ok
    end
  end

  @doc """
  Validates encryption context against reproduced encryption context.

  For any key that exists in both contexts, the values MUST be equal.
  Keys that exist only in one context are allowed.

  ## Examples

      iex> context = %{"key1" => "value1", "key2" => "value2"}
      iex> reproduced = %{"key1" => "value1"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_reproduced_context(context, reproduced)
      :ok

      iex> context = %{"key1" => "value1"}
      iex> reproduced = %{"key1" => "different"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_reproduced_context(context, reproduced)
      {:error, {:encryption_context_mismatch, "key1"}}

  """
  @spec validate_reproduced_context(
          %{String.t() => String.t()},
          %{String.t() => String.t()} | nil
        ) :: :ok | {:error, {:encryption_context_mismatch, String.t()}}
  def validate_reproduced_context(_context, nil), do: :ok

  def validate_reproduced_context(context, reproduced) when is_map(reproduced) do
    # Find any key where both contexts have a value but they differ
    mismatched_key =
      Enum.find(reproduced, fn {key, reproduced_value} ->
        case Map.fetch(context, key) do
          {:ok, context_value} -> context_value != reproduced_value
          :error -> false
        end
      end)

    case mismatched_key do
      nil -> :ok
      {key, _value} -> {:error, {:encryption_context_mismatch, key}}
    end
  end

  @doc """
  Merges reproduced encryption context into decryption context.

  Keys from reproduced context that are not in the original context
  are appended to the decryption materials context.

  ## Examples

      iex> context = %{"key1" => "value1"}
      iex> reproduced = %{"key1" => "value1", "key2" => "value2"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.merge_reproduced_context(context, reproduced)
      %{"key1" => "value1", "key2" => "value2"}

  """
  @spec merge_reproduced_context(
          %{String.t() => String.t()},
          %{String.t() => String.t()} | nil
        ) :: %{String.t() => String.t()}
  def merge_reproduced_context(context, nil), do: context

  def merge_reproduced_context(context, reproduced) when is_map(reproduced) do
    Map.merge(reproduced, context)
  end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles: `mix compile --warnings-as-errors`
- [x] Doctests pass: `mix test --only doctest` (will be verified in Phase 5)

#### Manual Verification:
- [x] Test reserved key detection in IEx
- [x] Test context mismatch detection in IEx
- [x] Test context merging in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 5: Unit Tests

### Overview

Create comprehensive unit tests for all helper functions.

### Changes Required

#### 1. Create Test File

**File**: `test/aws_encryption_sdk/cmm/behaviour_test.exs`
**Changes**: Create new test file

```elixir
defmodule AwsEncryptionSdk.Cmm.BehaviourTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Behaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  describe "reserved_encryption_context_key/0" do
    test "returns the reserved key" do
      assert Behaviour.reserved_encryption_context_key() == "aws-crypto-public-key"
    end
  end

  describe "default_algorithm_suite/1" do
    test "returns committed suite for require_encrypt_require_decrypt" do
      suite = Behaviour.default_algorithm_suite(:require_encrypt_require_decrypt)
      assert suite.id == 0x0578
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns committed suite for require_encrypt_allow_decrypt" do
      suite = Behaviour.default_algorithm_suite(:require_encrypt_allow_decrypt)
      assert suite.id == 0x0578
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns non-committed suite for forbid_encrypt_allow_decrypt" do
      suite = Behaviour.default_algorithm_suite(:forbid_encrypt_allow_decrypt)
      assert suite.id == 0x0378
      refute AlgorithmSuite.committed?(suite)
    end
  end

  describe "validate_commitment_policy_for_encrypt/2" do
    test "accepts committed suite with require_encrypt_require_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert :ok = Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
    end

    test "accepts committed suite with require_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert :ok = Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_allow_decrypt)
    end

    test "rejects non-committed suite with require_encrypt_require_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      assert {:error, :commitment_policy_requires_committed_suite} =
               Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
    end

    test "rejects committed suite with forbid_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert {:error, :commitment_policy_forbids_committed_suite} =
               Behaviour.validate_commitment_policy_for_encrypt(suite, :forbid_encrypt_allow_decrypt)
    end

    test "accepts non-committed suite with forbid_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      assert :ok = Behaviour.validate_commitment_policy_for_encrypt(suite, :forbid_encrypt_allow_decrypt)
    end
  end

  describe "validate_commitment_policy_for_decrypt/2" do
    test "accepts any suite with require_encrypt_allow_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok = Behaviour.validate_commitment_policy_for_decrypt(committed, :require_encrypt_allow_decrypt)
      assert :ok = Behaviour.validate_commitment_policy_for_decrypt(non_committed, :require_encrypt_allow_decrypt)
    end

    test "accepts any suite with forbid_encrypt_allow_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok = Behaviour.validate_commitment_policy_for_decrypt(committed, :forbid_encrypt_allow_decrypt)
      assert :ok = Behaviour.validate_commitment_policy_for_decrypt(non_committed, :forbid_encrypt_allow_decrypt)
    end

    test "only accepts committed suite with require_encrypt_require_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok = Behaviour.validate_commitment_policy_for_decrypt(committed, :require_encrypt_require_decrypt)
      assert {:error, :commitment_policy_requires_committed_suite} =
               Behaviour.validate_commitment_policy_for_decrypt(non_committed, :require_encrypt_require_decrypt)
    end
  end

  describe "validate_encryption_materials/1" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3>>)

      %{suite: suite, key: key, edk: edk}
    end

    test "accepts valid materials", %{suite: suite, key: key, edk: edk} do
      materials = EncryptionMaterials.new(suite, %{}, [edk], key)
      assert :ok = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials without plaintext data key", %{suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert {:error, :missing_plaintext_data_key} = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials with wrong key length", %{suite: suite, edk: edk} do
      wrong_key = :crypto.strong_rand_bytes(16)
      materials = EncryptionMaterials.new(suite, %{}, [edk], wrong_key)
      assert {:error, :invalid_plaintext_data_key_length} = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials without encrypted data keys", %{suite: suite, key: key} do
      materials = %EncryptionMaterials{
        algorithm_suite: suite,
        encryption_context: %{},
        encrypted_data_keys: [],
        plaintext_data_key: key
      }
      assert {:error, :missing_encrypted_data_keys} = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects signed suite without signing key", %{key: key, edk: edk} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      materials = EncryptionMaterials.new(signed_suite, %{}, [edk], key)
      assert {:error, :missing_signing_key} = Behaviour.validate_encryption_materials(materials)
    end

    test "accepts signed suite with signing key", %{key: key, edk: edk} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      signing_key = :crypto.strong_rand_bytes(48)
      materials = EncryptionMaterials.new(signed_suite, %{}, [edk], key, signing_key: signing_key)
      assert :ok = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials missing required context key", %{suite: suite, key: key, edk: edk} do
      materials = EncryptionMaterials.new(suite, %{}, [edk], key,
        required_encryption_context_keys: ["required_key"]
      )
      assert {:error, :missing_required_encryption_context_key} = Behaviour.validate_encryption_materials(materials)
    end

    test "accepts materials with required context keys present", %{suite: suite, key: key, edk: edk} do
      materials = EncryptionMaterials.new(suite, %{"required_key" => "value"}, [edk], key,
        required_encryption_context_keys: ["required_key"]
      )
      assert :ok = Behaviour.validate_encryption_materials(materials)
    end
  end

  describe "validate_decryption_materials/1" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)

      %{suite: suite, key: key}
    end

    test "accepts valid materials", %{suite: suite, key: key} do
      materials = DecryptionMaterials.new(suite, %{}, key)
      assert :ok = Behaviour.validate_decryption_materials(materials)
    end

    test "rejects materials without plaintext data key", %{suite: suite} do
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      assert {:error, :missing_plaintext_data_key} = Behaviour.validate_decryption_materials(materials)
    end

    test "rejects materials with wrong key length", %{suite: suite} do
      wrong_key = :crypto.strong_rand_bytes(16)
      materials = DecryptionMaterials.new(suite, %{}, wrong_key)
      assert {:error, :invalid_plaintext_data_key_length} = Behaviour.validate_decryption_materials(materials)
    end

    test "rejects signed suite without verification key", %{key: key} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      materials = DecryptionMaterials.new(signed_suite, %{}, key)
      assert {:error, :missing_verification_key} = Behaviour.validate_decryption_materials(materials)
    end

    test "accepts signed suite with verification key", %{key: key} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      verification_key = :crypto.strong_rand_bytes(48)
      materials = DecryptionMaterials.new(signed_suite, %{}, key, verification_key: verification_key)
      assert :ok = Behaviour.validate_decryption_materials(materials)
    end
  end

  describe "validate_encryption_context_for_encrypt/1" do
    test "accepts context without reserved key" do
      assert :ok = Behaviour.validate_encryption_context_for_encrypt(%{"key" => "value"})
    end

    test "accepts empty context" do
      assert :ok = Behaviour.validate_encryption_context_for_encrypt(%{})
    end

    test "rejects context with reserved key" do
      context = %{"aws-crypto-public-key" => "some_value"}
      assert {:error, :reserved_encryption_context_key} =
               Behaviour.validate_encryption_context_for_encrypt(context)
    end
  end

  describe "validate_signing_context_consistency/2" do
    test "accepts unsigned suite without public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert :ok = Behaviour.validate_signing_context_consistency(suite, %{})
    end

    test "accepts signed suite with public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      context = %{"aws-crypto-public-key" => "base64_key"}
      assert :ok = Behaviour.validate_signing_context_consistency(suite, context)
    end

    test "rejects signed suite without public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      assert {:error, :missing_public_key_in_context} =
               Behaviour.validate_signing_context_consistency(suite, %{})
    end

    test "rejects unsigned suite with public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"aws-crypto-public-key" => "base64_key"}
      assert {:error, :unexpected_public_key_in_context} =
               Behaviour.validate_signing_context_consistency(suite, context)
    end
  end

  describe "validate_reproduced_context/2" do
    test "accepts nil reproduced context" do
      assert :ok = Behaviour.validate_reproduced_context(%{"key" => "value"}, nil)
    end

    test "accepts matching values for shared keys" do
      context = %{"key1" => "value1", "key2" => "value2"}
      reproduced = %{"key1" => "value1"}
      assert :ok = Behaviour.validate_reproduced_context(context, reproduced)
    end

    test "accepts reproduced with extra keys" do
      context = %{"key1" => "value1"}
      reproduced = %{"key1" => "value1", "key2" => "value2"}
      assert :ok = Behaviour.validate_reproduced_context(context, reproduced)
    end

    test "rejects mismatched values" do
      context = %{"key1" => "value1"}
      reproduced = %{"key1" => "different"}
      assert {:error, {:encryption_context_mismatch, "key1"}} =
               Behaviour.validate_reproduced_context(context, reproduced)
    end
  end

  describe "merge_reproduced_context/2" do
    test "returns context unchanged when reproduced is nil" do
      context = %{"key1" => "value1"}
      assert %{"key1" => "value1"} = Behaviour.merge_reproduced_context(context, nil)
    end

    test "merges reproduced keys not in context" do
      context = %{"key1" => "value1"}
      reproduced = %{"key2" => "value2"}
      result = Behaviour.merge_reproduced_context(context, reproduced)
      assert result == %{"key1" => "value1", "key2" => "value2"}
    end

    test "context values take precedence over reproduced" do
      context = %{"key1" => "context_value"}
      reproduced = %{"key1" => "reproduced_value"}
      result = Behaviour.merge_reproduced_context(context, reproduced)
      assert result == %{"key1" => "context_value"}
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix test test/aws_encryption_sdk/cmm/behaviour_test.exs`
- [x] Full quality check: `mix quality`

#### Manual Verification:
- [x] Review test coverage is comprehensive

**Implementation Note**: After completing this phase and all automated verification passes, the implementation is complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] No compiler warnings: `mix compile --warnings-as-errors`

### Manual:
- [x] Module documentation is clear and comprehensive
- [x] Helper functions cover all spec requirements

## Testing Strategy

### Unit Tests

All helper functions have dedicated unit tests covering:
- Happy path (valid inputs)
- Error cases (invalid inputs)
- Edge cases (nil values, empty collections)
- All commitment policy combinations
- Signed and unsigned algorithm suites

### Doctest Integration

All public functions have doctests that serve as documentation and lightweight tests.

### Manual Testing Steps

1. Load module in IEx and verify callbacks are defined
2. Test commitment policy helpers with various suite/policy combinations
3. Test materials validation with intentionally incomplete materials
4. Test context validation with reserved key present

## References

- Issue: #36
- Research: `thoughts/shared/research/2026-01-26-GH36-cmm-behaviour.md`
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Keyring Behaviour (pattern): `lib/aws_encryption_sdk/keyring/behaviour.ex`
