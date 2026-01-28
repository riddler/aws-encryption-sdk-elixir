# AWS KMS Keyring Implementation Plan

## Overview

Implement the AWS KMS Keyring that encrypts and decrypts data keys using AWS KMS. This keyring:
- Generates new data keys using KMS `GenerateDataKey` (when no plaintext key exists)
- Encrypts existing data keys using KMS `Encrypt` (for multi-keyring scenarios)
- Decrypts data keys using KMS `Decrypt`

This is the core keyring for production use cases and enables integration with AWS KMS for key management.

**Issue**: #48
**Research**: `thoughts/shared/research/2026-01-27-GH48-aws-kms-keyring.md`

## Specification Requirements

### Source Documents
- [aws-kms-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md) - Main KMS keyring specification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - General keyring interface
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN validation requirements

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Key identifier MUST NOT be null or empty | aws-kms-keyring.md#initialization | MUST |
| KMS client MUST NOT be null | aws-kms-keyring.md#initialization | MUST |
| GenerateDataKey when no plaintext key | aws-kms-keyring.md#onencrypt | MUST |
| Encrypt when plaintext key exists | aws-kms-keyring.md#onencrypt | MUST |
| Response plaintext length MUST equal kdf_input_length | aws-kms-keyring.md#onencrypt | MUST |
| Response KeyId MUST be valid ARN | aws-kms-keyring.md#onencrypt | MUST |
| Provider ID MUST be "aws-kms" | aws-kms-keyring.md#onencrypt | MUST |
| Provider info MUST be response KeyId | aws-kms-keyring.md#onencrypt | MUST |
| Fail if plaintext key already set (decrypt) | aws-kms-keyring.md#ondecrypt | MUST |
| Filter EDKs by provider ID "aws-kms" | aws-kms-keyring.md#ondecrypt | MUST |
| Filter EDKs by ARN resource type "key" | aws-kms-keyring.md#ondecrypt | MUST |
| Match provider info to configured key | aws-kms-keyring.md#ondecrypt | MUST |
| Verify response KeyId matches configured key | aws-kms-keyring.md#ondecrypt | MUST |
| Collect all errors during decrypt | aws-kms-keyring.md#ondecrypt | MUST |
| Grant tokens MAY be provided | aws-kms-keyring.md#initialization | MAY |

## Current State Analysis

### Existing Infrastructure

**KMS Client Abstraction (Completed - Issue #46):**
- `lib/aws_encryption_sdk/keyring/kms_client.ex` - Behaviour with `generate_data_key/5`, `encrypt/5`, `decrypt/5`
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` - Production implementation
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Mock for testing

**KMS Key ARN Utilities (Completed - Issue #47):**
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` - ARN parsing, MRK detection, MRK matching

**Reference Implementations:**
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Pattern for `wrap_key/2` and `unwrap_key/3`
- `lib/aws_encryption_sdk/keyring/multi.ex` - Pattern for keyring dispatch

**Materials:**
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - `set_plaintext_data_key/2`, `add_encrypted_data_key/2`
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - `set_plaintext_data_key/2`

### Key Discoveries

1. `kdf_input_length` is the required data key length from algorithm suite (typically 16, 24, or 32 bytes)
2. Raw AES keyring pattern at `raw_aes.ex:246` shows EDK iteration with error filtering
3. Multi-keyring at `multi.ex:211-226` shows dispatch pattern for keyring types
4. Default CMM at `default.ex:74-88` needs dispatch clauses for AwsKms

## Desired End State

After this plan is complete:
1. `lib/aws_encryption_sdk/keyring/aws_kms.ex` exists with full implementation
2. `wrap_key/2` generates or encrypts data keys via KMS
3. `unwrap_key/3` decrypts EDKs via KMS with proper filtering
4. Default CMM and Multi-keyring dispatch to AwsKms correctly
5. Comprehensive unit tests using Mock KMS client

### Verification

```elixir
# In IEx:
{:ok, mock} = AwsEncryptionSdk.Keyring.KmsClient.Mock.new(%{
  {:generate_data_key, "arn:aws:kms:us-west-2:123:key/abc"} => %{
    plaintext: :crypto.strong_rand_bytes(32),
    ciphertext: :crypto.strong_rand_bytes(128),
    key_id: "arn:aws:kms:us-west-2:123:key/abc"
  }
})

{:ok, keyring} = AwsEncryptionSdk.Keyring.AwsKms.new(
  "arn:aws:kms:us-west-2:123:key/abc",
  mock
)

suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})

{:ok, result} = AwsEncryptionSdk.Keyring.AwsKms.wrap_key(keyring, materials)
# result.plaintext_data_key is set
# result.encrypted_data_keys has one EDK with provider_id "aws-kms"
```

## What We're NOT Doing

- AWS KMS Discovery Keyring (separate issue)
- AWS KMS MRK-aware Keyrings (separate issue)
- Integration tests with real AWS KMS (requires credentials)
- Streaming encryption/decryption

## Implementation Approach

Follow the established keyring pattern:
1. Define struct with `kms_key_id`, `kms_client`, `grant_tokens`
2. Implement `new/3` with validation per spec
3. Implement `wrap_key/2` with GenerateDataKey and Encrypt paths
4. Implement `unwrap_key/3` with EDK filtering and decryption
5. Add dispatch clauses to Default CMM and Multi-keyring
6. Add unit tests using Mock KMS client

---

## Phase 1: Struct and Constructor

### Overview

Define the AwsKms keyring struct and constructor with spec-compliant validation.

### Spec Requirements Addressed

- Key identifier MUST NOT be null or empty (aws-kms-keyring.md#initialization)
- KMS client MUST NOT be null (aws-kms-keyring.md#initialization)
- Grant tokens MAY be provided (aws-kms-keyring.md#initialization)

### Changes Required

#### 1. Create AWS KMS Keyring Module

**File**: `lib/aws_encryption_sdk/keyring/aws_kms.ex`
**Changes**: Create new file with struct and constructor

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKms do
  @moduledoc """
  AWS KMS Keyring implementation.

  Encrypts and decrypts data keys using AWS KMS. This keyring can:
  - Generate new data keys using KMS GenerateDataKey
  - Encrypt existing data keys using KMS Encrypt (for multi-keyring)
  - Decrypt data keys using KMS Decrypt

  ## Example

      {:ok, client} = KmsClient.ExAws.new(region: "us-west-2")
      {:ok, keyring} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", client)

      # Use with Default CMM
      cmm = Default.new(keyring)
      {:ok, materials} = Default.get_encryption_materials(cmm, request)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  @type t :: %__MODULE__{
          kms_key_id: String.t(),
          kms_client: struct(),
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]

  @doc """
  Creates a new AWS KMS Keyring.

  ## Parameters

  - `kms_key_id` - AWS KMS key identifier (ARN, alias ARN, alias name, or key ID)
  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `opts` - Optional keyword list:
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :key_id_required}` - kms_key_id is nil
  - `{:error, :key_id_empty}` - kms_key_id is empty string
  - `{:error, :invalid_key_id_type}` - kms_key_id is not a string
  - `{:error, :client_required}` - kms_client is nil
  - `{:error, :invalid_client_type}` - kms_client is not a struct

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", client)

      # With grant tokens
      {:ok, keyring} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", client,
        grant_tokens: ["token1", "token2"]
      )

  """
  @spec new(String.t(), struct(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_key_id, kms_client, opts \\ []) do
    with :ok <- validate_key_id(kms_key_id),
         :ok <- validate_client(kms_client) do
      {:ok,
       %__MODULE__{
         kms_key_id: kms_key_id,
         kms_client: kms_client,
         grant_tokens: Keyword.get(opts, :grant_tokens, [])
       }}
    end
  end

  defp validate_key_id(nil), do: {:error, :key_id_required}
  defp validate_key_id(""), do: {:error, :key_id_empty}
  defp validate_key_id(key_id) when is_binary(key_id), do: :ok
  defp validate_key_id(_), do: {:error, :invalid_key_id_type}

  defp validate_client(nil), do: {:error, :client_required}
  defp validate_client(%{__struct__: _}), do: :ok
  defp validate_client(_), do: {:error, :invalid_client_type}

  # Placeholder implementations for behaviour
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKms.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call AwsKms.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] Constructor tests pass:
  - `new/3` returns `{:ok, keyring}` with valid inputs
  - `new/3` returns `{:error, :key_id_required}` when key_id is nil
  - `new/3` returns `{:error, :key_id_empty}` when key_id is ""
  - `new/3` returns `{:error, :client_required}` when client is nil
  - Grant tokens are stored correctly

#### Manual Verification:
- [x] Module compiles without warnings
- [x] Struct can be created in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: wrap_key Implementation

### Overview

Implement `wrap_key/2` with both the GenerateDataKey path (no existing plaintext key) and Encrypt path (existing plaintext key from multi-keyring).

### Spec Requirements Addressed

- GenerateDataKey when no plaintext key (aws-kms-keyring.md#onencrypt)
- Encrypt when plaintext key exists (aws-kms-keyring.md#onencrypt)
- NumberOfBytes MUST be kdf_input_length (aws-kms-keyring.md#onencrypt)
- EncryptionContext MUST be from materials (aws-kms-keyring.md#onencrypt)
- GrantTokens MUST be from keyring (aws-kms-keyring.md#onencrypt)
- Response plaintext length validation (aws-kms-keyring.md#onencrypt)
- Response KeyId MUST be valid ARN (aws-kms-keyring.md#onencrypt)
- EDK provider ID MUST be "aws-kms" (aws-kms-keyring.md#onencrypt)
- EDK provider info MUST be response KeyId (aws-kms-keyring.md#onencrypt)

### Changes Required

#### 1. Add wrap_key Function

**File**: `lib/aws_encryption_sdk/keyring/aws_kms.ex`
**Changes**: Add wrap_key/2 implementation

```elixir
# Add aliases at top of module
alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
alias AwsEncryptionSdk.Keyring.KmsKeyArn
alias AwsEncryptionSdk.Materials.{EncryptedDataKey, EncryptionMaterials}

@provider_id "aws-kms"

@doc """
Wraps a data key using AWS KMS.

If materials don't have a plaintext data key, generates one using KMS GenerateDataKey.
If materials already have a plaintext data key, encrypts it using KMS Encrypt.

## Returns

- `{:ok, materials}` - Data key generated/encrypted and EDK added
- `{:error, reason}` - KMS operation failed or validation error

## Examples

    {:ok, result} = AwsKms.wrap_key(keyring, materials)

"""
@spec wrap_key(t(), EncryptionMaterials.t()) ::
        {:ok, EncryptionMaterials.t()} | {:error, term()}
def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    encrypt_existing_key(keyring, materials)
  else
    generate_new_key(keyring, materials)
  end
end

# GenerateDataKey path - no existing plaintext key
defp generate_new_key(keyring, materials) do
  number_of_bytes = materials.algorithm_suite.kdf_input_length
  client_module = keyring.kms_client.__struct__

  result =
    client_module.generate_data_key(
      keyring.kms_client,
      keyring.kms_key_id,
      number_of_bytes,
      materials.encryption_context,
      keyring.grant_tokens
    )

  with {:ok, response} <- result,
       :ok <- validate_plaintext_length(response.plaintext, number_of_bytes),
       :ok <- validate_key_id_is_arn(response.key_id) do
    edk = EncryptedDataKey.new(@provider_id, response.key_id, response.ciphertext)

    materials
    |> EncryptionMaterials.set_plaintext_data_key(response.plaintext)
    |> EncryptionMaterials.add_encrypted_data_key(edk)
    |> then(&{:ok, &1})
  end
end

# Encrypt path - existing plaintext key (multi-keyring scenario)
defp encrypt_existing_key(keyring, materials) do
  client_module = keyring.kms_client.__struct__

  result =
    client_module.encrypt(
      keyring.kms_client,
      keyring.kms_key_id,
      materials.plaintext_data_key,
      materials.encryption_context,
      keyring.grant_tokens
    )

  with {:ok, response} <- result,
       :ok <- validate_key_id_is_arn(response.key_id) do
    edk = EncryptedDataKey.new(@provider_id, response.key_id, response.ciphertext)
    {:ok, EncryptionMaterials.add_encrypted_data_key(materials, edk)}
  end
end

defp validate_plaintext_length(plaintext, expected) when byte_size(plaintext) == expected, do: :ok

defp validate_plaintext_length(plaintext, expected) do
  {:error, {:invalid_plaintext_length, expected: expected, actual: byte_size(plaintext)}}
end

defp validate_key_id_is_arn(key_id) do
  case KmsKeyArn.parse(key_id) do
    {:ok, _arn} -> :ok
    {:error, reason} -> {:error, {:invalid_response_key_id, reason}}
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] wrap_key tests pass:
  - Generates new key when no plaintext key exists
  - Encrypts existing key when plaintext key exists
  - EDK has correct provider_id "aws-kms"
  - EDK has correct provider_info (response key_id)
  - Validates plaintext length matches kdf_input_length
  - Validates response key_id is valid ARN
  - Returns error on KMS failure

#### Manual Verification:
- [x] wrap_key works in IEx with mock client

**Implementation Note**: After completing this phase, pause for manual verification before proceeding to Phase 3.

---

## Phase 3: unwrap_key Implementation

### Overview

Implement `unwrap_key/3` with EDK filtering by provider ID, ARN validation, key matching, and sequential decryption attempts.

### Spec Requirements Addressed

- Fail if plaintext key already set (aws-kms-keyring.md#ondecrypt)
- Filter EDKs by provider ID "aws-kms" (aws-kms-keyring.md#ondecrypt)
- Filter EDKs by ARN resource type "key" (aws-kms-keyring.md#ondecrypt)
- Match provider info to configured key (aws-kms-keyring.md#ondecrypt)
- Decrypt with configured key (aws-kms-keyring.md#ondecrypt)
- Verify response KeyId matches configured key (aws-kms-keyring.md#ondecrypt)
- Verify response plaintext length (aws-kms-keyring.md#ondecrypt)
- Return immediately on success (aws-kms-keyring.md#ondecrypt)
- Collect all errors on failure (aws-kms-keyring.md#ondecrypt)

### Changes Required

#### 1. Add unwrap_key Function

**File**: `lib/aws_encryption_sdk/keyring/aws_kms.ex`
**Changes**: Add unwrap_key/3 implementation

```elixir
# Add alias
alias AwsEncryptionSdk.Materials.DecryptionMaterials

@doc """
Unwraps a data key using AWS KMS.

Filters EDKs to find those encrypted with KMS, then attempts decryption
with the configured KMS key. Returns on first successful decryption.

## Returns

- `{:ok, materials}` - Data key successfully decrypted
- `{:error, :plaintext_data_key_already_set}` - Materials already have key
- `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

## Examples

    {:ok, result} = AwsKms.unwrap_key(keyring, materials, edks)

"""
@spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
        {:ok, DecryptionMaterials.t()} | {:error, term()}
def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:error, :plaintext_data_key_already_set}
  else
    try_decrypt_edks(keyring, materials, edks, [])
  end
end

defp try_decrypt_edks(_keyring, _materials, [], errors) do
  {:error, {:unable_to_decrypt_any_data_key, Enum.reverse(errors)}}
end

defp try_decrypt_edks(keyring, materials, [edk | rest], errors) do
  case try_decrypt_edk(keyring, materials, edk) do
    {:ok, plaintext} ->
      DecryptionMaterials.set_plaintext_data_key(materials, plaintext)

    {:error, reason} ->
      try_decrypt_edks(keyring, materials, rest, [reason | errors])
  end
end

defp try_decrypt_edk(keyring, materials, edk) do
  with :ok <- match_provider_id(edk),
       {:ok, arn} <- parse_provider_info_arn(edk),
       :ok <- validate_resource_type_is_key(arn),
       :ok <- match_key_identifier(keyring, edk.key_provider_info),
       {:ok, plaintext} <- call_kms_decrypt(keyring, materials, edk),
       :ok <- validate_decrypted_length(plaintext, materials.algorithm_suite.kdf_input_length) do
    {:ok, plaintext}
  end
end

defp match_provider_id(%{key_provider_id: @provider_id}), do: :ok
defp match_provider_id(%{key_provider_id: id}), do: {:error, {:provider_id_mismatch, id}}

defp parse_provider_info_arn(edk) do
  case KmsKeyArn.parse(edk.key_provider_info) do
    {:ok, arn} -> {:ok, arn}
    {:error, reason} -> {:error, {:invalid_provider_info_arn, reason}}
  end
end

defp validate_resource_type_is_key(%{resource_type: "key"}), do: :ok

defp validate_resource_type_is_key(%{resource_type: type}) do
  {:error, {:invalid_resource_type, type}}
end

defp match_key_identifier(keyring, provider_info) do
  if KmsKeyArn.mrk_match?(keyring.kms_key_id, provider_info) do
    :ok
  else
    {:error, {:key_identifier_mismatch, keyring.kms_key_id, provider_info}}
  end
end

defp call_kms_decrypt(keyring, materials, edk) do
  client_module = keyring.kms_client.__struct__

  result =
    client_module.decrypt(
      keyring.kms_client,
      keyring.kms_key_id,
      edk.ciphertext,
      materials.encryption_context,
      keyring.grant_tokens
    )

  with {:ok, response} <- result,
       :ok <- verify_response_key_id(keyring, response.key_id) do
    {:ok, response.plaintext}
  end
end

defp verify_response_key_id(keyring, response_key_id) do
  if KmsKeyArn.mrk_match?(keyring.kms_key_id, response_key_id) do
    :ok
  else
    {:error, {:response_key_id_mismatch, keyring.kms_key_id, response_key_id}}
  end
end

defp validate_decrypted_length(plaintext, expected) when byte_size(plaintext) == expected do
  :ok
end

defp validate_decrypted_length(plaintext, expected) do
  {:error, {:invalid_decrypted_length, expected: expected, actual: byte_size(plaintext)}}
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] unwrap_key tests pass:
  - Decrypts matching EDK successfully
  - Fails if plaintext key already set
  - Filters out non-"aws-kms" provider IDs
  - Filters out invalid ARNs in provider info
  - Filters out non-"key" resource types
  - Filters out non-matching key identifiers
  - Verifies response key_id matches configured key
  - Verifies decrypted length matches kdf_input_length
  - Collects all errors when no EDK decrypts

#### Manual Verification:
- [x] unwrap_key works in IEx with mock client
- [x] Round-trip: wrap_key then unwrap_key recovers original key

**Implementation Note**: After completing this phase, pause for manual verification before proceeding to Phase 4.

---

## Phase 4: CMM and Multi-Keyring Integration

### Overview

Add dispatch clauses to Default CMM and Multi-keyring so AwsKms keyrings work in the complete encryption/decryption flow.

### Changes Required

#### 1. Update Default CMM Dispatch

**File**: `lib/aws_encryption_sdk/cmm/default.ex`
**Changes**: Add AwsKms dispatch clauses

```elixir
# Add to aliases (around line 37)
alias AwsEncryptionSdk.Keyring.AwsKms

# Update keyring type (around line 40)
@type keyring :: RawAes.t() | RawRsa.t() | Multi.t() | AwsKms.t()

# Add dispatch clause for call_wrap_key (after line 84)
def call_wrap_key(%AwsKms{} = keyring, materials) do
  AwsKms.wrap_key(keyring, materials)
end

# Add dispatch clause for call_unwrap_key (after line 103)
def call_unwrap_key(%AwsKms{} = keyring, materials, edks) do
  AwsKms.unwrap_key(keyring, materials, edks)
end
```

#### 2. Update Multi-Keyring Dispatch

**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add AwsKms dispatch clauses

```elixir
# Add to aliases (around line 56)
alias AwsEncryptionSdk.Keyring.AwsKms

# Add dispatch clause for call_wrap_key (after line 222)
defp call_wrap_key(%AwsKms{} = keyring, materials) do
  AwsKms.wrap_key(keyring, materials)
end

# Add dispatch clause for call_unwrap_key (after line 290)
defp call_unwrap_key(%AwsKms{} = keyring, materials, edks) do
  AwsKms.unwrap_key(keyring, materials, edks)
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] Default CMM tests pass with AwsKms keyring
- [x] Multi-keyring tests pass:
  - AwsKms as generator
  - AwsKms as child
  - Mixed keyrings (AwsKms + RawAes)

#### Manual Verification:
- [x] End-to-end encryption works via Default CMM
- [x] End-to-end decryption works via Default CMM

**Implementation Note**: After completing this phase, pause for manual verification before proceeding to Phase 5.

---

## Phase 5: Comprehensive Unit Tests

### Overview

Add comprehensive unit tests for the AwsKms keyring using the Mock KMS client.

### Changes Required

#### 1. Create Test File

**File**: `test/aws_encryption_sdk/keyring/aws_kms_test.exs`
**Changes**: Create comprehensive test suite

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @different_key_arn "arn:aws:kms:us-west-2:123456789012:key/different-key-id"

  describe "new/3" do
    test "creates keyring with valid inputs" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      assert keyring.kms_key_id == @kms_key_arn
      assert keyring.kms_client == mock
      assert keyring.grant_tokens == []
    end

    test "stores grant tokens" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock, grant_tokens: ["token1", "token2"])
      assert keyring.grant_tokens == ["token1", "token2"]
    end

    test "rejects nil key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_required} = AwsKms.new(nil, mock)
    end

    test "rejects empty key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_empty} = AwsKms.new("", mock)
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKms.new(@kms_key_arn, nil)
    end

    test "rejects non-struct client" do
      assert {:error, :invalid_client_type} = AwsKms.new(@kms_key_arn, %{})
    end
  end

  describe "wrap_key/2 - GenerateDataKey path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})

      {:ok,
       keyring: keyring,
       materials: materials,
       plaintext_key: plaintext_key,
       ciphertext: ciphertext}
    end

    test "generates new data key when none exists", ctx do
      {:ok, result} = AwsKms.wrap_key(ctx.keyring, ctx.materials)

      assert result.plaintext_data_key == ctx.plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.key_provider_info == @kms_key_arn
      assert edk.ciphertext == ctx.ciphertext
    end

    test "returns error on KMS failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} =>
            {:error, {:kms_error, :access_denied, "Access denied"}}
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:kms_error, :access_denied, "Access denied"}} =
               AwsKms.wrap_key(keyring, ctx.materials)
    end

    test "validates plaintext length", ctx do
      # Return wrong length plaintext
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: :crypto.strong_rand_bytes(16),
            ciphertext: ctx.ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:invalid_plaintext_length, expected: 32, actual: 16}} =
               AwsKms.wrap_key(keyring, ctx.materials)
    end
  end

  describe "wrap_key/2 - Encrypt path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @kms_key_arn} => %{
            ciphertext: ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      # Materials with existing plaintext key (multi-keyring scenario)
      materials =
        EncryptionMaterials.new(suite, %{"purpose" => "test"}, [], plaintext_key)

      {:ok,
       keyring: keyring,
       materials: materials,
       plaintext_key: plaintext_key,
       ciphertext: ciphertext}
    end

    test "encrypts existing key", ctx do
      {:ok, result} = AwsKms.wrap_key(ctx.keyring, ctx.materials)

      # Plaintext key unchanged
      assert result.plaintext_data_key == ctx.plaintext_key
      # EDK added
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.ciphertext == ctx.ciphertext
    end
  end

  describe "unwrap_key/3" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: plaintext_key,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})
      edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

      {:ok,
       keyring: keyring,
       materials: materials,
       edks: [edk],
       plaintext_key: plaintext_key}
    end

    test "decrypts matching EDK", ctx do
      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, ctx.edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "fails if plaintext key already set", ctx do
      {:ok, materials_with_key} =
        DecryptionMaterials.set_plaintext_data_key(ctx.materials, ctx.plaintext_key)

      assert {:error, :plaintext_data_key_already_set} =
               AwsKms.unwrap_key(ctx.keyring, materials_with_key, ctx.edks)
    end

    test "filters out non-aws-kms EDKs", ctx do
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out invalid ARN in provider info", ctx do
      invalid_edk = EncryptedDataKey.new("aws-kms", "not-an-arn", <<1, 2, 3>>)
      edks = [invalid_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out non-matching key identifiers", ctx do
      other_edk = EncryptedDataKey.new("aws-kms", @different_key_arn, <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "collects errors when no EDK decrypts", ctx do
      # Remove the valid EDK
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKms.unwrap_key(ctx.keyring, ctx.materials, [other_edk])

      assert [{:provider_id_mismatch, "other-provider"}] = errors
    end

    test "returns error when no EDKs provided", ctx do
      assert {:error, {:unable_to_decrypt_any_data_key, []}} =
               AwsKms.unwrap_key(ctx.keyring, ctx.materials, [])
    end
  end

  describe "MRK matching" do
    @mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"
    @mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"

    test "decrypts MRK EDK from different region" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_west
          }
        })

      # Keyring configured with us-west-2 MRK
      {:ok, keyring} = AwsKms.new(@mrk_us_west, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK from us-east-1 MRK (same key, different region)
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKms.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality`
- [x] All test cases pass
- [x] Coverage for:
  - Constructor validation
  - GenerateDataKey path
  - Encrypt path
  - Decrypt with filtering
  - Error collection
  - MRK matching

#### Manual Verification:
- [x] Test output is clear and descriptive
- [x] No flaky tests

**Implementation Note**: This is the final phase. After all tests pass, the implementation is complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All new tests pass
- [x] No regressions in existing tests

### Manual:
- [x] End-to-end encryption/decryption with mock client
- [x] Keyring works with Default CMM
- [x] Keyring works in Multi-keyring as generator
- [x] Keyring works in Multi-keyring as child

## Testing Strategy

### Unit Tests

All unit tests use the Mock KMS client to avoid AWS dependencies:

```elixir
{:ok, mock} = Mock.new(%{
  {:generate_data_key, "arn:..."} => %{plaintext: <<...>>, ciphertext: <<...>>, key_id: "arn:..."},
  {:encrypt, "arn:..."} => %{ciphertext: <<...>>, key_id: "arn:..."},
  {:decrypt, "arn:..."} => %{plaintext: <<...>>, key_id: "arn:..."}
})
```

### Test Categories

1. **Constructor tests**: Validation of inputs per spec
2. **wrap_key tests**: Both GenerateDataKey and Encrypt paths
3. **unwrap_key tests**: EDK filtering, decryption, error collection
4. **Integration tests**: CMM and Multi-keyring dispatch
5. **MRK tests**: Cross-region MRK matching

### Manual Testing

```elixir
# In IEx
{:ok, mock} = AwsEncryptionSdk.Keyring.KmsClient.Mock.new(%{...})
{:ok, keyring} = AwsEncryptionSdk.Keyring.AwsKms.new("arn:...", mock)
cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)

# Encrypt
{:ok, enc_materials} = AwsEncryptionSdk.Cmm.Default.get_encryption_materials(cmm, %{
  encryption_context: %{"purpose" => "test"},
  commitment_policy: :require_encrypt_require_decrypt
})

# Decrypt
{:ok, dec_materials} = AwsEncryptionSdk.Cmm.Default.get_decryption_materials(cmm, %{
  algorithm_suite: enc_materials.algorithm_suite,
  commitment_policy: :require_encrypt_require_decrypt,
  encrypted_data_keys: enc_materials.encrypted_data_keys,
  encryption_context: enc_materials.encryption_context
})
```

## References

- Issue: #48
- Research: `thoughts/shared/research/2026-01-27-GH48-aws-kms-keyring.md`
- Spec - AWS KMS Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
- Spec - Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- KMS Client (Issue #46): Completed (fc70176)
- KMS ARN Utilities (Issue #47): Completed (6fb2002)
