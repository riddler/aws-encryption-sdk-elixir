# Keyring Behaviour Interface Implementation Plan

## Overview

Define the Keyring behaviour interface per the AWS Encryption SDK specification. This establishes the contract that all keyring implementations (Raw AES, Raw RSA, AWS KMS, Multi-Keyring) must follow for encryption and decryption operations.

**Issue**: #25 - Define Keyring behaviour interface
**Research**: `thoughts/shared/research/2026-01-25-GH25-keyring-behaviour.md`

## Specification Requirements

### Source Documents
- [framework/keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface specification (Version 0.2.4)
- [framework/structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Data structures

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| OnEncrypt MUST take encryption materials as input | keyring-interface.md#onencrypt | MUST |
| OnEncrypt MUST modify materials with generate and/or encrypt behavior | keyring-interface.md#onencrypt | MUST |
| OnEncrypt MUST output modified encryption materials on success | keyring-interface.md#onencrypt | MUST |
| OnEncrypt MUST fail if no behavior attempted | keyring-interface.md#onencrypt | MUST |
| OnDecrypt MUST take decryption materials and EDK list as input | keyring-interface.md#ondecrypt | MUST |
| OnDecrypt MUST fail if plaintext data key already set | keyring-interface.md#ondecrypt | MUST |
| OnDecrypt MUST output modified decryption materials on success | keyring-interface.md#ondecrypt | MUST |
| OnDecrypt MUST fail without modifying materials if no decryption attempted | keyring-interface.md#ondecrypt | MUST |
| Generate data key if encryption materials lack one | keyring-interface.md#generate-data-key | MUST |
| Don't generate data key if encryption materials have one | keyring-interface.md#generate-data-key | MUST |
| Data key length MUST equal algorithm suite's KDF input length | keyring-interface.md#generate-data-key | MUST |
| Data key MUST be cryptographically random | keyring-interface.md#generate-data-key | MUST |
| Key provider ID MUST be binary | keyring-interface.md#key-provider-id | MUST |
| Key provider ID MUST NOT start with "aws-kms" for non-KMS keyrings | keyring-interface.md#key-provider-id | MUST |

## Test Vectors

### Validation Strategy

The Keyring behaviour itself is an interface definition without direct test vectors. However, the behaviour will be validated through:

1. **Unit tests** - Contract validation with mock implementations
2. **Integration tests** - Real keyring implementations (Raw AES, Raw RSA) will validate the behaviour works correctly
3. **Test vector validation** - When Raw AES Keyring (#26) is implemented, decrypt test vectors will validate the full flow

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | N/A (struct modification) | DecryptionMaterials compatibility |
| 2 | N/A (behaviour definition) | Interface contract |
| 3 | Unit tests with mocks | Behaviour contract validation |

## Current State Analysis

### Existing Code

| File | Status | Notes |
|------|--------|-------|
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | Exists | Ready for keyring use |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | Exists | **Needs modification** - `plaintext_data_key` is enforced but should be optional |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | Exists | Ready for keyring use |
| `lib/aws_encryption_sdk/keyring/behaviour.ex` | Missing | To be created |

### Key Discoveries

1. **DecryptionMaterials issue**: Current struct enforces `plaintext_data_key`, but keyrings receive materials *without* a data key and must *set* it. This is a blocking issue.

2. **EncryptionMaterials is ready**: The struct supports optional `plaintext_data_key` scenario through its constructor, though the struct itself enforces the key. We should review whether EncryptionMaterials also needs modification for the "generate data key" scenario.

3. **Pattern established**: Other materials modules use `new/N` constructors with `opts` keyword list for optional fields.

## Desired End State

After this plan is complete:

1. `DecryptionMaterials` supports being created without a `plaintext_data_key` (for keyring input)
2. `EncryptionMaterials` supports being created without a `plaintext_data_key` (for generate data key scenario)
3. `AwsEncryptionSdk.Keyring.Behaviour` module defines:
   - `@callback on_encrypt(EncryptionMaterials.t()) :: {:ok, EncryptionMaterials.t()} | {:error, term()}`
   - `@callback on_decrypt(DecryptionMaterials.t(), [EncryptedDataKey.t()]) :: {:ok, DecryptionMaterials.t()} | {:error, term()}`
4. Helper functions exist for common keyring operations
5. Comprehensive tests validate the behaviour contract

### Verification

```bash
# All tests pass
mix test

# Dialyzer passes
mix dialyzer

# Behaviour can be implemented
# (verified by creating a minimal test keyring)
```

## What We're NOT Doing

- **Implementing specific keyrings** - Raw AES (#26), Raw RSA (#27), Multi-Keyring (#28) are separate issues
- **Implementing CMM** - The Cryptographic Materials Manager is Milestone 3
- **Key zeroing** - BEAM's immutable binaries make this impractical; documented as a known limitation
- **Streaming support** - Out of scope for this interface definition

## Implementation Approach

1. **Modify materials structs** to support keyring workflow (materials without data keys)
2. **Define the behaviour** with clear callback specifications and documentation
3. **Add helper functions** for common operations (provider ID validation, data key generation)
4. **Write comprehensive tests** to validate the contract

---

## Phase 1: Modify Materials Structs

### Overview

Update `DecryptionMaterials` and `EncryptionMaterials` to support the keyring workflow where materials may not have a plaintext data key initially.

### Spec Requirements Addressed

- OnDecrypt MUST take decryption materials as input (materials without data key)
- OnEncrypt with generate behavior starts with materials without data key

### Changes Required

#### 1. DecryptionMaterials

**File**: `lib/aws_encryption_sdk/materials/decryption_materials.ex`

**Changes**:
- Remove `plaintext_data_key` from `@enforce_keys`
- Add default `nil` value in struct
- Add `new_for_decrypt/3` constructor for keyring/CMM use
- Update typespec to allow `nil`

```elixir
@type t :: %__MODULE__{
        algorithm_suite: AlgorithmSuite.t(),
        encryption_context: %{String.t() => String.t()},
        plaintext_data_key: binary() | nil,
        verification_key: binary() | nil,
        required_encryption_context_keys: [String.t()]
      }

@enforce_keys [
  :algorithm_suite,
  :encryption_context
]

defstruct [
  :algorithm_suite,
  :encryption_context,
  :plaintext_data_key,
  :verification_key,
  required_encryption_context_keys: []
]

@doc """
Creates decryption materials for keyring/CMM use (without plaintext data key).

The keyring will set the plaintext_data_key during on_decrypt.

## Parameters

- `algorithm_suite` - Algorithm suite from message header
- `encryption_context` - Encryption context from message header
- `opts` - Optional fields (:verification_key, :required_encryption_context_keys)
"""
@spec new_for_decrypt(AlgorithmSuite.t(), map(), keyword()) :: t()
def new_for_decrypt(algorithm_suite, encryption_context, opts \\ []) do
  %__MODULE__{
    algorithm_suite: algorithm_suite,
    encryption_context: encryption_context,
    plaintext_data_key: nil,
    verification_key: Keyword.get(opts, :verification_key),
    required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
  }
end

@doc """
Sets the plaintext data key on decryption materials.

Used by keyrings after successfully decrypting an EDK.

## Returns

- `{:ok, updated_materials}` - Data key was set
- `{:error, :plaintext_data_key_already_set}` - Data key was already present
"""
@spec set_plaintext_data_key(t(), binary()) :: {:ok, t()} | {:error, :plaintext_data_key_already_set}
def set_plaintext_data_key(%__MODULE__{plaintext_data_key: nil} = materials, key) when is_binary(key) do
  {:ok, %{materials | plaintext_data_key: key}}
end

def set_plaintext_data_key(%__MODULE__{plaintext_data_key: _existing}, _key) do
  {:error, :plaintext_data_key_already_set}
end
```

#### 2. EncryptionMaterials

**File**: `lib/aws_encryption_sdk/materials/encryption_materials.ex`

**Changes**:
- Remove `plaintext_data_key` from `@enforce_keys`
- Add default `nil` value in struct
- Add `new_for_encrypt/3` constructor for keyring/CMM use
- Update typespec to allow `nil`
- Add `set_plaintext_data_key/2` helper

```elixir
@type t :: %__MODULE__{
        algorithm_suite: AlgorithmSuite.t(),
        encryption_context: %{String.t() => String.t()},
        encrypted_data_keys: [EncryptedDataKey.t()],
        plaintext_data_key: binary() | nil,
        signing_key: binary() | nil,
        required_encryption_context_keys: [String.t()]
      }

@enforce_keys [
  :algorithm_suite,
  :encryption_context
]

defstruct [
  :algorithm_suite,
  :encryption_context,
  encrypted_data_keys: [],
  plaintext_data_key: nil,
  signing_key: nil,
  required_encryption_context_keys: []
]

@doc """
Creates encryption materials for keyring/CMM use (without plaintext data key).

The keyring will generate and set the plaintext_data_key during on_encrypt.

## Parameters

- `algorithm_suite` - Algorithm suite to use
- `encryption_context` - Encryption context map
- `opts` - Optional fields (:signing_key, :required_encryption_context_keys)
"""
@spec new_for_encrypt(AlgorithmSuite.t(), map(), keyword()) :: t()
def new_for_encrypt(algorithm_suite, encryption_context, opts \\ []) do
  %__MODULE__{
    algorithm_suite: algorithm_suite,
    encryption_context: encryption_context,
    encrypted_data_keys: [],
    plaintext_data_key: nil,
    signing_key: Keyword.get(opts, :signing_key),
    required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
  }
end

@doc """
Sets the plaintext data key on encryption materials.

Used by keyrings after generating a data key.
"""
@spec set_plaintext_data_key(t(), binary()) :: t()
def set_plaintext_data_key(%__MODULE__{} = materials, key) when is_binary(key) do
  %{materials | plaintext_data_key: key}
end

@doc """
Adds an encrypted data key to the materials.

Used by keyrings after encrypting the data key.
"""
@spec add_encrypted_data_key(t(), EncryptedDataKey.t()) :: t()
def add_encrypted_data_key(%__MODULE__{} = materials, %EncryptedDataKey{} = edk) do
  %{materials | encrypted_data_keys: materials.encrypted_data_keys ++ [edk]}
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test`
- [x] Dialyzer passes: `mix dialyzer`
- [x] Existing integration tests still pass (backward compatible)

#### Manual Verification:
- [x] Can create DecryptionMaterials without plaintext_data_key in IEx
- [x] Can create EncryptionMaterials without plaintext_data_key in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Define Keyring Behaviour

### Overview

Create the `AwsEncryptionSdk.Keyring.Behaviour` module that defines the callbacks all keyrings must implement.

### Spec Requirements Addressed

- OnEncrypt interface specification
- OnDecrypt interface specification
- Key provider ID/info requirements

### Changes Required

#### 1. Keyring Behaviour Module

**File**: `lib/aws_encryption_sdk/keyring/behaviour.ex` (new file)

```elixir
defmodule AwsEncryptionSdk.Keyring.Behaviour do
  @moduledoc """
  Behaviour for keyring implementations.

  Keyrings are responsible for generating, encrypting, and decrypting data keys.
  All keyring implementations must implement this behaviour.

  ## Callbacks

  - `on_encrypt/1` - Generate and/or encrypt data keys during encryption
  - `on_decrypt/2` - Decrypt data keys during decryption

  ## OnEncrypt Behavior

  The `on_encrypt/1` callback receives encryption materials and MUST perform at least
  one of the following behaviors:

  1. **Generate Data Key**: If `materials.plaintext_data_key` is `nil`, generate a
     cryptographically random data key of the appropriate length for the algorithm suite.

  2. **Encrypt Data Key**: If `materials.plaintext_data_key` is set, encrypt it and
     add the resulting encrypted data key to the materials.

  A keyring MAY perform both behaviors (generate then encrypt).

  ## OnDecrypt Behavior

  The `on_decrypt/2` callback receives decryption materials (without a plaintext data key)
  and a list of encrypted data keys. It MUST:

  1. Fail immediately if `materials.plaintext_data_key` is already set
  2. Attempt to decrypt one of the provided EDKs
  3. On success, return materials with `plaintext_data_key` set
  4. On failure, return an error without modifying the materials

  ## Key Provider Constraints

  - Key provider IDs MUST be UTF-8 encoded binary strings
  - Key provider IDs MUST NOT start with "aws-kms" unless the keyring is an AWS KMS keyring
  - Key provider info SHOULD be UTF-8 encoded binary strings

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
  """

  alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials, EncryptedDataKey}

  @doc """
  OnEncrypt operation.

  Takes encryption materials and returns modified encryption materials.
  MUST perform at least one of: Generate Data Key or Encrypt Data Key.

  ## Behaviors

  1. If `materials.plaintext_data_key` is nil, MUST generate a data key
  2. If `materials.plaintext_data_key` is set, MUST encrypt it and add EDK
  3. After generating, MAY also encrypt the generated key

  ## Returns

  - `{:ok, %EncryptionMaterials{}}` - Successfully modified materials
  - `{:error, term()}` - Failed to perform any behavior
  """
  @callback on_encrypt(materials :: EncryptionMaterials.t()) ::
              {:ok, EncryptionMaterials.t()} | {:error, term()}

  @doc """
  OnDecrypt operation.

  Takes decryption materials and list of encrypted data keys.
  Returns modified decryption materials with plaintext data key set.

  ## Preconditions

  - MUST fail if `materials.plaintext_data_key` is already set

  ## Behaviors

  1. Attempt to decrypt one of the provided EDKs that this keyring can handle
  2. On success, set the plaintext_data_key on materials
  3. On failure, return error without modifying materials

  ## Returns

  - `{:ok, %DecryptionMaterials{}}` - Successfully decrypted a data key
  - `{:error, term()}` - Unable to decrypt any data key
  """
  @callback on_decrypt(
              materials :: DecryptionMaterials.t(),
              encrypted_data_keys :: [EncryptedDataKey.t()]
            ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}

  @doc """
  Validates that a key provider ID is valid for non-KMS keyrings.

  Per the spec, key provider IDs MUST NOT start with "aws-kms" unless
  the keyring is an AWS KMS keyring.

  ## Examples

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("my-provider")
      :ok

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("aws-kms")
      {:error, :reserved_provider_id}

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("aws-kms-mrk")
      {:error, :reserved_provider_id}
  """
  @spec validate_provider_id(String.t()) :: :ok | {:error, :reserved_provider_id}
  def validate_provider_id(provider_id) when is_binary(provider_id) do
    if String.starts_with?(provider_id, "aws-kms") do
      {:error, :reserved_provider_id}
    else
      :ok
    end
  end

  @doc """
  Generates a cryptographically random data key of the appropriate length.

  The length is determined by the algorithm suite's KDF input length.

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = AwsEncryptionSdk.Keyring.Behaviour.generate_data_key(suite)
      iex> byte_size(key)
      32
  """
  @spec generate_data_key(AwsEncryptionSdk.AlgorithmSuite.t()) :: binary()
  def generate_data_key(algorithm_suite) do
    key_length_bytes = div(algorithm_suite.data_key_length, 8)
    :crypto.strong_rand_bytes(key_length_bytes)
  end

  @doc """
  Checks if materials already have a plaintext data key set.

  Useful for implementing the precondition checks in keyrings.
  """
  @spec has_plaintext_data_key?(EncryptionMaterials.t() | DecryptionMaterials.t()) :: boolean()
  def has_plaintext_data_key?(%{plaintext_data_key: nil}), do: false
  def has_plaintext_data_key?(%{plaintext_data_key: key}) when is_binary(key), do: true
end
```

### Success Criteria

#### Automated Verification:
- [x] Module compiles: `mix compile`
- [x] Dialyzer passes: `mix dialyzer`
- [x] Helper functions work correctly (unit tests)

#### Manual Verification:
- [x] Documentation renders correctly: `mix docs` and view in browser
- [x] Behaviour can be used with `@behaviour` directive

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Add Behaviour Tests

### Overview

Create comprehensive tests for the keyring behaviour, including contract validation using a mock implementation.

### Changes Required

#### 1. Keyring Behaviour Tests

**File**: `test/aws_encryption_sdk/keyring/behaviour_test.exs` (new file)

```elixir
defmodule AwsEncryptionSdk.Keyring.BehaviourTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.Behaviour
  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials, EncryptedDataKey}

  describe "validate_provider_id/1" do
    test "accepts valid provider IDs" do
      assert :ok = Behaviour.validate_provider_id("my-provider")
      assert :ok = Behaviour.validate_provider_id("raw-aes")
      assert :ok = Behaviour.validate_provider_id("custom-keyring")
      assert :ok = Behaviour.validate_provider_id("")
    end

    test "rejects aws-kms provider ID" do
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms")
    end

    test "rejects provider IDs starting with aws-kms" do
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms-mrk")
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms-discovery")
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms/key")
    end
  end

  describe "generate_data_key/1" do
    test "generates key of correct length for 256-bit suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 32
    end

    test "generates key of correct length for 192-bit suite" do
      suite = AlgorithmSuite.aes_192_gcm_iv12_tag16_no_kdf()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 24
    end

    test "generates key of correct length for 128-bit suite" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_no_kdf()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 16
    end

    test "generates unique keys on each call" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      keys = for _ <- 1..100, do: Behaviour.generate_data_key(suite)
      unique_keys = Enum.uniq(keys)

      assert length(unique_keys) == 100
    end
  end

  describe "has_plaintext_data_key?/1" do
    test "returns false for encryption materials without key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      refute Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns true for encryption materials with key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", key)
      materials = EncryptionMaterials.new(suite, %{}, [edk], key)

      assert Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns false for decryption materials without key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      refute Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns true for decryption materials with key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, key)

      assert Behaviour.has_plaintext_data_key?(materials)
    end
  end
end
```

#### 2. EncryptionMaterials Tests Update

**File**: `test/aws_encryption_sdk/materials/encryption_materials_test.exs`

Add tests for new functions:

```elixir
describe "new_for_encrypt/3" do
  test "creates materials without plaintext data key" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    context = %{"key" => "value"}

    materials = EncryptionMaterials.new_for_encrypt(suite, context)

    assert materials.algorithm_suite == suite
    assert materials.encryption_context == context
    assert materials.plaintext_data_key == nil
    assert materials.encrypted_data_keys == []
    assert materials.signing_key == nil
  end

  test "accepts optional signing_key" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    signing_key = :crypto.strong_rand_bytes(32)

    materials = EncryptionMaterials.new_for_encrypt(suite, %{}, signing_key: signing_key)

    assert materials.signing_key == signing_key
  end
end

describe "set_plaintext_data_key/2" do
  test "sets the plaintext data key" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    key = :crypto.strong_rand_bytes(32)

    updated = EncryptionMaterials.set_plaintext_data_key(materials, key)

    assert updated.plaintext_data_key == key
  end
end

describe "add_encrypted_data_key/2" do
  test "adds EDK to empty list" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    edk = EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)

    updated = EncryptionMaterials.add_encrypted_data_key(materials, edk)

    assert updated.encrypted_data_keys == [edk]
  end

  test "appends EDK to existing list" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    edk1 = EncryptedDataKey.new("provider1", "info1", <<1>>)
    edk2 = EncryptedDataKey.new("provider2", "info2", <<2>>)
    key = :crypto.strong_rand_bytes(32)
    materials = EncryptionMaterials.new(suite, %{}, [edk1], key)

    updated = EncryptionMaterials.add_encrypted_data_key(materials, edk2)

    assert updated.encrypted_data_keys == [edk1, edk2]
  end
end
```

#### 3. DecryptionMaterials Tests Update

**File**: `test/aws_encryption_sdk/materials/decryption_materials_test.exs`

Add tests for new functions:

```elixir
describe "new_for_decrypt/3" do
  test "creates materials without plaintext data key" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    context = %{"key" => "value"}

    materials = DecryptionMaterials.new_for_decrypt(suite, context)

    assert materials.algorithm_suite == suite
    assert materials.encryption_context == context
    assert materials.plaintext_data_key == nil
    assert materials.verification_key == nil
  end

  test "accepts optional verification_key" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    verification_key = :crypto.strong_rand_bytes(32)

    materials = DecryptionMaterials.new_for_decrypt(suite, %{}, verification_key: verification_key)

    assert materials.verification_key == verification_key
  end
end

describe "set_plaintext_data_key/2" do
  test "sets key when not already present" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    key = :crypto.strong_rand_bytes(32)

    assert {:ok, updated} = DecryptionMaterials.set_plaintext_data_key(materials, key)
    assert updated.plaintext_data_key == key
  end

  test "returns error when key already present" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    key = :crypto.strong_rand_bytes(32)
    materials = DecryptionMaterials.new(suite, %{}, key)

    assert {:error, :plaintext_data_key_already_set} =
             DecryptionMaterials.set_plaintext_data_key(materials, <<1, 2, 3>>)
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix test`
- [x] Full quality check: `mix quality`

#### Manual Verification:
- [x] Test coverage is adequate for the behaviour contract
- [x] Edge cases are covered

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding to Final Verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All new tests pass
- [x] No regressions in existing tests

### Manual:
- [x] Behaviour can be implemented by a simple mock keyring
- [x] Documentation is clear and complete
- [x] Ready for Raw AES Keyring implementation (#26)

## Testing Strategy

### Unit Tests

1. **Helper function tests**:
   - `validate_provider_id/1` - Valid IDs, reserved IDs
   - `generate_data_key/1` - Correct lengths, uniqueness
   - `has_plaintext_data_key?/1` - Both material types

2. **Materials struct tests**:
   - New constructors work correctly
   - Setter functions work correctly
   - Type constraints are enforced

### Integration Tests

The behaviour will be fully validated when implementing:
- Raw AES Keyring (#26) - First concrete implementation
- Raw RSA Keyring (#27) - Second implementation
- Multi-Keyring (#28) - Composition of keyrings

### Manual Testing Steps

1. In IEx, create materials without data key:
   ```elixir
   alias AwsEncryptionSdk.{AlgorithmSuite, Materials.EncryptionMaterials}
   suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
   materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})
   ```

2. Verify behaviour module is usable:
   ```elixir
   # In a test module
   defmodule TestKeyring do
     @behaviour AwsEncryptionSdk.Keyring.Behaviour
     # ... implement callbacks
   end
   ```

## References

- Issue: #25
- Research: `thoughts/shared/research/2026-01-25-GH25-keyring-behaviour.md`
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Structures Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md
