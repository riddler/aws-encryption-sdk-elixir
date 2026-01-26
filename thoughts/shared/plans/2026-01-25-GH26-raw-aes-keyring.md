# Raw AES Keyring Implementation Plan

## Overview

Implement the Raw AES Keyring per the AWS Encryption SDK specification. This keyring uses locally-provided AES keys to wrap and unwrap data keys using AES-GCM. It enables encryption scenarios where keys are managed locally rather than through AWS KMS.

**Issue**: #26
**Research**: `thoughts/shared/research/2026-01-25-GH26-raw-aes-keyring.md`

## Specification Requirements

### Source Documents
- [framework/raw-aes-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md) - Raw AES keyring specification
- [framework/keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - General keyring interface

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Keyring accepts key_namespace, key_name, wrapping_key, wrapping_algorithm | raw-aes-keyring.md#initialization | MUST |
| Wrapping key length MUST be 128, 192, or 256 bits | raw-aes-keyring.md#wrapping-key | MUST |
| Wrapping key length MUST match algorithm | raw-aes-keyring.md#wrapping-algorithm | MUST |
| Support AES-GCM with 128/192/256-bit keys, 12-byte IV, 16-byte tag | raw-aes-keyring.md#wrapping-algorithm | MUST |
| Generate data key if not present on encrypt | raw-aes-keyring.md#onencrypt | MUST |
| Serialize encryption context for AAD | raw-aes-keyring.md#onencrypt | MUST |
| Encrypt data key using AES-GCM with wrapping key | raw-aes-keyring.md#onencrypt | MUST |
| Use cryptographically random IV (12 bytes) | raw-aes-keyring.md#onencrypt | MUST |
| Construct EDK with namespace as provider ID | raw-aes-keyring.md#onencrypt | MUST |
| Fail on decrypt if plaintext key already exists | raw-aes-keyring.md#ondecrypt | MUST |
| Process EDKs serially until one succeeds | raw-aes-keyring.md#ondecrypt | MUST |
| Match provider ID and key name for EDK selection | raw-aes-keyring.md#ondecrypt | MUST |
| Validate IV and tag lengths from provider info | raw-aes-keyring.md#ondecrypt | MUST |
| Decrypt using AES-GCM with serialized EC as AAD | raw-aes-keyring.md#ondecrypt | MUST |

## Test Vectors

### Validation Strategy
Each phase includes specific test vectors to validate the implementation.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 4 | `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Basic AES-256 decrypt |
| 4 | `917a3a40-3b92-48f7-9cbe-231c9bde6222` | Verify consistency |
| 5 | `4be2393c-2916-4668-ae7a-d26ddb8de593` | AES-128 key support |
| 5 | `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | AES-192 key support |

### Key Material

From test vectors `keys.json`:
- `aes-128`: 128-bit key (`AAECAwQFBgcICRAREhMUFQ==`)
- `aes-192`: 192-bit key (`AAECAwQFBgcICRAREhMUFRYXGBkgISIj`)
- `aes-256`: 256-bit key (`AAECAwQFBgcICRAREhMUFRYXGBkgISIjJCUmJygpMDE=`)

Test vectors use provider ID: `aws-raw-vectors-persistant` (note: "persistant" spelling in test vectors)

## Current State Analysis

### Existing Code

| File | Purpose |
|------|---------|
| `lib/aws_encryption_sdk/keyring/behaviour.ex` | Keyring behaviour with callbacks and helpers |
| `lib/aws_encryption_sdk/crypto/aes_gcm.ex` | AES-GCM encrypt/decrypt operations |
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials with `set_plaintext_data_key/2`, `add_encrypted_data_key/2` |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | DecryptionMaterials with `set_plaintext_data_key/2` |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EDK struct with `new/3` |
| `lib/aws_encryption_sdk/format/encryption_context.ex` | EC serialization with `serialize/1` |

### Key Discoveries

- `Keyring.Behaviour.generate_data_key/1` generates random data key from algorithm suite (`behaviour.ex:136-139`)
- `Keyring.Behaviour.has_plaintext_data_key?/1` checks if materials have a data key (`behaviour.ex:162-163`)
- `Keyring.Behaviour.validate_provider_id/1` validates non-reserved provider ID (`behaviour.ex:114-120`)
- `AesGcm.encrypt/5` returns `{ciphertext, auth_tag}` tuple (`aes_gcm.ex:31-36`)
- `AesGcm.decrypt/6` returns `{:ok, plaintext}` or `{:error, :authentication_failed}` (`aes_gcm.ex:55-64`)
- `EncryptionContext.serialize/1` returns empty binary for empty map, count-prefixed for non-empty (`encryption_context.ex:74-86`)

## Desired End State

A fully functional `AwsEncryptionSdk.Keyring.RawAes` module that:
1. Implements the `Keyring.Behaviour` callbacks
2. Supports AES-128, AES-192, and AES-256 wrapping keys
3. Passes all Raw AES keyring test vectors
4. Provides clear error messages for validation failures

### Verification:
- `mix quality` passes
- `mix test --only test_vectors` passes for Raw AES keyring tests
- Manual round-trip test in IEx demonstrates encrypt/decrypt cycle

## What We're NOT Doing

- AWS KMS keyring (separate issue)
- Raw RSA keyring (separate issue)
- Multi-keyring (separate issue)
- CMM implementation (separate issue)
- Streaming encryption/decryption (future milestone)

## Implementation Approach

The implementation follows a bottom-up approach:
1. Define the struct and validation (no dependencies)
2. Implement provider info serialization (needed by both encrypt/decrypt)
3. Implement OnEncrypt (uses serialization)
4. Implement OnDecrypt (uses serialization, validates against test vectors)
5. Validate with additional test vectors for different key sizes

---

## Phase 1: Core Struct and Validation

### Overview
Define the `RawAes` struct with constructor and validation logic.

### Spec Requirements Addressed
- Initialization parameters (raw-aes-keyring.md#initialization)
- Wrapping key length validation (raw-aes-keyring.md#wrapping-key)
- Key-algorithm match validation (raw-aes-keyring.md#wrapping-algorithm)

### Changes Required

#### 1. Create RawAes Module
**File**: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
**Changes**: Create new module with struct and `new/4` constructor

```elixir
defmodule AwsEncryptionSdk.Keyring.RawAes do
  @moduledoc """
  Raw AES Keyring implementation.

  Uses locally-provided AES keys to wrap and unwrap data keys using AES-GCM.
  Supports 128, 192, and 256-bit wrapping keys.

  ## Example

      keyring = RawAes.new("my-namespace", "my-key-name", wrapping_key, :aes_256_gcm)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @iv_length 12
  @tag_length 16
  @tag_length_bits 128

  @typedoc "Wrapping algorithm for AES-GCM"
  @type wrapping_algorithm :: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm

  @type t :: %__MODULE__{
          key_namespace: String.t(),
          key_name: String.t(),
          wrapping_key: binary(),
          wrapping_algorithm: wrapping_algorithm()
        }

  @enforce_keys [:key_namespace, :key_name, :wrapping_key, :wrapping_algorithm]
  defstruct @enforce_keys

  @wrapping_algorithms %{
    aes_128_gcm: %{cipher: :aes_128_gcm, key_bits: 128},
    aes_192_gcm: %{cipher: :aes_192_gcm, key_bits: 192},
    aes_256_gcm: %{cipher: :aes_256_gcm, key_bits: 256}
  }

  @doc """
  Creates a new Raw AES Keyring.

  ## Parameters

  - `key_namespace` - Key provider ID (must not start with "aws-kms")
  - `key_name` - Unique identifier for the wrapping key
  - `wrapping_key` - Raw AES key bytes (16, 24, or 32 bytes)
  - `wrapping_algorithm` - `:aes_128_gcm`, `:aes_192_gcm`, or `:aes_256_gcm`

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :reserved_provider_id}` - key_namespace starts with "aws-kms"
  - `{:error, :invalid_wrapping_algorithm}` - unsupported algorithm
  - `{:error, :invalid_key_length}` - wrapping key length doesn't match algorithm
  """
  @spec new(String.t(), String.t(), binary(), wrapping_algorithm()) ::
          {:ok, t()} | {:error, term()}
  def new(key_namespace, key_name, wrapping_key, wrapping_algorithm)
      when is_binary(key_namespace) and is_binary(key_name) and is_binary(wrapping_key) do
    with :ok <- KeyringBehaviour.validate_provider_id(key_namespace),
         {:ok, config} <- get_algorithm_config(wrapping_algorithm),
         :ok <- validate_key_length(wrapping_key, config) do
      {:ok,
       %__MODULE__{
         key_namespace: key_namespace,
         key_name: key_name,
         wrapping_key: wrapping_key,
         wrapping_algorithm: wrapping_algorithm
       }}
    end
  end

  defp get_algorithm_config(algorithm) do
    case Map.fetch(@wrapping_algorithms, algorithm) do
      {:ok, config} -> {:ok, config}
      :error -> {:error, :invalid_wrapping_algorithm}
    end
  end

  defp validate_key_length(key, %{key_bits: expected_bits}) do
    actual_bits = bit_size(key)

    if actual_bits == expected_bits do
      :ok
    else
      {:error, {:invalid_key_length, expected: expected_bits, actual: actual_bits}}
    end
  end

  # Placeholder callbacks (implemented in later phases)
  @impl true
  def on_encrypt(_materials) do
    {:error, :not_implemented}
  end

  @impl true
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, :not_implemented}
  end
end
```

#### 2. Create Unit Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test.exs`
**Changes**: Create test file with struct and validation tests

```elixir
defmodule AwsEncryptionSdk.Keyring.RawAesTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawAes

  describe "new/4" do
    test "creates keyring with valid 256-bit key" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, keyring} = RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)
      assert keyring.key_namespace == "my-namespace"
      assert keyring.key_name == "my-key"
      assert keyring.wrapping_key == key
      assert keyring.wrapping_algorithm == :aes_256_gcm
    end

    test "creates keyring with valid 192-bit key" do
      key = :crypto.strong_rand_bytes(24)
      assert {:ok, _keyring} = RawAes.new("ns", "name", key, :aes_192_gcm)
    end

    test "creates keyring with valid 128-bit key" do
      key = :crypto.strong_rand_bytes(16)
      assert {:ok, _keyring} = RawAes.new("ns", "name", key, :aes_128_gcm)
    end

    test "rejects reserved provider ID" do
      key = :crypto.strong_rand_bytes(32)
      assert {:error, :reserved_provider_id} = RawAes.new("aws-kms", "key", key, :aes_256_gcm)
      assert {:error, :reserved_provider_id} = RawAes.new("aws-kms-mrk", "key", key, :aes_256_gcm)
    end

    test "rejects invalid wrapping algorithm" do
      key = :crypto.strong_rand_bytes(32)
      assert {:error, :invalid_wrapping_algorithm} = RawAes.new("ns", "key", key, :aes_512_gcm)
    end

    test "rejects key length mismatch" do
      key_256 = :crypto.strong_rand_bytes(32)
      key_128 = :crypto.strong_rand_bytes(16)

      assert {:error, {:invalid_key_length, expected: 128, actual: 256}} =
               RawAes.new("ns", "key", key_256, :aes_128_gcm)

      assert {:error, {:invalid_key_length, expected: 256, actual: 128}} =
               RawAes.new("ns", "key", key_128, :aes_256_gcm)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] Struct can be created in IEx with valid parameters

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: Provider Info Serialization

### Overview
Implement helper functions for serializing and deserializing the key provider info field used in EDKs.

### Spec Requirements Addressed
- Key provider information format (raw-aes-keyring.md#key-provider-information)

### Provider Info Format

Per the spec, the provider info is serialized as:
```
<<key_name_length::16-big, key_name::binary,
  auth_tag_length_bits::32-big,
  iv_length::32-big,
  iv::binary>>
```

| Field | Size | Value |
|-------|------|-------|
| Key Name Length | 2 bytes | Variable |
| Key Name | Variable | UTF-8 string |
| Auth Tag Length | 4 bytes | 128 (bits) |
| IV Length | 4 bytes | 12 (bytes) |
| IV | 12 bytes | Random |

### Changes Required

#### 1. Add Provider Info Functions
**File**: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
**Changes**: Add `serialize_provider_info/2` and `deserialize_provider_info/1` functions

```elixir
# Add after the struct definition, before on_encrypt/on_decrypt

@doc false
@spec serialize_provider_info(String.t(), binary()) :: binary()
def serialize_provider_info(key_name, iv) when byte_size(iv) == @iv_length do
  key_name_bytes = key_name
  key_name_len = byte_size(key_name_bytes)

  <<
    key_name_len::16-big,
    key_name_bytes::binary,
    @tag_length_bits::32-big,
    @iv_length::32-big,
    iv::binary
  >>
end

@doc false
@spec deserialize_provider_info(binary()) ::
        {:ok, %{key_name: String.t(), tag_length_bits: integer(), iv_length: integer(), iv: binary()}}
        | {:error, term()}
def deserialize_provider_info(<<
      key_name_len::16-big,
      key_name::binary-size(key_name_len),
      tag_length_bits::32-big,
      iv_length::32-big,
      iv::binary-size(iv_length)
    >>) do
  {:ok,
   %{
     key_name: key_name,
     tag_length_bits: tag_length_bits,
     iv_length: iv_length,
     iv: iv
   }}
end

def deserialize_provider_info(_data), do: {:error, :invalid_provider_info_format}
```

#### 2. Add Provider Info Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test.exs`
**Changes**: Add test cases for provider info serialization

```elixir
describe "serialize_provider_info/2" do
  test "serializes provider info correctly" do
    iv = :crypto.strong_rand_bytes(12)
    result = RawAes.serialize_provider_info("my-key", iv)

    # key_name_len (2) + "my-key" (6) + tag_len (4) + iv_len (4) + iv (12) = 28
    assert byte_size(result) == 28

    # Verify structure
    <<
      key_name_len::16-big,
      key_name::binary-size(key_name_len),
      tag_length_bits::32-big,
      iv_length::32-big,
      extracted_iv::binary-size(12)
    >> = result

    assert key_name == "my-key"
    assert tag_length_bits == 128
    assert iv_length == 12
    assert extracted_iv == iv
  end
end

describe "deserialize_provider_info/1" do
  test "deserializes valid provider info" do
    iv = :crypto.strong_rand_bytes(12)
    serialized = RawAes.serialize_provider_info("test-key", iv)

    assert {:ok, info} = RawAes.deserialize_provider_info(serialized)
    assert info.key_name == "test-key"
    assert info.tag_length_bits == 128
    assert info.iv_length == 12
    assert info.iv == iv
  end

  test "returns error for invalid format" do
    assert {:error, :invalid_provider_info_format} = RawAes.deserialize_provider_info(<<1, 2, 3>>)
  end

  test "round-trips through serialize/deserialize" do
    iv = :crypto.strong_rand_bytes(12)
    key_name = "namespace/key-name-with-special-chars"

    serialized = RawAes.serialize_provider_info(key_name, iv)
    assert {:ok, info} = RawAes.deserialize_provider_info(serialized)

    assert info.key_name == key_name
    assert info.iv == iv
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] Serialization produces expected binary format in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 3: OnEncrypt Implementation

### Overview
Implement the `on_encrypt/1` callback to generate/wrap data keys.

### Spec Requirements Addressed
- Data key generation (raw-aes-keyring.md#onencrypt)
- Encryption context serialization (raw-aes-keyring.md#onencrypt)
- AES-GCM wrapping (raw-aes-keyring.md#onencrypt)
- EDK construction (raw-aes-keyring.md#onencrypt)

### Changes Required

#### 1. Implement on_encrypt/1
**File**: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
**Changes**: Replace placeholder `on_encrypt/1` with full implementation

```elixir
alias AwsEncryptionSdk.Crypto.AesGcm
alias AwsEncryptionSdk.Format.EncryptionContext

@impl true
@spec on_encrypt(EncryptionMaterials.t()) :: {:ok, EncryptionMaterials.t()} | {:error, term()}
def on_encrypt(%EncryptionMaterials{} = materials) do
  keyring = get_keyring_from_context()  # This needs to be passed differently - see note below

  # Actually, the keyring needs to be part of the call. Looking at the behaviour,
  # on_encrypt takes materials only. The keyring struct IS the module, so we need
  # to implement this as a function that takes the keyring struct explicitly.
  {:error, :not_implemented}
end

# We need to change the approach - the behaviour callbacks need access to the keyring state.
# Looking at how other SDKs do this, the keyring is typically passed or the callbacks
# are instance methods. In Elixir with behaviours, we'll need a different pattern.
```

**Note**: The behaviour pattern needs adjustment. The callbacks `on_encrypt/1` and `on_decrypt/2` don't have access to the keyring struct. We need to add explicit functions that take the keyring as the first argument, or use a protocol instead.

**Revised approach**: Add functions that take keyring as first parameter:

```elixir
@doc """
Wraps a data key using this keyring's wrapping key.

If materials don't have a plaintext data key, one will be generated.
The wrapped key is added to the materials as an EDK.
"""
@spec wrap_key(t(), EncryptionMaterials.t()) :: {:ok, EncryptionMaterials.t()} | {:error, term()}
def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
  with {:ok, materials} <- ensure_data_key(keyring, materials),
       {:ok, serialized_ec} <- serialize_encryption_context(materials.encryption_context),
       {:ok, edk} <- encrypt_data_key(keyring, materials.plaintext_data_key, serialized_ec) do
    {:ok, EncryptionMaterials.add_encrypted_data_key(materials, edk)}
  end
end

defp ensure_data_key(keyring, materials) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:ok, materials}
  else
    key = KeyringBehaviour.generate_data_key(materials.algorithm_suite)
    {:ok, EncryptionMaterials.set_plaintext_data_key(materials, key)}
  end
end

defp serialize_encryption_context(ec) do
  # EncryptionContext.serialize/1 always succeeds for valid maps
  {:ok, EncryptionContext.serialize(ec)}
end

defp encrypt_data_key(%__MODULE__{} = keyring, plaintext_key, aad) do
  iv = :crypto.strong_rand_bytes(@iv_length)
  cipher = keyring.wrapping_algorithm

  {encrypted_key, tag} = AesGcm.encrypt(cipher, keyring.wrapping_key, iv, plaintext_key, aad)

  # Ciphertext field is encrypted_key || tag
  ciphertext = encrypted_key <> tag

  # Provider info includes key name and IV
  provider_info = serialize_provider_info(keyring.key_name, iv)

  edk = EncryptedDataKey.new(keyring.key_namespace, provider_info, ciphertext)
  {:ok, edk}
end

# Behaviour callback delegates to wrap_key
# But we need the keyring instance... This is the challenge.
```

**Final approach**: The behaviour callbacks in Elixir typically work with a module, not an instance. We need to either:
1. Pass the keyring struct in the materials (not spec-compliant)
2. Use a different pattern (protocol or explicit functions)

Looking at the existing behaviour definition, the callbacks take materials only. The typical Elixir pattern would be to have the keyring module implement the callbacks, but the keyring configuration (key_namespace, wrapping_key, etc.) needs to come from somewhere.

**Solution**: Implement explicit `wrap_key/2` and `unwrap_key/3` functions that take the keyring struct, and have the behaviour callbacks be implemented when the keyring is used through a CMM or wrapper that tracks the keyring instance.

For now, implement the explicit functions and add `@impl true` callbacks that return an error explaining they need to be called with the keyring struct:

```elixir
@impl true
def on_encrypt(_materials) do
  {:error, {:must_use_wrap_key, "Call RawAes.wrap_key(keyring, materials) instead"}}
end

@impl true
def on_decrypt(_materials, _edks) do
  {:error, {:must_use_unwrap_key, "Call RawAes.unwrap_key(keyring, materials, edks) instead"}}
end
```

#### 2. Add OnEncrypt Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test.exs`
**Changes**: Add test cases for wrap_key

```elixir
alias AwsEncryptionSdk.AlgorithmSuite
alias AwsEncryptionSdk.Materials.EncryptionMaterials

describe "wrap_key/2" do
  setup do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    {:ok, keyring: keyring, suite: suite}
  end

  test "generates data key when not present", %{keyring: keyring, suite: suite} do
    materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})
    assert materials.plaintext_data_key == nil

    assert {:ok, result} = RawAes.wrap_key(keyring, materials)
    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == 32
  end

  test "wraps existing data key", %{keyring: keyring, suite: suite} do
    existing_key = :crypto.strong_rand_bytes(32)
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

    assert {:ok, result} = RawAes.wrap_key(keyring, materials)
    assert result.plaintext_data_key == existing_key
  end

  test "adds EDK to materials", %{keyring: keyring, suite: suite} do
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})

    assert {:ok, result} = RawAes.wrap_key(keyring, materials)
    assert length(result.encrypted_data_keys) == 1

    [edk] = result.encrypted_data_keys
    assert edk.key_provider_id == "test-namespace"
    assert is_binary(edk.key_provider_info)
    assert is_binary(edk.ciphertext)
  end

  test "EDK provider info contains key name and IV", %{keyring: keyring, suite: suite} do
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})

    assert {:ok, result} = RawAes.wrap_key(keyring, materials)
    [edk] = result.encrypted_data_keys

    assert {:ok, info} = RawAes.deserialize_provider_info(edk.key_provider_info)
    assert info.key_name == "test-key"
    assert info.iv_length == 12
    assert info.tag_length_bits == 128
  end

  test "uses encryption context as AAD", %{keyring: keyring, suite: suite} do
    ec = %{"key1" => "value1", "key2" => "value2"}
    materials = EncryptionMaterials.new_for_encrypt(suite, ec)

    # Should succeed - AAD is used internally
    assert {:ok, _result} = RawAes.wrap_key(keyring, materials)
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] `wrap_key/2` can be called in IEx and produces valid EDK

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 4: OnDecrypt Implementation

### Overview
Implement the `unwrap_key/3` function to find and decrypt matching EDKs.

### Spec Requirements Addressed
- Existing key check (raw-aes-keyring.md#ondecrypt)
- Serial processing of EDKs (raw-aes-keyring.md#ondecrypt)
- Provider ID and key name matching (raw-aes-keyring.md#ondecrypt)
- IV and tag length validation (raw-aes-keyring.md#ondecrypt)
- AES-GCM unwrapping (raw-aes-keyring.md#ondecrypt)

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Basic AES-256 decrypt | Success |
| `917a3a40-3b92-48f7-9cbe-231c9bde6222` | AES-256 consistency check | Success |

### Changes Required

#### 1. Implement unwrap_key/3
**File**: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
**Changes**: Add `unwrap_key/3` function

```elixir
@doc """
Unwraps a data key using this keyring's wrapping key.

Iterates through EDKs to find one that:
1. Has matching key_provider_id (key_namespace)
2. Has matching key_name in provider_info
3. Successfully decrypts with this keyring's wrapping key

## Returns

- `{:ok, materials}` - Data key successfully unwrapped and set
- `{:error, :plaintext_data_key_already_set}` - Materials already have a key
- `{:error, :unable_to_decrypt_data_key}` - No matching EDK could be decrypted
"""
@spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
        {:ok, DecryptionMaterials.t()} | {:error, term()}
def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:error, :plaintext_data_key_already_set}
  else
    try_decrypt_edks(keyring, materials, edks)
  end
end

defp try_decrypt_edks(keyring, materials, edks) do
  serialized_ec = EncryptionContext.serialize(materials.encryption_context)

  result =
    Enum.reduce_while(edks, :no_match, fn edk, _acc ->
      case try_decrypt_edk(keyring, edk, serialized_ec) do
        {:ok, plaintext_key} -> {:halt, {:ok, plaintext_key}}
        {:error, _reason} -> {:cont, :no_match}
      end
    end)

  case result do
    {:ok, plaintext_key} ->
      DecryptionMaterials.set_plaintext_data_key(materials, plaintext_key)

    :no_match ->
      {:error, :unable_to_decrypt_data_key}
  end
end

defp try_decrypt_edk(keyring, edk, aad) do
  with :ok <- match_provider_id(keyring, edk),
       {:ok, info} <- deserialize_provider_info(edk.key_provider_info),
       :ok <- match_key_name(keyring, info),
       :ok <- validate_iv_length(info),
       :ok <- validate_tag_length(info),
       {:ok, encrypted_key, tag} <- split_ciphertext(edk.ciphertext, info) do
    AesGcm.decrypt(
      keyring.wrapping_algorithm,
      keyring.wrapping_key,
      info.iv,
      encrypted_key,
      aad,
      tag
    )
  end
end

defp match_provider_id(keyring, edk) do
  if edk.key_provider_id == keyring.key_namespace do
    :ok
  else
    {:error, :provider_id_mismatch}
  end
end

defp match_key_name(keyring, info) do
  if info.key_name == keyring.key_name do
    :ok
  else
    {:error, :key_name_mismatch}
  end
end

defp validate_iv_length(%{iv_length: @iv_length}), do: :ok
defp validate_iv_length(%{iv_length: actual}), do: {:error, {:invalid_iv_length, actual}}

defp validate_tag_length(%{tag_length_bits: @tag_length_bits}), do: :ok
defp validate_tag_length(%{tag_length_bits: actual}), do: {:error, {:invalid_tag_length, actual}}

defp split_ciphertext(ciphertext, _info) do
  # Tag is always last 16 bytes
  ciphertext_len = byte_size(ciphertext) - @tag_length

  if ciphertext_len > 0 do
    <<encrypted_key::binary-size(ciphertext_len), tag::binary-size(@tag_length)>> = ciphertext
    {:ok, encrypted_key, tag}
  else
    {:error, :ciphertext_too_short}
  end
end
```

#### 2. Add OnDecrypt Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test.exs`
**Changes**: Add test cases for unwrap_key

```elixir
alias AwsEncryptionSdk.Materials.DecryptionMaterials

describe "unwrap_key/3" do
  setup do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    {:ok, keyring: keyring, suite: suite}
  end

  test "decrypts EDK created by same keyring", %{keyring: keyring, suite: suite} do
    ec = %{"context" => "test"}

    # Encrypt
    enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
    assert {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

    # Decrypt
    dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
    assert {:ok, dec_result} = RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

    assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
  end

  test "fails if plaintext data key already set", %{keyring: keyring, suite: suite} do
    existing_key = :crypto.strong_rand_bytes(32)
    materials = DecryptionMaterials.new(suite, %{}, existing_key)

    assert {:error, :plaintext_data_key_already_set} =
             RawAes.unwrap_key(keyring, materials, [])
  end

  test "skips EDKs with wrong provider ID", %{keyring: keyring, suite: suite} do
    ec = %{}

    # Create EDK with different provider
    other_key = :crypto.strong_rand_bytes(32)
    {:ok, other_keyring} = RawAes.new("other-namespace", "test-key", other_key, :aes_256_gcm)
    enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
    {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

    # Try to decrypt with original keyring
    dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
    assert {:error, :unable_to_decrypt_data_key} =
             RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
  end

  test "skips EDKs with wrong key name", %{keyring: keyring, suite: suite} do
    ec = %{}

    # Create EDK with different key name
    {:ok, other_keyring} = RawAes.new("test-namespace", "other-key", keyring.wrapping_key, :aes_256_gcm)
    enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
    {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

    # Try to decrypt with original keyring
    dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
    assert {:error, :unable_to_decrypt_data_key} =
             RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
  end

  test "fails with wrong encryption context (AAD mismatch)", %{keyring: keyring, suite: suite} do
    # Encrypt with one context
    enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"key" => "value1"})
    {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

    # Try to decrypt with different context
    dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"key" => "value2"})
    assert {:error, :unable_to_decrypt_data_key} =
             RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
  end

  test "returns error when no EDKs provided", %{keyring: keyring, suite: suite} do
    materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    assert {:error, :unable_to_decrypt_data_key} = RawAes.unwrap_key(keyring, materials, [])
  end
end
```

#### 3. Add Test Vector Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs`
**Changes**: Create test file for test vector validation

```elixir
defmodule AwsEncryptionSdk.Keyring.RawAesTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

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

  describe "AES-256 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 83928d8e-9f97-4861-8f70-ab1eaa6930ea", %{harness: harness} do
      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"
      run_decrypt_test(harness, test_id)
    end

    @tag timeout: 120_000
    test "decrypts test vector 917a3a40-3b92-48f7-9cbe-231c9bde6222", %{harness: harness} do
      test_id = "917a3a40-3b92-48f7-9cbe-231c9bde6222"
      run_decrypt_test(harness, test_id)
    end
  end

  defp run_decrypt_test(nil, _test_id), do: :ok

  defp run_decrypt_test(harness, test_id) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Get key material for raw AES keyring
    [master_key | _] = test.master_keys
    assert master_key["type"] == "raw"
    assert master_key["algorithm"] == "aes"

    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    {:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)

    # Create keyring
    provider_id = master_key["provider-id"]
    key_name = master_key["encryption-algorithm"]  # This might need adjustment based on actual test vector format
    wrapping_algorithm = cipher_for_key_bits(key_data["bits"])

    {:ok, keyring} = RawAes.new(provider_id, key_name, raw_key, wrapping_algorithm)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key
    edks = message.header.encrypted_data_keys
    {:ok, result} = RawAes.unwrap_key(keyring, materials, edks)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end

  defp cipher_for_key_bits(128), do: :aes_128_gcm
  defp cipher_for_key_bits(192), do: :aes_192_gcm
  defp cipher_for_key_bits(256), do: :aes_256_gcm
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test.exs`
- [x] Test vectors pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs --include test_vectors` (if vectors available)
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] Round-trip encrypt/decrypt works in IEx
- [x] Decryption of test vector ciphertext succeeds

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 5: Additional Key Sizes and Edge Cases

### Overview
Validate AES-128 and AES-192 key support with test vectors and add edge case tests.

### Test Vectors for This Phase

| Test ID | Key Type | Notes |
|---------|----------|-------|
| `4be2393c-2916-4668-ae7a-d26ddb8de593` | aes-128 | 128-bit key support |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | aes-192 | 192-bit key support |

### Changes Required

#### 1. Add AES-128/192 Test Vector Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs`
**Changes**: Add test cases for other key sizes

```elixir
describe "AES-128 decrypt vectors" do
  @tag timeout: 120_000
  test "decrypts test vector 4be2393c-2916-4668-ae7a-d26ddb8de593", %{harness: harness} do
    test_id = "4be2393c-2916-4668-ae7a-d26ddb8de593"
    run_decrypt_test(harness, test_id)
  end
end

describe "AES-192 decrypt vectors" do
  @tag timeout: 120_000
  test "decrypts test vector a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1", %{harness: harness} do
    test_id = "a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1"
    run_decrypt_test(harness, test_id)
  end
end
```

#### 2. Add Edge Case Unit Tests
**File**: `test/aws_encryption_sdk/keyring/raw_aes_test.exs`
**Changes**: Add edge case tests

```elixir
describe "edge cases" do
  test "handles empty encryption context" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Encrypt with empty context
    enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

    # Decrypt with empty context
    dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    {:ok, dec_result} = RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

    assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
  end

  test "handles large encryption context" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Create large encryption context
    ec = for i <- 1..100, into: %{}, do: {"key-#{i}", "value-#{String.duplicate("x", 100)}"}

    enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
    {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

    dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
    {:ok, dec_result} = RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

    assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
  end

  test "handles unicode key names" do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("namespace-日本語", "キー名-🔑", key, :aes_256_gcm)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

    dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    {:ok, dec_result} = RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

    assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
  end

  test "round-trips all supported key sizes" do
    for {size, algorithm} <- [{16, :aes_128_gcm}, {24, :aes_192_gcm}, {32, :aes_256_gcm}] do
      key = :crypto.strong_rand_bytes(size)
      {:ok, keyring} = RawAes.new("ns", "key", key, algorithm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key,
             "Round-trip failed for #{algorithm}"
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All unit tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test.exs`
- [x] All test vector tests pass: `mix test test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs --include test_vectors`
- [x] Full quality check passes: `mix quality`

#### Manual Verification:
- [x] Round-trip works for all three key sizes in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to final verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All test vectors pass (if available)

### Manual:
- [x] End-to-end feature verification in IEx:
  ```elixir
  # Create keyring
  key = :crypto.strong_rand_bytes(32)
  {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)

  # Create encryption materials
  suite = AwsEncryptionSdk.AlgorithmSuite.default()
  enc_materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})

  # Wrap key
  {:ok, wrapped} = AwsEncryptionSdk.Keyring.RawAes.wrap_key(keyring, enc_materials)

  # Verify EDK was created
  [edk] = wrapped.encrypted_data_keys

  # Create decryption materials
  dec_materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})

  # Unwrap key
  {:ok, unwrapped} = AwsEncryptionSdk.Keyring.RawAes.unwrap_key(keyring, dec_materials, [edk])

  # Verify keys match
  unwrapped.plaintext_data_key == wrapped.plaintext_data_key  # => true
  ```

## Testing Strategy

### Unit Tests
- Struct creation and validation
- Provider info serialization/deserialization
- Key wrapping (on_encrypt behavior)
- Key unwrapping (on_decrypt behavior)
- Error conditions (mismatched keys, provider IDs, etc.)
- Edge cases (empty context, unicode, all key sizes)

### Test Vector Integration

Test vectors are integrated using the harness infrastructure:

```elixir
# Module setup
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()

# Load harness in setup_all
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

Test vectors validate:
- Correct ciphertext decryption
- Interoperability with other SDK implementations
- Correct handling of provider info format

Run with: `mix test --only test_vectors`

### Manual Testing Steps
1. Create keyring with valid parameters in IEx
2. Wrap a data key and verify EDK structure
3. Unwrap the EDK and verify key recovery
4. Test with different key sizes (128, 192, 256)
5. Test with various encryption contexts

## References

- Issue: #26
- Research: `thoughts/shared/research/2026-01-25-GH26-raw-aes-keyring.md`
- Raw AES Keyring Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md
- Keyring Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
