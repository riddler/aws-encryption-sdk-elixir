# Default CMM Implementation Plan

## Overview

Implement the Default CMM that wraps a keyring and provides the standard CMM behavior for encryption and decryption operations, including full ECDSA signing support.

**Issue**: #37 - Implement Default CMM with keyring orchestration
**Research**: `thoughts/shared/research/2026-01-26-GH37-default-cmm.md`

## Specification Requirements

### Source Documents
- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - CMM behaviour interface
- [default-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md) - Default CMM implementation

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Accept keyring in constructor | default-cmm.md#keyring | MUST |
| Default algorithm suite based on policy | default-cmm.md#get-encryption-materials | MUST |
| Validate suite against commitment policy | default-cmm.md#get-encryption-materials | MUST |
| Fail if `aws-crypto-public-key` in request context | default-cmm.md#get-encryption-materials | MUST |
| Generate signing key for signed suites | default-cmm.md#get-encryption-materials | MUST |
| Add base64 public key to context for signed suites | default-cmm.md#get-encryption-materials | MUST |
| Call keyring on_encrypt | default-cmm.md#get-encryption-materials | MUST |
| Validate plaintext data key non-NULL and correct length | cmm-interface.md#get-encryption-materials | MUST |
| Validate at least one EDK | cmm-interface.md#get-encryption-materials | MUST |
| Extract verification key from context for signed suites | default-cmm.md#decrypt-materials | MUST |
| Fail if signed suite but no `aws-crypto-public-key` | default-cmm.md#decrypt-materials | MUST |
| Fail if non-signed suite but `aws-crypto-public-key` present | default-cmm.md#decrypt-materials | MUST |
| Validate reproduced context against message context | cmm-interface.md#decrypt-materials | MUST |
| Call keyring on_decrypt | default-cmm.md#decrypt-materials | MUST |

## Test Vectors

### Validation Strategy

Each phase includes specific test vectors to validate the implementation.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 3 | `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Basic decrypt with AES-256, committed suite 0x0478 |
| 3 | `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | Decrypt with AES-192 |
| 3 | `d20b31a6-200d-4fdb-819d-7ded46c99d10` | Decrypt with RSA keyring |
| 4 | Unit tests | Encrypt round-trip with non-signing suites |
| 5 | Test vectors with 0x0578/0x0378 | Signing suite validation |

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

## Current State Analysis

### Existing Code

- `lib/aws_encryption_sdk/cmm/behaviour.ex` - Complete CMM behaviour with all validation helpers
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - EncryptionMaterials struct with mutators
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - DecryptionMaterials struct with mutators
- `lib/aws_encryption_sdk/keyring/multi.ex` - Multi-keyring with dispatch pattern to reuse
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring
- `lib/aws_encryption_sdk/keyring/raw_rsa.ex` - Raw RSA keyring

### Key Discoveries

- CMM Behaviour provides all validation functions - no need to reimplement
- Multi-keyring `call_wrap_key/2` and `call_unwrap_key/3` pattern should be reused
- ECDSA module does NOT exist - needs to be created for signing support
- Materials structs have `new_for_encrypt/3` and `new_for_decrypt/3` for CMM use

### Missing Components

- `lib/aws_encryption_sdk/crypto/ecdsa.ex` - ECDSA key generation and operations
- `lib/aws_encryption_sdk/cmm/default.ex` - Default CMM implementation

## Desired End State

After this plan is complete:

1. `AwsEncryptionSdk.Cmm.Default` module exists with:
   - `new/1` constructor accepting a keyring
   - `get_encryption_materials/2` implementing full CMM encrypt flow
   - `get_decryption_materials/2` implementing full CMM decrypt flow

2. `AwsEncryptionSdk.Crypto.ECDSA` module exists with:
   - `generate_key_pair/1` for P-384 key generation
   - `encode_public_key/1` for base64 encoding
   - `decode_public_key/1` for base64 decoding

3. All test vectors pass for both signing and non-signing suites

4. Verification:
   ```elixir
   # Create keyring
   {:ok, keyring} = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

   # Create CMM
   cmm = Default.new(keyring)

   # Encrypt flow
   {:ok, enc_materials} = Default.get_encryption_materials(cmm, %{
     encryption_context: %{"purpose" => "test"},
     commitment_policy: :require_encrypt_require_decrypt
   })

   # Decrypt flow
   {:ok, dec_materials} = Default.get_decryption_materials(cmm, %{
     algorithm_suite: enc_materials.algorithm_suite,
     commitment_policy: :require_encrypt_require_decrypt,
     encrypted_data_keys: enc_materials.encrypted_data_keys,
     encryption_context: enc_materials.encryption_context
   })
   ```

## What We're NOT Doing

- **Caching CMM** - Separate advanced feature (future issue)
- **Required Encryption Context CMM** - Separate feature (future issue)
- **AWS KMS keyring support** - Not yet implemented, only RawAes, RawRsa, Multi supported
- **Full ECDSA signing/verification** - Only key generation and encoding for CMM use
- **Streaming support** - Future milestone

## Implementation Approach

1. **Create ECDSA module first** - Required for signing key generation
2. **Implement Default CMM struct and constructor** - Basic module setup
3. **Implement get_decryption_materials** - Simpler flow, test vectors available
4. **Implement get_encryption_materials** - More complex with signing key generation
5. **Add signing suite support** - Full ECDSA integration

---

## Phase 1: ECDSA Crypto Module

### Overview

Create the ECDSA module for P-384 key pair generation and public key encoding/decoding needed by the CMM for signed algorithm suites.

### Spec Requirements Addressed

- Generate signing key for signed suites (default-cmm.md#get-encryption-materials)
- Add base64 public key to context (default-cmm.md#get-encryption-materials)
- Extract verification key from context (default-cmm.md#decrypt-materials)

### Changes Required

#### 1. Create ECDSA Module
**File**: `lib/aws_encryption_sdk/crypto/ecdsa.ex`

```elixir
defmodule AwsEncryptionSdk.Crypto.ECDSA do
  @moduledoc """
  ECDSA operations for AWS Encryption SDK.

  Provides key generation and encoding for P-384 (secp384r1) curve
  used by signed algorithm suites.

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
  """

  @type key_pair :: {private_key :: binary(), public_key :: binary()}
  @type curve :: :secp384r1

  @doc """
  Generates an ECDSA key pair for the P-384 curve.

  Returns `{private_key, public_key}` where:
  - `private_key` is the raw private key bytes
  - `public_key` is the uncompressed public key point

  ## Examples

      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

  """
  @spec generate_key_pair(curve()) :: key_pair()
  def generate_key_pair(:secp384r1) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp384r1)
    {private_key, public_key}
  end

  @doc """
  Encodes a public key to base64 for storage in encryption context.

  The public key is stored as-is (uncompressed point format) and base64 encoded.

  ## Examples

      encoded = ECDSA.encode_public_key(public_key)
      # => "BH..."

  """
  @spec encode_public_key(binary()) :: String.t()
  def encode_public_key(public_key) when is_binary(public_key) do
    Base.encode64(public_key)
  end

  @doc """
  Decodes a base64-encoded public key from encryption context.

  ## Examples

      {:ok, public_key} = ECDSA.decode_public_key("BH...")

  """
  @spec decode_public_key(String.t()) :: {:ok, binary()} | {:error, :invalid_base64}
  def decode_public_key(encoded) when is_binary(encoded) do
    case Base.decode64(encoded) do
      {:ok, public_key} -> {:ok, public_key}
      :error -> {:error, :invalid_base64}
    end
  end
end
```

#### 2. Create ECDSA Tests
**File**: `test/aws_encryption_sdk/crypto/ecdsa_test.exs`

```elixir
defmodule AwsEncryptionSdk.Crypto.ECDSATest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.ECDSA

  describe "generate_key_pair/1" do
    test "generates valid P-384 key pair" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      # P-384 private key is 48 bytes
      assert byte_size(private_key) == 48

      # P-384 uncompressed public key is 97 bytes (0x04 || x || y)
      assert byte_size(public_key) == 97
      assert :binary.first(public_key) == 0x04
    end

    test "generates unique key pairs" do
      {priv1, pub1} = ECDSA.generate_key_pair(:secp384r1)
      {priv2, pub2} = ECDSA.generate_key_pair(:secp384r1)

      refute priv1 == priv2
      refute pub1 == pub2
    end
  end

  describe "encode_public_key/1 and decode_public_key/1" do
    test "round-trips public key" do
      {_private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      encoded = ECDSA.encode_public_key(public_key)
      assert is_binary(encoded)
      assert String.printable?(encoded)

      {:ok, decoded} = ECDSA.decode_public_key(encoded)
      assert decoded == public_key
    end

    test "decode_public_key returns error for invalid base64" do
      assert {:error, :invalid_base64} = ECDSA.decode_public_key("not-valid-base64!!!")
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/crypto/ecdsa_test.exs`
- [x] Code compiles: `mix compile --warnings-as-errors`

#### Manual Verification:
- [ ] Key generation produces valid P-384 keys in IEx

**Implementation Note**: After completing this phase and all automated verification passes, proceed to the next phase.

---

## Phase 2: Default CMM Module Structure

### Overview

Create the Default CMM module with struct definition, constructor, and keyring dispatch helpers.

### Spec Requirements Addressed

- Accept keyring in constructor (default-cmm.md#keyring)

### Changes Required

#### 1. Create Default CMM Module
**File**: `lib/aws_encryption_sdk/cmm/default.ex`

```elixir
defmodule AwsEncryptionSdk.Cmm.Default do
  @moduledoc """
  Default Cryptographic Materials Manager implementation.

  The Default CMM wraps a keyring and provides the standard CMM behavior for
  encryption and decryption operations. It handles:

  - Algorithm suite selection and validation against commitment policy
  - Signing key generation for signed algorithm suites
  - Keyring orchestration for data key generation/encryption/decryption
  - Materials validation

  ## Example

      # Create a keyring
      {:ok, keyring} = RawAes.new("namespace", "key-name", key_bytes, :aes_256_gcm)

      # Create the CMM
      cmm = Default.new(keyring)

      # Get encryption materials
      {:ok, materials} = Default.get_encryption_materials(cmm, %{
        encryption_context: %{"purpose" => "example"},
        commitment_policy: :require_encrypt_require_decrypt
      })

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
  """

  @behaviour AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes, RawRsa}
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  @type keyring :: RawAes.t() | RawRsa.t() | Multi.t()

  @type t :: %__MODULE__{
          keyring: keyring()
        }

  defstruct [:keyring]

  @doc """
  Creates a new Default CMM wrapping the given keyring.

  ## Parameters

  - `keyring` - A keyring struct (RawAes, RawRsa, or Multi)

  ## Examples

      {:ok, aes_keyring} = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)
      cmm = Default.new(aes_keyring)

  """
  @spec new(keyring()) :: t()
  def new(keyring) do
    %__MODULE__{keyring: keyring}
  end

  # Keyring dispatch helpers - reuse pattern from Multi-keyring

  @doc false
  def call_wrap_key(%RawAes{} = keyring, materials) do
    RawAes.wrap_key(keyring, materials)
  end

  def call_wrap_key(%RawRsa{} = keyring, materials) do
    RawRsa.wrap_key(keyring, materials)
  end

  def call_wrap_key(%Multi{} = keyring, materials) do
    Multi.wrap_key(keyring, materials)
  end

  def call_wrap_key(keyring, _materials) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  @doc false
  def call_unwrap_key(%RawAes{} = keyring, materials, edks) do
    RawAes.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%RawRsa{} = keyring, materials, edks) do
    RawRsa.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%Multi{} = keyring, materials, edks) do
    Multi.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(keyring, _materials, _edks) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  # Placeholder implementations - will be completed in Phases 3 and 4

  @impl CmmBehaviour
  def get_encryption_materials(_cmm, _request) do
    {:error, :not_implemented}
  end

  @impl CmmBehaviour
  def get_decryption_materials(_cmm, _request) do
    {:error, :not_implemented}
  end
end
```

#### 2. Create Default CMM Tests (Structure)
**File**: `test/aws_encryption_sdk/cmm/default_test.exs`

```elixir
defmodule AwsEncryptionSdk.Cmm.DefaultTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.RawAes

  # Helper to create a test keyring
  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "new/1" do
    test "creates CMM with keyring" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      assert %Default{keyring: ^keyring} = cmm
    end
  end

  describe "call_wrap_key/2" do
    test "dispatches to RawAes keyring" do
      keyring = create_test_keyring()
      suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})

      {:ok, result} = Default.call_wrap_key(keyring, materials)

      assert result.plaintext_data_key != nil
      assert length(result.encrypted_data_keys) == 1
    end
  end

  describe "call_unwrap_key/3" do
    test "dispatches to RawAes keyring" do
      keyring = create_test_keyring()
      suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # First wrap a key
      enc_materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

      # Then unwrap it
      dec_materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, result} = Default.call_unwrap_key(keyring, dec_materials, wrapped.encrypted_data_keys)

      assert result.plaintext_data_key == wrapped.plaintext_data_key
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/cmm/default_test.exs`
- [x] Code compiles: `mix compile --warnings-as-errors`

#### Manual Verification:
- [ ] `Default.new/1` creates CMM struct in IEx

**Implementation Note**: After completing this phase and all automated verification passes, proceed to the next phase.

---

## Phase 3: get_decryption_materials Implementation

### Overview

Implement the full `get_decryption_materials/2` function with commitment policy validation, encryption context handling, verification key extraction, and keyring invocation.

### Spec Requirements Addressed

- Validate suite against commitment policy (default-cmm.md#decrypt-materials)
- Validate reproduced context (cmm-interface.md#decrypt-materials)
- Merge reproduced context (cmm-interface.md#decrypt-materials)
- Validate signing context consistency (default-cmm.md#decrypt-materials)
- Extract verification key for signed suites (default-cmm.md#decrypt-materials)
- Call keyring on_decrypt (default-cmm.md#decrypt-materials)
- Validate returned materials (cmm-interface.md#decrypt-materials)

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | AES-256, committed suite 0x0478 | Success |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | AES-192, committed suite | Success |
| `d20b31a6-200d-4fdb-819d-7ded46c99d10` | RSA PKCS1, legacy suite | Success |

### Changes Required

#### 1. Implement get_decryption_materials
**File**: `lib/aws_encryption_sdk/cmm/default.ex`

Replace the placeholder `get_decryption_materials/2` with:

```elixir
@impl CmmBehaviour
def get_decryption_materials(%__MODULE__{keyring: keyring}, request) do
  %{
    algorithm_suite: suite,
    commitment_policy: policy,
    encrypted_data_keys: edks,
    encryption_context: context
  } = request

  reproduced_context = Map.get(request, :reproduced_encryption_context)

  with :ok <- CmmBehaviour.validate_commitment_policy_for_decrypt(suite, policy),
       :ok <- CmmBehaviour.validate_reproduced_context(context, reproduced_context),
       merged_context = CmmBehaviour.merge_reproduced_context(context, reproduced_context),
       :ok <- CmmBehaviour.validate_signing_context_consistency(suite, merged_context),
       {:ok, verification_key} <- extract_verification_key(suite, merged_context),
       initial_materials = create_initial_decryption_materials(suite, merged_context, verification_key),
       {:ok, materials} <- call_unwrap_key(keyring, initial_materials, edks),
       :ok <- CmmBehaviour.validate_decryption_materials(materials) do
    {:ok, materials}
  end
end

defp extract_verification_key(suite, context) do
  if AlgorithmSuite.signed?(suite) do
    reserved_key = CmmBehaviour.reserved_encryption_context_key()

    case Map.fetch(context, reserved_key) do
      {:ok, encoded_key} ->
        Crypto.ECDSA.decode_public_key(encoded_key)

      :error ->
        # This should have been caught by validate_signing_context_consistency
        {:error, :missing_verification_key}
    end
  else
    {:ok, nil}
  end
end

defp create_initial_decryption_materials(suite, context, verification_key) do
  DecryptionMaterials.new_for_decrypt(suite, context, verification_key: verification_key)
end
```

Add required alias at the top:

```elixir
alias AwsEncryptionSdk.AlgorithmSuite
alias AwsEncryptionSdk.Crypto.ECDSA
```

#### 2. Add Decryption Tests
**File**: `test/aws_encryption_sdk/cmm/default_test.exs`

Add to existing test file:

```elixir
describe "get_decryption_materials/2" do
  setup do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Create encryption materials to get valid EDKs
    enc_materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
    {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

    {:ok,
     cmm: cmm,
     suite: suite,
     edks: wrapped.encrypted_data_keys,
     plaintext_key: wrapped.plaintext_data_key}
  end

  test "decrypts with committed suite and require policy", ctx do
    request = %{
      algorithm_suite: ctx.suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: ctx.edks,
      encryption_context: %{}
    }

    {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)

    assert materials.plaintext_data_key == ctx.plaintext_key
    assert materials.algorithm_suite == ctx.suite
    assert materials.encryption_context == %{}
  end

  test "decrypts with allow_decrypt policy", ctx do
    request = %{
      algorithm_suite: ctx.suite,
      commitment_policy: :require_encrypt_allow_decrypt,
      encrypted_data_keys: ctx.edks,
      encryption_context: %{}
    }

    {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)
    assert materials.plaintext_data_key == ctx.plaintext_key
  end

  test "fails with non-committed suite and require_require policy" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    # Non-committed suite
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

    request = %{
      algorithm_suite: suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: [],
      encryption_context: %{}
    }

    assert {:error, :commitment_policy_requires_committed_suite} =
             Default.get_decryption_materials(cmm, request)
  end

  test "validates reproduced context matches", ctx do
    request = %{
      algorithm_suite: ctx.suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: ctx.edks,
      encryption_context: %{"key" => "value"},
      reproduced_encryption_context: %{"key" => "different"}
    }

    assert {:error, {:encryption_context_mismatch, "key"}} =
             Default.get_decryption_materials(ctx.cmm, request)
  end

  test "merges reproduced context", ctx do
    request = %{
      algorithm_suite: ctx.suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: ctx.edks,
      encryption_context: %{"stored" => "value"},
      reproduced_encryption_context: %{"reproduced" => "value2"}
    }

    {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)

    assert materials.encryption_context["stored"] == "value"
    assert materials.encryption_context["reproduced"] == "value2"
  end
end
```

#### 3. Create Test Vector Tests
**File**: `test/aws_encryption_sdk/cmm/default_test_vectors_test.exs`

```elixir
defmodule AwsEncryptionSdk.Cmm.DefaultTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Keyring.{RawAes, RawRsa}

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

  describe "get_decryption_materials with test vectors" do
    @tag :test_vectors
    test "decrypts AES-256 committed suite", %{harness: harness} do
      skip_if_no_harness(harness)

      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"
      {:ok, test} = TestVectorHarness.get_test(harness, test_id)
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _rest} = Message.deserialize(ciphertext)

      # Create keyring from test vector key
      [master_key | _] = test.master_keys
      keyring = create_keyring_from_test(harness, master_key)

      # Create CMM and get decryption materials
      cmm = Default.new(keyring)

      request = %{
        algorithm_suite: message.header.algorithm_suite,
        commitment_policy: :require_encrypt_allow_decrypt,
        encrypted_data_keys: message.header.encrypted_data_keys,
        encryption_context: message.header.encryption_context
      }

      {:ok, materials} = Default.get_decryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil
      assert byte_size(materials.plaintext_data_key) == message.header.algorithm_suite.kdf_input_length
    end
  end

  defp skip_if_no_harness(nil), do: ExUnit.configure(exclude: [:test_vectors])
  defp skip_if_no_harness(_harness), do: :ok

  defp create_keyring_from_test(harness, master_key) do
    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)

    case key_data["type"] do
      "raw" when key_data["algorithm"] == "aes" ->
        {:ok, key_bytes} = TestVectorHarness.decode_key_material(key_data)
        provider_id = master_key["provider-id"]
        key_name = master_key["encryption-algorithm"]

        wrapping_algorithm =
          case byte_size(key_bytes) do
            16 -> :aes_128_gcm
            24 -> :aes_192_gcm
            32 -> :aes_256_gcm
          end

        {:ok, keyring} = RawAes.new(provider_id, key_name, key_bytes, wrapping_algorithm)
        keyring

      "raw" when key_data["algorithm"] == "rsa" ->
        {:ok, private_key} = TestVectorHarness.decode_key_material(key_data)
        provider_id = master_key["provider-id"]
        key_name = master_key["encryption-algorithm"]
        padding = parse_rsa_padding(master_key["padding-algorithm"])

        {:ok, keyring} = RawRsa.new(provider_id, key_name, padding, private_key: private_key)
        keyring
    end
  end

  defp parse_rsa_padding("pkcs1"), do: :pkcs1
  defp parse_rsa_padding("oaep-mgf1-sha256"), do: {:oaep, :sha256}
  defp parse_rsa_padding("oaep-mgf1-sha1"), do: {:oaep, :sha}
  defp parse_rsa_padding("oaep-mgf1-sha384"), do: {:oaep, :sha384}
  defp parse_rsa_padding("oaep-mgf1-sha512"), do: {:oaep, :sha512}
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/cmm/default_test.exs`
- [ ] Test vectors pass: `mix test --only test_vectors test/aws_encryption_sdk/cmm/default_test_vectors_test.exs` (requires unzipping test vectors)
- [x] Code compiles: `mix compile --warnings-as-errors` (one expected warning for EncryptionMaterials until Phase 4)

#### Manual Verification:
- [ ] `Default.get_decryption_materials/2` works in IEx with manually created EDKs
- [ ] Test vectors work after unzipping

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 4: get_encryption_materials Implementation (Non-Signing)

### Overview

Implement the core `get_encryption_materials/2` function for non-signing suites, including algorithm suite selection, commitment policy validation, and keyring invocation.

### Spec Requirements Addressed

- Default algorithm suite based on policy (default-cmm.md#get-encryption-materials)
- Validate suite against commitment policy (default-cmm.md#get-encryption-materials)
- Fail if `aws-crypto-public-key` in request context (default-cmm.md#get-encryption-materials)
- Call keyring on_encrypt (default-cmm.md#get-encryption-materials)
- Validate plaintext data key (cmm-interface.md#get-encryption-materials)
- Validate at least one EDK (cmm-interface.md#get-encryption-materials)

### Changes Required

#### 1. Implement get_encryption_materials (Non-Signing)
**File**: `lib/aws_encryption_sdk/cmm/default.ex`

Replace the placeholder `get_encryption_materials/2` with:

```elixir
@impl CmmBehaviour
def get_encryption_materials(%__MODULE__{keyring: keyring}, request) do
  %{
    encryption_context: context,
    commitment_policy: policy
  } = request

  requested_suite = Map.get(request, :algorithm_suite)
  required_keys = Map.get(request, :required_encryption_context_keys, [])

  with :ok <- CmmBehaviour.validate_encryption_context_for_encrypt(context),
       suite = select_algorithm_suite(requested_suite, policy),
       :ok <- CmmBehaviour.validate_commitment_policy_for_encrypt(suite, policy),
       {:ok, context_with_signing, signing_key} <- maybe_add_signing_context(suite, context),
       initial_materials = create_initial_encryption_materials(suite, context_with_signing, signing_key, required_keys),
       {:ok, materials} <- call_wrap_key(keyring, initial_materials),
       :ok <- CmmBehaviour.validate_encryption_materials(materials) do
    {:ok, materials}
  end
end

defp select_algorithm_suite(nil, policy) do
  CmmBehaviour.default_algorithm_suite(policy)
end

defp select_algorithm_suite(suite, _policy) do
  suite
end

defp maybe_add_signing_context(suite, context) do
  if AlgorithmSuite.signed?(suite) do
    {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
    encoded_public_key = ECDSA.encode_public_key(public_key)
    reserved_key = CmmBehaviour.reserved_encryption_context_key()
    updated_context = Map.put(context, reserved_key, encoded_public_key)
    {:ok, updated_context, private_key}
  else
    {:ok, context, nil}
  end
end

defp create_initial_encryption_materials(suite, context, signing_key, required_keys) do
  EncryptionMaterials.new_for_encrypt(suite, context,
    signing_key: signing_key,
    required_encryption_context_keys: required_keys
  )
end
```

#### 2. Add Encryption Tests
**File**: `test/aws_encryption_sdk/cmm/default_test.exs`

Add to existing test file:

```elixir
describe "get_encryption_materials/2" do
  test "encrypts with default committed suite" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)

    request = %{
      encryption_context: %{"purpose" => "test"},
      commitment_policy: :require_encrypt_require_decrypt
    }

    {:ok, materials} = Default.get_encryption_materials(cmm, request)

    # Default suite for require_* is committed with signing (0x0578)
    assert materials.algorithm_suite.id == 0x0578
    assert materials.plaintext_data_key != nil
    assert length(materials.encrypted_data_keys) >= 1
    assert materials.encryption_context["purpose"] == "test"
    # Signing suite adds public key
    assert Map.has_key?(materials.encryption_context, "aws-crypto-public-key")
    assert materials.signing_key != nil
  end

  test "encrypts with specified non-signing suite" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, materials} = Default.get_encryption_materials(cmm, request)

    assert materials.algorithm_suite == suite
    assert materials.plaintext_data_key != nil
    assert length(materials.encrypted_data_keys) >= 1
    # Non-signing suite should not have public key
    refute Map.has_key?(materials.encryption_context, "aws-crypto-public-key")
    assert materials.signing_key == nil
  end

  test "fails with non-committed suite and require policy" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

    request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    assert {:error, :commitment_policy_requires_committed_suite} =
             Default.get_encryption_materials(cmm, request)
  end

  test "fails with committed suite and forbid policy" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    request = %{
      encryption_context: %{},
      commitment_policy: :forbid_encrypt_allow_decrypt,
      algorithm_suite: suite
    }

    assert {:error, :commitment_policy_forbids_committed_suite} =
             Default.get_encryption_materials(cmm, request)
  end

  test "fails when encryption context contains reserved key" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)

    request = %{
      encryption_context: %{"aws-crypto-public-key" => "malicious"},
      commitment_policy: :require_encrypt_require_decrypt
    }

    assert {:error, :reserved_encryption_context_key} =
             Default.get_encryption_materials(cmm, request)
  end

  test "uses default non-committed suite for forbid policy" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)

    request = %{
      encryption_context: %{},
      commitment_policy: :forbid_encrypt_allow_decrypt
    }

    {:ok, materials} = Default.get_encryption_materials(cmm, request)

    # Default for forbid is non-committed with signing (0x0378)
    assert materials.algorithm_suite.id == 0x0378
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/cmm/default_test.exs`
- [ ] Full quality check: `mix quality --quick`

#### Manual Verification:
- [ ] Round-trip encrypt/decrypt works in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 5: Signing Suite Integration & Round-Trip Tests

### Overview

Complete integration testing for signing suites, ensuring the full encrypt/decrypt round-trip works with ECDSA key generation and verification key extraction.

### Spec Requirements Addressed

- Generate signing key for signed suites (default-cmm.md#get-encryption-materials)
- Add base64 public key to context (default-cmm.md#get-encryption-materials)
- Extract verification key from context (default-cmm.md#decrypt-materials)
- Include signing key in materials (cmm-interface.md#get-encryption-materials)
- Include verification key in materials (cmm-interface.md#decrypt-materials)

### Changes Required

#### 1. Add Round-Trip Integration Tests
**File**: `test/aws_encryption_sdk/cmm/default_test.exs`

Add to existing test file:

```elixir
describe "encrypt/decrypt round-trip" do
  test "round-trips with non-signing committed suite" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Encrypt
    enc_request = %{
      encryption_context: %{"tenant" => "acme"},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    # Decrypt
    dec_request = %{
      algorithm_suite: enc_materials.algorithm_suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: enc_materials.encryption_context
    }

    {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

    assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
    assert dec_materials.verification_key == nil
  end

  test "round-trips with signing committed suite (0x0578)" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

    # Encrypt
    enc_request = %{
      encryption_context: %{"tenant" => "acme"},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    assert enc_materials.signing_key != nil
    assert Map.has_key?(enc_materials.encryption_context, "aws-crypto-public-key")

    # Decrypt
    dec_request = %{
      algorithm_suite: enc_materials.algorithm_suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: enc_materials.encryption_context
    }

    {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

    assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
    assert dec_materials.verification_key != nil
  end

  test "round-trips with signing non-committed suite (0x0378)" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()

    # Encrypt
    enc_request = %{
      encryption_context: %{},
      commitment_policy: :forbid_encrypt_allow_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    # Decrypt
    dec_request = %{
      algorithm_suite: enc_materials.algorithm_suite,
      commitment_policy: :forbid_encrypt_allow_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: enc_materials.encryption_context
    }

    {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

    assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
  end

  test "decryption fails when signing context missing for signed suite" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

    # Get encryption materials first
    enc_request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    # Remove the public key from context (simulating corrupted message)
    corrupted_context = Map.delete(enc_materials.encryption_context, "aws-crypto-public-key")

    dec_request = %{
      algorithm_suite: suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: corrupted_context
    }

    assert {:error, :missing_public_key_in_context} =
             Default.get_decryption_materials(cmm, dec_request)
  end

  test "decryption fails when non-signed suite has public key in context" do
    keyring = create_test_keyring()
    cmm = Default.new(keyring)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Get encryption materials
    enc_request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    # Add spurious public key to context
    corrupted_context = Map.put(enc_materials.encryption_context, "aws-crypto-public-key", "fake")

    dec_request = %{
      algorithm_suite: suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: corrupted_context
    }

    assert {:error, :unexpected_public_key_in_context} =
             Default.get_decryption_materials(cmm, dec_request)
  end
end
```

#### 2. Add Multi-Keyring Integration Tests
**File**: `test/aws_encryption_sdk/cmm/default_test.exs`

```elixir
describe "with Multi-keyring" do
  test "encrypts with multi-keyring" do
    key1 = :crypto.strong_rand_bytes(32)
    key2 = :crypto.strong_rand_bytes(32)
    {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
    {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
    {:ok, multi} = AwsEncryptionSdk.Keyring.Multi.new(generator: keyring1, children: [keyring2])

    cmm = Default.new(multi)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, materials} = Default.get_encryption_materials(cmm, request)

    # Should have 2 EDKs (one from each keyring)
    assert length(materials.encrypted_data_keys) == 2
  end

  test "decrypts with any keyring in multi-keyring" do
    key1 = :crypto.strong_rand_bytes(32)
    key2 = :crypto.strong_rand_bytes(32)
    {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
    {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
    {:ok, multi} = AwsEncryptionSdk.Keyring.Multi.new(generator: keyring1, children: [keyring2])

    cmm = Default.new(multi)
    suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    # Encrypt with multi
    enc_request = %{
      encryption_context: %{},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

    # Decrypt with single keyring (second one)
    single_cmm = Default.new(keyring2)

    dec_request = %{
      algorithm_suite: suite,
      commitment_policy: :require_encrypt_require_decrypt,
      encrypted_data_keys: enc_materials.encrypted_data_keys,
      encryption_context: enc_materials.encryption_context
    }

    {:ok, dec_materials} = Default.get_decryption_materials(single_cmm, dec_request)

    assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix test test/aws_encryption_sdk/cmm/`
- [ ] Full quality check: `mix quality`

#### Manual Verification:
- [ ] Full encrypt/decrypt round-trip with signing suite works in IEx
- [ ] Verification key can be used for ECDSA verification (if needed later)

**Implementation Note**: After completing this phase and all automated verification passes, the Default CMM implementation is complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality` - **ALL CHECKS PASSED** ✅
  - Coverage: 93.2% (above 93% threshold)
  - Credo: No issues
  - Dialyzer: No warnings
  - Tests: 386 of 386 passed
- [x] All CMM tests pass: `mix test test/aws_encryption_sdk/cmm/`
- [ ] Test vectors pass: `mix test --only test_vectors` (requires unzipping test vector files)
- [x] Doctests pass: included in CMM tests

### Manual:
- [ ] End-to-end feature verification in IEx:
  ```elixir
  # Full round-trip test
  {:ok, keyring} = RawAes.new("ns", "key", :crypto.strong_rand_bytes(32), :aes_256_gcm)
  cmm = Default.new(keyring)

  # Encrypt
  {:ok, enc} = Default.get_encryption_materials(cmm, %{
    encryption_context: %{"test" => "data"},
    commitment_policy: :require_encrypt_require_decrypt
  })

  # Decrypt
  {:ok, dec} = Default.get_decryption_materials(cmm, %{
    algorithm_suite: enc.algorithm_suite,
    commitment_policy: :require_encrypt_require_decrypt,
    encrypted_data_keys: enc.encrypted_data_keys,
    encryption_context: enc.encryption_context
  })

  enc.plaintext_data_key == dec.plaintext_data_key  # => true
  ```

## Testing Strategy

### Unit Tests

Tests in `test/aws_encryption_sdk/cmm/default_test.exs`:
- Constructor creates CMM struct
- Keyring dispatch helpers work
- get_encryption_materials with various commitment policies
- get_decryption_materials with various commitment policies
- Reserved key validation
- Reproduced context validation
- Signing suite integration
- Multi-keyring integration

### Test Vector Integration

Test vectors are integrated in `test/aws_encryption_sdk/cmm/default_test_vectors_test.exs`:
- Decryption with AES keyrings
- Decryption with RSA keyrings
- Various algorithm suites

### Manual Testing Steps

1. Create CMM in IEx and verify struct
2. Test encrypt/decrypt round-trip with non-signing suite
3. Test encrypt/decrypt round-trip with signing suite (0x0578)
4. Verify signing key is generated during encryption
5. Verify verification key is extracted during decryption

## References

- Issue: #37
- Research: `thoughts/shared/research/2026-01-26-GH37-default-cmm.md`
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Default CMM Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
