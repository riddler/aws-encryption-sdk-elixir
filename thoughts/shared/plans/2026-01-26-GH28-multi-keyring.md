# Multi-Keyring Implementation Plan

## Overview

Implement the Multi-Keyring per the AWS Encryption SDK specification. The Multi-Keyring composes multiple keyrings together, enabling encryption with multiple keys and flexible decryption with any available key.

**Issue**: #28
**Research**: `thoughts/shared/research/2026-01-26-GH28-multi-keyring.md`

## Specification Requirements

### Source Documents
- [multi-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md) - Multi-keyring composition behavior
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Base keyring contract

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| At least one keyring (generator or children) required | multi-keyring.md#inputs | MUST |
| Generator required if children empty | multi-keyring.md#inputs | MUST |
| Fail if materials have plaintext key (with generator) | multi-keyring.md#onencrypt | MUST |
| Call generator first on encrypt | multi-keyring.md#onencrypt | MUST |
| Fail if generator fails | multi-keyring.md#onencrypt | MUST |
| Fail if generator returns no plaintext key | multi-keyring.md#onencrypt | MUST |
| Fail if no generator and no plaintext key | multi-keyring.md#onencrypt | MUST |
| Call OnEncrypt on each child (chained) | multi-keyring.md#onencrypt | MUST |
| Fail if any child fails on encrypt | multi-keyring.md#onencrypt | MUST |
| Fail if materials have plaintext key on decrypt | multi-keyring.md#ondecrypt | MUST |
| Try generator first, then children on decrypt | multi-keyring.md#ondecrypt | MUST |
| Pass unmodified materials to each keyring on decrypt | multi-keyring.md#ondecrypt | MUST |
| Return immediately on first decrypt success | multi-keyring.md#ondecrypt | MUST |
| Collect errors and continue on decrypt failure | multi-keyring.md#ondecrypt | MUST |
| Fail with collected errors if all keyrings fail | multi-keyring.md#ondecrypt | MUST |

## Test Vectors

### Validation Strategy

Each phase includes specific test vectors to validate the implementation.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 2 | `8a967e4e-*`, `6b8d3386-*` | Basic multi-RSA decryption |
| 4 | All 7 multi-RSA vectors | Full decryption coverage |

### Multi-RSA Test Vectors (Available)

| Test ID | Keys | Padding Schemes | Expected Result |
|---------|------|-----------------|-----------------|
| `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` | 2 RSA | PKCS1 + OAEP-SHA256 | Success |
| `6b8d3386-9824-46db-8764-8d58d8086f77` | 2 RSA | OAEP-SHA256 (2x) | Success |
| `afb2ba6d-e8b7-4c74-99ff-f7925485a868` | 2 RSA | PKCS1 + OAEP-SHA256 | Success |
| `bca8fe01-878d-4705-9ee4-8ea9faf6328b` | 2 RSA | OAEP-SHA1 + OAEP-SHA256 | Success |
| `1aa68ab1-3752-48e8-af6b-cea6650df263` | 2 RSA | OAEP-SHA384 + OAEP-SHA256 | Success |
| `aba06ffc-a839-4639-967c-a739d8626adc` | 2 RSA | OAEP-SHA512 + OAEP-SHA256 | Success |
| `e05108d7-cde8-42ae-8901-ee7d39af0eae` | 2 RSA | OAEP-SHA256 (2x) | Success |

### Harness Setup Pattern

```elixir
# In test file setup_all
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
```

## Current State Analysis

### Existing Keyring Pattern

The existing keyrings (Raw AES, Raw RSA) follow this pattern:
- Implement `@behaviour AwsEncryptionSdk.Keyring.Behaviour`
- Provide `wrap_key/2` for encryption (keyring + materials -> materials with EDK)
- Provide `unwrap_key/3` for decryption (keyring + materials + edks -> materials with plaintext key)
- Behaviour callbacks (`on_encrypt/1`, `on_decrypt/2`) return errors directing users to explicit functions

### Key Discoveries

1. **`wrap_key/2` pattern** (`raw_aes.ex:177-185`): Generates data key if missing, encrypts it, adds EDK to materials
2. **`unwrap_key/3` pattern** (`raw_aes.ex:244-252`): Checks for existing key, iterates EDKs with `reduce_while`, halts on success
3. **Materials modification**: Use `EncryptionMaterials.add_encrypted_data_key/2` and `DecryptionMaterials.set_plaintext_data_key/2`
4. **Error accumulation**: Decryption uses `reduce_while` with `:no_match` accumulator

### Dependencies

- `AwsEncryptionSdk.Keyring.Behaviour` - Behaviour definition
- `AwsEncryptionSdk.Keyring.RawAes` - For testing with AES keyrings
- `AwsEncryptionSdk.Keyring.RawRsa` - For testing with RSA keyrings
- `AwsEncryptionSdk.Materials.EncryptionMaterials` - Encryption materials struct
- `AwsEncryptionSdk.Materials.DecryptionMaterials` - Decryption materials struct

## Desired End State

After implementation:

1. `AwsEncryptionSdk.Keyring.Multi` module exists with:
   - `new/1` constructor accepting `:generator` and `:children` options
   - `wrap_key/2` for encryption flow
   - `unwrap_key/3` for decryption flow

2. All 7 multi-RSA test vectors pass

3. Unit tests cover:
   - Constructor validation (at least one keyring required)
   - Generator-only encryption/decryption
   - Children-only encryption/decryption (with pre-existing plaintext key)
   - Generator + children combined
   - Error cases (all keyrings fail, missing generator with no plaintext key)

### Verification

```bash
# All tests pass
mix test

# Test vectors specifically
mix test --only test_vectors

# Quality checks
mix quality
```

## What We're NOT Doing

- AWS KMS keyring integration (separate issue, requires AWS credentials)
- Streaming encryption/decryption
- Caching CMM integration
- Behaviour callback implementation (following existing pattern of explicit functions)

## Implementation Approach

Follow the existing keyring pattern:
1. Multi-keyring stores references to generator and children keyrings
2. `wrap_key/2` calls child keyrings' `wrap_key/2` in sequence (chained)
3. `unwrap_key/3` calls child keyrings' `unwrap_key/3` with original materials (not chained)
4. Error collection on decrypt, fail-fast on encrypt

---

## Phase 1: Core Structure & Constructor

### Overview

Create the Multi module with struct definition and `new/1` constructor with validation per spec requirements.

### Spec Requirements Addressed

- "A keyring MUST define at least one of the following: Generator Keyring or Child Keyrings"
- "If the list of child keyrings is empty, a generator keyring MUST be defined"

### Test Vectors for This Phase

None - unit tests only for constructor validation.

### Changes Required

#### 1. Create Multi-Keyring Module

**File**: `lib/aws_encryption_sdk/keyring/multi.ex` (new file)

```elixir
defmodule AwsEncryptionSdk.Keyring.Multi do
  @moduledoc """
  Multi-Keyring implementation.

  Composes multiple keyrings together, enabling encryption with multiple keys
  and flexible decryption with any available key.

  ## Use Cases

  - **Redundancy**: Encrypt with multiple keys so any one can decrypt
  - **Key rotation**: Include both old and new keys during transitions
  - **Multi-party access**: Different parties can decrypt with their respective keys

  ## Encryption Behavior

  - Generator keyring (if provided) generates and wraps the plaintext data key
  - Each child keyring wraps the plaintext data key (adding additional EDKs)
  - All keyrings must succeed (fail-fast)
  - EDKs accumulate through the pipeline

  ## Decryption Behavior

  - Attempts decryption with generator first (if provided), then children
  - Each keyring receives the original, unmodified materials
  - Returns immediately on first successful decryption
  - Fails only if all keyrings fail to decrypt

  ## Security Note

  Any keyring in the multi-keyring can decrypt data encrypted with this keyring.
  Users should understand the security implications of their keyring composition.

  ## Example

      # Create keyrings
      {:ok, aes_keyring} = RawAes.new("ns", "aes-key", aes_key, :aes_256_gcm)
      {:ok, rsa_keyring} = RawRsa.new("ns", "rsa-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      # Create multi-keyring with generator and child
      {:ok, multi} = Multi.new(generator: aes_keyring, children: [rsa_keyring])

      # Encrypt - AES generates key, both keyrings wrap it
      {:ok, enc_materials} = Multi.wrap_key(multi, materials)

      # Decrypt - tries AES first, then RSA
      {:ok, dec_materials} = Multi.unwrap_key(multi, materials, edks)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type keyring :: struct()

  @type t :: %__MODULE__{
          generator: keyring() | nil,
          children: [keyring()]
        }

  defstruct [:generator, children: []]

  @doc """
  Creates a new Multi-Keyring.

  ## Options

  - `:generator` - Optional keyring that generates the plaintext data key during encryption
  - `:children` - List of keyrings that wrap the data key (default: `[]`)

  At least one of generator or children must be provided.
  If children is empty, generator is required.

  ## Returns

  - `{:ok, multi_keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :no_keyrings_provided}` - Neither generator nor children provided
  - `{:error, :generator_required_when_no_children}` - Children empty but no generator

  ## Examples

      # Generator with children
      {:ok, multi} = Multi.new(generator: aes_keyring, children: [rsa_keyring])

      # Generator only
      {:ok, multi} = Multi.new(generator: aes_keyring)

      # Children only (materials must already have plaintext data key for encryption)
      {:ok, multi} = Multi.new(children: [rsa_keyring_1, rsa_keyring_2])

  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts \\ []) when is_list(opts) do
    generator = Keyword.get(opts, :generator)
    children = Keyword.get(opts, :children, [])

    with :ok <- validate_at_least_one_keyring(generator, children),
         :ok <- validate_generator_when_no_children(generator, children) do
      {:ok, %__MODULE__{generator: generator, children: children}}
    end
  end

  defp validate_at_least_one_keyring(nil, []), do: {:error, :no_keyrings_provided}
  defp validate_at_least_one_keyring(_generator, _children), do: :ok

  defp validate_generator_when_no_children(nil, []), do: {:error, :generator_required_when_no_children}
  defp validate_generator_when_no_children(_generator, _children), do: :ok

  @doc """
  Returns the list of all keyrings in this multi-keyring.

  Useful for understanding which keyrings will be used for encryption/decryption.

  ## Examples

      {:ok, multi} = Multi.new(generator: gen, children: [child1, child2])
      Multi.list_keyrings(multi)
      # => [gen, child1, child2]

  """
  @spec list_keyrings(t()) :: [keyring()]
  def list_keyrings(%__MODULE__{generator: nil, children: children}), do: children
  def list_keyrings(%__MODULE__{generator: gen, children: children}), do: [gen | children]

  # Placeholder implementations - will be completed in Phases 2 and 3

  @doc """
  Wraps a data key using all keyrings in the multi-keyring.

  See module documentation for encryption behavior details.
  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = _keyring, %EncryptionMaterials{} = _materials) do
    {:error, :not_implemented}
  end

  @doc """
  Unwraps a data key using the keyrings in the multi-keyring.

  See module documentation for decryption behavior details.
  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = _keyring, %DecryptionMaterials{} = _materials, _edks) do
    {:error, :not_implemented}
  end

  # Behaviour callbacks - follow existing pattern of directing to explicit functions
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call Multi.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call Multi.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

#### 2. Create Unit Test File

**File**: `test/aws_encryption_sdk/keyring/multi_test.exs` (new file)

```elixir
defmodule AwsEncryptionSdk.Keyring.MultiTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  # Helper to create a test keyring
  defp create_aes_keyring(name \\ "test-key") do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", name, key, :aes_256_gcm)
    keyring
  end

  describe "new/1" do
    test "creates multi-keyring with generator only" do
      generator = create_aes_keyring("generator")
      assert {:ok, multi} = Multi.new(generator: generator)
      assert multi.generator == generator
      assert multi.children == []
    end

    test "creates multi-keyring with children only" do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      assert {:ok, multi} = Multi.new(children: [child1, child2])
      assert multi.generator == nil
      assert multi.children == [child1, child2]
    end

    test "creates multi-keyring with generator and children" do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      assert {:ok, multi} = Multi.new(generator: generator, children: [child1])
      assert multi.generator == generator
      assert multi.children == [child1]
    end

    test "fails when no generator and no children" do
      assert {:error, :no_keyrings_provided} = Multi.new([])
      assert {:error, :no_keyrings_provided} = Multi.new(generator: nil, children: [])
    end

    test "accepts empty children list with generator" do
      generator = create_aes_keyring("generator")
      assert {:ok, multi} = Multi.new(generator: generator, children: [])
      assert multi.generator == generator
      assert multi.children == []
    end
  end

  describe "list_keyrings/1" do
    test "returns generator followed by children" do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      assert Multi.list_keyrings(multi) == [generator, child1, child2]
    end

    test "returns only children when no generator" do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      assert Multi.list_keyrings(multi) == [child1, child2]
    end

    test "returns only generator when no children" do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      assert Multi.list_keyrings(multi) == [generator]
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Quality checks: `mix quality --quick`
- [x] Module compiles without warnings

#### Manual Verification:
- [x] Struct can be created in IEx: `{:ok, m} = AwsEncryptionSdk.Keyring.Multi.new(generator: keyring)`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Decryption Flow

### Overview

Implement `unwrap_key/3` with sequential keyring iteration, passing unmodified materials to each keyring and returning on first success.

### Spec Requirements Addressed

- "If the decryption materials already contain a plaintext data key, the keyring MUST fail"
- "If the generator keyring is defined, this keyring MUST first attempt to decrypt using the generator keyring"
- "For each keyring to be used for decryption, the multi-keyring MUST call that keyring's OnDecrypt using the unmodified decryption materials"
- "If the child keyring's OnDecrypt call succeeds, the multi-keyring MUST immediately return"
- "If the child keyring's OnDecrypt call fails, the multi-keyring MUST collect the error and continue"
- "OnDecrypt MUST return a failure message containing the collected failure messages"

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` | 2 RSA keys (PKCS1 + OAEP-SHA256) | Success |
| `6b8d3386-9824-46db-8764-8d58d8086f77` | 2 RSA keys (OAEP-SHA256 x2) | Success |

### Changes Required

#### 1. Implement unwrap_key/3

**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Replace placeholder `unwrap_key/3` with full implementation

```elixir
  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour

  @doc """
  Unwraps a data key using the keyrings in the multi-keyring.

  Attempts decryption with generator first (if present), then each child keyring
  in order. Returns immediately when any keyring successfully decrypts.

  Each keyring receives the original, unmodified materials (not chained).

  ## Returns

  - `{:ok, materials}` - Data key successfully unwrapped by one of the keyrings
  - `{:error, :plaintext_data_key_already_set}` - Materials already have a key
  - `{:error, {:all_keyrings_failed, [reasons]}}` - All keyrings failed to decrypt

  ## Examples

      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      {:ok, result} = Multi.unwrap_key(multi, dec_materials, edks)

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      keyrings = list_keyrings(keyring)
      attempt_decryption(keyrings, materials, edks, [])
    end
  end

  defp attempt_decryption([], _materials, _edks, errors) do
    # All keyrings failed - return collected errors
    {:error, {:all_keyrings_failed, Enum.reverse(errors)}}
  end

  defp attempt_decryption([keyring | rest], materials, edks, errors) do
    # Call the keyring's unwrap_key with unmodified materials
    case call_unwrap_key(keyring, materials, edks) do
      {:ok, result_materials} ->
        # Success - return immediately
        {:ok, result_materials}

      {:error, reason} ->
        # Collect error and continue to next keyring
        attempt_decryption(rest, materials, edks, [reason | errors])
    end
  end

  # Dispatch to the appropriate unwrap_key function based on keyring type
  defp call_unwrap_key(%AwsEncryptionSdk.Keyring.RawAes{} = keyring, materials, edks) do
    AwsEncryptionSdk.Keyring.RawAes.unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(%AwsEncryptionSdk.Keyring.RawRsa{} = keyring, materials, edks) do
    AwsEncryptionSdk.Keyring.RawRsa.unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(%__MODULE__{} = keyring, materials, edks) do
    # Nested multi-keyring
    unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(keyring, _materials, _edks) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end
```

#### 2. Add Decryption Unit Tests

**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add describe block for `unwrap_key/3`

```elixir
  describe "unwrap_key/3" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "fails if materials already have plaintext key", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      existing_key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, existing_key)

      assert {:error, :plaintext_data_key_already_set} =
               Multi.unwrap_key(multi, materials, [])
    end

    test "decrypts with generator keyring", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      # Encrypt with the keyring
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      # Decrypt with multi-keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "decrypts with child keyring when generator fails", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(generator: generator, children: [child])

      # Encrypt with child keyring only
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(child, enc_materials)

      # Decrypt with multi-keyring - generator will fail, child will succeed
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "returns immediately on first success", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Encrypt with child1
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(child1, enc_materials)

      # Decrypt - should succeed with child1, never try child2
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "collects errors when all keyrings fail", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Create EDK that neither keyring can decrypt (from a different keyring)
      other_keyring = create_aes_keyring("other")
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

      # Decrypt - both should fail
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      result = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert {:error, {:all_keyrings_failed, errors}} = result
      assert length(errors) == 2
    end

    test "returns error when no EDKs provided", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      result = Multi.unwrap_key(multi, dec_materials, [])

      assert {:error, {:all_keyrings_failed, _errors}} = result
    end
  end
```

#### 3. Create Test Vector Test File

**File**: `test/aws_encryption_sdk/keyring/multi_test_vectors_test.exs` (new file)

```elixir
defmodule AwsEncryptionSdk.Keyring.MultiTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.{Multi, RawRsa}
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

  describe "Multi-RSA decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts 8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e (PKCS1 + OAEP-SHA256)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e")
    end

    @tag timeout: 120_000
    test "decrypts 6b8d3386-9824-46db-8764-8d58d8086f77 (OAEP-SHA256 x2)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "6b8d3386-9824-46db-8764-8d58d8086f77")
    end
  end

  defp run_multi_rsa_decrypt_test(nil, _test_id), do: :ok

  defp run_multi_rsa_decrypt_test(harness, test_id) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _remainder} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Build keyrings for each master key
    keyrings = build_keyrings_from_master_keys(harness, test.master_keys, message.header.encrypted_data_keys)

    # Create multi-keyring with all keyrings as children (no generator)
    {:ok, multi} = Multi.new(children: keyrings)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key using multi-keyring
    {:ok, result} = Multi.unwrap_key(multi, materials, message.header.encrypted_data_keys)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end

  defp build_keyrings_from_master_keys(harness, master_keys, edks) do
    master_keys
    |> Enum.with_index()
    |> Enum.map(fn {mk, idx} ->
      build_keyring(harness, mk, Enum.at(edks, idx))
    end)
    |> Enum.filter(&(&1 != nil))
  end

  defp build_keyring(harness, %{"type" => "raw", "encryption-algorithm" => "rsa"} = mk, edk) do
    key_id = mk["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)

    # Only build keyring if we can decrypt (need private key)
    case key_data do
      %{"decrypt" => true} ->
        {:ok, pem_material} = TestVectorHarness.decode_key_material(key_data)
        {:ok, private_key} = RawRsa.load_private_key_pem(pem_material)

        padding_scheme = parse_padding_scheme(mk)
        provider_id = mk["provider-id"]
        # For RSA, provider_info in EDK is the key name
        key_name = if edk, do: edk.key_provider_info, else: mk["key"]

        {:ok, keyring} = RawRsa.new(provider_id, key_name, padding_scheme, private_key: private_key)
        keyring

      _ ->
        # Can't decrypt with this key (public-only or KMS)
        nil
    end
  end

  defp build_keyring(_harness, _mk, _edk), do: nil

  defp parse_padding_scheme(%{"padding-algorithm" => "pkcs1"}), do: :pkcs1_v1_5

  defp parse_padding_scheme(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => hash}) do
    {:oaep, String.to_atom(hash)}
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Test vector tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test_vectors_test.exs`
- [x] Quality checks: `mix quality --quick`

#### Manual Verification:
- [x] Decrypt test vector in IEx using multi-keyring with RSA children

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Encryption Flow

### Overview

Implement `wrap_key/2` with generator + children chaining. Generator creates the data key, then each child wraps it.

### Spec Requirements Addressed

- "This keyring MUST fail if the input encryption materials already contain a plaintext data key" (when generator present)
- "This keyring MUST first call the generator keyring's OnEncrypt"
- "This keyring MUST fail if the generator keyring's OnEncrypt returns encryption materials that do not contain a plaintext data key"
- "If a generator keyring is not provided and the input encryption materials do not contain a plaintext data key, OnEncrypt MUST fail"
- "For each keyring in the child keyrings list, OnEncrypt MUST be called with the encryption materials returned by the previous OnEncrypt call"
- "If the child keyring's OnEncrypt fails, this OnEncrypt MUST also fail"

### Test Vectors for This Phase

None - unit tests for round-trip encryption/decryption.

### Changes Required

#### 1. Implement wrap_key/2

**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Replace placeholder `wrap_key/2` with full implementation

```elixir
  @doc """
  Wraps a data key using all keyrings in the multi-keyring.

  If a generator is present, it generates and wraps the plaintext data key.
  Each child keyring then wraps the same plaintext data key, adding additional EDKs.

  All keyrings must succeed (fail-fast on any error).

  ## Returns

  - `{:ok, materials}` - Data key wrapped by all keyrings
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key (with generator)
  - `{:error, :no_plaintext_data_key}` - No generator and materials have no plaintext key
  - `{:error, {:generator_failed, reason}}` - Generator keyring failed
  - `{:error, {:generator_did_not_produce_key}}` - Generator didn't set plaintext key
  - `{:error, {:child_keyring_failed, index, reason}}` - Child keyring failed

  ## Examples

      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, result} = Multi.wrap_key(multi, enc_materials)

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    with {:ok, materials} <- maybe_call_generator(keyring.generator, materials),
         {:ok, materials} <- validate_has_plaintext_key(keyring.generator, materials),
         {:ok, materials} <- wrap_with_children(keyring.children, materials) do
      {:ok, materials}
    end
  end

  # When generator is present, call it first
  defp maybe_call_generator(nil, materials), do: {:ok, materials}

  defp maybe_call_generator(generator, materials) do
    # Spec: MUST fail if materials already have plaintext key when generator present
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      case call_wrap_key(generator, materials) do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, {:generator_failed, reason}}
      end
    end
  end

  # Validate that we have a plaintext key after generator (or before children if no generator)
  defp validate_has_plaintext_key(_generator, materials) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:ok, materials}
    else
      {:error, :no_plaintext_data_key}
    end
  end

  # Call each child keyring in sequence, chaining outputs
  defp wrap_with_children(children, materials) do
    children
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, materials}, fn {child, index}, {:ok, acc_materials} ->
      case call_wrap_key(child, acc_materials) do
        {:ok, result} ->
          {:cont, {:ok, result}}

        {:error, reason} ->
          {:halt, {:error, {:child_keyring_failed, index, reason}}}
      end
    end)
  end

  # Dispatch to the appropriate wrap_key function based on keyring type
  defp call_wrap_key(%AwsEncryptionSdk.Keyring.RawAes{} = keyring, materials) do
    AwsEncryptionSdk.Keyring.RawAes.wrap_key(keyring, materials)
  end

  defp call_wrap_key(%AwsEncryptionSdk.Keyring.RawRsa{} = keyring, materials) do
    AwsEncryptionSdk.Keyring.RawRsa.wrap_key(keyring, materials)
  end

  defp call_wrap_key(%__MODULE__{} = keyring, materials) do
    # Nested multi-keyring
    wrap_key(keyring, materials)
  end

  defp call_wrap_key(keyring, _materials) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end
```

#### 2. Add Encryption Unit Tests

**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add describe block for `wrap_key/2`

```elixir
  describe "wrap_key/2" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "generates and wraps key with generator only", %{suite: suite} do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      {:ok, result} = Multi.wrap_key(multi, materials)

      assert is_binary(result.plaintext_data_key)
      assert byte_size(result.plaintext_data_key) == 32
      assert length(result.encrypted_data_keys) == 1
    end

    test "wraps existing key with children only", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Pre-set plaintext data key (required when no generator)
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      {:ok, result} = Multi.wrap_key(multi, materials)

      assert result.plaintext_data_key == existing_key
      assert length(result.encrypted_data_keys) == 2
    end

    test "fails if no generator and no plaintext key", %{suite: suite} do
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(children: [child])

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      assert {:error, :no_plaintext_data_key} = Multi.wrap_key(multi, materials)
    end

    test "fails if materials have plaintext key when generator present", %{suite: suite} do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:error, :plaintext_data_key_already_set} = Multi.wrap_key(multi, materials)
    end

    test "generator followed by children adds multiple EDKs", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, result} = Multi.wrap_key(multi, materials)

      # Generator + 2 children = 3 EDKs
      assert length(result.encrypted_data_keys) == 3
    end

    test "round-trips encrypt/decrypt with generator only", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"context" => "test"})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"context" => "test"})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "round-trips encrypt/decrypt with generator and children", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Decrypt - any single keyring should work
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "can decrypt with subset of keyrings", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child = create_aes_keyring("child")
      {:ok, encrypt_multi} = Multi.new(generator: generator, children: [child])

      # Encrypt with both
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(encrypt_multi, enc_materials)
      assert length(enc_result.encrypted_data_keys) == 2

      # Decrypt with only the child keyring
      {:ok, decrypt_multi} = Multi.new(children: [child])
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(decrypt_multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] All multi_test.exs tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Quality checks: `mix quality --quick`

#### Manual Verification:
- [x] Round-trip encrypt/decrypt in IEx with generator + children

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: Edge Cases & Full Test Coverage

### Overview

Add remaining test vectors and edge case unit tests to ensure full spec compliance.

### Spec Requirements Addressed

All remaining edge cases and validation of full spec compliance.

### Test Vectors for This Phase

| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| `afb2ba6d-e8b7-4c74-99ff-f7925485a868` | 2 RSA keys (PKCS1 + OAEP-SHA256) | Success |
| `bca8fe01-878d-4705-9ee4-8ea9faf6328b` | 2 RSA keys (OAEP-SHA1 + OAEP-SHA256) | Success |
| `1aa68ab1-3752-48e8-af6b-cea6650df263` | 2 RSA keys (OAEP-SHA384 + OAEP-SHA256) | Success |
| `aba06ffc-a839-4639-967c-a739d8626adc` | 2 RSA keys (OAEP-SHA512 + OAEP-SHA256) | Success |
| `e05108d7-cde8-42ae-8901-ee7d39af0eae` | 2 RSA keys (OAEP-SHA256 x2) | Success |

### Changes Required

#### 1. Add Remaining Test Vectors

**File**: `test/aws_encryption_sdk/keyring/multi_test_vectors_test.exs`
**Changes**: Add remaining test vector tests

```elixir
  describe "Multi-RSA decrypt vectors - extended" do
    @tag timeout: 120_000
    test "decrypts afb2ba6d-e8b7-4c74-99ff-f7925485a868", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "afb2ba6d-e8b7-4c74-99ff-f7925485a868")
    end

    @tag timeout: 120_000
    test "decrypts bca8fe01-878d-4705-9ee4-8ea9faf6328b (OAEP-SHA1 + SHA256)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "bca8fe01-878d-4705-9ee4-8ea9faf6328b")
    end

    @tag timeout: 120_000
    test "decrypts 1aa68ab1-3752-48e8-af6b-cea6650df263 (OAEP-SHA384 + SHA256)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "1aa68ab1-3752-48e8-af6b-cea6650df263")
    end

    @tag timeout: 120_000
    test "decrypts aba06ffc-a839-4639-967c-a739d8626adc (OAEP-SHA512 + SHA256)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "aba06ffc-a839-4639-967c-a739d8626adc")
    end

    @tag timeout: 120_000
    test "decrypts e05108d7-cde8-42ae-8901-ee7d39af0eae (OAEP-SHA256 x2)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "e05108d7-cde8-42ae-8901-ee7d39af0eae")
    end
  end
```

#### 2. Add Edge Case Unit Tests

**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add edge case tests

```elixir
  describe "edge cases" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "handles nested multi-keyrings", %{suite: suite} do
      inner_gen = create_aes_keyring("inner-gen")
      inner_child = create_aes_keyring("inner-child")
      {:ok, inner_multi} = Multi.new(generator: inner_gen, children: [inner_child])

      outer_child = create_aes_keyring("outer-child")
      {:ok, outer_multi} = Multi.new(generator: inner_multi, children: [outer_child])

      # Encrypt with nested multi-keyring
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(outer_multi, enc_materials)

      # Should have 3 EDKs: inner-gen + inner-child + outer-child
      assert length(enc_result.encrypted_data_keys) == 3

      # Decrypt with nested multi-keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(outer_multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "preserves encryption context through wrap/unwrap", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      ec = %{"purpose" => "test", "user" => "alice"}

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "fails with wrong encryption context", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"key" => "value1"})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"key" => "value2"})
      result = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert {:error, {:all_keyrings_failed, _errors}} = result
    end

    test "single child keyring works", %{suite: suite} do
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(children: [child])

      # Need existing plaintext key since no generator
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      {:ok, enc_result} = Multi.wrap_key(multi, materials)
      assert length(enc_result.encrypted_data_keys) == 1

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == existing_key
    end

    test "handles many children", %{suite: suite} do
      generator = create_aes_keyring("generator")
      children = for i <- 1..10, do: create_aes_keyring("child-#{i}")
      {:ok, multi} = Multi.new(generator: generator, children: children)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Generator + 10 children = 11 EDKs
      assert length(enc_result.encrypted_data_keys) == 11

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix test`
- [x] All test vectors pass: `mix test --only test_vectors`
- [x] Full quality checks: `mix quality`

#### Manual Verification:
- [x] End-to-end feature verification with multiple keyring types

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All test vectors pass: `mix test --only test_vectors`

### Manual:
- [x] Create multi-keyring with Raw AES + Raw RSA in IEx
- [x] Encrypt and decrypt successfully
- [x] Verify EDK count matches keyring count

## Testing Strategy

### Unit Tests

Test coverage for:
- Constructor validation (no keyrings, generator only, children only, both)
- `wrap_key/2` (generator generates key, children wrap existing, fail-fast on error)
- `unwrap_key/3` (generator first, children sequence, collect errors, first success wins)
- Edge cases (nested multi-keyring, encryption context, many children)

### Test Vector Integration

```elixir
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

Run with: `mix test --only test_vectors`

### Manual Testing Steps

1. Create AES and RSA keyrings in IEx
2. Create multi-keyring with generator + children
3. Encrypt plaintext and verify EDK count
4. Decrypt with full multi-keyring
5. Decrypt with subset (only one keyring)

## References

- Issue: #28
- Research: `thoughts/shared/research/2026-01-26-GH28-multi-keyring.md`
- Multi-Keyring Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md
- Keyring Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
