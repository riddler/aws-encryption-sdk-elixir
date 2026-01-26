# Raw RSA Keyring Implementation Plan

## Overview

Implement the Raw RSA Keyring per the AWS Encryption SDK specification. This keyring uses locally-provided RSA key pairs to wrap and unwrap data keys using asymmetric encryption with configurable padding schemes.

**Issue**: #27 - Implement Raw RSA Keyring
**Research**: `thoughts/shared/research/2026-01-25-GH27-raw-rsa-keyring.md`

## Specification Requirements

### Source Documents
- [raw-rsa-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md) - Primary spec
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Behaviour contract
- [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - EDK structure

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Constructor requires key_namespace, key_name, padding_scheme, at least one key | raw-rsa-keyring.md#initialization | MUST |
| Only support defined padding schemes (PKCS1, OAEP-SHA1/256/384/512) | raw-rsa-keyring.md#initialization | MUST |
| MGF1 hash must match OAEP hash | raw-rsa-keyring.md#initialization | MUST |
| Key namespace must not be "aws-kms" | raw-rsa-keyring.md#security | MUST |
| OnEncrypt requires public key | raw-rsa-keyring.md#on-encrypt | MUST |
| OnEncrypt must not derive public from private | raw-rsa-keyring.md#on-encrypt | MUST |
| OnDecrypt requires private key | raw-rsa-keyring.md#on-decrypt | MUST |
| OnDecrypt fails if plaintext key already set | raw-rsa-keyring.md#on-decrypt | MUST |
| EDK provider_id = key_namespace, provider_info = key_name | raw-rsa-keyring.md#on-encrypt | MUST |
| Support PEM-encoded X.509 SubjectPublicKeyInfo | raw-rsa-keyring.md#initialization | SHOULD |
| Support PEM-encoded PKCS#8 PrivateKeyInfo | raw-rsa-keyring.md#initialization | SHOULD |

## Test Vectors

### Validation Strategy
Each phase includes specific test vectors to validate the implementation.
Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary
| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 3 | `d20b31a6-200d-4fdb-819d-7ded46c99d10` | PKCS1 v1.5 decryption |
| 3 | `24088ba0-bf47-4d06-bb12-f6ba40956bd6` | OAEP-SHA256 decryption |
| 3 | `7c640f28-9fa1-4ff9-9179-196149f8c346` | OAEP-SHA1 decryption |
| 3 | `0ad7c010-79ad-4710-876b-21c677c97b19` | OAEP-SHA384 decryption |
| 3 | `a2adc73f-6885-4a1c-a2bb-3294d48766b4` | OAEP-SHA512 decryption |

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

### Existing Code:
- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour with `validate_provider_id/1`, `generate_data_key/1`, `has_plaintext_data_key?/1`
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Reference implementation to follow (339 lines)
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EDK struct with `new/3`
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - Has `set_plaintext_data_key/2`, `add_encrypted_data_key/2`
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - Has `set_plaintext_data_key/2`

### Key Patterns from Raw AES (to follow):
- Struct with `@enforce_keys` for required fields (raw_aes.ex:41-42)
- Constructor with `with` chain validation (raw_aes.ex:85-98)
- `wrap_key/2` public function for encryption (raw_aes.ex:179-185)
- `unwrap_key/3` public function for decryption (raw_aes.ex:246-252)
- `try_decrypt_edks/3` with `Enum.reduce_while` pattern (raw_aes.ex:254-272)
- Behaviour callbacks that return helpful error messages (raw_aes.ex:328-338)

### Key Differences from Raw AES:
1. **Provider Info**: RSA uses only `key_name` (no IV/tag structure), AES has `key_name + tag_len + iv_len + iv`
2. **Keys**: RSA has separate `public_key`/`private_key` (optional), AES has single `wrapping_key` (required)
3. **No AAD**: RSA encryption doesn't use encryption context as AAD (unlike AES-GCM)
4. **Padding Options**: RSA has 5 padding schemes, AES has 3 cipher sizes

## Desired End State

After this plan is complete:
1. `lib/aws_encryption_sdk/keyring/raw_rsa.ex` exists implementing the Keyring behaviour
2. All 5 padding schemes work: `:pkcs1_v1_5`, `{:oaep, :sha1}`, `{:oaep, :sha256}`, `{:oaep, :sha384}`, `{:oaep, :sha512}`
3. PEM key loading works for both public and private keys
4. Unit tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test.exs`
5. Test vector tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs --only test_vectors`
6. Full quality check passes: `mix quality`

## What We're NOT Doing

- AWS KMS keyring (separate issue #XX)
- Multi-keyring (issue #28 - depends on this)
- DER key loading (PEM only per SHOULD requirement)
- Key size validation/enforcement (spec doesn't mandate minimum)
- Password-protected PEM keys

## Implementation Approach

Follow the Raw AES keyring pattern exactly:
1. Define struct with required/optional fields
2. Constructor validates and returns `{:ok, struct}` or `{:error, reason}`
3. `wrap_key/2` handles encryption (requires public key)
4. `unwrap_key/3` handles decryption (requires private key)
5. Behaviour callbacks return helpful error messages directing to explicit functions

---

## Phase 1: Core Structure & Constructor

### Overview
Create the module with struct definition, type specs, constructor, and PEM loading helpers.

### Spec Requirements Addressed
- Constructor requires key_namespace, key_name, padding_scheme, at least one key (MUST)
- Only support defined padding schemes (MUST)
- Key namespace must not be "aws-kms" (MUST)
- Support PEM-encoded keys (SHOULD)

### Changes Required:

#### 1. Create Raw RSA Keyring Module
**File**: `lib/aws_encryption_sdk/keyring/raw_rsa.ex`
**Changes**: New file with struct, types, constructor, and PEM helpers

```elixir
defmodule AwsEncryptionSdk.Keyring.RawRsa do
  @moduledoc """
  Raw RSA Keyring implementation.

  Uses locally-provided RSA key pairs to wrap and unwrap data keys using
  asymmetric encryption. Supports multiple padding schemes.

  ## Example

      iex> {:ok, public_key} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem_string)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawRsa.new("my-ns", "my-key", {:oaep, :sha256}, public_key: public_key)
      iex> is_struct(keyring, AwsEncryptionSdk.Keyring.RawRsa)
      true

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @typedoc "RSA padding scheme"
  @type padding_scheme ::
          :pkcs1_v1_5
          | {:oaep, :sha1}
          | {:oaep, :sha256}
          | {:oaep, :sha384}
          | {:oaep, :sha512}

  @typedoc "RSA public key in Erlang format"
  @type rsa_public_key :: {:RSAPublicKey, integer(), integer()}

  @typedoc "RSA private key in Erlang format"
  @type rsa_private_key :: tuple()

  @type t :: %__MODULE__{
          key_namespace: String.t(),
          key_name: String.t(),
          padding_scheme: padding_scheme(),
          public_key: rsa_public_key() | nil,
          private_key: rsa_private_key() | nil
        }

  @enforce_keys [:key_namespace, :key_name, :padding_scheme]
  defstruct [:key_namespace, :key_name, :padding_scheme, :public_key, :private_key]

  @valid_padding_schemes [:pkcs1_v1_5, {:oaep, :sha1}, {:oaep, :sha256}, {:oaep, :sha384}, {:oaep, :sha512}]

  @doc """
  Creates a new Raw RSA Keyring.

  ## Parameters

  - `key_namespace` - Key provider ID (must not start with "aws-kms")
  - `key_name` - Unique identifier for the key pair
  - `padding_scheme` - One of `:pkcs1_v1_5`, `{:oaep, :sha1}`, `{:oaep, :sha256}`, `{:oaep, :sha384}`, `{:oaep, :sha512}`
  - `opts` - Keyword list with `:public_key` and/or `:private_key` (at least one required)

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :reserved_provider_id}` - key_namespace starts with "aws-kms"
  - `{:error, :invalid_padding_scheme}` - unsupported padding scheme
  - `{:error, :no_keys_provided}` - neither public nor private key provided

  ## Examples

      iex> {:ok, pub} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
      iex> keyring.padding_scheme
      {:oaep, :sha256}

  """
  @spec new(String.t(), String.t(), padding_scheme(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def new(key_namespace, key_name, padding_scheme, opts \\ [])
      when is_binary(key_namespace) and is_binary(key_name) and is_list(opts) do
    public_key = Keyword.get(opts, :public_key)
    private_key = Keyword.get(opts, :private_key)

    with :ok <- KeyringBehaviour.validate_provider_id(key_namespace),
         :ok <- validate_padding_scheme(padding_scheme),
         :ok <- validate_at_least_one_key(public_key, private_key) do
      {:ok,
       %__MODULE__{
         key_namespace: key_namespace,
         key_name: key_name,
         padding_scheme: padding_scheme,
         public_key: public_key,
         private_key: private_key
       }}
    end
  end

  defp validate_padding_scheme(scheme) when scheme in @valid_padding_schemes, do: :ok
  defp validate_padding_scheme(_scheme), do: {:error, :invalid_padding_scheme}

  defp validate_at_least_one_key(nil, nil), do: {:error, :no_keys_provided}
  defp validate_at_least_one_key(_public, _private), do: :ok

  @doc """
  Loads an RSA public key from PEM-encoded string.

  Supports X.509 SubjectPublicKeyInfo and RSAPublicKey formats.

  ## Examples

      iex> pem = "-----BEGIN PUBLIC KEY-----\\n..."
      iex> {:ok, key} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem)

  """
  @spec load_public_key_pem(String.t()) :: {:ok, rsa_public_key()} | {:error, term()}
  def load_public_key_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{:SubjectPublicKeyInfo, der, _}] ->
        {:ok, :public_key.der_decode(:SubjectPublicKeyInfo, der)}

      [{:RSAPublicKey, der, _}] ->
        {:ok, :public_key.der_decode(:RSAPublicKey, der)}

      [] ->
        {:error, :invalid_pem_format}

      _other ->
        {:error, :unsupported_key_type}
    end
  rescue
    _ -> {:error, :pem_decode_failed}
  end

  @doc """
  Loads an RSA private key from PEM-encoded string.

  Supports PKCS#8 PrivateKeyInfo and RSAPrivateKey formats.

  ## Examples

      iex> pem = "-----BEGIN PRIVATE KEY-----\\n..."
      iex> {:ok, key} = AwsEncryptionSdk.Keyring.RawRsa.load_private_key_pem(pem)

  """
  @spec load_private_key_pem(String.t()) :: {:ok, rsa_private_key()} | {:error, term()}
  def load_private_key_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{:PrivateKeyInfo, der, _}] ->
        {:ok, :public_key.der_decode(:PrivateKeyInfo, der)}

      [{:RSAPrivateKey, der, _}] ->
        {:ok, :public_key.der_decode(:RSAPrivateKey, der)}

      [] ->
        {:error, :invalid_pem_format}

      _other ->
        {:error, :unsupported_key_type}
    end
  rescue
    _ -> {:error, :pem_decode_failed}
  end

  # Behaviour callbacks (Phase 3 will add wrap_key/unwrap_key)
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call RawRsa.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call RawRsa.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test.exs` (constructor tests only)
- [x] Compiles without warnings: `mix compile --warnings-as-errors`
- [x] Dialyzer passes: `mix dialyzer`

#### Manual Verification:
- [x] In IEx, can create keyring with PEM keys from test vectors
- [x] Constructor rejects "aws-kms" namespace
- [x] Constructor rejects invalid padding schemes
- [x] Constructor requires at least one key

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: Wrap Key (Encryption)

### Overview
Implement `wrap_key/2` to encrypt data keys using RSA public key encryption.

### Spec Requirements Addressed
- OnEncrypt requires public key (MUST)
- OnEncrypt must not derive public from private (MUST)
- Generate data key if not present (MUST)
- EDK provider_id = key_namespace, provider_info = key_name (MUST)

### Changes Required:

#### 1. Add Padding Options Helper
**File**: `lib/aws_encryption_sdk/keyring/raw_rsa.ex`
**Changes**: Add function to convert padding scheme to Erlang options

```elixir
# Add after @valid_padding_schemes

@doc false
@spec padding_options(padding_scheme()) :: list()
def padding_options(:pkcs1_v1_5), do: [{:rsa_padding, :rsa_pkcs1_padding}]

def padding_options({:oaep, :sha1}) do
  [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha}, {:rsa_mgf1_md, :sha}]
end

def padding_options({:oaep, :sha256}) do
  [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha256}, {:rsa_mgf1_md, :sha256}]
end

def padding_options({:oaep, :sha384}) do
  [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha384}, {:rsa_mgf1_md, :sha384}]
end

def padding_options({:oaep, :sha512}) do
  [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha512}, {:rsa_mgf1_md, :sha512}]
end
```

#### 2. Add wrap_key/2 Function
**File**: `lib/aws_encryption_sdk/keyring/raw_rsa.ex`
**Changes**: Add wrap_key implementation

```elixir
@doc """
Wraps a data key using this keyring's public key.

If materials don't have a plaintext data key, one will be generated.
The wrapped key is added to the materials as an EDK.

## Examples

    iex> {:ok, pub} = RawRsa.load_public_key_pem(pem)
    iex> {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
    iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
    iex> {:ok, result} = RawRsa.wrap_key(keyring, materials)
    iex> length(result.encrypted_data_keys) == 1
    true

"""
@spec wrap_key(t(), EncryptionMaterials.t()) ::
        {:ok, EncryptionMaterials.t()} | {:error, term()}
def wrap_key(%__MODULE__{public_key: nil}, _materials) do
  {:error, :no_public_key}
end

def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
  with {:ok, materials} <- ensure_data_key(keyring, materials),
       {:ok, edk} <- encrypt_data_key(keyring, materials.plaintext_data_key) do
    {:ok, EncryptionMaterials.add_encrypted_data_key(materials, edk)}
  end
end

defp ensure_data_key(_keyring, materials) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:ok, materials}
  else
    key = KeyringBehaviour.generate_data_key(materials.algorithm_suite)
    {:ok, EncryptionMaterials.set_plaintext_data_key(materials, key)}
  end
end

defp encrypt_data_key(%__MODULE__{} = keyring, plaintext_key) do
  padding_opts = padding_options(keyring.padding_scheme)

  try do
    ciphertext = :public_key.encrypt_public(plaintext_key, keyring.public_key, padding_opts)

    # For RSA, provider_info is just the key_name (no additional structure like AES)
    edk = EncryptedDataKey.new(keyring.key_namespace, keyring.key_name, ciphertext)
    {:ok, edk}
  rescue
    _ -> {:error, :encryption_failed}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test.exs`
- [x] Compiles without warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] In IEx, wrap_key generates data key when not present
- [x] In IEx, wrap_key encrypts existing data key
- [x] In IEx, wrap_key fails when no public key configured
- [x] EDK has correct provider_id (key_namespace) and provider_info (key_name)

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 3: Unwrap Key (Decryption) & Test Vectors

### Overview
Implement `unwrap_key/3` to decrypt data keys and validate against official test vectors.

### Spec Requirements Addressed
- OnDecrypt requires private key (MUST)
- OnDecrypt fails if plaintext key already set (MUST)
- Attempt to decrypt EDKs in list order (MUST)
- Only decrypt EDK if provider_id and provider_info match (MUST)
- Return immediately on first success (MUST)
- Fail without modifying materials if all attempts fail (MUST)

### Test Vectors for This Phase

| Test ID | Description | Padding | Expected Result |
|---------|-------------|---------|-----------------|
| `d20b31a6-200d-4fdb-819d-7ded46c99d10` | PKCS1 v1.5 single keyring | PKCS1 | Success |
| `24088ba0-bf47-4d06-bb12-f6ba40956bd6` | OAEP-SHA256 single keyring | OAEP-SHA256 | Success |
| `7c640f28-9fa1-4ff9-9179-196149f8c346` | OAEP-SHA1 single keyring | OAEP-SHA1 | Success |
| `0ad7c010-79ad-4710-876b-21c677c97b19` | OAEP-SHA384 single keyring | OAEP-SHA384 | Success |
| `a2adc73f-6885-4a1c-a2bb-3294d48766b4` | OAEP-SHA512 single keyring | OAEP-SHA512 | Success |

### Changes Required:

#### 1. Add unwrap_key/3 Function
**File**: `lib/aws_encryption_sdk/keyring/raw_rsa.ex`
**Changes**: Add unwrap_key implementation

```elixir
@doc """
Unwraps a data key using this keyring's private key.

Iterates through EDKs to find one that:
1. Has matching key_provider_id (key_namespace)
2. Has matching key_provider_info (key_name)
3. Successfully decrypts with this keyring's private key

## Returns

- `{:ok, materials}` - Data key successfully unwrapped and set
- `{:error, :no_private_key}` - No private key configured
- `{:error, :plaintext_data_key_already_set}` - Materials already have a key
- `{:error, :unable_to_decrypt_data_key}` - No matching EDK could be decrypted

## Examples

    iex> {:ok, priv} = RawRsa.load_private_key_pem(pem)
    iex> {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, private_key: priv)
    iex> dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
    iex> {:ok, result} = RawRsa.unwrap_key(keyring, dec_materials, edks)
    iex> is_binary(result.plaintext_data_key)
    true

"""
@spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
        {:ok, DecryptionMaterials.t()} | {:error, term()}
def unwrap_key(%__MODULE__{private_key: nil}, _materials, _edks) do
  {:error, :no_private_key}
end

def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:error, :plaintext_data_key_already_set}
  else
    try_decrypt_edks(keyring, materials, edks)
  end
end

defp try_decrypt_edks(keyring, materials, edks) do
  result =
    Enum.reduce_while(edks, :no_match, fn edk, _acc ->
      case try_decrypt_edk(keyring, edk) do
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

defp try_decrypt_edk(keyring, edk) do
  with :ok <- match_provider_id(keyring, edk),
       :ok <- match_key_name(keyring, edk) do
    decrypt_with_private_key(keyring, edk.ciphertext)
  end
end

defp match_provider_id(keyring, edk) do
  if edk.key_provider_id == keyring.key_namespace do
    :ok
  else
    {:error, :provider_id_mismatch}
  end
end

defp match_key_name(keyring, edk) do
  if edk.key_provider_info == keyring.key_name do
    :ok
  else
    {:error, :key_name_mismatch}
  end
end

defp decrypt_with_private_key(keyring, ciphertext) do
  padding_opts = padding_options(keyring.padding_scheme)

  try do
    plaintext = :public_key.decrypt_private(ciphertext, keyring.private_key, padding_opts)
    {:ok, plaintext}
  rescue
    _ -> {:error, :decryption_failed}
  end
end
```

#### 2. Create Test Vector Test File
**File**: `test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs`
**Changes**: New file for test vector validation

```elixir
defmodule AwsEncryptionSdk.Keyring.RawRsaTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawRsa
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

  describe "RSA PKCS1 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector d20b31a6-200d-4fdb-819d-7ded46c99d10", %{harness: harness} do
      run_rsa_decrypt_test(harness, "d20b31a6-200d-4fdb-819d-7ded46c99d10", :pkcs1_v1_5)
    end
  end

  describe "RSA OAEP-SHA256 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 24088ba0-bf47-4d06-bb12-f6ba40956bd6", %{harness: harness} do
      run_rsa_decrypt_test(harness, "24088ba0-bf47-4d06-bb12-f6ba40956bd6", {:oaep, :sha256})
    end
  end

  describe "RSA OAEP-SHA1 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 7c640f28-9fa1-4ff9-9179-196149f8c346", %{harness: harness} do
      run_rsa_decrypt_test(harness, "7c640f28-9fa1-4ff9-9179-196149f8c346", {:oaep, :sha1})
    end
  end

  describe "RSA OAEP-SHA384 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 0ad7c010-79ad-4710-876b-21c677c97b19", %{harness: harness} do
      run_rsa_decrypt_test(harness, "0ad7c010-79ad-4710-876b-21c677c97b19", {:oaep, :sha384})
    end
  end

  describe "RSA OAEP-SHA512 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector a2adc73f-6885-4a1c-a2bb-3294d48766b4", %{harness: harness} do
      run_rsa_decrypt_test(harness, "a2adc73f-6885-4a1c-a2bb-3294d48766b4", {:oaep, :sha512})
    end
  end

  defp run_rsa_decrypt_test(nil, _test_id, _padding), do: :ok

  defp run_rsa_decrypt_test(harness, test_id, padding_scheme) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _remainder} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Get key material for raw RSA keyring
    [master_key | _rest_master_keys] = test.master_keys
    assert master_key["type"] == "raw"

    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    {:ok, pem_material} = TestVectorHarness.decode_key_material(key_data)

    # Load private key from PEM
    {:ok, private_key} = RawRsa.load_private_key_pem(pem_material)

    # Extract EDKs from message header
    edks = message.header.encrypted_data_keys
    [edk | _rest_edks] = edks

    # For RSA, provider_info is just the key name (unlike AES which has structured format)
    provider_id = master_key["provider-id"]
    key_name = edk.key_provider_info

    # Create keyring
    {:ok, keyring} = RawRsa.new(provider_id, key_name, padding_scheme, private_key: private_key)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key
    {:ok, result} = RawRsa.unwrap_key(keyring, materials, edks)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test.exs`
- [x] Test vectors pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs --only test_vectors`
- [x] Compiles without warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] In IEx, unwrap_key decrypts EDK correctly
- [x] In IEx, unwrap_key fails when no private key configured
- [x] In IEx, unwrap_key fails when plaintext key already set
- [x] In IEx, unwrap_key skips EDKs with wrong provider_id/key_name

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 4: Comprehensive Unit Tests

### Overview
Add comprehensive unit tests following the pattern from `raw_aes_test.exs`.

### Changes Required:

#### 1. Create Unit Test File
**File**: `test/aws_encryption_sdk/keyring/raw_rsa_test.exs`
**Changes**: New file with comprehensive tests

```elixir
defmodule AwsEncryptionSdk.Keyring.RawRsaTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.RawRsa
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  # Generate test RSA key pair for unit tests
  setup_all do
    # Generate 2048-bit RSA key pair for testing
    private_key = :public_key.generate_key({:rsa, 2048, 65537})

    # Extract public key from private
    {:RSAPrivateKey, _, modulus, public_exp, _, _, _, _, _, _, _} = private_key
    public_key = {:RSAPublicKey, modulus, public_exp}

    {:ok, private_key: private_key, public_key: public_key}
  end

  describe "new/4" do
    test "creates keyring with public key only", %{public_key: pub} do
      assert {:ok, keyring} = RawRsa.new("my-ns", "my-key", {:oaep, :sha256}, public_key: pub)
      assert keyring.key_namespace == "my-ns"
      assert keyring.key_name == "my-key"
      assert keyring.padding_scheme == {:oaep, :sha256}
      assert keyring.public_key == pub
      assert keyring.private_key == nil
    end

    test "creates keyring with private key only", %{private_key: priv} do
      assert {:ok, keyring} = RawRsa.new("ns", "key", :pkcs1_v1_5, private_key: priv)
      assert keyring.private_key == priv
      assert keyring.public_key == nil
    end

    test "creates keyring with both keys", %{public_key: pub, private_key: priv} do
      assert {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha1}, public_key: pub, private_key: priv)
      assert keyring.public_key == pub
      assert keyring.private_key == priv
    end

    test "supports all padding schemes", %{public_key: pub} do
      for scheme <- [:pkcs1_v1_5, {:oaep, :sha1}, {:oaep, :sha256}, {:oaep, :sha384}, {:oaep, :sha512}] do
        assert {:ok, _keyring} = RawRsa.new("ns", "key", scheme, public_key: pub),
               "Failed to create keyring with #{inspect(scheme)}"
      end
    end

    test "rejects reserved provider ID", %{public_key: pub} do
      assert {:error, :reserved_provider_id} = RawRsa.new("aws-kms", "key", {:oaep, :sha256}, public_key: pub)
      assert {:error, :reserved_provider_id} = RawRsa.new("aws-kms-mrk", "key", {:oaep, :sha256}, public_key: pub)
    end

    test "rejects invalid padding scheme", %{public_key: pub} do
      assert {:error, :invalid_padding_scheme} = RawRsa.new("ns", "key", :invalid, public_key: pub)
      assert {:error, :invalid_padding_scheme} = RawRsa.new("ns", "key", {:oaep, :md5}, public_key: pub)
    end

    test "rejects when no keys provided" do
      assert {:error, :no_keys_provided} = RawRsa.new("ns", "key", {:oaep, :sha256})
      assert {:error, :no_keys_provided} = RawRsa.new("ns", "key", {:oaep, :sha256}, [])
    end
  end

  describe "wrap_key/2" do
    setup %{public_key: pub, private_key: priv} do
      {:ok, keyring} = RawRsa.new("test-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "generates data key when not present", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert is_binary(result.plaintext_data_key)
      assert byte_size(result.plaintext_data_key) == 32
    end

    test "wraps existing data key", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert result.plaintext_data_key == existing_key
    end

    test "adds EDK to materials", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert length(result.encrypted_data_keys) == 1

      [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "test-ns"
      assert edk.key_provider_info == "test-key"
      assert is_binary(edk.ciphertext)
    end

    test "fails when no public key configured", %{private_key: priv, suite: suite} do
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, private_key: priv)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :no_public_key} = RawRsa.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3" do
    setup %{public_key: pub, private_key: priv} do
      {:ok, keyring} = RawRsa.new("test-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "decrypts EDK created by same keyring", %{keyring: keyring, suite: suite} do
      ec = %{"context" => "test"}

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      {:ok, dec_result} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "fails if plaintext data key already set", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, existing_key)

      assert {:error, :plaintext_data_key_already_set} = RawRsa.unwrap_key(keyring, materials, [])
    end

    test "skips EDKs with wrong provider ID", %{keyring: keyring, suite: suite, public_key: pub, private_key: priv} do
      ec = %{}

      # Create EDK with different provider
      {:ok, other_keyring} = RawRsa.new("other-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      assert {:error, :unable_to_decrypt_data_key} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "skips EDKs with wrong key name", %{keyring: keyring, suite: suite, public_key: pub, private_key: priv} do
      ec = %{}

      # Create EDK with different key name
      {:ok, other_keyring} = RawRsa.new("test-ns", "other-key", {:oaep, :sha256}, public_key: pub, private_key: priv)
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      assert {:error, :unable_to_decrypt_data_key} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "fails when no private key configured", %{public_key: pub, suite: suite} do
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, :no_private_key} = RawRsa.unwrap_key(keyring, materials, [])
    end

    test "returns error when no EDKs provided", %{keyring: keyring, suite: suite} do
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      assert {:error, :unable_to_decrypt_data_key} = RawRsa.unwrap_key(keyring, materials, [])
    end
  end

  describe "round-trip all padding schemes" do
    setup %{public_key: pub, private_key: priv} do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, public_key: pub, private_key: priv, suite: suite}
    end

    test "round-trips with PKCS1 v1.5", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, :pkcs1_v1_5, suite)
    end

    test "round-trips with OAEP-SHA1", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha1}, suite)
    end

    test "round-trips with OAEP-SHA256", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha256}, suite)
    end

    test "round-trips with OAEP-SHA384", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha384}, suite)
    end

    test "round-trips with OAEP-SHA512", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha512}, suite)
    end

    defp assert_round_trip(pub, priv, scheme, suite) do
      {:ok, keyring} = RawRsa.new("ns", "key", scheme, public_key: pub, private_key: priv)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key,
             "Round-trip failed for #{inspect(scheme)}"
    end
  end

  describe "edge cases" do
    test "handles unicode key names", %{public_key: pub, private_key: priv} do
      {:ok, keyring} = RawRsa.new("namespace-日本語", "キー名-🔑", {:oaep, :sha256}, public_key: pub, private_key: priv)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "handles empty encryption context", %{public_key: pub, private_key: priv} do
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub, private_key: priv)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] All unit tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test.exs`
- [x] All test vector tests pass: `mix test test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs --only test_vectors`
- [x] Full quality check: `mix quality`

#### Manual Verification:
- [ ] Review test coverage is comprehensive
- [ ] All edge cases from spec are covered

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full quality check: `mix quality`
- [x] All tests pass: `mix test`
- [x] Test vectors pass: `mix test --only test_vectors`
- [x] Dialyzer passes: `mix dialyzer`

### Manual:
- [ ] End-to-end encryption/decryption works in IEx
- [ ] Can load real PEM keys from test vectors
- [ ] All 5 padding schemes work correctly
- [ ] Error messages are helpful and clear

## Testing Strategy

### Unit Tests:
- Constructor validation (all error cases)
- wrap_key with and without existing data key
- unwrap_key with matching and non-matching EDKs
- Round-trip for all 5 padding schemes
- Edge cases (unicode names, empty context)

### Test Vector Integration:

Test vectors are integrated using the harness infrastructure:

```elixir
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

- Test vectors validate: RSA decryption with all padding schemes
- Run with: `mix test --only test_vectors`

### Manual Testing Steps:
1. Load test vector RSA keys in IEx
2. Create keyring with each padding scheme
3. Wrap and unwrap data key
4. Verify round-trip produces same key

## References

- Issue: #27
- Research: `thoughts/shared/research/2026-01-25-GH27-raw-rsa-keyring.md`
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md
- Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- Erlang :public_key: https://www.erlang.org/doc/apps/public_key/public_key.html
