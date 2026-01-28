# AWS KMS Discovery Keyring Implementation Plan

## Overview

Implement the AWS KMS Discovery Keyring - a **decrypt-only** keyring that can decrypt data keys encrypted by any KMS key the caller has access to. Unlike the standard AWS KMS Keyring, the discovery keyring does not have a pre-configured key ID. Instead, it extracts the key ARN from each EDK's provider info and attempts decryption using that ARN.

**Issue**: #49
**Research**: `thoughts/shared/research/2026-01-28-GH49-aws-kms-discovery-keyring.md`

## Specification Requirements

### Source Documents
- [aws-kms-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md) - Primary specification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface requirements

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Implement Keyring interface | keyring-interface.md | MUST |
| Client MUST NOT be null | initialization | MUST |
| Discovery filter requires both partition AND accounts | initialization | MUST |
| OnEncrypt MUST fail | onencrypt | MUST |
| Reject materials with existing plaintext key | ondecrypt | MUST |
| Provider ID MUST match "aws-kms" | ondecrypt | MUST |
| Provider info MUST be valid ARN with resource_type="key" | ondecrypt | MUST |
| Discovery filter partition MUST match | ondecrypt | MUST |
| Discovery filter accounts MUST contain EDK account | ondecrypt | MUST |
| Use ARN from provider info as KeyId for decrypt | ondecrypt | MUST |
| Response KeyId MUST equal provider info ARN | ondecrypt | MUST |
| Plaintext length MUST match algorithm suite | ondecrypt | MUST |
| Collect errors and try next EDK on failure | ondecrypt | MUST |
| Return aggregate error if all EDKs fail | ondecrypt | MUST |

### Key Difference from Standard KMS Keyring

| Aspect | AwsKms Keyring | AwsKmsDiscovery Keyring |
|--------|----------------|-------------------------|
| Key configuration | Required `kms_key_id` | No key configured |
| Encryption | Supported | MUST fail |
| Key for decrypt | Uses configured key ID | Uses ARN from EDK provider info |
| Key matching | MRK-aware matching | No matching (filter only) |
| Response validation | MRK-aware comparison | Exact ARN comparison |

## Test Vectors

### Validation Strategy

Test vectors validate basic decryption functionality. Discovery filter behavior is tested with mock-based unit tests since test vectors don't include filter scenarios.

### Test Vector Summary

| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 2 | `686aae13-ec9b-4eab-9dc0-0a1794a2ba34` | Basic single-key decryption |
| 2 | `008a5704-9930-4340-809d-1c27ff7b4868` | Multiple EDKs iteration |

### Available KMS Keys (from test vectors keys.json)

| Key ID | ARN | Notes |
|--------|-----|-------|
| `us-west-2-decryptable` | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | Standard key |
| `us-west-2-encrypt-only` | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | Cannot decrypt |

## Current State Analysis

### Existing Infrastructure

The AWS KMS Keyring infrastructure is already in place:

- `lib/aws_encryption_sdk/keyring/aws_kms.ex:1-303` - Standard AWS KMS keyring (encrypt + decrypt)
- `lib/aws_encryption_sdk/keyring/kms_client.ex:1-162` - KMS client behaviour definition
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Mock implementation for testing
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex:1-350` - KMS key ARN parsing and validation

### Key Patterns to Follow

**Constructor pattern** (from `aws_kms.ex:76-86`):
```elixir
def new(kms_client, opts \\ []) do
  with :ok <- validate_client(kms_client),
       :ok <- validate_discovery_filter(opts[:discovery_filter]) do
    {:ok, %__MODULE__{...}}
  end
end
```

**Decryption iteration pattern** (from `aws_kms.ex:210-221`):
```elixir
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
```

### Functions to Reuse from AwsKms

These helper functions from `aws_kms.ex` can be extracted or duplicated:
- `validate_client/1` (lines 93-95) - Client validation
- `match_provider_id/1` (lines 235-236) - Provider ID check
- `parse_provider_info_arn/1` (lines 238-242) - ARN parsing
- `validate_resource_type_is_key/1` (lines 245-249) - Resource type check
- `validate_decrypted_length/2` (lines 285-291) - Length validation

## Desired End State

After implementation:

1. `AwsEncryptionSdk.Keyring.AwsKmsDiscovery` module exists with:
   - `new/2` constructor accepting `(kms_client, opts)`
   - `wrap_key/2` that always returns `{:error, :discovery_keyring_cannot_encrypt}`
   - `unwrap_key/3` that decrypts using provider info ARN

2. Discovery filter support:
   - Optional `discovery_filter` option with `partition` and `accounts`
   - EDKs filtered by partition and account before decryption attempt

3. Integration:
   - Works with `Default` CMM for decrypt-only flows
   - Works with `Multi` keyring as a child keyring

### Verification

```elixir
# Create discovery keyring
{:ok, client} = KmsClient.Mock.new(%{...})
{:ok, keyring} = AwsKmsDiscovery.new(client)

# Encryption must fail
{:error, :discovery_keyring_cannot_encrypt} = AwsKmsDiscovery.wrap_key(keyring, enc_materials)

# Decryption uses ARN from EDK
edk = EncryptedDataKey.new("aws-kms", "arn:aws:kms:us-west-2:123:key/abc", ciphertext)
{:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, dec_materials, [edk])
```

## What We're NOT Doing

- **MRK Discovery Keyring** - Separate future issue; uses MRK-aware matching
- **Region-based filtering** - Spec doesn't require it; KMS API handles region validation
- **Streaming support** - Out of scope for this issue
- **Caching** - No CMM caching in this implementation

---

## Phase 1: Core Discovery Keyring Structure

### Overview

Create the basic module structure with constructor, validation, and `wrap_key` that always fails. This establishes the foundation without any decrypt logic.

### Spec Requirements Addressed

- Client MUST NOT be null (initialization)
- Discovery filter requires both partition AND accounts (initialization)
- OnEncrypt MUST fail (onencrypt)

### Changes Required

#### 1. Create Discovery Keyring Module

**File**: `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex`

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsDiscovery do
  @moduledoc """
  AWS KMS Discovery Keyring implementation.

  A decrypt-only keyring that can decrypt data keys encrypted by any AWS KMS key
  the caller has access to. Unlike the standard AWS KMS Keyring, this keyring does
  not have a pre-configured key ID - it extracts the key ARN from each EDK's
  provider info.

  ## Example

      {:ok, client} = KmsClient.ExAws.new(region: "us-west-2")
      {:ok, keyring} = AwsKmsDiscovery.new(client)

      # Decrypt with any accessible KMS key
      {:ok, materials} = AwsKmsDiscovery.unwrap_key(keyring, materials, edks)

  ## Discovery Filter

  Optionally restrict which keys can be used for decryption:

      {:ok, keyring} = AwsKmsDiscovery.new(client,
        discovery_filter: %{
          partition: "aws",
          accounts: ["123456789012", "987654321098"]
        }
      )

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials}

  @type discovery_filter :: %{
          partition: String.t(),
          accounts: [String.t(), ...]
        }

  @type t :: %__MODULE__{
          kms_client: struct(),
          discovery_filter: discovery_filter() | nil,
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_client]
  defstruct [:kms_client, :discovery_filter, grant_tokens: []]

  @doc """
  Creates a new AWS KMS Discovery Keyring.

  ## Parameters

  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `opts` - Optional keyword list:
    - `:discovery_filter` - Map with `:partition` (string) and `:accounts` (list of strings)
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :client_required}` - kms_client is nil
  - `{:error, :invalid_client_type}` - kms_client is not a struct
  - `{:error, :invalid_discovery_filter}` - filter missing partition or accounts
  - `{:error, :discovery_filter_accounts_empty}` - accounts list is empty
  - `{:error, :invalid_account_ids}` - accounts contains non-string values

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKmsDiscovery.new(client)

      # With discovery filter
      {:ok, keyring} = AwsKmsDiscovery.new(client,
        discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
      )

  """
  @spec new(struct(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_client, opts \\ []) do
    with :ok <- validate_client(kms_client),
         :ok <- validate_discovery_filter(opts[:discovery_filter]) do
      {:ok,
       %__MODULE__{
         kms_client: kms_client,
         discovery_filter: opts[:discovery_filter],
         grant_tokens: Keyword.get(opts, :grant_tokens, [])
       }}
    end
  end

  defp validate_client(nil), do: {:error, :client_required}
  defp validate_client(%{__struct__: _}), do: :ok
  defp validate_client(_), do: {:error, :invalid_client_type}

  defp validate_discovery_filter(nil), do: :ok

  defp validate_discovery_filter(%{partition: partition, accounts: accounts})
       when is_binary(partition) and is_list(accounts) do
    cond do
      accounts == [] ->
        {:error, :discovery_filter_accounts_empty}

      not Enum.all?(accounts, &is_binary/1) ->
        {:error, :invalid_account_ids}

      true ->
        :ok
    end
  end

  defp validate_discovery_filter(_), do: {:error, :invalid_discovery_filter}

  @doc """
  Discovery keyrings cannot encrypt - this always fails.

  ## Returns

  Always returns `{:error, :discovery_keyring_cannot_encrypt}`
  """
  @spec wrap_key(t(), EncryptionMaterials.t()) :: {:error, :discovery_keyring_cannot_encrypt}
  def wrap_key(%__MODULE__{}, %EncryptionMaterials{}) do
    {:error, :discovery_keyring_cannot_encrypt}
  end

  @doc """
  Unwraps a data key using AWS KMS Discovery.

  Placeholder - will be implemented in Phase 2.
  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{}, %DecryptionMaterials{}, _edks) do
    {:error, :not_implemented}
  end

  # Behaviour callbacks - direct to wrap_key/unwrap_key
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsDiscovery.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call AwsKmsDiscovery.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

#### 2. Create Initial Test File

**File**: `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsDiscoveryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  describe "new/2" do
    test "creates keyring with valid client" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsDiscovery.new(mock)
      assert keyring.kms_client == mock
      assert keyring.discovery_filter == nil
      assert keyring.grant_tokens == []
    end

    test "stores grant tokens" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsDiscovery.new(mock, grant_tokens: ["token1", "token2"])
      assert keyring.grant_tokens == ["token1", "token2"]
    end

    test "stores valid discovery filter" do
      {:ok, mock} = Mock.new()
      filter = %{partition: "aws", accounts: ["123456789012"]}
      {:ok, keyring} = AwsKmsDiscovery.new(mock, discovery_filter: filter)
      assert keyring.discovery_filter == filter
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKmsDiscovery.new(nil)
    end

    test "rejects non-struct client" do
      assert {:error, :invalid_client_type} = AwsKmsDiscovery.new(%{})
    end

    test "rejects discovery filter missing partition" do
      {:ok, mock} = Mock.new()
      assert {:error, :invalid_discovery_filter} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{accounts: ["123"]})
    end

    test "rejects discovery filter missing accounts" do
      {:ok, mock} = Mock.new()
      assert {:error, :invalid_discovery_filter} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws"})
    end

    test "rejects discovery filter with empty accounts" do
      {:ok, mock} = Mock.new()
      assert {:error, :discovery_filter_accounts_empty} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws", accounts: []})
    end

    test "rejects discovery filter with non-string accounts" do
      {:ok, mock} = Mock.new()
      assert {:error, :invalid_account_ids} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws", accounts: [123]})
    end
  end

  describe "wrap_key/2" do
    test "always fails - discovery keyrings cannot encrypt" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :discovery_keyring_cannot_encrypt} =
               AwsKmsDiscovery.wrap_key(keyring, materials)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`
- [x] Code compiles: `mix compile --warnings-as-errors`
- [x] Formatting: `mix format --check-formatted`

#### Manual Verification:
- [x] In IEx: `AwsKmsDiscovery.new(mock)` returns `{:ok, keyring}`
- [x] In IEx: `AwsKmsDiscovery.wrap_key(keyring, materials)` returns `{:error, :discovery_keyring_cannot_encrypt}`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for confirmation before proceeding to Phase 2.

---

## Phase 2: Basic Discovery Decryption

### Overview

Implement `unwrap_key/3` that iterates through EDKs, filters by provider ID and ARN validity, and attempts decryption using the ARN from the EDK's provider info.

### Spec Requirements Addressed

- Reject materials with existing plaintext key (ondecrypt)
- Provider ID MUST match "aws-kms" (ondecrypt)
- Provider info MUST be valid ARN with resource_type="key" (ondecrypt)
- Use ARN from provider info as KeyId for decrypt (ondecrypt)
- Response KeyId MUST equal provider info ARN (ondecrypt)
- Plaintext length MUST match algorithm suite (ondecrypt)
- Collect errors and try next EDK on failure (ondecrypt)
- Return aggregate error if all EDKs fail (ondecrypt)

### Changes Required

#### 1. Implement unwrap_key/3

**File**: `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex`

Add these aliases at the top:
```elixir
alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
alias AwsEncryptionSdk.Keyring.KmsKeyArn
alias AwsEncryptionSdk.Materials.EncryptedDataKey
```

Add provider ID constant:
```elixir
@provider_id "aws-kms"
```

Replace the placeholder `unwrap_key/3`:
```elixir
@doc """
Unwraps a data key using AWS KMS Discovery.

Iterates through EDKs, filtering by provider ID and ARN validity.
For each matching EDK, extracts the key ARN from provider info and
attempts decryption with KMS.

## Returns

- `{:ok, materials}` - Data key successfully decrypted
- `{:error, :plaintext_data_key_already_set}` - Materials already have key
- `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

## Examples

    {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, edks)

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

defp call_kms_decrypt(keyring, materials, edk) do
  client_module = keyring.kms_client.__struct__

  # Discovery keyring uses the ARN from provider info as the key_id
  # (unlike standard keyring which uses its configured key_id)
  result =
    client_module.decrypt(
      keyring.kms_client,
      edk.key_provider_info,
      edk.ciphertext,
      materials.encryption_context,
      keyring.grant_tokens
    )

  with {:ok, response} <- result,
       :ok <- verify_response_key_id(edk.key_provider_info, response.key_id) do
    {:ok, response.plaintext}
  end
end

# Discovery keyring uses exact comparison (no MRK matching)
defp verify_response_key_id(expected, actual) when expected == actual, do: :ok

defp verify_response_key_id(expected, actual) do
  {:error, {:response_key_id_mismatch, expected, actual}}
end

defp validate_decrypted_length(plaintext, expected) when byte_size(plaintext) == expected do
  :ok
end

defp validate_decrypted_length(plaintext, expected) do
  {:error, {:invalid_decrypted_length, expected: expected, actual: byte_size(plaintext)}}
end
```

#### 2. Add Decryption Tests

**File**: `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`

Add to aliases:
```elixir
alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}
```

Add test constants:
```elixir
@kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
@different_key_arn "arn:aws:kms:us-west-2:123456789012:key/different-key-id"
```

Add new describe block:
```elixir
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

    {:ok, keyring} = AwsKmsDiscovery.new(mock)
    materials = DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})
    edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

    {:ok, keyring: keyring, materials: materials, edks: [edk], plaintext_key: plaintext_key}
  end

  test "decrypts EDK using provider info as key_id", ctx do
    {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, ctx.edks)
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "fails if plaintext key already set", ctx do
    {:ok, materials_with_key} =
      DecryptionMaterials.set_plaintext_data_key(ctx.materials, ctx.plaintext_key)

    assert {:error, :plaintext_data_key_already_set} =
             AwsKmsDiscovery.unwrap_key(ctx.keyring, materials_with_key, ctx.edks)
  end

  test "filters out non-aws-kms EDKs", ctx do
    other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)
    edks = [other_edk | ctx.edks]

    {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "filters out invalid ARN in provider info", ctx do
    invalid_edk = EncryptedDataKey.new("aws-kms", "not-an-arn", <<1, 2, 3>>)
    edks = [invalid_edk | ctx.edks]

    {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "filters out non-key resource types (alias)", ctx do
    alias_arn = "arn:aws:kms:us-west-2:123456789012:alias/my-alias"
    alias_edk = EncryptedDataKey.new("aws-kms", alias_arn, <<1, 2, 3>>)
    edks = [alias_edk | ctx.edks]

    {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "collects errors when no EDK decrypts", ctx do
    other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, [other_edk])

    assert [{:provider_id_mismatch, "other-provider"}] = errors
  end

  test "returns error when no EDKs provided", ctx do
    assert {:error, {:unable_to_decrypt_any_data_key, []}} =
             AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, [])
  end

  test "verifies response key_id matches provider info exactly", ctx do
    # Mock returns different key_id (discovery keyring uses exact match, not MRK match)
    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @kms_key_arn} => %{
          plaintext: ctx.plaintext_key,
          key_id: @different_key_arn
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

    assert [{:response_key_id_mismatch, @kms_key_arn, @different_key_arn}] = errors
  end

  test "validates decrypted plaintext length", ctx do
    wrong_length_key = :crypto.strong_rand_bytes(16)

    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @kms_key_arn} => %{
          plaintext: wrong_length_key,
          key_id: @kms_key_arn
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

    assert [{:invalid_decrypted_length, expected: 32, actual: 16}] = errors
  end

  test "returns error on KMS decrypt failure", ctx do
    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @kms_key_arn} => {:error, {:kms_error, :access_denied, "Access denied"}}
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

    assert [{:kms_error, :access_denied, "Access denied"}] = errors
  end

  test "tries multiple EDKs until one succeeds" do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_key = :crypto.strong_rand_bytes(32)
    ciphertext = :crypto.strong_rand_bytes(128)

    {:ok, mock} =
      Mock.new(%{
        # First key fails
        {:decrypt, @kms_key_arn} => {:error, {:kms_error, :access_denied, "Access denied"}},
        # Second key succeeds
        {:decrypt, @different_key_arn} => %{
          plaintext: plaintext_key,
          key_id: @different_key_arn
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock)
    materials = DecryptionMaterials.new_for_decrypt(suite, %{})

    edk1 = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)
    edk2 = EncryptedDataKey.new("aws-kms", @different_key_arn, ciphertext)

    {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk1, edk2])
    assert result.plaintext_data_key == plaintext_key
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`
- [x] Code compiles: `mix compile --warnings-as-errors`
- [x] Quality check: `mix quality --quick`

#### Manual Verification:
- [x] In IEx: Discovery keyring successfully decrypts an EDK using the ARN from provider info
- [x] In IEx: Multiple EDKs are tried in order until one succeeds

**Implementation Note**: After completing this phase and all automated verification passes, pause here for confirmation before proceeding to Phase 3.

---

## Phase 3: Discovery Filter Support

### Overview

Add discovery filter logic to filter EDKs by partition and account before attempting decryption.

### Spec Requirements Addressed

- Discovery filter partition MUST match (ondecrypt)
- Discovery filter accounts MUST contain EDK account (ondecrypt)

### Changes Required

#### 1. Add Filter Logic to unwrap_key

**File**: `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex`

Update `try_decrypt_edk/3` to include filter check:
```elixir
defp try_decrypt_edk(keyring, materials, edk) do
  with :ok <- match_provider_id(edk),
       {:ok, arn} <- parse_provider_info_arn(edk),
       :ok <- validate_resource_type_is_key(arn),
       :ok <- passes_discovery_filter(keyring.discovery_filter, arn),  # NEW
       {:ok, plaintext} <- call_kms_decrypt(keyring, materials, edk),
       :ok <- validate_decrypted_length(plaintext, materials.algorithm_suite.kdf_input_length) do
    {:ok, plaintext}
  end
end
```

Add the filter functions:
```elixir
# No filter configured - all EDKs pass
defp passes_discovery_filter(nil, _arn), do: :ok

defp passes_discovery_filter(%{partition: filter_partition, accounts: filter_accounts}, arn) do
  with :ok <- match_partition(filter_partition, arn.partition),
       :ok <- match_account(filter_accounts, arn.account) do
    :ok
  end
end

defp match_partition(filter_partition, arn_partition) when filter_partition == arn_partition do
  :ok
end

defp match_partition(filter_partition, arn_partition) do
  {:error, {:partition_mismatch, expected: filter_partition, actual: arn_partition}}
end

defp match_account(filter_accounts, arn_account) do
  if arn_account in filter_accounts do
    :ok
  else
    {:error, {:account_not_in_filter, account: arn_account, allowed: filter_accounts}}
  end
end
```

#### 2. Add Filter Tests

**File**: `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`

Add new describe block:
```elixir
describe "unwrap_key/3 with discovery filter" do
  @aws_partition_key "arn:aws:kms:us-west-2:123456789012:key/abc123"
  @aws_cn_partition_key "arn:aws-cn:kms:cn-north-1:123456789012:key/abc123"
  @different_account_key "arn:aws:kms:us-west-2:999999999999:key/abc123"

  setup do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_key = :crypto.strong_rand_bytes(32)
    ciphertext = :crypto.strong_rand_bytes(128)

    {:ok,
     suite: suite,
     plaintext_key: plaintext_key,
     ciphertext: ciphertext}
  end

  test "accepts EDK matching partition filter", ctx do
    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @aws_partition_key} => %{
          plaintext: ctx.plaintext_key,
          key_id: @aws_partition_key
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock,
      discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
    )

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

    {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "rejects EDK with mismatched partition", ctx do
    {:ok, mock} = Mock.new()
    {:ok, keyring} = AwsKmsDiscovery.new(mock,
      discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
    )

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_cn_partition_key, ctx.ciphertext)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

    assert [{:partition_mismatch, expected: "aws", actual: "aws-cn"}] = errors
  end

  test "accepts EDK with account in filter list", ctx do
    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @aws_partition_key} => %{
          plaintext: ctx.plaintext_key,
          key_id: @aws_partition_key
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock,
      discovery_filter: %{partition: "aws", accounts: ["111111111111", "123456789012", "222222222222"]}
    )

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

    {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "rejects EDK with account not in filter list", ctx do
    {:ok, mock} = Mock.new()
    {:ok, keyring} = AwsKmsDiscovery.new(mock,
      discovery_filter: %{partition: "aws", accounts: ["111111111111"]}
    )

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

    assert [{:account_not_in_filter, account: "123456789012", allowed: ["111111111111"]}] = errors
  end

  test "no filter allows any partition and account", ctx do
    {:ok, mock} =
      Mock.new(%{
        {:decrypt, @aws_cn_partition_key} => %{
          plaintext: ctx.plaintext_key,
          key_id: @aws_cn_partition_key
        }
      })

    {:ok, keyring} = AwsKmsDiscovery.new(mock)  # No filter

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_cn_partition_key, ctx.ciphertext)

    {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
    assert result.plaintext_data_key == ctx.plaintext_key
  end

  test "filter is checked before KMS call", ctx do
    # Mock has no decrypt responses configured - if KMS is called, it will fail
    {:ok, mock} = Mock.new()
    {:ok, keyring} = AwsKmsDiscovery.new(mock,
      discovery_filter: %{partition: "aws-cn", accounts: ["123456789012"]}
    )

    materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

    # Should fail with partition mismatch, not a KMS error
    assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
             AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

    assert [{:partition_mismatch, expected: "aws-cn", actual: "aws"}] = errors
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`
- [x] Quality check: `mix quality --quick`

#### Manual Verification:
- [x] In IEx: Discovery filter correctly rejects EDKs with wrong partition
- [x] In IEx: Discovery filter correctly rejects EDKs with account not in list

**Implementation Note**: After completing this phase and all automated verification passes, pause here for confirmation before proceeding to Phase 4.

---

## Phase 4: CMM & Multi-Keyring Integration

### Overview

Add dispatch clauses to Default CMM and Multi-keyring to support the discovery keyring.

### Changes Required

#### 1. Update Default CMM

**File**: `lib/aws_encryption_sdk/cmm/default.ex`

Add alias:
```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
```

Add dispatch clause for decrypt (after existing AwsKms clause):
```elixir
defp decrypt_with_keyring(%AwsKmsDiscovery{} = keyring, materials, edks) do
  AwsKmsDiscovery.unwrap_key(keyring, materials, edks)
end
```

Add dispatch clause for encrypt (to provide clear error):
```elixir
defp encrypt_with_keyring(%AwsKmsDiscovery{} = keyring, materials) do
  AwsKmsDiscovery.wrap_key(keyring, materials)
end
```

#### 2. Update Multi-Keyring

**File**: `lib/aws_encryption_sdk/keyring/multi.ex`

Add alias:
```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
```

Add dispatch clause for decrypt:
```elixir
defp unwrap_with_keyring(%AwsKmsDiscovery{} = keyring, materials, edks) do
  AwsKmsDiscovery.unwrap_key(keyring, materials, edks)
end
```

Add dispatch clause for encrypt:
```elixir
defp wrap_with_keyring(%AwsKmsDiscovery{} = keyring, materials) do
  AwsKmsDiscovery.wrap_key(keyring, materials)
end
```

#### 3. Add Integration Tests

**File**: `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`

Add new describe block:
```elixir
describe "integration with Default CMM" do
  alias AwsEncryptionSdk.Cmm.Default

  test "CMM decrypt uses discovery keyring" do
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

    {:ok, keyring} = AwsKmsDiscovery.new(mock)
    cmm = Default.new(keyring)

    edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)
    request = %{algorithm_suite: suite, encryption_context: %{}, encrypted_data_keys: [edk]}

    {:ok, materials} = Default.decrypt_materials(cmm, request)
    assert materials.plaintext_data_key == plaintext_key
  end

  test "CMM encrypt fails with discovery keyring" do
    {:ok, mock} = Mock.new()
    {:ok, keyring} = AwsKmsDiscovery.new(mock)
    cmm = Default.new(keyring)

    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    request = %{algorithm_suite: suite, encryption_context: %{}}

    assert {:error, :discovery_keyring_cannot_encrypt} = Default.encryption_materials(cmm, request)
  end
end

describe "integration with Multi-keyring" do
  alias AwsEncryptionSdk.Keyring.Multi

  test "multi-keyring can use discovery keyring for decrypt" do
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

    {:ok, discovery_keyring} = AwsKmsDiscovery.new(mock)
    {:ok, multi} = Multi.new(nil, [discovery_keyring])

    materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

    {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
    assert result.plaintext_data_key == plaintext_key
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] All tests pass: `mix test`
- [x] Full quality check: `mix quality`

#### Manual Verification:
- [x] In IEx: Default CMM successfully decrypts using discovery keyring
- [x] In IEx: Multi-keyring with discovery child keyring decrypts successfully

**Implementation Note**: After completing this phase and all automated verification passes, pause here for final confirmation.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All discovery keyring tests pass

### Manual:
- [x] Create discovery keyring and successfully decrypt a message
- [x] Verify encryption fails with clear error
- [x] Test discovery filter blocks unexpected accounts
- [x] Test discovery filter blocks unexpected partitions

## Testing Strategy

### Unit Tests

Located in `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs`:

- Constructor validation (client required, filter validation)
- wrap_key always fails
- unwrap_key decryption flow
- Provider ID filtering
- ARN validation (resource_type must be "key")
- Discovery filter partition matching
- Discovery filter account matching
- Error aggregation across multiple EDKs
- Response key_id exact match verification
- Plaintext length validation

### Integration Tests

- Default CMM integration for decrypt
- Multi-keyring as child keyring
- Error propagation through CMM

### Test Vector Integration

Test vectors can be used for integration testing when AWS credentials are available:

```elixir
# Future test vector integration
@moduletag :test_vectors
@moduletag skip: not TestVectorSetup.vectors_available?()

# Test vector IDs for discovery keyring scenarios:
# - 686aae13-ec9b-4eab-9dc0-0a1794a2ba34 (single KMS key)
# - 008a5704-9930-4340-809d-1c27ff7b4868 (multiple KMS keys)
```

## References

- Issue: #49
- Research: `thoughts/shared/research/2026-01-28-GH49-aws-kms-discovery-keyring.md`
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
- Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
