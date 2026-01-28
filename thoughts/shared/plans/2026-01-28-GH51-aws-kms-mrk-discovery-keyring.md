# AWS KMS MRK Discovery Keyring Implementation Plan

## Overview

Implement the AWS KMS Multi-Region Key (MRK) Discovery Keyring - a decrypt-only keyring that combines discovery keyring behavior with MRK awareness. Unlike the basic discovery keyring that uses exact ARN matching, the MRK Discovery Keyring reconstructs ARNs with the configured region for MRK keys, enabling cross-region decryption, while filtering out non-MRK keys from different regions.

**Issue**: #51
**Research**: `thoughts/shared/research/2026-01-28-GH51-aws-kms-mrk-discovery-keyring.md`

## Specification Requirements

### Source Documents
- [aws-kms-mrk-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md) - Primary specification
- [aws-kms-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md) - Base discovery behavior
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Accept KMS client, region string, optional discovery filter, optional grant tokens | Constructor | MUST |
| KMS client MUST NOT be null | Constructor | MUST |
| Region MUST NOT be null or empty | Constructor | MUST |
| Discovery filter validation (both partition and accounts required) | Constructor | MUST |
| OnEncrypt MUST fail | OnEncrypt | MUST |
| Early return if materials already have plaintext data key | OnDecrypt | MUST |
| Filter EDKs by provider ID = "aws-kms" | OnDecrypt | MUST |
| Filter EDKs by valid ARN with resource type "key" | OnDecrypt | MUST |
| Apply discovery filter (partition/account matching) | OnDecrypt | MUST |
| **For MRK: Reconstruct ARN with configured region** | OnDecrypt | MUST |
| **For non-MRK: Filter out if region doesn't match** | OnDecrypt | MUST |
| Validate response KeyId matches request KeyId | OnDecrypt | MUST |
| Validate plaintext length matches algorithm suite | OnDecrypt | MUST |
| Collect errors and continue to next EDK on failure | OnDecrypt | MUST |
| Region should match KMS client region | Constructor | SHOULD |

## Test Vectors

### Validation Strategy
Unit tests with mock KMS client for MRK-specific scenarios. The test vectors for MRK discovery keyrings require cross-region KMS access which is validated through mocked scenarios.

### Test Scenarios Summary

| Phase | Scenario | Purpose |
|-------|----------|---------|
| 1 | Constructor validation | Region required, client required, filter validation |
| 2 | Basic MRK same region | MRK decrypt without region reconstruction |
| 3 | Cross-region MRK | **Core value** - reconstruct ARN with configured region |
| 4 | Non-MRK filtering | Filter out non-MRK keys from different regions |
| 5 | Discovery filter + MRK | Filter applied before MRK reconstruction |

## Current State Analysis

### Key Discoveries:

1. **`AwsKmsDiscovery` (`lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex`)** provides the base pattern:
   - Struct: `kms_client`, `discovery_filter`, `grant_tokens`
   - `wrap_key/2` returns `{:error, :discovery_keyring_cannot_encrypt}`
   - `unwrap_key/3` filters EDKs, calls KMS, validates response
   - Uses **exact** KeyId comparison at line 228

2. **`KmsKeyArn` (`lib/aws_encryption_sdk/keyring/kms_key_arn.ex`)** has all MRK utilities:
   - `mrk?/1` - checks if identifier is MRK (mrk- prefix)
   - `to_string/1` - reconstructs ARN from struct
   - Struct update `%{arn | region: region}` supported

3. **CMM dispatch** (`lib/aws_encryption_sdk/cmm/default.ex:37`) needs alias and clauses added
4. **Multi-keyring dispatch** (`lib/aws_encryption_sdk/keyring/multi.ex:55`) needs alias and clauses added

## Desired End State

After implementation:

1. `AwsKmsMrkDiscovery` module exists at `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex`
2. Keyring can decrypt EDKs encrypted with MRKs from any region
3. Keyring filters out non-MRK EDKs from different regions
4. CMM and Multi-keyring dispatch support the new keyring type
5. All tests pass: `mix quality`

**Verification Command**: `mix test test/aws_encryption_sdk/keyring/aws_kms_mrk_discovery_test.exs`

## What We're NOT Doing

- AWS KMS MRK Discovery Multi-Keyring (convenience constructor) - separate issue
- Real KMS integration tests (requires AWS credentials)
- Streaming decryption support
- Region validation against client (SHOULD requirement - defer to later)

## Implementation Approach

Copy `AwsKmsDiscovery` as the base and modify for MRK awareness:

1. Add `region` field (required) to struct
2. Add region validation in constructor
3. Add `determine_decrypt_key_id/2` for MRK ARN reconstruction
4. Modify `call_kms_decrypt/3` to use determined key ID
5. Keep response validation as exact match (using reconstructed ARN)

---

## Phase 1: Core Module Structure

### Overview
Create the `AwsKmsMrkDiscovery` module with struct, constructor, and `wrap_key/2` (encryption prohibition).

### Spec Requirements Addressed
- KMS client MUST NOT be null
- Region MUST NOT be null or empty
- Discovery filter validation
- OnEncrypt MUST fail

### Changes Required:

#### 1. Create MRK Discovery Keyring Module
**File**: `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex`
**Changes**: Create new file based on AwsKmsDiscovery pattern

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery do
  @moduledoc """
  AWS KMS MRK Discovery Keyring implementation.

  A decrypt-only keyring that combines discovery keyring behavior with MRK awareness.
  For MRK keys, it reconstructs the ARN with the configured region, enabling
  cross-region decryption. For non-MRK keys, it filters out EDKs where the
  region doesn't match.

  ## Example

      {:ok, client} = KmsClient.ExAws.new(region: "us-west-2")
      {:ok, keyring} = AwsKmsMrkDiscovery.new(client, "us-west-2")

      # Can decrypt MRK-encrypted data from ANY region
      {:ok, materials} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type discovery_filter :: %{
          partition: String.t(),
          accounts: [String.t(), ...]
        }

  @type t :: %__MODULE__{
          kms_client: struct(),
          region: String.t(),
          discovery_filter: discovery_filter() | nil,
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_client, :region]
  defstruct [:kms_client, :region, :discovery_filter, grant_tokens: []]

  @provider_id "aws-kms"

  @doc """
  Creates a new AWS KMS MRK Discovery Keyring.

  ## Parameters

  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `region` - AWS region string for this keyring (e.g., "us-west-2")
  - `opts` - Optional keyword list:
    - `:discovery_filter` - Map with `:partition` (string) and `:accounts` (list of strings)
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure
  """
  @spec new(struct(), String.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_client, region, opts \\ []) do
    with :ok <- validate_client(kms_client),
         :ok <- validate_region(region),
         :ok <- validate_discovery_filter(opts[:discovery_filter]) do
      {:ok,
       %__MODULE__{
         kms_client: kms_client,
         region: region,
         discovery_filter: opts[:discovery_filter],
         grant_tokens: Keyword.get(opts, :grant_tokens, [])
       }}
    end
  end

  defp validate_client(nil), do: {:error, :client_required}
  defp validate_client(%{__struct__: _module}), do: :ok
  defp validate_client(_invalid), do: {:error, :invalid_client_type}

  defp validate_region(nil), do: {:error, :region_required}
  defp validate_region(""), do: {:error, :region_empty}
  defp validate_region(region) when is_binary(region), do: :ok
  defp validate_region(_invalid), do: {:error, :invalid_region_type}

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

  defp validate_discovery_filter(_invalid), do: {:error, :invalid_discovery_filter}

  @doc """
  MRK Discovery keyrings cannot encrypt - this always fails.
  """
  @spec wrap_key(t(), EncryptionMaterials.t()) :: {:error, :discovery_keyring_cannot_encrypt}
  def wrap_key(%__MODULE__{}, %EncryptionMaterials{}) do
    {:error, :discovery_keyring_cannot_encrypt}
  end

  # Placeholder for Phase 2
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{}, %DecryptionMaterials{}, _edks) do
    {:error, :not_implemented}
  end

  # Behaviour callbacks
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsMrkDiscovery.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error,
     {:must_use_unwrap_key, "Call AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks) instead"}}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Module compiles: `mix compile`
- [x] Constructor tests pass for valid inputs
- [x] Constructor rejects nil client, nil/empty region, invalid filter

#### Manual Verification:
- [ ] IEx: `{:ok, keyring} = AwsKmsMrkDiscovery.new(mock_client, "us-west-2")` works
- [ ] IEx: `AwsKmsMrkDiscovery.wrap_key(keyring, materials)` returns `{:error, :discovery_keyring_cannot_encrypt}`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation.

---

## Phase 2: OnDecrypt - MRK Region Handling

### Overview
Implement the core `unwrap_key/3` function with MRK-aware region handling - the key differentiator from the base discovery keyring.

### Spec Requirements Addressed
- Early return if materials already have plaintext data key
- Filter EDKs by provider ID = "aws-kms"
- Filter EDKs by valid ARN with resource type "key"
- **For MRK: Reconstruct ARN with configured region**
- **For non-MRK: Filter out if region doesn't match**
- Validate response KeyId matches request KeyId
- Validate plaintext length

### Changes Required:

#### 1. Implement unwrap_key and MRK handling
**File**: `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex`
**Changes**: Replace placeholder `unwrap_key/3` with full implementation

```elixir
  @doc """
  Unwraps a data key using AWS KMS MRK Discovery.

  For MRK EDKs, reconstructs the ARN with the keyring's configured region
  before calling KMS Decrypt, enabling cross-region decryption.

  For non-MRK EDKs, filters out any where the region doesn't match.
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
         :ok <- passes_discovery_filter(keyring.discovery_filter, arn),
         {:ok, decrypt_key_id} <- determine_decrypt_key_id(arn, keyring.region),
         {:ok, plaintext} <- call_kms_decrypt(keyring, materials, edk, decrypt_key_id),
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
  defp validate_resource_type_is_key(%{resource_type: type}), do: {:error, {:invalid_resource_type, type}}

  # Discovery filter matching (reused from base discovery)
  defp passes_discovery_filter(nil, _arn), do: :ok

  defp passes_discovery_filter(%{partition: filter_partition, accounts: filter_accounts}, arn) do
    with :ok <- match_partition(filter_partition, arn.partition) do
      match_account(filter_accounts, arn.account)
    end
  end

  defp match_partition(filter_partition, arn_partition) when filter_partition == arn_partition, do: :ok
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

  # KEY DIFFERENTIATOR: MRK-aware region handling
  defp determine_decrypt_key_id(arn, region) do
    if KmsKeyArn.mrk?(arn) do
      # MRK: Reconstruct ARN with configured region
      reconstructed = %{arn | region: region}
      {:ok, KmsKeyArn.to_string(reconstructed)}
    else
      # Non-MRK: Must be in same region
      if arn.region == region do
        {:ok, KmsKeyArn.to_string(arn)}
      else
        {:error, {:non_mrk_region_mismatch, expected: region, actual: arn.region}}
      end
    end
  end

  defp call_kms_decrypt(keyring, materials, edk, decrypt_key_id) do
    client_module = keyring.kms_client.__struct__

    result =
      client_module.decrypt(
        keyring.kms_client,
        decrypt_key_id,
        edk.ciphertext,
        materials.encryption_context,
        keyring.grant_tokens
      )

    with {:ok, response} <- result,
         :ok <- verify_response_key_id(decrypt_key_id, response.key_id) do
      {:ok, response.plaintext}
    end
  end

  # MRK Discovery uses exact comparison (we already reconstructed the ARN)
  defp verify_response_key_id(expected, actual) when expected == actual, do: :ok
  defp verify_response_key_id(expected, actual) do
    {:error, {:response_key_id_mismatch, expected, actual}}
  end

  defp validate_decrypted_length(plaintext, expected) when byte_size(plaintext) == expected, do: :ok
  defp validate_decrypted_length(plaintext, expected) do
    {:error, {:invalid_decrypted_length, expected: expected, actual: byte_size(plaintext)}}
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/aws_kms_mrk_discovery_test.exs`
- [x] MRK cross-region decryption works
- [x] Non-MRK different-region EDKs are filtered out
- [x] Non-MRK same-region EDKs work

#### Manual Verification:
- [ ] IEx test: Create keyring in us-west-2, decrypt EDK from us-east-1 MRK

**Implementation Note**: After completing this phase, pause for manual confirmation.

---

## Phase 3: CMM and Multi-Keyring Integration

### Overview
Add dispatch clauses so `AwsKmsMrkDiscovery` works with Default CMM and Multi-keyring.

### Changes Required:

#### 1. Update CMM Dispatch
**File**: `lib/aws_encryption_sdk/cmm/default.ex`
**Changes**: Add alias and dispatch clauses

Add to alias line (line 37):
```elixir
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, AwsKmsMrkDiscovery, Multi, RawAes, RawRsa}
```

Add to @type keyring union (after line 46):
```elixir
| AwsKmsMrkDiscovery.t()
```

Add dispatch clause (after line 102):
```elixir
def call_wrap_key(%AwsKmsMrkDiscovery{} = keyring, materials) do
  AwsKmsMrkDiscovery.wrap_key(keyring, materials)
end
```

Add dispatch clause (after line 133):
```elixir
def call_unwrap_key(%AwsKmsMrkDiscovery{} = keyring, materials, edks) do
  AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)
end
```

#### 2. Update Multi-Keyring Dispatch
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add alias and dispatch clauses

Add to alias line (line 55):
```elixir
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, AwsKmsMrkDiscovery, RawAes, RawRsa}
```

Add dispatch clause (after line 229):
```elixir
defp call_wrap_key(%AwsKmsMrkDiscovery{} = keyring, materials) do
  AwsKmsMrkDiscovery.wrap_key(keyring, materials)
end
```

Add dispatch clause (after line 309):
```elixir
defp call_unwrap_key(%AwsKmsMrkDiscovery{} = keyring, materials, edks) do
  AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] CMM integration tests pass
- [x] Multi-keyring integration tests pass

#### Manual Verification:
- [ ] IEx: CMM can use MRK Discovery keyring for decrypt
- [ ] IEx: Multi-keyring can include MRK Discovery keyring

**Implementation Note**: After completing this phase, pause for manual confirmation.

---

## Phase 4: Comprehensive Unit Tests

### Overview
Create complete test file covering all scenarios.

### Changes Required:

#### 1. Create Test File
**File**: `test/aws_encryption_sdk/keyring/aws_kms_mrk_discovery_test.exs`
**Changes**: Create comprehensive tests

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkDiscoveryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Default, as: DefaultCmm
  alias AwsEncryptionSdk.Keyring.{AwsKmsMrkDiscovery, Multi}
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"
  @mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"
  @non_mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @non_mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

  describe "new/3" do
    test "creates keyring with valid inputs" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      assert keyring.kms_client == mock
      assert keyring.region == "us-west-2"
      assert keyring.discovery_filter == nil
      assert keyring.grant_tokens == []
    end

    test "stores discovery filter and grant tokens" do
      {:ok, mock} = Mock.new()
      filter = %{partition: "aws", accounts: ["123456789012"]}
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2",
        discovery_filter: filter,
        grant_tokens: ["token1"]
      )
      assert keyring.discovery_filter == filter
      assert keyring.grant_tokens == ["token1"]
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKmsMrkDiscovery.new(nil, "us-west-2")
    end

    test "rejects nil region" do
      {:ok, mock} = Mock.new()
      assert {:error, :region_required} = AwsKmsMrkDiscovery.new(mock, nil)
    end

    test "rejects empty region" do
      {:ok, mock} = Mock.new()
      assert {:error, :region_empty} = AwsKmsMrkDiscovery.new(mock, "")
    end

    test "rejects invalid discovery filter" do
      {:ok, mock} = Mock.new()
      assert {:error, :invalid_discovery_filter} =
        AwsKmsMrkDiscovery.new(mock, "us-west-2", discovery_filter: %{partition: "aws"})
    end
  end

  describe "wrap_key/2" do
    test "always fails - discovery keyrings cannot encrypt" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :discovery_keyring_cannot_encrypt} =
        AwsKmsMrkDiscovery.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3 - MRK same region" do
    test "decrypts MRK EDK when regions match" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new(%{
        {:decrypt, @mrk_us_west} => %{
          plaintext: plaintext_key,
          key_id: @mrk_us_west
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "unwrap_key/3 - MRK cross-region (KEY VALUE PROPOSITION)" do
    test "decrypts us-east-1 MRK EDK with us-west-2 keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      # KMS in us-west-2 receives decrypt call with reconstructed ARN
      reconstructed_arn = "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} = Mock.new(%{
        {:decrypt, reconstructed_arn} => %{
          plaintext: plaintext_key,
          key_id: reconstructed_arn
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      # EDK from us-east-1 (different region!)
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "decrypts us-west-2 MRK EDK with us-east-1 keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} = Mock.new(%{
        {:decrypt, reconstructed_arn} => %{
          plaintext: plaintext_key,
          key_id: reconstructed_arn
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-east-1")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "unwrap_key/3 - non-MRK region filtering" do
    test "decrypts non-MRK EDK when region matches" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new(%{
        {:decrypt, @non_mrk_us_west} => %{
          plaintext: plaintext_key,
          key_id: @non_mrk_us_west
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @non_mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "filters out non-MRK EDK from different region" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      # EDK from us-east-1 non-MRK
      edk = EncryptedDataKey.new("aws-kms", @non_mrk_us_east, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
        AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:non_mrk_region_mismatch, expected: "us-west-2", actual: "us-east-1"}] = errors
    end
  end

  describe "unwrap_key/3 - discovery filter with MRK" do
    test "applies filter before MRK reconstruction" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2",
        discovery_filter: %{partition: "aws", accounts: ["999999999999"]}
      )

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
        AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:account_not_in_filter, account: "123456789012", allowed: ["999999999999"]}] = errors
    end

    test "MRK cross-region works with matching filter" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn = "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} = Mock.new(%{
        {:decrypt, reconstructed_arn} => %{
          plaintext: plaintext_key,
          key_id: reconstructed_arn
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2",
        discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
      )

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "integration with Default CMM" do
    test "CMM decrypt uses MRK discovery keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new(%{
        {:decrypt, @mrk_us_west} => %{
          plaintext: plaintext_key,
          key_id: @mrk_us_west
        }
      })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      cmm = DefaultCmm.new(keyring)

      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      request = %{
        algorithm_suite: suite,
        encryption_context: %{},
        encrypted_data_keys: [edk],
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = DefaultCmm.get_decryption_materials(cmm, request)
      assert materials.plaintext_data_key == plaintext_key
    end

    test "CMM encrypt fails with MRK discovery keyring" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      cmm = DefaultCmm.new(keyring)

      request = %{encryption_context: %{}, commitment_policy: :require_encrypt_require_decrypt}

      assert {:error, :discovery_keyring_cannot_encrypt} =
        DefaultCmm.get_encryption_materials(cmm, request)
    end
  end

  describe "integration with Multi-keyring" do
    test "multi-keyring can use MRK discovery keyring for decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn = "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} = Mock.new(%{
        {:decrypt, reconstructed_arn} => %{
          plaintext: plaintext_key,
          key_id: reconstructed_arn
        }
      })

      {:ok, discovery_keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      {:ok, multi} = Multi.new(children: [discovery_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] All tests pass: `mix quality`
- [x] No compiler warnings

#### Manual Verification:
- [ ] Review test coverage visually

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] Specific tests: `mix test test/aws_encryption_sdk/keyring/aws_kms_mrk_discovery_test.exs`

### Manual:
- [ ] IEx: Create MRK Discovery keyring with us-west-2 region
- [ ] IEx: Verify cross-region decryption works (EDK from us-east-1, decrypt with us-west-2 keyring)
- [ ] IEx: Verify non-MRK different-region EDK is filtered out

## Testing Strategy

### Unit Tests:
- Constructor validation (client, region, discovery filter)
- Encryption prohibition
- MRK same-region decryption
- **MRK cross-region decryption (key value proposition)**
- Non-MRK same-region decryption
- Non-MRK different-region filtering
- Discovery filter application
- Error collection and reporting

### Manual Testing Steps:
1. Start IEx with `iex -S mix`
2. Create mock KMS client
3. Create MRK Discovery keyring
4. Test cross-region MRK decryption
5. Test non-MRK filtering

## References

- Issue: #51
- Research: `thoughts/shared/research/2026-01-28-GH51-aws-kms-mrk-discovery-keyring.md`
- Spec - MRK Discovery Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md
- Spec - Discovery Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
