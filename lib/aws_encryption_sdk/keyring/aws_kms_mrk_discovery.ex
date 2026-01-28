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

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKmsMrkDiscovery.new(client, "us-west-2")

      # With discovery filter
      {:ok, keyring} = AwsKmsMrkDiscovery.new(client, "us-west-2",
        discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
      )

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

  ## Returns

  Always returns `{:error, :discovery_keyring_cannot_encrypt}`
  """
  @spec wrap_key(t(), EncryptionMaterials.t()) :: {:error, :discovery_keyring_cannot_encrypt}
  def wrap_key(%__MODULE__{}, %EncryptionMaterials{}) do
    {:error, :discovery_keyring_cannot_encrypt}
  end

  @doc """
  Unwraps a data key using AWS KMS MRK Discovery.

  For MRK EDKs, reconstructs the ARN with the keyring's configured region
  before calling KMS Decrypt, enabling cross-region decryption.

  For non-MRK EDKs, filters out any where the region doesn't match.

  ## Returns

  - `{:ok, materials}` - Data key successfully decrypted
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key
  - `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

  ## Examples

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)

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

  defp validate_resource_type_is_key(%{resource_type: type}),
    do: {:error, {:invalid_resource_type, type}}

  # Discovery filter matching (reused from base discovery)
  defp passes_discovery_filter(nil, _arn), do: :ok

  defp passes_discovery_filter(%{partition: filter_partition, accounts: filter_accounts}, arn) do
    with :ok <- match_partition(filter_partition, arn.partition) do
      match_account(filter_accounts, arn.account)
    end
  end

  defp match_partition(filter_partition, arn_partition) when filter_partition == arn_partition,
    do: :ok

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

  defp validate_decrypted_length(plaintext, expected) when byte_size(plaintext) == expected,
    do: :ok

  defp validate_decrypted_length(plaintext, expected) do
    {:error, {:invalid_decrypted_length, expected: expected, actual: byte_size(plaintext)}}
  end

  # Behaviour callbacks
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsMrkDiscovery.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error,
     {:must_use_unwrap_key,
      "Call AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks) instead"}}
  end
end
