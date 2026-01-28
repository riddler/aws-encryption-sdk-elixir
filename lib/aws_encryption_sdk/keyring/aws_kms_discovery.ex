defmodule AwsEncryptionSdk.Keyring.AwsKmsDiscovery do
  @moduledoc """
  AWS KMS Discovery Keyring implementation.

  A decrypt-only keyring that can decrypt data encrypted with ANY KMS key
  the caller has access to. Unlike the standard `AwsKms` keyring, this keyring
  does not require knowing the key ARN in advance.

  ## Use Cases

  - **Decryption services**: Services that decrypt data from multiple sources
  - **Migration**: Decrypt data while transitioning between KMS keys
  - **Flexible decryption**: When the encrypting key is not known at decrypt time

  ## Security Warning

  Discovery keyrings will attempt to decrypt using ANY KMS key ARN found in
  the encrypted data keys. Use a discovery filter to restrict which keys
  can be used:

  ```elixir
  {:ok, keyring} = AwsKmsDiscovery.new(client,
    discovery_filter: %{
      partition: "aws",
      accounts: ["123456789012"]  # Only allow keys from this account
    }
  )
  ```

  ## Operations

  ### Encryption

  Discovery keyrings **cannot encrypt**. `wrap_key/2` always returns
  `{:error, :discovery_keyring_cannot_encrypt}`.

  For encryption, use:
  - `AwsKms` keyring if you know the key ARN
  - `Multi` keyring with an `AwsKms` generator for encryption + discovery for decryption

  ### Decryption (unwrap_key)

  1. Filters EDKs by provider ID "aws-kms"
  2. Validates each EDK's key ARN format
  3. Applies discovery filter (if configured)
  4. Attempts KMS Decrypt using the ARN from each EDK
  5. Returns on first successful decryption

  ## Discovery Filter

  Restrict which KMS keys can be used for decryption:

  | Field | Description | Required |
  |-------|-------------|----------|
  | `partition` | AWS partition ("aws", "aws-cn", "aws-us-gov") | Yes |
  | `accounts` | List of allowed AWS account IDs | Yes |

  ## IAM Permissions Required

  The principal needs `kms:Decrypt` on ALL keys that might be encountered:

  ```json
  {
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": [
      "arn:aws:kms:*:123456789012:key/*",
      "arn:aws:kms:*:987654321098:key/*"
    ]
  }
  ```

  Or use a condition to limit to specific accounts:

  ```json
  {
    "Effect": "Allow",
    "Action": "kms:Decrypt",
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "kms:CallerAccount": ["123456789012", "987654321098"]
      }
    }
  }
  ```

  ## Examples

  ### Basic Discovery Decryption

  ```elixir
  alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
  alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Client

  # Create discovery keyring
  {:ok, kms_client} = ExAws.new(region: "us-west-2")
  {:ok, keyring} = AwsKmsDiscovery.new(kms_client)

  # Create client
  cmm = Default.new(keyring)
  client = Client.new(cmm)

  # Decrypt data (encrypted with any accessible KMS key)
  {:ok, {plaintext, context}} = Client.decrypt(client, ciphertext)
  ```

  ### With Discovery Filter (Recommended)

  ```elixir
  {:ok, keyring} = AwsKmsDiscovery.new(kms_client,
    discovery_filter: %{
      partition: "aws",
      accounts: ["123456789012", "987654321098"]
    }
  )
  ```

  ### Encrypt with KMS, Decrypt with Discovery

  ```elixir
  alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, Multi}

  # Encryption keyring - knows the key
  {:ok, encrypt_keyring} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", kms_client)

  # Decryption keyring - discovery mode
  {:ok, decrypt_keyring} = AwsKmsDiscovery.new(kms_client,
    discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
  )

  # Use different clients for encrypt vs decrypt
  encrypt_client = Client.new(Default.new(encrypt_keyring))
  decrypt_client = Client.new(Default.new(decrypt_keyring))
  ```

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
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
          discovery_filter: discovery_filter() | nil,
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_client]
  defstruct [:kms_client, :discovery_filter, grant_tokens: []]

  @provider_id "aws-kms"

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
  defp validate_client(%{__struct__: _module}), do: :ok
  defp validate_client(_invalid), do: {:error, :invalid_client_type}

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
         :ok <- passes_discovery_filter(keyring.discovery_filter, arn),
         {:ok, plaintext} <- call_kms_decrypt(keyring, materials, edk),
         :ok <-
           validate_decrypted_length(plaintext, materials.algorithm_suite.kdf_input_length) do
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

  # No filter configured - all EDKs pass
  defp passes_discovery_filter(nil, _arn), do: :ok

  defp passes_discovery_filter(%{partition: filter_partition, accounts: filter_accounts}, arn) do
    with :ok <- match_partition(filter_partition, arn.partition) do
      match_account(filter_accounts, arn.account)
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

  # Behaviour callbacks - direct to wrap_key/unwrap_key
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsDiscovery.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error,
     {:must_use_unwrap_key, "Call AwsKmsDiscovery.unwrap_key(keyring, materials, edks) instead"}}
  end
end
