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

  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @provider_id "aws-kms"

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
  defp validate_key_id(_invalid_key_id), do: {:error, :invalid_key_id_type}

  defp validate_client(nil), do: {:error, :client_required}
  defp validate_client(%{__struct__: _struct_name}), do: :ok
  defp validate_client(_invalid_client), do: {:error, :invalid_client_type}

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

  defp validate_plaintext_length(plaintext, expected) when byte_size(plaintext) == expected,
    do: :ok

  defp validate_plaintext_length(plaintext, expected) do
    {:error, {:invalid_plaintext_length, expected: expected, actual: byte_size(plaintext)}}
  end

  defp validate_key_id_is_arn(key_id) do
    case KmsKeyArn.parse(key_id) do
      {:ok, _arn} -> :ok
      {:error, reason} -> {:error, {:invalid_response_key_id, reason}}
    end
  end

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
