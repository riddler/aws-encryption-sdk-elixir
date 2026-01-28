defmodule AwsEncryptionSdk.Keyring.AwsKmsMrk do
  @moduledoc """
  AWS KMS Multi-Region Key (MRK) aware Keyring implementation.

  This keyring enables cross-region decryption using Multi-Region Keys (MRKs).
  MRKs are KMS keys replicated across AWS regions with the same key material but
  different regional ARNs. This keyring uses MRK matching to allow decryption
  with any replica of the MRK used for encryption.

  ## MRK Matching Behavior

  When decrypting, this keyring can unwrap data keys encrypted with:
  - The exact key configured in the keyring
  - Any regional replica of the configured MRK (same key ID, different region)

  This enables cross-region disaster recovery and data access scenarios where
  data encrypted in one region can be decrypted in another region using the
  regional replica of the same MRK.

  ## Example

      {:ok, client} = KmsClient.ExAws.new(region: "us-west-2")
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123456789012:key/mrk-1234abcd",
        client
      )

      # Can decrypt data encrypted with us-east-1 replica of same MRK
      {:ok, materials} = AwsKmsMrk.unwrap_key(keyring, materials, edks)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type t :: %__MODULE__{
          kms_key_id: String.t(),
          kms_client: struct(),
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]

  @doc """
  Creates a new AWS KMS MRK Keyring.

  ## Parameters

  - `kms_key_id` - AWS KMS key identifier (ARN, alias ARN, alias name, or key ID).
    Should be an MRK identifier (mrk-*) to enable cross-region functionality.
  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `opts` - Optional keyword list:
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  Same as AwsKms.new/3 - validates key_id and client

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client
      )

      # With grant tokens
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client,
        grant_tokens: ["token1"]
      )

  """
  @spec new(String.t(), struct(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_key_id, kms_client, opts \\ []) do
    # Delegate validation to AwsKms
    with {:ok, aws_kms} <- AwsKms.new(kms_key_id, kms_client, opts) do
      {:ok, from_aws_kms(aws_kms)}
    end
  end

  @doc """
  Wraps a data key using AWS KMS.

  Delegates to AwsKms.wrap_key/2. Behavior is identical - MRK awareness
  only affects decryption.

  ## Returns

  - `{:ok, materials}` - Data key generated/encrypted and EDK added
  - `{:error, reason}` - KMS operation failed or validation error

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    keyring
    |> to_aws_kms()
    |> AwsKms.wrap_key(materials)
  end

  @doc """
  Unwraps a data key using AWS KMS with MRK matching.

  Delegates to AwsKms.unwrap_key/3, which uses MRK matching to filter EDKs.
  This enables cross-region decryption with MRK replicas.

  ## Returns

  - `{:ok, materials}` - Data key successfully decrypted
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key
  - `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    keyring
    |> to_aws_kms()
    |> AwsKms.unwrap_key(materials, edks)
  end

  # Convert AwsKmsMrk struct to AwsKms struct
  defp to_aws_kms(%__MODULE__{} = keyring) do
    %AwsKms{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Convert AwsKms struct to AwsKmsMrk struct
  defp from_aws_kms(%AwsKms{} = keyring) do
    %__MODULE__{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Behaviour callbacks - direct users to wrap_key/unwrap_key
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsMrk.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error,
     {:must_use_unwrap_key, "Call AwsKmsMrk.unwrap_key(keyring, materials, edks) instead"}}
  end
end
