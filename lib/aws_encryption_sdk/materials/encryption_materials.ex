defmodule AwsEncryptionSdk.Materials.EncryptionMaterials do
  @moduledoc """
  Materials required for encryption operations.

  These materials are typically provided by a Cryptographic Materials Manager (CMM)
  or can be constructed directly for testing purposes.
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  @type t :: %__MODULE__{
          algorithm_suite: AlgorithmSuite.t(),
          encryption_context: %{String.t() => String.t()},
          encrypted_data_keys: [EncryptedDataKey.t()],
          plaintext_data_key: binary() | nil,
          signing_key: binary() | nil,
          required_encryption_context_keys: [String.t()]
        }

  @enforce_keys [
    :algorithm_suite,
    :encryption_context
  ]

  defstruct [
    :algorithm_suite,
    :encryption_context,
    encrypted_data_keys: [],
    plaintext_data_key: nil,
    signing_key: nil,
    required_encryption_context_keys: []
  ]

  @doc """
  Creates new encryption materials with plaintext data key and encrypted data keys.

  Use this constructor when you already have a data key and EDKs (e.g., for testing
  or when bypassing the keyring/CMM flow).

  ## Parameters

  - `algorithm_suite` - Algorithm suite to use
  - `encryption_context` - Encryption context map
  - `encrypted_data_keys` - List of encrypted data keys
  - `plaintext_data_key` - Raw data key bytes
  - `opts` - Optional fields (:signing_key, :required_encryption_context_keys)

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new(suite, %{}, [edk], key)
      iex> is_binary(materials.plaintext_data_key)
      true

  """
  @spec new(AlgorithmSuite.t(), map(), [EncryptedDataKey.t()], binary(), keyword()) :: t()
  def new(
        algorithm_suite,
        encryption_context,
        encrypted_data_keys,
        plaintext_data_key,
        opts \\ []
      ) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      encrypted_data_keys: encrypted_data_keys,
      plaintext_data_key: plaintext_data_key,
      signing_key: Keyword.get(opts, :signing_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end

  @doc """
  Creates encryption materials for keyring/CMM use (without plaintext data key).

  The keyring will generate and set the plaintext_data_key during on_encrypt.

  ## Parameters

  - `algorithm_suite` - Algorithm suite to use
  - `encryption_context` - Encryption context map
  - `opts` - Optional fields (:signing_key, :required_encryption_context_keys)

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> materials.plaintext_data_key
      nil

  """
  @spec new_for_encrypt(AlgorithmSuite.t(), map(), keyword()) :: t()
  def new_for_encrypt(algorithm_suite, encryption_context, opts \\ []) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      encrypted_data_keys: [],
      plaintext_data_key: nil,
      signing_key: Keyword.get(opts, :signing_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end

  @doc """
  Sets the plaintext data key on encryption materials.

  Used by keyrings after generating a data key.

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> key = :crypto.strong_rand_bytes(32)
      iex> updated = AwsEncryptionSdk.Materials.EncryptionMaterials.set_plaintext_data_key(materials, key)
      iex> updated.plaintext_data_key == key
      true

  """
  @spec set_plaintext_data_key(t(), binary()) :: t()
  def set_plaintext_data_key(%__MODULE__{} = materials, key) when is_binary(key) do
    %{materials | plaintext_data_key: key}
  end

  @doc """
  Adds an encrypted data key to the materials.

  Used by keyrings after encrypting the data key.

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      iex> updated = AwsEncryptionSdk.Materials.EncryptionMaterials.add_encrypted_data_key(materials, edk)
      iex> length(updated.encrypted_data_keys)
      1

  """
  @spec add_encrypted_data_key(t(), EncryptedDataKey.t()) :: t()
  def add_encrypted_data_key(%__MODULE__{} = materials, %EncryptedDataKey{} = edk) do
    %{materials | encrypted_data_keys: materials.encrypted_data_keys ++ [edk]}
  end
end
