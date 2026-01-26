defmodule AwsEncryptionSdk.Materials.DecryptionMaterials do
  @moduledoc """
  Materials required for decryption operations.

  These materials are typically provided by a Cryptographic Materials Manager (CMM)
  or can be constructed directly for testing purposes.
  """

  alias AwsEncryptionSdk.AlgorithmSuite

  @type t :: %__MODULE__{
          algorithm_suite: AlgorithmSuite.t(),
          encryption_context: %{String.t() => String.t()},
          plaintext_data_key: binary() | nil,
          verification_key: binary() | nil,
          required_encryption_context_keys: [String.t()]
        }

  @enforce_keys [
    :algorithm_suite,
    :encryption_context
  ]

  defstruct [
    :algorithm_suite,
    :encryption_context,
    :plaintext_data_key,
    :verification_key,
    required_encryption_context_keys: []
  ]

  @doc """
  Creates new decryption materials with a plaintext data key.

  Use this constructor when you already have a decrypted data key (e.g., for testing
  or when bypassing the keyring/CMM flow).

  ## Parameters

  - `algorithm_suite` - Algorithm suite from message header
  - `encryption_context` - Encryption context from message header
  - `plaintext_data_key` - Decrypted data key
  - `opts` - Optional fields (:verification_key, :required_encryption_context_keys)

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new(suite, %{}, key)
      iex> is_binary(materials.plaintext_data_key)
      true

  """
  @spec new(AlgorithmSuite.t(), map(), binary(), keyword()) :: t()
  def new(algorithm_suite, encryption_context, plaintext_data_key, opts \\ []) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      plaintext_data_key: plaintext_data_key,
      verification_key: Keyword.get(opts, :verification_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end

  @doc """
  Creates decryption materials for keyring/CMM use (without plaintext data key).

  The keyring will set the plaintext_data_key during on_decrypt.

  ## Parameters

  - `algorithm_suite` - Algorithm suite from message header
  - `encryption_context` - Encryption context from message header
  - `opts` - Optional fields (:verification_key, :required_encryption_context_keys)

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new_for_decrypt(suite, %{})
      iex> materials.plaintext_data_key
      nil

  """
  @spec new_for_decrypt(AlgorithmSuite.t(), map(), keyword()) :: t()
  def new_for_decrypt(algorithm_suite, encryption_context, opts \\ []) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      plaintext_data_key: nil,
      verification_key: Keyword.get(opts, :verification_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end

  @doc """
  Sets the plaintext data key on decryption materials.

  Used by keyrings after successfully decrypting an EDK.

  ## Returns

  - `{:ok, updated_materials}` - Data key was set
  - `{:error, :plaintext_data_key_already_set}` - Data key was already present

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new_for_decrypt(suite, %{})
      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, updated} = AwsEncryptionSdk.Materials.DecryptionMaterials.set_plaintext_data_key(materials, key)
      iex> updated.plaintext_data_key == key
      true

  """
  @spec set_plaintext_data_key(t(), binary()) ::
          {:ok, t()} | {:error, :plaintext_data_key_already_set}
  def set_plaintext_data_key(%__MODULE__{plaintext_data_key: nil} = materials, key)
      when is_binary(key) do
    {:ok, %{materials | plaintext_data_key: key}}
  end

  def set_plaintext_data_key(%__MODULE__{plaintext_data_key: _existing}, _key) do
    {:error, :plaintext_data_key_already_set}
  end
end
