defmodule AwsEncryptionSdk.Keyring.Behaviour do
  @moduledoc """
  Behaviour for keyring implementations.

  Keyrings are responsible for generating, encrypting, and decrypting data keys.
  All keyring implementations must implement this behaviour.

  For help choosing a keyring, see the [Choosing Components](choosing-components.html) guide.

  ## Callbacks

  - `on_encrypt/1` - Generate and/or encrypt data keys during encryption
  - `on_decrypt/2` - Decrypt data keys during decryption

  ## OnEncrypt Behavior

  The `on_encrypt/1` callback receives encryption materials and MUST perform at least
  one of the following behaviors:

  1. **Generate Data Key**: If `materials.plaintext_data_key` is `nil`, generate a
     cryptographically random data key of the appropriate length for the algorithm suite.

  2. **Encrypt Data Key**: If `materials.plaintext_data_key` is set, encrypt it and
     add the resulting encrypted data key to the materials.

  A keyring MAY perform both behaviors (generate then encrypt).

  ## OnDecrypt Behavior

  The `on_decrypt/2` callback receives decryption materials (without a plaintext data key)
  and a list of encrypted data keys. It MUST:

  1. Fail immediately if `materials.plaintext_data_key` is already set
  2. Attempt to decrypt one of the provided EDKs
  3. On success, return materials with `plaintext_data_key` set
  4. On failure, return an error without modifying the materials

  ## Key Provider Constraints

  - Key provider IDs MUST be UTF-8 encoded binary strings
  - Key provider IDs MUST NOT start with "aws-kms" unless the keyring is an AWS KMS keyring
  - Key provider info SHOULD be UTF-8 encoded binary strings

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
  """

  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @doc """
  OnEncrypt operation.

  Takes encryption materials and returns modified encryption materials.
  MUST perform at least one of: Generate Data Key or Encrypt Data Key.

  ## Behaviors

  1. If `materials.plaintext_data_key` is nil, MUST generate a data key
  2. If `materials.plaintext_data_key` is set, MUST encrypt it and add EDK
  3. After generating, MAY also encrypt the generated key

  ## Returns

  - `{:ok, %EncryptionMaterials{}}` - Successfully modified materials
  - `{:error, term()}` - Failed to perform any behavior
  """
  @callback on_encrypt(materials :: EncryptionMaterials.t()) ::
              {:ok, EncryptionMaterials.t()} | {:error, term()}

  @doc """
  OnDecrypt operation.

  Takes decryption materials and list of encrypted data keys.
  Returns modified decryption materials with plaintext data key set.

  ## Preconditions

  - MUST fail if `materials.plaintext_data_key` is already set

  ## Behaviors

  1. Attempt to decrypt one of the provided EDKs that this keyring can handle
  2. On success, set the plaintext_data_key on materials
  3. On failure, return error without modifying materials

  ## Returns

  - `{:ok, %DecryptionMaterials{}}` - Successfully decrypted a data key
  - `{:error, term()}` - Unable to decrypt any data key
  """
  @callback on_decrypt(
              materials :: DecryptionMaterials.t(),
              encrypted_data_keys :: [EncryptedDataKey.t()]
            ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}

  @doc """
  Validates that a key provider ID is valid for non-KMS keyrings.

  Per the spec, key provider IDs MUST NOT start with "aws-kms" unless
  the keyring is an AWS KMS keyring.

  ## Examples

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("my-provider")
      :ok

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("aws-kms")
      {:error, :reserved_provider_id}

      iex> AwsEncryptionSdk.Keyring.Behaviour.validate_provider_id("aws-kms-mrk")
      {:error, :reserved_provider_id}

  """
  @spec validate_provider_id(String.t()) :: :ok | {:error, :reserved_provider_id}
  def validate_provider_id(provider_id) when is_binary(provider_id) do
    if String.starts_with?(provider_id, "aws-kms") do
      {:error, :reserved_provider_id}
    else
      :ok
    end
  end

  @doc """
  Generates a cryptographically random data key of the appropriate length.

  The length is determined by the algorithm suite's KDF input length.

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = AwsEncryptionSdk.Keyring.Behaviour.generate_data_key(suite)
      iex> byte_size(key)
      32

  """
  @spec generate_data_key(AwsEncryptionSdk.AlgorithmSuite.t()) :: binary()
  def generate_data_key(algorithm_suite) do
    key_length_bytes = div(algorithm_suite.data_key_length, 8)
    :crypto.strong_rand_bytes(key_length_bytes)
  end

  @doc """
  Checks if materials already have a plaintext data key set.

  Useful for implementing the precondition checks in keyrings.

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> AwsEncryptionSdk.Keyring.Behaviour.has_plaintext_data_key?(materials)
      false

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new(suite, %{}, [edk], key)
      iex> AwsEncryptionSdk.Keyring.Behaviour.has_plaintext_data_key?(materials)
      true

  """
  @spec has_plaintext_data_key?(EncryptionMaterials.t() | DecryptionMaterials.t()) :: boolean()
  def has_plaintext_data_key?(%{plaintext_data_key: nil}), do: false
  def has_plaintext_data_key?(%{plaintext_data_key: key}) when is_binary(key), do: true
end
