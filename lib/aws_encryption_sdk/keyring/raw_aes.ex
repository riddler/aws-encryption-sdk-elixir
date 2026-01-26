defmodule AwsEncryptionSdk.Keyring.RawAes do
  @moduledoc """
  Raw AES Keyring implementation.

  Uses locally-provided AES keys to wrap and unwrap data keys using AES-GCM.
  Supports 128, 192, and 256-bit wrapping keys.

  ## Example

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("my-namespace", "my-key-name", key, :aes_256_gcm)
      iex> is_struct(keyring, AwsEncryptionSdk.Keyring.RawAes)
      true

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @iv_length 12
  @tag_length 16
  @tag_length_bits 128

  @typedoc "Wrapping algorithm for AES-GCM"
  @type wrapping_algorithm :: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm

  @type t :: %__MODULE__{
          key_namespace: String.t(),
          key_name: String.t(),
          wrapping_key: binary(),
          wrapping_algorithm: wrapping_algorithm()
        }

  @enforce_keys [:key_namespace, :key_name, :wrapping_key, :wrapping_algorithm]
  defstruct @enforce_keys

  @wrapping_algorithms %{
    aes_128_gcm: %{cipher: :aes_128_gcm, key_bits: 128},
    aes_192_gcm: %{cipher: :aes_192_gcm, key_bits: 192},
    aes_256_gcm: %{cipher: :aes_256_gcm, key_bits: 256}
  }

  @doc """
  Creates a new Raw AES Keyring.

  ## Parameters

  - `key_namespace` - Key provider ID (must not start with "aws-kms")
  - `key_name` - Unique identifier for the wrapping key
  - `wrapping_key` - Raw AES key bytes (16, 24, or 32 bytes)
  - `wrapping_algorithm` - `:aes_128_gcm`, `:aes_192_gcm`, or `:aes_256_gcm`

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :reserved_provider_id}` - key_namespace starts with "aws-kms"
  - `{:error, :invalid_wrapping_algorithm}` - unsupported algorithm
  - `{:error, :invalid_key_length}` - wrapping key length doesn't match algorithm

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)
      iex> keyring.key_namespace
      "my-namespace"

      iex> key = :crypto.strong_rand_bytes(32)
      iex> AwsEncryptionSdk.Keyring.RawAes.new("aws-kms", "key", key, :aes_256_gcm)
      {:error, :reserved_provider_id}

  """
  @spec new(String.t(), String.t(), binary(), wrapping_algorithm()) ::
          {:ok, t()} | {:error, term()}
  def new(key_namespace, key_name, wrapping_key, wrapping_algorithm)
      when is_binary(key_namespace) and is_binary(key_name) and is_binary(wrapping_key) do
    with :ok <- KeyringBehaviour.validate_provider_id(key_namespace),
         {:ok, config} <- get_algorithm_config(wrapping_algorithm),
         :ok <- validate_key_length(wrapping_key, config) do
      {:ok,
       %__MODULE__{
         key_namespace: key_namespace,
         key_name: key_name,
         wrapping_key: wrapping_key,
         wrapping_algorithm: wrapping_algorithm
       }}
    end
  end

  defp get_algorithm_config(algorithm) do
    case Map.fetch(@wrapping_algorithms, algorithm) do
      {:ok, config} -> {:ok, config}
      :error -> {:error, :invalid_wrapping_algorithm}
    end
  end

  defp validate_key_length(key, %{key_bits: expected_bits}) do
    actual_bits = bit_size(key)

    if actual_bits == expected_bits do
      :ok
    else
      {:error, {:invalid_key_length, expected: expected_bits, actual: actual_bits}}
    end
  end

  @doc false
  @spec serialize_provider_info(String.t(), binary()) :: binary()
  def serialize_provider_info(key_name, iv) when byte_size(iv) == @iv_length do
    # Spec format: key_name (no length prefix) + tag_length (4 bytes) + iv_length (4 bytes) + iv
    <<
      key_name::binary,
      @tag_length_bits::32-big,
      @iv_length::32-big,
      iv::binary
    >>
  end

  @doc false
  @spec deserialize_provider_info(t(), binary()) ::
          {:ok,
           %{key_name: String.t(), tag_length_bits: integer(), iv_length: integer(), iv: binary()}}
          | {:error, term()}
  def deserialize_provider_info(%__MODULE__{} = keyring, provider_info) do
    # The key name has no length prefix in the spec format
    # We know the expected key name length from the keyring configuration
    key_name_len = byte_size(keyring.key_name)
    expected_total_len = key_name_len + 4 + 4 + @iv_length

    if byte_size(provider_info) != expected_total_len do
      {:error, :invalid_provider_info_format}
    else
      <<
        key_name::binary-size(key_name_len),
        tag_length_bits::32-big,
        iv_length::32-big,
        iv::binary-size(@iv_length)
      >> = provider_info

      {:ok,
       %{
         key_name: key_name,
         tag_length_bits: tag_length_bits,
         iv_length: iv_length,
         iv: iv
       }}
    end
  end

  @doc """
  Wraps a data key using this keyring's wrapping key.

  If materials don't have a plaintext data key, one will be generated.
  The wrapped key is added to the materials as an EDK.

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> {:ok, result} = AwsEncryptionSdk.Keyring.RawAes.wrap_key(keyring, materials)
      iex> is_binary(result.plaintext_data_key) and length(result.encrypted_data_keys) == 1
      true

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    with {:ok, materials} <- ensure_data_key(keyring, materials),
         {:ok, serialized_ec} <- serialize_encryption_context(materials.encryption_context),
         {:ok, edk} <- encrypt_data_key(keyring, materials.plaintext_data_key, serialized_ec) do
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

  defp serialize_encryption_context(ec) do
    # EncryptionContext.serialize/1 always succeeds for valid maps
    {:ok, EncryptionContext.serialize(ec)}
  end

  defp encrypt_data_key(%__MODULE__{} = keyring, plaintext_key, aad) do
    iv = :crypto.strong_rand_bytes(@iv_length)
    cipher = keyring.wrapping_algorithm

    {encrypted_key, tag} = AesGcm.encrypt(cipher, keyring.wrapping_key, iv, plaintext_key, aad)

    # Ciphertext field is encrypted_key || tag
    ciphertext = encrypted_key <> tag

    # Provider info includes key name and IV
    provider_info = serialize_provider_info(keyring.key_name, iv)

    edk = EncryptedDataKey.new(keyring.key_namespace, provider_info, ciphertext)
    {:ok, edk}
  end

  @doc """
  Unwraps a data key using this keyring's wrapping key.

  Iterates through EDKs to find one that:
  1. Has matching key_provider_id (key_namespace)
  2. Has matching key_name in provider_info
  3. Successfully decrypts with this keyring's wrapping key

  ## Returns

  - `{:ok, materials}` - Data key successfully unwrapped and set
  - `{:error, :plaintext_data_key_already_set}` - Materials already have a key
  - `{:error, :unable_to_decrypt_data_key}` - No matching EDK could be decrypted

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> enc_materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> {:ok, wrapped} = AwsEncryptionSdk.Keyring.RawAes.wrap_key(keyring, enc_materials)
      iex> dec_materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new_for_decrypt(suite, %{})
      iex> {:ok, unwrapped} = AwsEncryptionSdk.Keyring.RawAes.unwrap_key(keyring, dec_materials, wrapped.encrypted_data_keys)
      iex> unwrapped.plaintext_data_key == wrapped.plaintext_data_key
      true

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      try_decrypt_edks(keyring, materials, edks)
    end
  end

  defp try_decrypt_edks(keyring, materials, edks) do
    serialized_ec = EncryptionContext.serialize(materials.encryption_context)

    result =
      Enum.reduce_while(edks, :no_match, fn edk, _acc ->
        case try_decrypt_edk(keyring, edk, serialized_ec) do
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

  defp try_decrypt_edk(keyring, edk, aad) do
    with :ok <- match_provider_id(keyring, edk),
         {:ok, info} <- deserialize_provider_info(keyring, edk.key_provider_info),
         :ok <- match_key_name(keyring, info),
         :ok <- validate_iv_length(info),
         :ok <- validate_tag_length(info),
         {:ok, encrypted_key, tag} <- split_ciphertext(edk.ciphertext, info) do
      AesGcm.decrypt(
        keyring.wrapping_algorithm,
        keyring.wrapping_key,
        info.iv,
        encrypted_key,
        aad,
        tag
      )
    end
  end

  defp match_provider_id(keyring, edk) do
    if edk.key_provider_id == keyring.key_namespace do
      :ok
    else
      {:error, :provider_id_mismatch}
    end
  end

  defp match_key_name(keyring, info) do
    if info.key_name == keyring.key_name do
      :ok
    else
      {:error, :key_name_mismatch}
    end
  end

  defp validate_iv_length(%{iv_length: @iv_length}), do: :ok
  defp validate_iv_length(%{iv_length: actual}), do: {:error, {:invalid_iv_length, actual}}

  defp validate_tag_length(%{tag_length_bits: @tag_length_bits}), do: :ok

  defp validate_tag_length(%{tag_length_bits: actual}),
    do: {:error, {:invalid_tag_length, actual}}

  defp split_ciphertext(ciphertext, _info) do
    # Tag is always last 16 bytes
    ciphertext_len = byte_size(ciphertext) - @tag_length

    if ciphertext_len > 0 do
      <<encrypted_key::binary-size(ciphertext_len), tag::binary-size(@tag_length)>> = ciphertext
      {:ok, encrypted_key, tag}
    else
      {:error, :ciphertext_too_short}
    end
  end

  # Behaviour callback delegates to wrap_key
  # The behaviour callbacks need the keyring instance, so they explain how to use the explicit functions
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call RawAes.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call RawAes.unwrap_key(keyring, materials, edks) instead"}}
  end
end
