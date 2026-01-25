defmodule AwsEncryptionSdk.Crypto.AesGcm do
  @moduledoc """
  AES-GCM encryption and decryption operations.

  Wraps Erlang `:crypto` functions for AES-GCM with 128, 192, or 256-bit keys.
  All operations use 12-byte IVs and 16-byte authentication tags as required
  by the AWS Encryption SDK.
  """

  @iv_length 12
  @tag_length 16

  @typedoc "AES-GCM cipher type for :crypto module"
  @type cipher :: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm

  @doc """
  Encrypts plaintext using AES-GCM.

  ## Parameters

  - `cipher` - `:aes_128_gcm`, `:aes_192_gcm`, or `:aes_256_gcm`
  - `key` - Encryption key (16, 24, or 32 bytes)
  - `iv` - Initialization vector (12 bytes)
  - `plaintext` - Data to encrypt
  - `aad` - Additional authenticated data

  ## Returns

  `{ciphertext, auth_tag}` tuple where auth_tag is 16 bytes.
  """
  @spec encrypt(cipher(), binary(), binary(), binary(), binary()) :: {binary(), binary()}
  def encrypt(cipher, key, iv, plaintext, aad)
      when cipher in [:aes_128_gcm, :aes_192_gcm, :aes_256_gcm] and
             byte_size(iv) == @iv_length do
    :crypto.crypto_one_time_aead(cipher, key, iv, plaintext, aad, @tag_length, true)
  end

  @doc """
  Decrypts ciphertext using AES-GCM.

  ## Parameters

  - `cipher` - `:aes_128_gcm`, `:aes_192_gcm`, or `:aes_256_gcm`
  - `key` - Decryption key (16, 24, or 32 bytes)
  - `iv` - Initialization vector (12 bytes)
  - `ciphertext` - Data to decrypt
  - `aad` - Additional authenticated data
  - `auth_tag` - Authentication tag (16 bytes)

  ## Returns

  - `{:ok, plaintext}` on successful decryption and authentication
  - `{:error, :authentication_failed}` if tag verification fails
  """
  @spec decrypt(cipher(), binary(), binary(), binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, :authentication_failed}
  def decrypt(cipher, key, iv, ciphertext, aad, auth_tag)
      when cipher in [:aes_128_gcm, :aes_192_gcm, :aes_256_gcm] and
             byte_size(iv) == @iv_length and
             byte_size(auth_tag) == @tag_length do
    case :crypto.crypto_one_time_aead(cipher, key, iv, ciphertext, aad, auth_tag, false) do
      :error -> {:error, :authentication_failed}
      plaintext when is_binary(plaintext) -> {:ok, plaintext}
    end
  end

  @doc """
  Returns the required key length in bytes for a cipher.
  """
  @spec key_length(cipher()) :: 16 | 24 | 32
  def key_length(:aes_128_gcm), do: 16
  def key_length(:aes_192_gcm), do: 24
  def key_length(:aes_256_gcm), do: 32

  @doc """
  Returns the IV length (always 12 bytes for AES-GCM).
  """
  @spec iv_length() :: 12
  def iv_length, do: @iv_length

  @doc """
  Returns the authentication tag length (always 16 bytes).
  """
  @spec tag_length() :: 16
  def tag_length, do: @tag_length

  @doc """
  Constructs an IV from a sequence number.

  The IV is the sequence number padded to 12 bytes (big-endian).
  Used for frame encryption/decryption.
  """
  @spec sequence_number_to_iv(non_neg_integer()) :: binary()
  def sequence_number_to_iv(sequence_number)
      when is_integer(sequence_number) and sequence_number >= 0 do
    <<0::64, sequence_number::32-big>>
  end

  @doc """
  Returns a zero IV (12 zero bytes).

  Used for header authentication tag computation.
  """
  @spec zero_iv() :: binary()
  def zero_iv, do: :binary.copy(<<0>>, @iv_length)
end
