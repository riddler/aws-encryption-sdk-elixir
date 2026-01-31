defmodule AwsEncryptionSdk.Crypto.ECDSA do
  @moduledoc """
  ECDSA operations for AWS Encryption SDK.

  Provides key generation and encoding for P-384 (secp384r1) curve
  used by signed algorithm suites.

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
  """

  @type key_pair :: {private_key :: binary(), public_key :: binary()}
  @type curve :: :secp384r1

  @doc """
  Generates an ECDSA key pair for the P-384 curve.

  Returns `{private_key, public_key}` where:
  - `private_key` is the raw private key bytes
  - `public_key` is the uncompressed public key point

  ## Examples

      iex> {private_key, public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> byte_size(private_key)
      48
      iex> byte_size(public_key)
      97

  """
  @spec generate_key_pair(curve()) :: key_pair()
  def generate_key_pair(:secp384r1) do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp384r1)
    {private_key, public_key}
  end

  @doc """
  Encodes a public key to base64 for storage in encryption context.

  The public key is stored as-is (uncompressed point format) and base64 encoded.

  ## Examples

      iex> {_private_key, public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> encoded = AwsEncryptionSdk.Crypto.ECDSA.encode_public_key(public_key)
      iex> String.printable?(encoded)
      true

  """
  @spec encode_public_key(binary()) :: String.t()
  def encode_public_key(public_key) when is_binary(public_key) do
    Base.encode64(public_key)
  end

  @doc """
  Decodes a base64-encoded public key from encryption context.

  ## Examples

      iex> {_private_key, public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> encoded = AwsEncryptionSdk.Crypto.ECDSA.encode_public_key(public_key)
      iex> {:ok, decoded} = AwsEncryptionSdk.Crypto.ECDSA.decode_public_key(encoded)
      iex> decoded == public_key
      true

  """
  @spec decode_public_key(String.t()) :: {:ok, binary()} | {:error, :invalid_base64}
  def decode_public_key(encoded) when is_binary(encoded) do
    case Base.decode64(encoded) do
      {:ok, public_key} -> {:ok, public_key}
      :error -> {:error, :invalid_base64}
    end
  end

  @doc """
  Generates an ECDSA signature over the given message using SHA-384.

  ## Parameters

  - `message` - Binary data to sign
  - `private_key` - Raw private key bytes (48 bytes for P-384)
  - `curve` - Elliptic curve to use (`:secp384r1`)

  ## Returns

  - DER-encoded ECDSA signature

  ## Examples

      iex> {private_key, _public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> message = "test message"
      iex> signature = AwsEncryptionSdk.Crypto.ECDSA.sign(message, private_key, :secp384r1)
      iex> is_binary(signature)
      true

  """
  @spec sign(binary(), binary(), curve()) :: binary()
  def sign(message, private_key, :secp384r1) when is_binary(message) and is_binary(private_key) do
    :crypto.sign(:ecdsa, :sha384, message, [private_key, :secp384r1])
  end

  @doc """
  Signs a pre-computed digest using ECDSA P-384.

  This is useful for streaming where the hash is accumulated incrementally.

  ## Parameters

  - `digest` - SHA-384 digest (48 bytes)
  - `private_key` - Raw private key bytes

  ## Returns

  - DER-encoded ECDSA signature

  ## Examples

      iex> {private_key, _public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> digest = :crypto.hash(:sha384, "test message")
      iex> signature = AwsEncryptionSdk.Crypto.ECDSA.sign_digest(digest, private_key)
      iex> is_binary(signature)
      true

  """
  @spec sign_digest(binary(), binary()) :: binary()
  def sign_digest(digest, private_key) when byte_size(digest) == 48 and is_binary(private_key) do
    :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [private_key, :secp384r1])
  end

  @doc """
  Verifies an ECDSA signature against a pre-computed digest.

  ## Parameters

  - `digest` - SHA-384 digest (48 bytes)
  - `signature` - DER-encoded ECDSA signature
  - `public_key` - Raw public key bytes

  ## Returns

  - `true` if valid, `false` otherwise

  ## Examples

      iex> {private_key, public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> digest = :crypto.hash(:sha384, "test message")
      iex> signature = AwsEncryptionSdk.Crypto.ECDSA.sign_digest(digest, private_key)
      iex> AwsEncryptionSdk.Crypto.ECDSA.verify_digest(digest, signature, public_key)
      true

  """
  @spec verify_digest(binary(), binary(), binary()) :: boolean()
  def verify_digest(digest, signature, public_key)
      when byte_size(digest) == 48 and is_binary(signature) and is_binary(public_key) do
    :crypto.verify(:ecdsa, :sha384, {:digest, digest}, signature, [public_key, :secp384r1])
  end

  @doc """
  Verifies an ECDSA signature over the given message using SHA-384.

  ## Parameters

  - `message` - Binary data that was signed
  - `signature` - DER-encoded ECDSA signature
  - `public_key` - Raw public key bytes (97 bytes uncompressed point for P-384)
  - `curve` - Elliptic curve to use (`:secp384r1`)

  ## Returns

  - `true` if signature is valid
  - `false` if signature is invalid

  ## Examples

      iex> {private_key, public_key} = AwsEncryptionSdk.Crypto.ECDSA.generate_key_pair(:secp384r1)
      iex> message = "test message"
      iex> signature = AwsEncryptionSdk.Crypto.ECDSA.sign(message, private_key, :secp384r1)
      iex> AwsEncryptionSdk.Crypto.ECDSA.verify(message, signature, public_key, :secp384r1)
      true

  """
  @spec verify(binary(), binary(), binary(), curve()) :: boolean()
  def verify(message, signature, public_key, :secp384r1)
      when is_binary(message) and is_binary(signature) and is_binary(public_key) do
    :crypto.verify(:ecdsa, :sha384, message, signature, [public_key, :secp384r1])
  end
end
