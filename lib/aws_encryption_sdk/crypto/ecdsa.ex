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
end
