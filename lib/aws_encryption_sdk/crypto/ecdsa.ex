defmodule AwsEncryptionSdk.Crypto.ECDSA do
  @moduledoc """
  ECDSA operations for AWS Encryption SDK.

  Provides key generation and encoding for P-384 (secp384r1) curve
  used by signed algorithm suites.

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
  """

  @type key_pair :: {private_key :: binary(), public_key :: binary()}
  @type curve :: :secp384r1 | :secp256r1

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
    # Normalize public key to uncompressed format if needed
    normalized_key = normalize_public_key(public_key, :secp384r1)
    :crypto.verify(:ecdsa, :sha384, message, signature, [normalized_key, :secp384r1])
  end

  @doc """
  Normalizes a public key to uncompressed format.

  Handles both compressed (0x02/0x03 prefix, 49 bytes for P-384 or 33 bytes for P-256)
  and uncompressed (0x04 prefix, 97 bytes for P-384 or 65 bytes for P-256) formats.

  The curve is auto-detected from the key size when possible:
  - 33 bytes compressed or 65 bytes uncompressed → secp256r1
  - 49 bytes compressed or 97 bytes uncompressed → secp384r1
  """
  @spec normalize_public_key(binary(), curve()) :: binary()
  def normalize_public_key(<<0x04, _rest::binary>> = uncompressed_key, _curve) do
    # Already uncompressed
    uncompressed_key
  end

  # 33-byte key = P-256 compressed (1 prefix + 32 bytes x)
  def normalize_public_key(<<prefix, _x_coord::binary-size(32)>> = compressed_key, _curve)
      when prefix in [0x02, 0x03] do
    decompress_ec_point(compressed_key, :secp256r1)
  end

  # 49-byte key = P-384 compressed (1 prefix + 48 bytes x)
  def normalize_public_key(<<prefix, _x_coord::binary-size(48)>> = compressed_key, _curve)
      when prefix in [0x02, 0x03] do
    decompress_ec_point(compressed_key, :secp384r1)
  end

  def normalize_public_key(key, _curve), do: key

  # Manual EC point decompression for NIST curves
  # Uses simplified modular square root since p ≡ 3 (mod 4) for both P-256 and P-384
  # See SEC 1 v2.0 Section 2.3.4: https://www.secg.org/sec1-v2.pdf

  # secp256r1 (P-256): 33-byte compressed key (1 prefix + 32 bytes x)
  defp decompress_ec_point(<<prefix, x_bytes::binary-size(32)>>, :secp256r1)
       when prefix in [0x02, 0x03] do
    # secp256r1 curve parameters
    # p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF

    # b coefficient from secp256r1 specification
    b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

    decompress_with_params(prefix, x_bytes, p, b, 32)
  end

  # secp384r1 (P-384): 49-byte compressed key (1 prefix + 48 bytes x)
  defp decompress_ec_point(<<prefix, x_bytes::binary-size(48)>>, :secp384r1)
       when prefix in [0x02, 0x03] do
    # secp384r1 curve parameters
    # p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    p =
      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF

    # b coefficient from secp384r1 specification
    b =
      0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF

    decompress_with_params(prefix, x_bytes, p, b, 48)
  end

  defp decompress_ec_point(key, _curve), do: key

  # Generic decompression using curve parameters
  defp decompress_with_params(prefix, x_bytes, p, b, coord_size) do
    # a = -3 (mod p), which is p - 3 for both curves
    a = p - 3

    # Convert x bytes to integer
    x = :binary.decode_unsigned(x_bytes, :big)

    # Calculate y² = x³ + ax + b (mod p)
    # Note: The curve equation is y² = x³ - 3x + b, and a = -3
    x_cubed = mod_pow(x, 3, p)
    ax = mod(a * x, p)
    y_squared = mod(x_cubed + ax + b, p)

    # Since p ≡ 3 (mod 4), we can compute sqrt using: y = y²^((p+1)/4) mod p
    exponent = div(p + 1, 4)
    y = mod_pow(y_squared, exponent, p)

    # Determine if we need to negate y based on the prefix
    # prefix 0x02 = even y, prefix 0x03 = odd y
    y_is_odd = Integer.mod(y, 2) == 1
    prefix_wants_odd = prefix == 0x03

    final_y =
      if y_is_odd == prefix_wants_odd do
        y
      else
        # Use the other root: -y mod p = p - y
        p - y
      end

    # Convert y back to binary (big-endian, zero-padded)
    y_bytes = :binary.encode_unsigned(final_y, :big)
    y_bytes_padded = pad_to_length(y_bytes, coord_size)

    # Build uncompressed point: 0x04 || x || y
    <<0x04, x_bytes::binary, y_bytes_padded::binary>>
  end

  # Modular exponentiation using Erlang's built-in
  defp mod_pow(base, exp, mod) do
    :crypto.mod_pow(base, exp, mod)
    |> :binary.decode_unsigned(:big)
  end

  # Modular reduction for potentially negative numbers
  defp mod(n, p) when n >= 0, do: Integer.mod(n, p)
  defp mod(n, p), do: Integer.mod(n + p, p)

  # Pad binary to specified length with leading zeros
  defp pad_to_length(binary, length) when byte_size(binary) >= length, do: binary

  defp pad_to_length(binary, length) do
    padding_size = length - byte_size(binary)
    <<0::size(padding_size * 8), binary::binary>>
  end
end
