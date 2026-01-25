defmodule AwsEncryptionSdk.Crypto.HKDF do
  @moduledoc """
  HKDF (HMAC-based Key Derivation Function) implementation per RFC 5869.

  HKDF is used by the AWS Encryption SDK to derive data encryption keys and
  commitment keys from plaintext data keys. It consists of two steps:

  1. **Extract**: Takes input keying material (IKM) and an optional salt,
     producing a pseudorandom key (PRK)
  2. **Expand**: Takes the PRK and optional context info, producing output
     keying material (OKM) of the desired length

  ## Supported Hash Algorithms

  - `:sha256` - Used by algorithm suites 0x0114, 0x0146, 0x0178, 0x0214
  - `:sha384` - Used by algorithm suites 0x0346, 0x0378
  - `:sha512` - Used by committed suites 0x0478, 0x0578

  ## References

  - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
  - [AWS Encryption SDK Algorithm Suites](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md)
  """

  @typedoc "Supported hash algorithms for HKDF operations"
  @type hash :: :sha256 | :sha384 | :sha512

  @hash_lengths %{
    sha256: 32,
    sha384: 48,
    sha512: 64
  }

  @doc """
  HKDF-Extract: Extract a pseudorandom key from input keying material.

  Per RFC 5869 Section 2.2:
  ```
  PRK = HMAC-Hash(salt, IKM)
  ```

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `salt` - Optional salt value (non-secret random value). If `nil` or empty
    binary, defaults to a string of `HashLen` zero bytes.
  - `ikm` - Input keying material

  ## Returns

  The pseudorandom key (PRK) as a binary of `HashLen` bytes.

  ## Examples

      iex> prk = AwsEncryptionSdk.Crypto.HKDF.extract(:sha256, <<0, 1, 2>>, <<0x0b::8, 0x0b::8>>)
      iex> byte_size(prk)
      32
  """
  @spec extract(hash(), binary() | nil, binary()) :: binary()
  def extract(hash, salt, ikm) when hash in [:sha256, :sha384, :sha512] do
    effective_salt = effective_salt(hash, salt)
    :crypto.mac(:hmac, hash, effective_salt, ikm)
  end

  @doc """
  HKDF-Expand: Expand a pseudorandom key to the desired length.

  Per RFC 5869 Section 2.3:
  ```
  N = ceil(L/HashLen)
  T = T(1) | T(2) | T(3) | ... | T(N)
  OKM = first L octets of T

  where:
  T(0) = empty string
  T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
  ```

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `prk` - Pseudorandom key (typically output from `extract/3`)
  - `info` - Optional context and application specific information (can be empty)
  - `length` - Desired output length in bytes (must be <= 255 * HashLen)

  ## Returns

  - `{:ok, okm}` - Output keying material of the requested length
  - `{:error, :output_length_exceeded}` - If length > 255 * HashLen

  ## Examples

      iex> prk = :crypto.strong_rand_bytes(32)
      iex> {:ok, okm} = AwsEncryptionSdk.Crypto.HKDF.expand(:sha256, prk, "context", 32)
      iex> byte_size(okm)
      32
  """
  @spec expand(hash(), binary(), binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :output_length_exceeded}
  def expand(hash, prk, info, length)
      when hash in [:sha256, :sha384, :sha512] and is_binary(prk) and is_binary(info) and
             is_integer(length) and length >= 0 do
    hash_len = @hash_lengths[hash]
    max_length = 255 * hash_len

    if length > max_length do
      {:error, :output_length_exceeded}
    else
      okm = do_expand(hash, prk, info, length, hash_len)
      {:ok, okm}
    end
  end

  @doc """
  Combined HKDF: Extract-then-Expand in a single call.

  This is the standard way to use HKDF - it combines the extract and expand
  steps for convenience.

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `ikm` - Input keying material
  - `salt` - Optional salt value (if `nil` or empty, uses HashLen zero bytes)
  - `info` - Optional context and application specific information
  - `length` - Desired output length in bytes

  ## Returns

  - `{:ok, okm}` - Output keying material of the requested length
  - `{:error, :output_length_exceeded}` - If length > 255 * HashLen

  ## Examples

      iex> ikm = :crypto.strong_rand_bytes(32)
      iex> {:ok, key} = AwsEncryptionSdk.Crypto.HKDF.derive(:sha256, ikm, nil, "label", 32)
      iex> byte_size(key)
      32
  """
  @spec derive(hash(), binary(), binary() | nil, binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :output_length_exceeded}
  def derive(hash, ikm, salt, info, length)
      when hash in [:sha256, :sha384, :sha512] and is_binary(ikm) and is_binary(info) and
             is_integer(length) and length >= 0 do
    prk = extract(hash, salt, ikm)
    expand(hash, prk, info, length)
  end

  @doc """
  Returns the output length in bytes for a given hash algorithm.

  ## Examples

      iex> AwsEncryptionSdk.Crypto.HKDF.hash_length(:sha256)
      32

      iex> AwsEncryptionSdk.Crypto.HKDF.hash_length(:sha512)
      64
  """
  @spec hash_length(hash()) :: pos_integer()
  def hash_length(:sha256), do: 32
  def hash_length(:sha384), do: 48
  def hash_length(:sha512), do: 64

  # Private functions

  @spec effective_salt(hash(), binary() | nil) :: binary()
  defp effective_salt(hash, nil), do: :binary.copy(<<0>>, @hash_lengths[hash])
  defp effective_salt(hash, <<>>), do: :binary.copy(<<0>>, @hash_lengths[hash])
  defp effective_salt(_hash, salt) when is_binary(salt), do: salt

  @spec do_expand(hash(), binary(), binary(), non_neg_integer(), pos_integer()) :: binary()
  defp do_expand(_hash, _prk, _info, 0, _hash_len), do: <<>>

  defp do_expand(hash, prk, info, length, hash_len) do
    iterations = ceil(length / hash_len)

    {_last_t, okm} =
      Enum.reduce(1..iterations, {<<>>, <<>>}, fn i, {prev_t, acc} ->
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        t = :crypto.mac(:hmac, hash, prk, [prev_t, info, <<i::8>>])
        {t, <<acc::binary, t::binary>>}
      end)

    binary_part(okm, 0, length)
  end
end
