defmodule AwsEncryptionSdk.TestSupport.AesKeywrap do
  @moduledoc """
  AES Key Wrap (RFC 3394) implementation for test support.

  This module provides AES-KEYWRAP functionality needed to unwrap encrypted
  data keys from test vectors. This is NOT a production implementation and
  should only be used in tests.

  The production Raw AES Keyring will have a proper implementation.
  """

  @default_iv <<0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6>>

  @doc """
  Unwraps a key using AES Key Wrap (RFC 3394).

  ## Parameters

  - `kek` - Key encryption key (16, 24, or 32 bytes)
  - `wrapped` - Wrapped key data (must be a multiple of 8 bytes, minimum 24 bytes)

  ## Returns

  - `{:ok, unwrapped_key}` - Successfully unwrapped
  - `{:error, :integrity_check_failed}` - IV mismatch (tampering detected)
  - `{:error, :invalid_length}` - Invalid wrapped key length
  """
  @spec unwrap(binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def unwrap(kek, wrapped) when byte_size(wrapped) >= 24 and rem(byte_size(wrapped), 8) == 0 do
    cipher = cipher_for_key_size(byte_size(kek))
    n = div(byte_size(wrapped), 8) - 1

    # Step 1: Initialize variables
    # A = C[0] (first 8 bytes)
    # R = C[1..n] (remaining 8-byte blocks)
    <<a::binary-size(8), rest::binary>> = wrapped
    r = for i <- 1..n, do: binary_part(rest, (i - 1) * 8, 8)

    # Step 2: Compute intermediate values (6 iterations per block)
    {final_a, final_r} = unwrap_rounds(cipher, kek, a, r, n)

    # Step 3: Check IV
    if final_a == @default_iv do
      {:ok, IO.iodata_to_binary(final_r)}
    else
      {:error, :integrity_check_failed}
    end
  end

  def unwrap(_kek, _wrapped), do: {:error, :invalid_length}

  # RFC 3394 unwrap algorithm
  defp unwrap_rounds(cipher, kek, a, r, n) do
    # For j = 5 to 0 (6 iterations)
    Enum.reduce(5..0, {a, r}, fn j, {a_acc, r_acc} ->
      # For i = n to 1
      Enum.reduce(n..1, {a_acc, r_acc}, fn i, {a_inner, r_inner} ->
        # t = n * j + i
        t = n * j + i

        # A XOR t
        a_xor_t = xor_last_byte(a_inner, t)

        # B = AES-1(K, (A ^ t) | R[i])
        b = :crypto.crypto_one_time(cipher, kek, <<>>, a_xor_t <> Enum.at(r_inner, i - 1), false)

        # A = MSB(64, B)
        <<new_a::binary-size(8), new_r_i::binary-size(8)>> = b

        # R[i] = LSB(64, B)
        new_r = List.replace_at(r_inner, i - 1, new_r_i)

        {new_a, new_r}
      end)
    end)
  end

  # XOR the last byte of an 8-byte binary with a value
  defp xor_last_byte(<<prefix::binary-size(7), last_byte::8>>, value) do
    # Convert value to 8 bytes (big-endian)
    <<value_bytes::64>> = <<value::64-big>>
    # XOR the binaries
    :crypto.exor(<<prefix::binary-size(7), last_byte::8>>, <<value_bytes::64>>)
  end

  defp cipher_for_key_size(16), do: :aes_128_ecb
  defp cipher_for_key_size(24), do: :aes_192_ecb
  defp cipher_for_key_size(32), do: :aes_256_ecb
end
