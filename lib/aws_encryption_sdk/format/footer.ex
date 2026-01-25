defmodule AwsEncryptionSdk.Format.Footer do
  @moduledoc """
  Message footer serialization and deserialization.

  The footer contains an ECDSA signature that covers the entire message
  (header + body). It is only present when using algorithm suites that
  include digital signatures.

  ## Format

  ```
  | Field            | Size      |
  |------------------|-----------|
  | Signature Length | 2 bytes   | Uint16
  | Signature        | Variable  | DER-encoded ECDSA signature
  ```

  ## Signature Encoding

  ECDSA signatures are DER-encoded per RFC 3279. The length varies:
  - P-256 (ECDSA_P256): typically 70-72 bytes
  - P-384 (ECDSA_P384): typically 102-104 bytes
  """

  @typedoc "Footer structure"
  @type t :: %{signature: binary()}

  @doc """
  Serializes a footer with the given signature.

  ## Parameters

  - `signature` - DER-encoded ECDSA signature

  ## Examples

      iex> Footer.serialize(<<48, 69, 1, 2, 3>>)
      {:ok, <<0, 5, 48, 69, 1, 2, 3>>}
  """
  @spec serialize(binary()) :: {:ok, binary()}
  def serialize(signature) when is_binary(signature) do
    length = byte_size(signature)
    {:ok, <<length::16-big, signature::binary>>}
  end

  @doc """
  Deserializes a footer from binary data.

  Returns `{:ok, footer_map, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<length::16-big, rest::binary>>) when byte_size(rest) >= length do
    <<signature::binary-size(length), remaining::binary>> = rest
    {:ok, %{signature: signature}, remaining}
  end

  def deserialize(<<_length::16-big, _rest::binary>>), do: {:error, :incomplete_footer}
  def deserialize(_invalid), do: {:error, :invalid_footer}
end
