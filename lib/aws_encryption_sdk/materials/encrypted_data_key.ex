defmodule AwsEncryptionSdk.Materials.EncryptedDataKey do
  @moduledoc """
  Encrypted Data Key (EDK) structure.

  An EDK contains a data key encrypted by a specific key provider. Each message
  contains one or more EDKs, allowing decryption with any of the corresponding
  master keys.

  ## Fields

  - `:key_provider_id` - UTF-8 identifier for the key provider (e.g., "aws-kms")
  - `:key_provider_info` - Provider-specific key information (binary)
  - `:ciphertext` - The encrypted data key (binary)

  ## Serialization Format

  Per message-header.md:
  ```
  | Field              | Length        | Type   |
  |--------------------|---------------|--------|
  | Provider ID Length | 2 bytes       | Uint16 |
  | Provider ID        | Variable      | UTF-8  |
  | Provider Info Len  | 2 bytes       | Uint16 |
  | Provider Info      | Variable      | Binary |
  | Ciphertext Length  | 2 bytes       | Uint16 |
  | Ciphertext         | Variable      | Binary |
  ```
  """

  @typedoc "Encrypted Data Key structure"
  @type t :: %__MODULE__{
          key_provider_id: String.t(),
          key_provider_info: binary(),
          ciphertext: binary()
        }

  @enforce_keys [:key_provider_id, :key_provider_info, :ciphertext]
  defstruct @enforce_keys

  @doc """
  Creates a new EncryptedDataKey.

  ## Examples

      iex> AwsEncryptionSdk.Materials.EncryptedDataKey.new("aws-kms", "key-arn", <<1, 2, 3>>)
      %AwsEncryptionSdk.Materials.EncryptedDataKey{
        key_provider_id: "aws-kms",
        key_provider_info: "key-arn",
        ciphertext: <<1, 2, 3>>
      }
  """
  @spec new(String.t(), binary(), binary()) :: t()
  def new(key_provider_id, key_provider_info, ciphertext)
      when is_binary(key_provider_id) and is_binary(key_provider_info) and is_binary(ciphertext) do
    %__MODULE__{
      key_provider_id: key_provider_id,
      key_provider_info: key_provider_info,
      ciphertext: ciphertext
    }
  end

  @doc """
  Serializes an EDK to binary format.

  ## Format
  ```
  <<provider_id_len::16-big, provider_id::binary,
    provider_info_len::16-big, provider_info::binary,
    ciphertext_len::16-big, ciphertext::binary>>
  ```
  """
  @spec serialize(t()) :: binary()
  def serialize(%__MODULE__{} = edk) do
    provider_id_bytes = edk.key_provider_id
    provider_id_len = byte_size(provider_id_bytes)
    provider_info_len = byte_size(edk.key_provider_info)
    ciphertext_len = byte_size(edk.ciphertext)

    <<
      provider_id_len::16-big,
      provider_id_bytes::binary,
      provider_info_len::16-big,
      edk.key_provider_info::binary,
      ciphertext_len::16-big,
      edk.ciphertext::binary
    >>
  end

  @doc """
  Serializes a list of EDKs with a count prefix.

  ## Format
  ```
  <<count::16-big, edk1::binary, edk2::binary, ...>>
  ```
  """
  @spec serialize_list([t()]) :: {:ok, binary()} | {:error, :empty_edk_list}
  def serialize_list([]), do: {:error, :empty_edk_list}

  def serialize_list(edks) when is_list(edks) do
    count = length(edks)
    serialized = edks |> Enum.map(&serialize/1) |> IO.iodata_to_binary()
    {:ok, <<count::16-big, serialized::binary>>}
  end

  @doc """
  Deserializes an EDK from binary format.

  Returns `{:ok, edk, rest}` on success, or `{:error, reason}` on failure.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<
        provider_id_len::16-big,
        provider_id::binary-size(provider_id_len),
        provider_info_len::16-big,
        provider_info::binary-size(provider_info_len),
        ciphertext_len::16-big,
        ciphertext::binary-size(ciphertext_len),
        rest::binary
      >>) do
    edk = %__MODULE__{
      key_provider_id: provider_id,
      key_provider_info: provider_info,
      ciphertext: ciphertext
    }

    {:ok, edk, rest}
  end

  def deserialize(_data), do: {:error, :invalid_edk_format}

  @doc """
  Deserializes a list of EDKs with count prefix.

  Returns `{:ok, edks, rest}` on success.
  """
  @spec deserialize_list(binary()) :: {:ok, [t()], binary()} | {:error, term()}
  def deserialize_list(<<count::16-big, rest::binary>>) when count > 0 do
    deserialize_n(rest, count, [])
  end

  def deserialize_list(<<0::16-big, _rest::binary>>), do: {:error, :empty_edk_list}
  def deserialize_list(_data), do: {:error, :invalid_edk_list_format}

  defp deserialize_n(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp deserialize_n(data, n, acc) do
    case deserialize(data) do
      {:ok, edk, rest} -> deserialize_n(rest, n - 1, [edk | acc])
      {:error, _reason} = error -> error
    end
  end
end
