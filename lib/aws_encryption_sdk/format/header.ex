defmodule AwsEncryptionSdk.Format.Header do
  @moduledoc """
  Message header serialization and deserialization.

  Supports both version 1.0 and 2.0 header formats.

  ## Version 2.0 Format (Committed Suites)

  ```
  | Field                | Size      |
  |----------------------|-----------|
  | Version              | 1 byte    | 0x02
  | Algorithm Suite ID   | 2 bytes   |
  | Message ID           | 32 bytes  |
  | AAD Length           | 2 bytes   |
  | AAD (enc context)    | Variable  |
  | EDK Count            | 2 bytes   |
  | EDKs                 | Variable  |
  | Content Type         | 1 byte    |
  | Frame Length         | 4 bytes   |
  | Algorithm Suite Data | 32 bytes  | (commitment key)
  | Auth Tag             | 16 bytes  |
  ```

  ## Version 1.0 Format (Legacy)

  ```
  | Field                | Size      |
  |----------------------|-----------|
  | Version              | 1 byte    | 0x01
  | Type                 | 1 byte    | 0x80
  | Algorithm Suite ID   | 2 bytes   |
  | Message ID           | 16 bytes  |
  | AAD Length           | 2 bytes   |
  | AAD (enc context)    | Variable  |
  | EDK Count            | 2 bytes   |
  | EDKs                 | Variable  |
  | Content Type         | 1 byte    |
  | Reserved             | 4 bytes   | 0x00000000
  | IV Length            | 1 byte    |
  | Frame Length         | 4 bytes   |
  | IV                   | Variable  |
  | Auth Tag             | 16 bytes  |
  ```
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  @type content_type :: :framed | :non_framed

  @typedoc "Message header structure"
  @type t :: %__MODULE__{
          version: 1 | 2,
          algorithm_suite: AlgorithmSuite.t(),
          message_id: binary(),
          encryption_context: EncryptionContext.t(),
          encrypted_data_keys: [EncryptedDataKey.t()],
          content_type: content_type(),
          frame_length: non_neg_integer(),
          algorithm_suite_data: binary() | nil,
          header_iv: binary() | nil,
          header_auth_tag: binary()
        }

  @enforce_keys [
    :version,
    :algorithm_suite,
    :message_id,
    :encryption_context,
    :encrypted_data_keys,
    :content_type,
    :frame_length,
    :header_auth_tag
  ]

  defstruct [
    :version,
    :algorithm_suite,
    :message_id,
    :encryption_context,
    :encrypted_data_keys,
    :content_type,
    :frame_length,
    :algorithm_suite_data,
    :header_iv,
    :header_auth_tag
  ]

  @content_type_non_framed 0x01
  @content_type_framed 0x02

  @doc """
  Generates a new random message ID for the given version.

  - Version 1: 16 random bytes
  - Version 2: 32 random bytes
  """
  @spec generate_message_id(1 | 2) :: binary()
  def generate_message_id(1), do: :crypto.strong_rand_bytes(16)
  def generate_message_id(2), do: :crypto.strong_rand_bytes(32)

  @doc """
  Serializes the header body (everything except the auth tag).

  This is the data that gets authenticated by the header auth tag.
  """
  @spec serialize_body(t()) :: {:ok, binary()} | {:error, term()}
  def serialize_body(%__MODULE__{version: 2} = header) do
    serialize_v2_body(header)
  end

  def serialize_body(%__MODULE__{version: 1} = header) do
    serialize_v1_body(header)
  end

  @doc """
  Serializes a complete header including the auth tag.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{version: 2} = header) do
    with {:ok, body} <- serialize_v2_body(header) do
      {:ok, <<0x02>> <> body <> header.header_auth_tag}
    end
  end

  def serialize(%__MODULE__{version: 1} = header) do
    with {:ok, body} <- serialize_v1_body(header) do
      auth_section = <<header.header_iv::binary, header.header_auth_tag::binary>>
      {:ok, <<0x01, 0x80>> <> body <> auth_section}
    end
  end

  @doc """
  Deserializes a header from binary data.

  Returns `{:ok, header, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<0x02, rest::binary>>), do: deserialize_v2(rest)
  def deserialize(<<0x01, 0x80, rest::binary>>), do: deserialize_v1(rest)
  def deserialize(<<0x01, type, _rest::binary>>), do: {:error, {:invalid_type, type}}
  def deserialize(<<version, _rest::binary>>), do: {:error, {:unsupported_version, version}}
  def deserialize(_incomplete), do: {:error, :incomplete_header}

  # Version 2 serialization

  defp serialize_v2_body(%__MODULE__{version: 2} = header) do
    aad_binary = EncryptionContext.serialize(header.encryption_context)
    aad_length = byte_size(aad_binary)

    with {:ok, edks_binary} <- EncryptedDataKey.serialize_list(header.encrypted_data_keys) do
      content_type_byte = encode_content_type(header.content_type)
      frame_length = if header.content_type == :non_framed, do: 0, else: header.frame_length
      suite_data = header.algorithm_suite_data || <<0::256>>

      body =
        <<
          header.algorithm_suite.id::16-big,
          header.message_id::binary-size(32),
          aad_length::16-big,
          aad_binary::binary,
          edks_binary::binary,
          content_type_byte::8,
          frame_length::32-big,
          suite_data::binary-size(32)
        >>

      {:ok, body}
    end
  end

  # Version 2 deserialization

  defp deserialize_v2(<<
         algorithm_id::16-big,
         message_id::binary-size(32),
         aad_length::16-big,
         rest::binary
       >>) do
    with {:ok, suite} <- AlgorithmSuite.by_id(algorithm_id),
         {:ok, encryption_context, rest} <- deserialize_aad(rest, aad_length),
         {:ok, edks, rest} <- EncryptedDataKey.deserialize_list(rest),
         {:ok, content_type, frame_length, suite_data, auth_tag, rest} <-
           deserialize_v2_tail(rest) do
      header = %__MODULE__{
        version: 2,
        algorithm_suite: suite,
        message_id: message_id,
        encryption_context: encryption_context,
        encrypted_data_keys: edks,
        content_type: content_type,
        frame_length: frame_length,
        algorithm_suite_data: suite_data,
        header_iv: nil,
        header_auth_tag: auth_tag
      }

      {:ok, header, rest}
    end
  end

  defp deserialize_v2(_invalid), do: {:error, :invalid_v2_header}

  defp deserialize_v2_tail(<<
         content_type_byte::8,
         frame_length::32-big,
         suite_data::binary-size(32),
         auth_tag::binary-size(16),
         rest::binary
       >>) do
    with {:ok, content_type} <- decode_content_type(content_type_byte) do
      {:ok, content_type, frame_length, suite_data, auth_tag, rest}
    end
  end

  defp deserialize_v2_tail(_invalid), do: {:error, :invalid_v2_header_tail}

  # Version 1 serialization

  defp serialize_v1_body(%__MODULE__{version: 1} = header) do
    aad_binary = EncryptionContext.serialize(header.encryption_context)
    aad_length = byte_size(aad_binary)

    with {:ok, edks_binary} <- EncryptedDataKey.serialize_list(header.encrypted_data_keys) do
      content_type_byte = encode_content_type(header.content_type)
      frame_length = if header.content_type == :non_framed, do: 0, else: header.frame_length
      iv_length = header.algorithm_suite.iv_length

      body =
        <<
          header.algorithm_suite.id::16-big,
          header.message_id::binary-size(16),
          aad_length::16-big,
          aad_binary::binary,
          edks_binary::binary,
          content_type_byte::8,
          0::32,
          iv_length::8,
          frame_length::32-big
        >>

      {:ok, body}
    end
  end

  # Version 1 deserialization

  defp deserialize_v1(<<
         algorithm_id::16-big,
         message_id::binary-size(16),
         aad_length::16-big,
         rest::binary
       >>) do
    with {:ok, suite} <- AlgorithmSuite.by_id(algorithm_id),
         {:ok, encryption_context, rest} <- deserialize_aad(rest, aad_length),
         {:ok, edks, rest} <- EncryptedDataKey.deserialize_list(rest),
         {:ok, content_type, frame_length, iv, auth_tag, rest} <-
           deserialize_v1_tail(rest, suite.iv_length) do
      header = %__MODULE__{
        version: 1,
        algorithm_suite: suite,
        message_id: message_id,
        encryption_context: encryption_context,
        encrypted_data_keys: edks,
        content_type: content_type,
        frame_length: frame_length,
        algorithm_suite_data: nil,
        header_iv: iv,
        header_auth_tag: auth_tag
      }

      {:ok, header, rest}
    end
  end

  defp deserialize_v1(_invalid), do: {:error, :invalid_v1_header}

  defp deserialize_v1_tail(
         <<
           content_type_byte::8,
           0::32,
           iv_length::8,
           frame_length::32-big,
           rest::binary
         >>,
         expected_iv_length
       )
       when iv_length == expected_iv_length do
    with {:ok, content_type} <- decode_content_type(content_type_byte),
         <<iv::binary-size(iv_length), auth_tag::binary-size(16), rest::binary>> <- rest do
      {:ok, content_type, frame_length, iv, auth_tag, rest}
    else
      _error -> {:error, :invalid_v1_header_auth}
    end
  end

  defp deserialize_v1_tail(<<_byte::8, reserved::32, _rest::binary>>, _expected_iv_length)
       when reserved != 0 do
    {:error, :invalid_reserved_field}
  end

  defp deserialize_v1_tail(_invalid, _expected_iv_length), do: {:error, :invalid_v1_header_tail}

  # Common helpers

  defp deserialize_aad(data, 0), do: {:ok, %{}, data}

  defp deserialize_aad(data, aad_length) when byte_size(data) >= aad_length do
    <<aad_binary::binary-size(aad_length), rest::binary>> = data

    case EncryptionContext.deserialize(aad_binary) do
      {:ok, context, <<>>} -> {:ok, context, rest}
      {:ok, _context, _trailing} -> {:error, :aad_length_mismatch}
      error -> error
    end
  end

  defp deserialize_aad(_insufficient_data, _aad_length), do: {:error, :incomplete_aad}

  defp encode_content_type(:non_framed), do: @content_type_non_framed
  defp encode_content_type(:framed), do: @content_type_framed

  defp decode_content_type(@content_type_non_framed), do: {:ok, :non_framed}
  defp decode_content_type(@content_type_framed), do: {:ok, :framed}
  defp decode_content_type(byte), do: {:error, {:invalid_content_type, byte}}
end
