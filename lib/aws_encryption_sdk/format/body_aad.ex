defmodule AwsEncryptionSdk.Format.BodyAad do
  @moduledoc """
  Message Body AAD (Additional Authenticated Data) serialization.

  Used as AAD input to AES-GCM when encrypting/decrypting message body content.

  ## Format

  Per message-body-aad.md:
  ```
  | Field           | Size           | Type   |
  |-----------------|----------------|--------|
  | Message ID      | 16 (v1) or 32 (v2) bytes | Binary |
  | Body AAD Content| Variable       | UTF-8  |
  | Sequence Number | 4 bytes        | Uint32 |
  | Content Length  | 8 bytes        | Uint64 |
  ```

  The Body AAD Content string varies by content type:
  - Non-framed: "AWSKMSEncryptionClient Single Block"
  - Regular frame: "AWSKMSEncryptionClient Frame"
  - Final frame: "AWSKMSEncryptionClient Final Frame"
  """

  @non_framed_content "AWSKMSEncryptionClient Single Block"
  @regular_frame_content "AWSKMSEncryptionClient Frame"
  @final_frame_content "AWSKMSEncryptionClient Final Frame"

  @typedoc "Content type for Body AAD"
  @type content_type :: :non_framed | :regular_frame | :final_frame

  @doc """
  Serializes Message Body AAD for use in AES-GCM encryption/decryption.

  ## Parameters

  - `message_id` - 16 bytes (v1) or 32 bytes (v2)
  - `content_type` - `:non_framed`, `:regular_frame`, or `:final_frame`
  - `sequence_number` - Frame sequence number (1 for non-framed)
  - `content_length` - Plaintext length being encrypted

  ## Examples

      iex> message_id = :crypto.strong_rand_bytes(32)
      iex> aad = AwsEncryptionSdk.Format.BodyAad.serialize(message_id, :non_framed, 1, 1024)
      iex> byte_size(aad)
      79  # 32 + 35 + 4 + 8
  """
  @spec serialize(binary(), content_type(), pos_integer(), non_neg_integer()) :: binary()
  def serialize(message_id, content_type, sequence_number, content_length)
      when is_binary(message_id) and
             content_type in [:non_framed, :regular_frame, :final_frame] and
             is_integer(sequence_number) and sequence_number > 0 and
             is_integer(content_length) and content_length >= 0 do
    body_content = content_string(content_type)

    <<
      message_id::binary,
      body_content::binary,
      sequence_number::32-big,
      content_length::64-big
    >>
  end

  @doc """
  Returns the Body AAD Content string for a given content type.
  """
  @spec content_string(content_type()) :: String.t()
  def content_string(:non_framed), do: @non_framed_content
  def content_string(:regular_frame), do: @regular_frame_content
  def content_string(:final_frame), do: @final_frame_content
end
