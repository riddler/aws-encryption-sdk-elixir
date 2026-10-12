defmodule AwsEncryptionSdk.Format.Body do
  @moduledoc """
  Message body serialization and deserialization.

  Supports both framed and non-framed body formats.

  ## Non-Framed Format

  ```
  | Field           | Size      |
  |-----------------|-----------|
  | IV              | 12 bytes  |
  | Content Length  | 8 bytes   | Uint64
  | Ciphertext      | Variable  |
  | Auth Tag        | 16 bytes  |
  ```

  ## Framed Format

  Regular frames:
  ```
  | Field           | Size      |
  |-----------------|-----------|
  | Sequence Number | 4 bytes   | Uint32 (1, 2, 3, ...)
  | IV              | 12 bytes  |
  | Ciphertext      | frame_length bytes |
  | Auth Tag        | 16 bytes  |
  ```

  Final frame:
  ```
  | Field           | Size      |
  |-----------------|-----------|
  | Seq Number End  | 4 bytes   | 0xFFFFFFFF
  | Sequence Number | 4 bytes   | Actual sequence number
  | IV              | 12 bytes  |
  | Content Length  | 4 bytes   | Uint32
  | Ciphertext      | Variable  |
  | Auth Tag        | 16 bytes  |
  ```
  """

  @iv_length 12
  @auth_tag_length 16
  @final_frame_marker 0xFFFFFFFF
  # The specification allows at most 2^32 - 1 frames in one message. The
  # final frame's sequence number is the frame count, so no frame is
  # numbered above it and no regular frame reaches the final-frame marker.
  @max_frames 4_294_967_295
  # 2^36 - 32 = 64 GiB
  @max_non_framed_content 68_719_476_704

  @typedoc "Non-framed body structure"
  @type non_framed :: %{
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary()
        }

  @typedoc "Regular frame structure"
  @type regular_frame :: %{
          sequence_number: pos_integer(),
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary()
        }

  @typedoc "Final frame structure"
  @type final_frame :: %{
          sequence_number: pos_integer(),
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary(),
          final: true
        }

  @typedoc "Any frame type"
  @type frame :: regular_frame() | final_frame()

  # Non-framed body functions

  @doc """
  Serializes a non-framed body.

  ## Parameters

  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content
  - `auth_tag` - 16-byte authentication tag

  ## Returns

  `{:ok, binary}` on success, `{:error, reason}` if content exceeds 64 GiB limit.
  """
  @spec serialize_non_framed(binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, :content_too_large}
  def serialize_non_framed(iv, ciphertext, auth_tag)
      when byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    content_length = byte_size(ciphertext)

    if content_length > @max_non_framed_content do
      {:error, :content_too_large}
    else
      body =
        <<
          iv::binary-size(@iv_length),
          content_length::64-big,
          ciphertext::binary,
          auth_tag::binary-size(@auth_tag_length)
        >>

      {:ok, body}
    end
  end

  @doc """
  Deserializes a non-framed body.

  Returns `{:ok, body_map, rest}` on success.
  """
  @spec deserialize_non_framed(binary()) :: {:ok, non_framed(), binary()} | {:error, term()}
  def deserialize_non_framed(<<
        iv::binary-size(@iv_length),
        content_length::64-big,
        rest::binary
      >>)
      when content_length <= @max_non_framed_content do
    case rest do
      <<ciphertext::binary-size(content_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        body = %{
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag
        }

        {:ok, body, remaining}

      _insufficient_data ->
        {:error, :incomplete_non_framed_body}
    end
  end

  def deserialize_non_framed(
        <<_iv::binary-size(@iv_length), content_length::64-big, _rest::binary>>
      )
      when content_length > @max_non_framed_content do
    {:error, :content_too_large}
  end

  def deserialize_non_framed(_invalid), do: {:error, :invalid_non_framed_body}

  # Framed body functions

  @doc """
  Returns the number of frames a framed body holds for `plaintext_length`
  bytes split into frames of `frame_length` bytes.

  Every full frame but the last is a regular frame, and the remainder (or the
  last full frame) is the final frame: an empty plaintext is one empty final
  frame, and a plaintext of exactly `n * frame_length` bytes is `n` frames.
  """
  @spec frame_count(non_neg_integer(), pos_integer()) :: pos_integer()
  def frame_count(0, frame_length) when is_integer(frame_length) and frame_length > 0, do: 1

  def frame_count(plaintext_length, frame_length)
      when is_integer(plaintext_length) and plaintext_length > 0 and
             is_integer(frame_length) and frame_length > 0 do
    div(plaintext_length + frame_length - 1, frame_length)
  end

  @doc """
  Checks a message's frame count against the specification's limit of
  2^32 - 1 frames.

  Returns `:ok` when a message of `frame_count` frames may be written, and
  `{:error, :max_frames_exceeded}` when it would exceed the limit.
  """
  @spec check_frame_count(pos_integer()) :: :ok | {:error, :max_frames_exceeded}
  def check_frame_count(frame_count) when is_integer(frame_count) and frame_count > 0 do
    if frame_count <= @max_frames, do: :ok, else: {:error, :max_frames_exceeded}
  end

  @doc """
  Serializes a regular frame.

  ## Parameters

  - `sequence_number` - Frame sequence (1, 2, 3, ...), below 2^32 - 1: a
    final frame follows every regular frame
  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content (must be exactly frame_length bytes)
  - `auth_tag` - 16-byte authentication tag
  """
  @spec serialize_regular_frame(pos_integer(), binary(), binary(), binary()) :: binary()
  def serialize_regular_frame(sequence_number, iv, ciphertext, auth_tag)
      when is_integer(sequence_number) and sequence_number > 0 and
             sequence_number < @max_frames and
             byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    <<
      sequence_number::32-big,
      iv::binary-size(@iv_length),
      ciphertext::binary,
      auth_tag::binary-size(@auth_tag_length)
    >>
  end

  @doc """
  Serializes a final frame.

  ## Parameters

  - `sequence_number` - Frame sequence number, the message's frame count (at
    most 2^32 - 1)
  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content (may be shorter than frame_length)
  - `auth_tag` - 16-byte authentication tag
  """
  @spec serialize_final_frame(pos_integer(), binary(), binary(), binary()) :: binary()
  def serialize_final_frame(sequence_number, iv, ciphertext, auth_tag)
      when is_integer(sequence_number) and sequence_number > 0 and
             sequence_number <= @max_frames and
             byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    content_length = byte_size(ciphertext)

    <<
      @final_frame_marker::32-big,
      sequence_number::32-big,
      iv::binary-size(@iv_length),
      content_length::32-big,
      ciphertext::binary,
      auth_tag::binary-size(@auth_tag_length)
    >>
  end

  @doc """
  Deserializes a frame (regular or final).

  Returns `{:ok, frame_map, rest}` where frame_map includes `:final` key for final frames.
  """
  @spec deserialize_frame(binary(), pos_integer()) ::
          {:ok, frame(), binary()} | {:error, term()}
  def deserialize_frame(
        <<@final_frame_marker::32-big, sequence_number::32-big, iv::binary-size(@iv_length),
          content_length::32-big, rest::binary>>,
        _frame_length
      ) do
    case rest do
      <<ciphertext::binary-size(content_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        frame = %{
          sequence_number: sequence_number,
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag,
          final: true
        }

        {:ok, frame, remaining}

      _insufficient_data ->
        {:error, :incomplete_final_frame}
    end
  end

  def deserialize_frame(
        <<sequence_number::32-big, iv::binary-size(@iv_length), rest::binary>>,
        frame_length
      )
      when sequence_number != @final_frame_marker do
    case rest do
      <<ciphertext::binary-size(frame_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        frame = %{
          sequence_number: sequence_number,
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag
        }

        {:ok, frame, remaining}

      _insufficient_data ->
        {:error, :incomplete_regular_frame}
    end
  end

  def deserialize_frame(_invalid, _frame_length), do: {:error, :invalid_frame_format}

  @doc """
  Deserializes all frames from a framed body.

  Returns `{:ok, frames, rest}` where frames is a list ordered by sequence number.
  """
  @spec deserialize_all_frames(binary(), pos_integer()) ::
          {:ok, [frame()], binary()} | {:error, term()}
  def deserialize_all_frames(data, frame_length) do
    deserialize_frames_loop(data, frame_length, 1, [])
  end

  defp deserialize_frames_loop(data, frame_length, expected_seq, acc) do
    case deserialize_frame(data, frame_length) do
      {:ok, %{final: true} = frame, rest} ->
        if frame.sequence_number == expected_seq do
          {:ok, Enum.reverse([frame | acc]), rest}
        else
          {:error, {:sequence_mismatch, expected_seq, frame.sequence_number}}
        end

      {:ok, frame, rest} ->
        if frame.sequence_number == expected_seq do
          deserialize_frames_loop(rest, frame_length, expected_seq + 1, [frame | acc])
        else
          {:error, {:sequence_mismatch, expected_seq, frame.sequence_number}}
        end

      {:error, _reason} = error ->
        error
    end
  end
end
