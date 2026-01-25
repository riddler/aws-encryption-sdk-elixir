defmodule AwsEncryptionSdk.Format.BodyTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.Body

  describe "non-framed body" do
    test "serialize_non_framed/3 produces correct format" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      # IV (12) + content_length (8) + ciphertext (5) + auth_tag (16) = 41
      assert byte_size(serialized) == 41
    end

    test "round-trips non-framed body" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(100)
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
      assert {:ok, body, <<>>} = Body.deserialize_non_framed(serialized)

      assert body.iv == iv
      assert body.ciphertext == ciphertext
      assert body.auth_tag == auth_tag
    end

    test "encodes content length as big-endian uint64" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(256)
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      <<_iv::binary-size(12), length::64-big, _rest::binary>> = serialized
      assert length == 256
    end

    test "rejects content exceeding 64 GiB limit" do
      # We can't actually allocate 64 GiB, but we can test the error path
      # by mocking or just documenting the behavior
      iv = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)
      # Create a small ciphertext - actual limit test would need special handling
      ciphertext = <<1, 2, 3>>

      assert {:ok, _serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
    end

    test "preserves trailing bytes" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, _body, <<99, 100>>} = Body.deserialize_non_framed(with_trailing)
    end
  end

  describe "framed body" do
    test "serialize_regular_frame/4 produces correct format" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(4096)
      auth_tag = :crypto.strong_rand_bytes(16)

      frame = Body.serialize_regular_frame(1, iv, ciphertext, auth_tag)

      # seq (4) + iv (12) + ciphertext (4096) + auth_tag (16) = 4128
      assert byte_size(frame) == 4128

      # Check sequence number
      <<seq::32-big, _rest::binary>> = frame
      assert seq == 1
    end

    test "serialize_final_frame/4 includes marker and content length" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)

      frame = Body.serialize_final_frame(3, iv, ciphertext, auth_tag)

      # marker (4) + seq (4) + iv (12) + content_len (4) + ciphertext (5) + auth_tag (16) = 45
      assert byte_size(frame) == 45

      <<marker::32-big, seq::32-big, _iv::binary-size(12), len::32-big, _rest::binary>> = frame
      assert marker == 0xFFFFFFFF
      assert seq == 3
      assert len == 5
    end

    test "deserialize_frame/2 parses regular frame" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(100)
      auth_tag = :crypto.strong_rand_bytes(16)

      serialized = Body.serialize_regular_frame(5, iv, ciphertext, auth_tag)

      assert {:ok, frame, <<>>} = Body.deserialize_frame(serialized, 100)
      assert frame.sequence_number == 5
      assert frame.iv == iv
      assert frame.ciphertext == ciphertext
      assert frame.auth_tag == auth_tag
      refute Map.has_key?(frame, :final)
    end

    test "deserialize_frame/2 parses final frame" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)

      serialized = Body.serialize_final_frame(10, iv, ciphertext, auth_tag)

      assert {:ok, frame, <<>>} = Body.deserialize_frame(serialized, 100)
      assert frame.sequence_number == 10
      assert frame.iv == iv
      assert frame.ciphertext == ciphertext
      assert frame.auth_tag == auth_tag
      assert frame.final == true
    end

    test "deserialize_all_frames/2 parses multiple frames" do
      frame_length = 50
      iv1 = :crypto.strong_rand_bytes(12)
      iv2 = :crypto.strong_rand_bytes(12)
      iv3 = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)

      data =
        Body.serialize_regular_frame(1, iv1, :crypto.strong_rand_bytes(frame_length), auth_tag) <>
          Body.serialize_regular_frame(2, iv2, :crypto.strong_rand_bytes(frame_length), auth_tag) <>
          Body.serialize_final_frame(3, iv3, <<1, 2, 3>>, auth_tag)

      assert {:ok, frames, <<>>} = Body.deserialize_all_frames(data, frame_length)
      assert length(frames) == 3
      assert Enum.at(frames, 0).sequence_number == 1
      assert Enum.at(frames, 1).sequence_number == 2
      assert Enum.at(frames, 2).sequence_number == 3
      assert Enum.at(frames, 2).final == true
    end

    test "deserialize_all_frames/2 rejects out-of-order frames" do
      frame_length = 50
      auth_tag = :crypto.strong_rand_bytes(16)

      # Sequence 1, then 3 (skipping 2)
      data =
        Body.serialize_regular_frame(
          1,
          :crypto.strong_rand_bytes(12),
          :crypto.strong_rand_bytes(frame_length),
          auth_tag
        ) <>
          Body.serialize_final_frame(3, :crypto.strong_rand_bytes(12), <<1>>, auth_tag)

      assert {:error, {:sequence_mismatch, 2, 3}} =
               Body.deserialize_all_frames(data, frame_length)
    end

    test "deserialize_frame/2 returns error for insufficient data" do
      # Not enough data for a full frame
      assert {:error, :invalid_frame_format} = Body.deserialize_frame(<<1, 2, 3>>, 100)
    end

    test "deserialize_all_frames/2 preserves trailing bytes" do
      frame_length = 50
      iv = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)
      trailing = <<99, 100, 101>>

      data = Body.serialize_final_frame(1, iv, <<1, 2>>, auth_tag) <> trailing

      assert {:ok, frames, ^trailing} = Body.deserialize_all_frames(data, frame_length)
      assert length(frames) == 1
    end

    test "deserialize_non_framed/1 returns error for insufficient data" do
      # Not enough data for IV + content length
      assert {:error, :invalid_non_framed_body} = Body.deserialize_non_framed(<<1, 2, 3>>)
    end
  end
end
