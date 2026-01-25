defmodule AwsEncryptionSdk.Format.BodyAadTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.BodyAad

  describe "serialize/4" do
    test "produces correct size for v1 message ID (16 bytes)" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :non_framed, 1, 1024)

      # 16 + 35 ("AWSKMSEncryptionClient Single Block") + 4 + 8 = 63
      assert byte_size(aad) == 63
    end

    test "produces correct size for v2 message ID (32 bytes)" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :non_framed, 1, 1024)

      # 32 + 35 + 4 + 8 = 79
      assert byte_size(aad) == 79
    end

    test "produces correct size for regular frame" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :regular_frame, 1, 4096)

      # 32 + 28 ("AWSKMSEncryptionClient Frame") + 4 + 8 = 72
      assert byte_size(aad) == 72
    end

    test "produces correct size for final frame" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :final_frame, 5, 100)

      # 32 + 34 ("AWSKMSEncryptionClient Final Frame") + 4 + 8 = 78
      assert byte_size(aad) == 78
    end

    test "includes message ID at start" do
      message_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      aad = BodyAad.serialize(message_id, :non_framed, 1, 0)

      assert binary_part(aad, 0, 16) == message_id
    end

    test "includes content string after message ID" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :regular_frame, 1, 0)

      content_string = binary_part(aad, 16, 28)
      assert content_string == "AWSKMSEncryptionClient Frame"
    end

    test "encodes sequence number as big-endian uint32" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :non_framed, 256, 0)

      # Sequence number starts after message_id (16) + content string (35)
      <<_skip::binary-size(51), seq::32-big, _rest::binary>> = aad
      assert seq == 256
    end

    test "encodes content length as big-endian uint64" do
      message_id = :crypto.strong_rand_bytes(16)
      content_length = 0x0001_0002_0003_0004
      aad = BodyAad.serialize(message_id, :non_framed, 1, content_length)

      # Content length is last 8 bytes
      <<_skip::binary-size(55), len::64-big>> = aad
      assert len == content_length
    end
  end

  describe "content_string/1" do
    test "returns correct string for non_framed" do
      assert BodyAad.content_string(:non_framed) == "AWSKMSEncryptionClient Single Block"
    end

    test "returns correct string for regular_frame" do
      assert BodyAad.content_string(:regular_frame) == "AWSKMSEncryptionClient Frame"
    end

    test "returns correct string for final_frame" do
      assert BodyAad.content_string(:final_frame) == "AWSKMSEncryptionClient Final Frame"
    end
  end
end
