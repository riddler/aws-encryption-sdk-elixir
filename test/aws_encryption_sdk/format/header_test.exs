defmodule AwsEncryptionSdk.Format.HeaderTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "generate_message_id/1" do
    test "generates 16 bytes for version 1" do
      id = Header.generate_message_id(1)
      assert byte_size(id) == 16
    end

    test "generates 32 bytes for version 2" do
      id = Header.generate_message_id(2)
      assert byte_size(id) == 32
    end

    test "generates unique IDs" do
      id1 = Header.generate_message_id(2)
      id2 = Header.generate_message_id(2)
      assert id1 != id2
    end
  end

  describe "v2 header serialization" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{"key" => "value"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :framed,
        frame_length: 4096,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_iv: nil,
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header: header}
    end

    test "round-trips a v2 header", %{header: header} do
      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)

      assert deserialized.version == header.version
      assert deserialized.algorithm_suite.id == header.algorithm_suite.id
      assert deserialized.message_id == header.message_id
      assert deserialized.encryption_context == header.encryption_context
      assert deserialized.content_type == header.content_type
      assert deserialized.frame_length == header.frame_length
      assert deserialized.algorithm_suite_data == header.algorithm_suite_data
      assert deserialized.header_auth_tag == header.header_auth_tag
    end

    test "starts with version byte 0x02", %{header: header} do
      assert {:ok, <<0x02, _rest::binary>>} = Header.serialize(header)
    end

    test "encodes algorithm suite ID as big-endian", %{header: header} do
      assert {:ok, <<0x02, 0x04, 0x78, _rest::binary>>} = Header.serialize(header)
    end

    test "non-framed content type sets frame_length to 0" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 4096,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)
      assert deserialized.frame_length == 0
    end
  end

  describe "v1 header serialization" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      header = %Header{
        version: 1,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(16),
        encryption_context: %{"key" => "value"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :framed,
        frame_length: 4096,
        algorithm_suite_data: nil,
        header_iv: :crypto.strong_rand_bytes(12),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header: header}
    end

    test "round-trips a v1 header", %{header: header} do
      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)

      assert deserialized.version == header.version
      assert deserialized.algorithm_suite.id == header.algorithm_suite.id
      assert deserialized.message_id == header.message_id
      assert deserialized.encryption_context == header.encryption_context
      assert deserialized.content_type == header.content_type
      assert deserialized.frame_length == header.frame_length
      assert deserialized.header_iv == header.header_iv
      assert deserialized.header_auth_tag == header.header_auth_tag
    end

    test "starts with version 0x01 and type 0x80", %{header: header} do
      assert {:ok, <<0x01, 0x80, _rest::binary>>} = Header.serialize(header)
    end
  end

  describe "deserialize/1 error handling" do
    test "rejects unsupported version" do
      assert {:error, {:unsupported_version, 0x03}} = Header.deserialize(<<0x03, 0::200>>)
    end

    test "rejects invalid type for v1" do
      assert {:error, {:invalid_type, 0x81}} = Header.deserialize(<<0x01, 0x81, 0::200>>)
    end

    test "rejects unknown algorithm suite" do
      # v2 header with invalid algorithm ID 0xFFFF
      header = <<0x02, 0xFF, 0xFF, 0::800>>
      assert {:error, :unknown_suite_id} = Header.deserialize(header)
    end
  end
end
