defmodule AwsEncryptionSdk.Format.MessageTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.Footer
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "requires_footer?/1" do
    test "returns true for signed suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      assert Message.requires_footer?(header)
    end

    test "returns false for unsigned suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      refute Message.requires_footer?(header)
    end
  end

  describe "deserialize/1 with non-framed body" do
    test "deserializes unsigned message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{"k" => "v"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)
      {:ok, body_bin} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      message_bin = header_bin <> body_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.algorithm_suite.id == suite.id
      assert message.body.ciphertext == ciphertext
      assert message.footer == nil
    end

    test "deserializes signed message with footer" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)
      {:ok, body_bin} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      signature = :crypto.strong_rand_bytes(103)
      {:ok, footer_bin} = Footer.serialize(signature)

      message_bin = header_bin <> body_bin <> footer_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.algorithm_suite.id == suite.id
      assert message.body.ciphertext == ciphertext
      assert message.footer.signature == signature
    end
  end

  describe "deserialize/1 with framed body" do
    test "deserializes framed message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      frame_length = 100

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :framed,
        frame_length: frame_length,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      auth_tag = :crypto.strong_rand_bytes(16)

      body_bin =
        Body.serialize_regular_frame(
          1,
          :crypto.strong_rand_bytes(12),
          :crypto.strong_rand_bytes(frame_length),
          auth_tag
        ) <>
          Body.serialize_final_frame(2, :crypto.strong_rand_bytes(12), <<1, 2, 3>>, auth_tag)

      message_bin = header_bin <> body_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.content_type == :framed
      assert length(message.body) == 2
      assert Enum.at(message.body, 0).sequence_number == 1
      assert Enum.at(message.body, 1).sequence_number == 2
      assert Enum.at(message.body, 1).final == true
    end
  end
end
