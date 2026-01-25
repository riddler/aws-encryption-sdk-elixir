defmodule AwsEncryptionSdk.DecryptTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Decrypt
  alias AwsEncryptionSdk.Encrypt
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.TestSupport.TestVectorHarness

  # NOTE: Full test vector validation requires keyring implementation to unwrap EDKs.
  # These tests are skipped until Raw AES Keyring is implemented.
  # Round-trip tests in encrypt_test.exs provide comprehensive validation.

  describe "decrypt/2 with test vectors" do
    setup do
      manifest_path = "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"

      case File.exists?(manifest_path) do
        true ->
          {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
          {:ok, harness: harness}

        false ->
          {:ok, harness: nil}
      end
    end

    @tag :test_vectors
    @tag :skip
    test "decrypts raw AES-256 keyring message", %{harness: harness} do
      skip_if_no_harness(harness)

      # Use specific test ID from plan
      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"

      # Load test data
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, expected_plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)

      # Get key material
      {:ok, key_data} = TestVectorHarness.get_key(harness, "aes-256")
      {:ok, plaintext_data_key} = TestVectorHarness.decode_key_material(key_data)

      # Parse message to get algorithm suite and encryption context
      {:ok, message, <<>>} = Message.deserialize(ciphertext)

      # Create decryption materials
      materials =
        DecryptionMaterials.new(
          message.header.algorithm_suite,
          message.header.encryption_context,
          plaintext_data_key
        )

      # Decrypt
      assert {:ok, result} = Decrypt.decrypt(ciphertext, materials)
      assert result.plaintext == expected_plaintext
    end

    @tag :test_vectors
    @tag :skip
    test "decrypts raw AES-128 keyring message", %{harness: harness} do
      skip_if_no_harness(harness)

      # Use specific test ID from plan
      test_id = "4be2393c-2916-4668-ae7a-d26ddb8de593"

      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, expected_plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)
      {:ok, key_data} = TestVectorHarness.get_key(harness, "aes-128")
      {:ok, plaintext_data_key} = TestVectorHarness.decode_key_material(key_data)
      {:ok, message, <<>>} = Message.deserialize(ciphertext)

      materials =
        DecryptionMaterials.new(
          message.header.algorithm_suite,
          message.header.encryption_context,
          plaintext_data_key
        )

      assert {:ok, result} = Decrypt.decrypt(ciphertext, materials)
      assert result.plaintext == expected_plaintext
    end
  end

  describe "decrypt/2 error cases" do
    test "detects Base64-encoded message (version 1)" do
      # "AQ" is Base64 of 0x01 (version 1)
      base64_message = "AQVeryLongBase64EncodedMessage..."

      materials =
        DecryptionMaterials.new(
          AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
          %{},
          :crypto.strong_rand_bytes(32)
        )

      assert {:error, :base64_encoded_message} = Decrypt.decrypt(base64_message, materials)
    end

    test "detects Base64-encoded message (version 2)" do
      # "Ag" is Base64 of 0x02 (version 2)
      base64_message = "AgVeryLongBase64EncodedMessage..."

      materials =
        DecryptionMaterials.new(
          AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
          %{},
          :crypto.strong_rand_bytes(32)
        )

      assert {:error, :base64_encoded_message} = Decrypt.decrypt(base64_message, materials)
    end

    test "fails with commitment mismatch for committed suite" do
      # Create an encrypted message with one key
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      correct_key = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", correct_key)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], correct_key)
      {:ok, enc_result} = Encrypt.encrypt(enc_materials, "test")

      # Try to decrypt with wrong key (commitment will fail)
      {:ok, message, _rest} = Message.deserialize(enc_result.ciphertext)

      dec_materials =
        DecryptionMaterials.new(
          message.header.algorithm_suite,
          message.header.encryption_context,
          wrong_key
        )

      assert {:error, :commitment_mismatch} =
               Decrypt.decrypt(enc_result.ciphertext, dec_materials)
    end

    test "fails with header authentication failed" do
      # Create a message then tamper with the header auth tag
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)
      {:ok, enc_result} = Encrypt.encrypt(enc_materials, "test")

      # Tamper with the header auth tag (last 16 bytes of header before body)
      {:ok, message, _rest} = Message.deserialize(enc_result.ciphertext)
      {:ok, header_bytes} = Header.serialize(message.header)
      header_len = byte_size(header_bytes)

      # Flip a bit in the auth tag
      <<prefix::binary-size(header_len - 1), last_byte::8, rest::binary>> = enc_result.ciphertext
      tampered = <<prefix::binary, bxor(last_byte, 1)::8, rest::binary>>

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:error, :header_authentication_failed} = Decrypt.decrypt(tampered, dec_materials)
    end

    test "fails with body authentication failed when frame is tampered" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)
      {:ok, enc_result} = Encrypt.encrypt(enc_materials, "test data for tampering")

      # Tamper with the ciphertext body (flip a bit somewhere in the middle)
      {:ok, message, _rest} = Message.deserialize(enc_result.ciphertext)
      {:ok, header_bytes} = Header.serialize(message.header)
      header_len = byte_size(header_bytes)
      mid_point = header_len + 50

      <<prefix::binary-size(mid_point), byte::8, rest::binary>> = enc_result.ciphertext
      tampered = <<prefix::binary, bxor(byte, 1)::8, rest::binary>>

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:error, :body_authentication_failed} = Decrypt.decrypt(tampered, dec_materials)
    end
  end

  # Helper functions

  defp skip_if_no_harness(nil) do
    flunk("Test vectors not available")
  end

  defp skip_if_no_harness(_harness), do: :ok
end
