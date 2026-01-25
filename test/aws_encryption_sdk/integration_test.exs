defmodule AwsEncryptionSdk.IntegrationTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk
  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  describe "cross-suite compatibility" do
    test "v2 message (0x0478) round-trips correctly" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert suite.message_format_version == 2
      assert_round_trip(suite, "Committed suite message")
    end

    test "v1 message (0x0178) round-trips correctly" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      assert suite.message_format_version == 1
      assert_round_trip(suite, "Legacy HKDF suite message")
    end
  end

  describe "edge cases" do
    test "handles unicode plaintext" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert_round_trip(suite, "Hello, 世界! 🔐")
    end

    test "handles binary plaintext with null bytes" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert_round_trip(suite, <<0, 1, 0, 2, 0, 3>>)
    end

    test "handles encryption context with special characters" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      context = %{
        "key with spaces" => "value with spaces",
        "unicode-key-🔑" => "unicode-value-🔐"
      }

      enc_materials = EncryptionMaterials.new(suite, context, [edk], plaintext_data_key)
      assert {:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, "test")

      dec_materials = DecryptionMaterials.new(suite, context, plaintext_data_key)
      assert {:ok, dec_result} = AwsEncryptionSdk.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.encryption_context == context
    end
  end

  describe "error conditions" do
    test "decrypt fails with wrong data key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      correct_key = :crypto.strong_rand_bytes(32)
      wrong_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", correct_key)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], correct_key)
      assert {:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, "secret")

      dec_materials = DecryptionMaterials.new(suite, %{}, wrong_key)
      assert {:error, _reason} = AwsEncryptionSdk.decrypt(enc_result.ciphertext, dec_materials)
    end

    test "decrypts successfully and returns actual encryption context from message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      enc_materials =
        EncryptionMaterials.new(suite, %{"key" => "value1"}, [edk], plaintext_data_key)

      assert {:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, "secret")

      # Decrypt with different encryption context in materials
      # (The decrypt function returns the actual EC from the message header, not from materials)
      dec_materials = DecryptionMaterials.new(suite, %{"key" => "value2"}, plaintext_data_key)
      assert {:ok, dec_result} = AwsEncryptionSdk.decrypt(enc_result.ciphertext, dec_materials)

      # The returned encryption context should match what was encrypted, not what was in dec_materials
      assert dec_result.encryption_context == %{"key" => "value1"}
      assert dec_result.plaintext == "secret"
    end
  end

  describe "public API convenience functions" do
    test "encrypt/2 and decrypt/2 work via main module" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)
      {:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, "test via main module")

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      {:ok, dec_result} = AwsEncryptionSdk.decrypt(enc_result.ciphertext, dec_materials)

      assert dec_result.plaintext == "test via main module"
    end
  end

  # Helper function
  defp assert_round_trip(suite, plaintext) do
    plaintext_data_key = :crypto.strong_rand_bytes(div(suite.data_key_length, 8))
    edk = EncryptedDataKey.new("test-provider", "test-key", plaintext_data_key)

    enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)
    assert {:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, plaintext)

    dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
    assert {:ok, dec_result} = AwsEncryptionSdk.decrypt(enc_result.ciphertext, dec_materials)
    assert dec_result.plaintext == plaintext
  end
end
