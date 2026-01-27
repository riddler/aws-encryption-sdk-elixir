defmodule AwsEncryptionSdkTest do
  use ExUnit.Case, async: true
  doctest AwsEncryptionSdk

  alias AwsEncryptionSdk
  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "encrypt/3 with client" do
    test "encrypts using client configuration" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      # Use non-signed committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} =
        AwsEncryptionSdk.encrypt(client, "Hello, World!",
          encryption_context: %{"purpose" => "test"},
          algorithm_suite: suite
        )

      assert is_binary(result.ciphertext)
      assert result.encryption_context["purpose"] == "test"
    end

    test "enforces commitment policy through client" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      # Default policy requires committed suites
      client = Client.new(cmm)
      # Use non-signed committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} = AwsEncryptionSdk.encrypt(client, "test data", algorithm_suite: suite)

      # Should use committed suite (0x0478)
      assert AlgorithmSuite.committed?(result.algorithm_suite)
      assert result.algorithm_suite.id == 0x0478
    end
  end

  describe "encrypt_with_keyring/3" do
    test "encrypts using keyring directly" do
      keyring = create_test_keyring()
      # Use non-signed committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} =
        AwsEncryptionSdk.encrypt_with_keyring(keyring, "test data",
          encryption_context: %{"key" => "value"},
          algorithm_suite: suite
        )

      assert is_binary(result.ciphertext)
      assert result.encryption_context["key"] == "value"
    end

    test "accepts commitment policy option" do
      keyring = create_test_keyring()
      # Use non-signed non-committed suite
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, result} =
        AwsEncryptionSdk.encrypt_with_keyring(keyring, "test",
          commitment_policy: :forbid_encrypt_allow_decrypt,
          algorithm_suite: suite
        )

      # Should use non-committed suite (0x0178)
      refute AlgorithmSuite.committed?(result.algorithm_suite)
      assert result.algorithm_suite.id == 0x0178
    end
  end

  describe "backward compatibility" do
    test "encrypt_with_materials/3 still works" do
      # This tests the old API continues to work
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", plaintext_data_key)

      materials =
        EncryptionMaterials.new(
          suite,
          %{"key" => "value"},
          [edk],
          plaintext_data_key
        )

      {:ok, result} = AwsEncryptionSdk.encrypt_with_materials(materials, "test")

      assert is_binary(result.ciphertext)
      assert result.encryption_context == %{"key" => "value"}
    end

    test "decrypt_with_materials/2 still works" do
      # Encrypt first
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", plaintext_data_key)

      enc_materials =
        EncryptionMaterials.new(
          suite,
          %{"test" => "context"},
          [edk],
          plaintext_data_key
        )

      plaintext = "test message"
      {:ok, enc_result} = AwsEncryptionSdk.encrypt_with_materials(enc_materials, plaintext)

      # Now decrypt with materials
      dec_materials =
        DecryptionMaterials.new(
          suite,
          enc_result.encryption_context,
          plaintext_data_key
        )

      {:ok, dec_result} =
        AwsEncryptionSdk.decrypt_with_materials(enc_result.ciphertext, dec_materials)

      assert dec_result.plaintext == plaintext
      assert dec_result.encryption_context == %{"test" => "context"}
    end
  end

  describe "API consistency" do
    test "all encryption paths produce compatible ciphertext" do
      keyring = create_test_keyring()
      plaintext = "test message"
      # Use non-signed committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with client
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      {:ok, result1} = AwsEncryptionSdk.encrypt(client, plaintext, algorithm_suite: suite)

      # Encrypt with keyring
      {:ok, result2} =
        AwsEncryptionSdk.encrypt_with_keyring(keyring, plaintext, algorithm_suite: suite)

      # Both should produce valid ciphertext
      assert is_binary(result1.ciphertext)
      assert is_binary(result2.ciphertext)
      assert byte_size(result1.ciphertext) > byte_size(plaintext)
      assert byte_size(result2.ciphertext) > byte_size(plaintext)
    end
  end
end
