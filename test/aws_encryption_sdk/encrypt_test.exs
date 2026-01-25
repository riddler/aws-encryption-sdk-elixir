defmodule AwsEncryptionSdk.EncryptTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Decrypt
  alias AwsEncryptionSdk.Encrypt
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  describe "encrypt/3" do
    test "encrypts plaintext with committed unsigned suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test-provider", "test-key-info", plaintext_data_key)

      materials =
        EncryptionMaterials.new(
          suite,
          %{"purpose" => "test"},
          [edk],
          plaintext_data_key
        )

      assert {:ok, result} = Encrypt.encrypt(materials, "Hello, World!")
      assert is_binary(result.ciphertext)
      assert result.algorithm_suite == suite
      assert result.encryption_context == %{"purpose" => "test"}
    end

    test "encrypts empty plaintext" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test-provider", "key", plaintext_data_key)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:ok, result} = Encrypt.encrypt(materials, <<>>)
      assert is_binary(result.ciphertext)
    end

    test "rejects reserved encryption context keys" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", plaintext_data_key)

      materials =
        EncryptionMaterials.new(
          suite,
          %{"aws-crypto-public-key" => "value"},
          [edk],
          plaintext_data_key
        )

      assert {:error, {:reserved_keys, ["aws-crypto-public-key"]}} =
               Encrypt.encrypt(materials, "test")
    end

    test "rejects deprecated algorithm suite for encryption" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", plaintext_data_key)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:error, :deprecated_algorithm_suite} = Encrypt.encrypt(materials, "test")
    end
  end

  describe "encrypt/3 then decrypt/2 round-trip" do
    test "round-trips with committed unsigned suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test-provider", "test-key", plaintext_data_key)
      plaintext = "Hello, this is a test message for round-trip encryption!"

      enc_materials =
        EncryptionMaterials.new(
          suite,
          %{"context" => "value"},
          [edk],
          plaintext_data_key
        )

      # Encrypt
      assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext)

      # Create decryption materials
      dec_materials =
        DecryptionMaterials.new(
          suite,
          enc_result.encryption_context,
          plaintext_data_key
        )

      # Decrypt
      assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
      assert dec_result.encryption_context == %{"context" => "value"}
    end

    test "round-trips with non-committed HKDF suite" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)
      plaintext = "Legacy suite test"

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)
      assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "round-trips with multi-frame message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      # Create plaintext larger than one frame
      plaintext = :crypto.strong_rand_bytes(10_000)

      enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      # Use small frame size to force multiple frames
      assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext, frame_length: 1024)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "round-trips with various plaintext sizes" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      for size <- [0, 1, 100, 4096, 4097, 8192] do
        plaintext = :crypto.strong_rand_bytes(size)

        enc_materials =
          EncryptionMaterials.new(suite, %{"size" => "#{size}"}, [edk], plaintext_data_key)

        assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext)

        dec_materials = DecryptionMaterials.new(suite, %{"size" => "#{size}"}, plaintext_data_key)
        assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
        assert dec_result.plaintext == plaintext, "Failed for size #{size}"
      end
    end
  end
end
