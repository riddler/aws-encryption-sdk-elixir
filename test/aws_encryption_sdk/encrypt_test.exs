defmodule AwsEncryptionSdk.EncryptTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.ECDSA
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

    test "accepts reserved encryption context keys from CMM" do
      # Note: Encrypt.encrypt no longer validates reserved keys because the CMM
      # may legitimately add them (e.g., aws-crypto-public-key for signed suites).
      # User-provided context validation happens at the Client layer.
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

      # Should succeed since CMM may have added this key
      assert {:ok, result} = Encrypt.encrypt(materials, "test")
      assert result.encryption_context["aws-crypto-public-key"] == "value"
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

    test "round-trips with signed committed suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)
      plaintext = "Test with signed suite"

      # Generate signing key pair
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      enc_materials =
        EncryptionMaterials.new(
          suite,
          %{"purpose" => "signed"},
          [edk],
          plaintext_data_key,
          signing_key: private_key
        )

      assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext)

      # Verify ciphertext has footer (signature)
      assert byte_size(enc_result.ciphertext) > byte_size(plaintext)

      # Create decryption materials with verification key
      dec_materials =
        DecryptionMaterials.new(
          suite,
          enc_result.encryption_context,
          plaintext_data_key,
          verification_key: public_key
        )

      assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "round-trips with signed non-committed suite" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)
      plaintext = "Legacy signed suite test"

      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      enc_materials =
        EncryptionMaterials.new(
          suite,
          %{},
          [edk],
          plaintext_data_key,
          signing_key: private_key
        )

      assert {:ok, enc_result} = Encrypt.encrypt(enc_materials, plaintext)

      dec_materials =
        DecryptionMaterials.new(suite, enc_result.encryption_context, plaintext_data_key,
          verification_key: public_key
        )

      assert {:ok, dec_result} = Decrypt.decrypt(enc_result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end
  end

  describe "frame length edge cases" do
    test "encrypts with very small frame length" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)
      plaintext = "Small frames test"

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      # Use very small frame length (1 byte per frame)
      assert {:ok, result} = Encrypt.encrypt(materials, plaintext, frame_length: 1)
      assert is_binary(result.ciphertext)
    end

    test "encrypts with plaintext exactly matching frame length" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      frame_length = 100
      plaintext = :crypto.strong_rand_bytes(frame_length)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:ok, result} = Encrypt.encrypt(materials, plaintext, frame_length: frame_length)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "encrypts with plaintext one byte over frame length" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      frame_length = 100
      plaintext = :crypto.strong_rand_bytes(frame_length + 1)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:ok, result} = Encrypt.encrypt(materials, plaintext, frame_length: frame_length)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "encrypts with plaintext one byte under frame length" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      frame_length = 100
      plaintext = :crypto.strong_rand_bytes(frame_length - 1)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:ok, result} = Encrypt.encrypt(materials, plaintext, frame_length: frame_length)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end

    test "encrypts with multiple exact frames" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key", plaintext_data_key)

      frame_length = 100
      # Exactly 3 frames
      plaintext = :crypto.strong_rand_bytes(frame_length * 3)

      materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

      assert {:ok, result} = Encrypt.encrypt(materials, plaintext, frame_length: frame_length)

      dec_materials = DecryptionMaterials.new(suite, %{}, plaintext_data_key)
      assert {:ok, dec_result} = Decrypt.decrypt(result.ciphertext, dec_materials)
      assert dec_result.plaintext == plaintext
    end
  end
end
