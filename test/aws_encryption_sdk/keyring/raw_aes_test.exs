defmodule AwsEncryptionSdk.Keyring.RawAesTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  describe "new/4" do
    test "creates keyring with valid 256-bit key" do
      key = :crypto.strong_rand_bytes(32)
      assert {:ok, keyring} = RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)
      assert keyring.key_namespace == "my-namespace"
      assert keyring.key_name == "my-key"
      assert keyring.wrapping_key == key
      assert keyring.wrapping_algorithm == :aes_256_gcm
    end

    test "creates keyring with valid 192-bit key" do
      key = :crypto.strong_rand_bytes(24)
      assert {:ok, _keyring} = RawAes.new("ns", "name", key, :aes_192_gcm)
    end

    test "creates keyring with valid 128-bit key" do
      key = :crypto.strong_rand_bytes(16)
      assert {:ok, _keyring} = RawAes.new("ns", "name", key, :aes_128_gcm)
    end

    test "rejects reserved provider ID" do
      key = :crypto.strong_rand_bytes(32)
      assert {:error, :reserved_provider_id} = RawAes.new("aws-kms", "key", key, :aes_256_gcm)

      assert {:error, :reserved_provider_id} =
               RawAes.new("aws-kms-mrk", "key", key, :aes_256_gcm)
    end

    test "rejects invalid wrapping algorithm" do
      key = :crypto.strong_rand_bytes(32)
      assert {:error, :invalid_wrapping_algorithm} = RawAes.new("ns", "key", key, :aes_512_gcm)
    end

    test "rejects key length mismatch" do
      key_256 = :crypto.strong_rand_bytes(32)
      key_128 = :crypto.strong_rand_bytes(16)

      assert {:error, {:invalid_key_length, expected: 128, actual: 256}} =
               RawAes.new("ns", "key", key_256, :aes_128_gcm)

      assert {:error, {:invalid_key_length, expected: 256, actual: 128}} =
               RawAes.new("ns", "key", key_128, :aes_256_gcm)
    end
  end

  describe "serialize_provider_info/2" do
    test "serializes provider info correctly" do
      iv = :crypto.strong_rand_bytes(12)
      result = RawAes.serialize_provider_info("my-key", iv)

      # "my-key" (6) + tag_len (4) + iv_len (4) + iv (12) = 26 (no length prefix per spec)
      assert byte_size(result) == 26

      # Verify structure
      <<
        key_name::binary-size(6),
        tag_length_bits::32-big,
        iv_length::32-big,
        extracted_iv::binary-size(12)
      >> = result

      assert key_name == "my-key"
      assert tag_length_bits == 128
      assert iv_length == 12
      assert extracted_iv == iv
    end
  end

  describe "deserialize_provider_info/2" do
    test "deserializes valid provider info" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("ns", "test-key", key, :aes_256_gcm)
      iv = :crypto.strong_rand_bytes(12)
      serialized = RawAes.serialize_provider_info("test-key", iv)

      assert {:ok, info} = RawAes.deserialize_provider_info(keyring, serialized)
      assert info.key_name == "test-key"
      assert info.tag_length_bits == 128
      assert info.iv_length == 12
      assert info.iv == iv
    end

    test "returns error for invalid format" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("ns", "test-key", key, :aes_256_gcm)

      assert {:error, :invalid_provider_info_format} =
               RawAes.deserialize_provider_info(keyring, <<1, 2, 3>>)
    end

    test "round-trips through serialize/deserialize" do
      key = :crypto.strong_rand_bytes(32)
      key_name = "namespace/key-name-with-special-chars"
      {:ok, keyring} = RawAes.new("ns", key_name, key, :aes_256_gcm)
      iv = :crypto.strong_rand_bytes(12)

      serialized = RawAes.serialize_provider_info(key_name, iv)
      assert {:ok, info} = RawAes.deserialize_provider_info(keyring, serialized)

      assert info.key_name == key_name
      assert info.iv == iv
    end
  end

  describe "wrap_key/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "generates data key when not present", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})
      assert materials.plaintext_data_key == nil

      assert {:ok, result} = RawAes.wrap_key(keyring, materials)
      assert is_binary(result.plaintext_data_key)
      assert byte_size(result.plaintext_data_key) == 32
    end

    test "wraps existing data key", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:ok, result} = RawAes.wrap_key(keyring, materials)
      assert result.plaintext_data_key == existing_key
    end

    test "adds EDK to materials", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:ok, result} = RawAes.wrap_key(keyring, materials)
      assert length(result.encrypted_data_keys) == 1

      [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "test-namespace"
      assert is_binary(edk.key_provider_info)
      assert is_binary(edk.ciphertext)
    end

    test "EDK provider info contains key name and IV", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:ok, result} = RawAes.wrap_key(keyring, materials)
      [edk] = result.encrypted_data_keys

      assert {:ok, info} = RawAes.deserialize_provider_info(keyring, edk.key_provider_info)
      assert info.key_name == "test-key"
      assert info.iv_length == 12
      assert info.tag_length_bits == 128
    end

    test "uses encryption context as AAD", %{keyring: keyring, suite: suite} do
      ec = %{"key1" => "value1", "key2" => "value2"}
      materials = EncryptionMaterials.new_for_encrypt(suite, ec)

      # Should succeed - AAD is used internally
      assert {:ok, _result} = RawAes.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "decrypts EDK created by same keyring", %{keyring: keyring, suite: suite} do
      ec = %{"context" => "test"}

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      assert {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:ok, dec_result} =
               RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "fails if plaintext data key already set", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, existing_key)

      assert {:error, :plaintext_data_key_already_set} =
               RawAes.unwrap_key(keyring, materials, [])
    end

    test "skips EDKs with wrong provider ID", %{keyring: keyring, suite: suite} do
      ec = %{}

      # Create EDK with different provider
      other_key = :crypto.strong_rand_bytes(32)
      {:ok, other_keyring} = RawAes.new("other-namespace", "test-key", other_key, :aes_256_gcm)
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:error, :unable_to_decrypt_data_key} =
               RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "skips EDKs with wrong key name", %{keyring: keyring, suite: suite} do
      ec = %{}

      # Create EDK with different key name
      {:ok, other_keyring} =
        RawAes.new("test-namespace", "other-key", keyring.wrapping_key, :aes_256_gcm)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:error, :unable_to_decrypt_data_key} =
               RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "fails with wrong encryption context (AAD mismatch)", %{keyring: keyring, suite: suite} do
      # Encrypt with one context
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"key" => "value1"})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      # Try to decrypt with different context
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"key" => "value2"})

      assert {:error, :unable_to_decrypt_data_key} =
               RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "returns error when no EDKs provided", %{keyring: keyring, suite: suite} do
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      assert {:error, :unable_to_decrypt_data_key} = RawAes.unwrap_key(keyring, materials, [])
    end
  end

  describe "edge cases" do
    test "handles empty encryption context" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with empty context
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      # Decrypt with empty context
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "handles large encryption context" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Create large encryption context
      ec = for i <- 1..100, into: %{}, do: {"key-#{i}", "value-#{String.duplicate("x", 100)}"}

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      {:ok, dec_result} =
        RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "handles unicode key names" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("namespace-日本語", "キー名-🔑", key, :aes_256_gcm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "round-trips all supported key sizes" do
      for {size, algorithm} <- [{16, :aes_128_gcm}, {24, :aes_192_gcm}, {32, :aes_256_gcm}] do
        key = :crypto.strong_rand_bytes(size)
        {:ok, keyring} = RawAes.new("ns", "key", key, algorithm)
        suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

        enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
        {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

        dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

        {:ok, dec_result} =
          RawAes.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

        assert dec_result.plaintext_data_key == enc_result.plaintext_data_key,
               "Round-trip failed for #{algorithm}"
      end
    end
  end
end
