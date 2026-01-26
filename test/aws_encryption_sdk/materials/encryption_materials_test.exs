defmodule AwsEncryptionSdk.Materials.EncryptionMaterialsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  describe "new/5" do
    test "creates materials with required fields" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      edk = EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)
      key = :crypto.strong_rand_bytes(32)

      materials = EncryptionMaterials.new(suite, %{"ctx" => "val"}, [edk], key)

      assert materials.algorithm_suite == suite
      assert materials.encryption_context == %{"ctx" => "val"}
      assert materials.encrypted_data_keys == [edk]
      assert materials.plaintext_data_key == key
      assert materials.signing_key == nil
      assert materials.required_encryption_context_keys == []
    end

    test "creates materials with optional fields" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      edk = EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)
      key = :crypto.strong_rand_bytes(32)
      signing_key = :crypto.strong_rand_bytes(48)

      materials =
        EncryptionMaterials.new(suite, %{}, [edk], key,
          signing_key: signing_key,
          required_encryption_context_keys: ["key1"]
        )

      assert materials.signing_key == signing_key
      assert materials.required_encryption_context_keys == ["key1"]
    end
  end

  describe "new_for_encrypt/3" do
    test "creates materials without plaintext data key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"key" => "value"}

      materials = EncryptionMaterials.new_for_encrypt(suite, context)

      assert materials.algorithm_suite == suite
      assert materials.encryption_context == context
      assert materials.plaintext_data_key == nil
      assert materials.encrypted_data_keys == []
      assert materials.signing_key == nil
    end

    test "accepts optional signing_key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      signing_key = :crypto.strong_rand_bytes(32)

      materials = EncryptionMaterials.new_for_encrypt(suite, %{}, signing_key: signing_key)

      assert materials.signing_key == signing_key
    end
  end

  describe "set_plaintext_data_key/2" do
    test "sets the plaintext data key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      key = :crypto.strong_rand_bytes(32)

      updated = EncryptionMaterials.set_plaintext_data_key(materials, key)

      assert updated.plaintext_data_key == key
    end
  end

  describe "add_encrypted_data_key/2" do
    test "adds EDK to empty list" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      edk = EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)

      updated = EncryptionMaterials.add_encrypted_data_key(materials, edk)

      assert updated.encrypted_data_keys == [edk]
    end

    test "appends EDK to existing list" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      edk1 = EncryptedDataKey.new("provider1", "info1", <<1>>)
      edk2 = EncryptedDataKey.new("provider2", "info2", <<2>>)
      key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new(suite, %{}, [edk1], key)

      updated = EncryptionMaterials.add_encrypted_data_key(materials, edk2)

      assert updated.encrypted_data_keys == [edk1, edk2]
    end
  end
end
