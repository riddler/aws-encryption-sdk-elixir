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
end
