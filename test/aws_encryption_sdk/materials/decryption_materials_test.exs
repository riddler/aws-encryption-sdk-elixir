defmodule AwsEncryptionSdk.Materials.DecryptionMaterialsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials

  describe "new/4" do
    test "creates materials with required fields" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)

      materials = DecryptionMaterials.new(suite, %{"ctx" => "val"}, key)

      assert materials.algorithm_suite == suite
      assert materials.encryption_context == %{"ctx" => "val"}
      assert materials.plaintext_data_key == key
      assert materials.verification_key == nil
      assert materials.required_encryption_context_keys == []
    end

    test "creates materials with optional verification key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      key = :crypto.strong_rand_bytes(32)
      verification_key = :crypto.strong_rand_bytes(48)

      materials = DecryptionMaterials.new(suite, %{}, key, verification_key: verification_key)

      assert materials.verification_key == verification_key
    end
  end
end
