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

  describe "new_for_decrypt/3" do
    test "creates materials without plaintext data key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"key" => "value"}

      materials = DecryptionMaterials.new_for_decrypt(suite, context)

      assert materials.algorithm_suite == suite
      assert materials.encryption_context == context
      assert materials.plaintext_data_key == nil
      assert materials.verification_key == nil
    end

    test "accepts optional verification_key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      verification_key = :crypto.strong_rand_bytes(32)

      materials =
        DecryptionMaterials.new_for_decrypt(suite, %{}, verification_key: verification_key)

      assert materials.verification_key == verification_key
    end
  end

  describe "set_plaintext_data_key/2" do
    test "sets key when not already present" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      key = :crypto.strong_rand_bytes(32)

      assert {:ok, updated} = DecryptionMaterials.set_plaintext_data_key(materials, key)
      assert updated.plaintext_data_key == key
    end

    test "returns error when key already present" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, key)

      assert {:error, :plaintext_data_key_already_set} =
               DecryptionMaterials.set_plaintext_data_key(materials, <<1, 2, 3>>)
    end
  end
end
