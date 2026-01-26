defmodule AwsEncryptionSdk.Keyring.BehaviourTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.Behaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  describe "validate_provider_id/1" do
    test "accepts valid provider IDs" do
      assert :ok = Behaviour.validate_provider_id("my-provider")
      assert :ok = Behaviour.validate_provider_id("raw-aes")
      assert :ok = Behaviour.validate_provider_id("custom-keyring")
      assert :ok = Behaviour.validate_provider_id("")
    end

    test "rejects aws-kms provider ID" do
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms")
    end

    test "rejects provider IDs starting with aws-kms" do
      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms-mrk")

      assert {:error, :reserved_provider_id} =
               Behaviour.validate_provider_id("aws-kms-discovery")

      assert {:error, :reserved_provider_id} = Behaviour.validate_provider_id("aws-kms/key")
    end
  end

  describe "generate_data_key/1" do
    test "generates key of correct length for 256-bit suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 32
    end

    test "generates key of correct length for 192-bit suite" do
      suite = AlgorithmSuite.aes_192_gcm_iv12_tag16_no_kdf()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 24
    end

    test "generates key of correct length for 128-bit suite" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_no_kdf()
      key = Behaviour.generate_data_key(suite)

      assert byte_size(key) == 16
    end

    test "generates unique keys on each call" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      keys = for _i <- 1..100, do: Behaviour.generate_data_key(suite)
      unique_keys = Enum.uniq(keys)

      assert length(unique_keys) == 100
    end
  end

  describe "has_plaintext_data_key?/1" do
    test "returns false for encryption materials without key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      refute Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns true for encryption materials with key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "key", key)
      materials = EncryptionMaterials.new(suite, %{}, [edk], key)

      assert Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns false for decryption materials without key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      refute Behaviour.has_plaintext_data_key?(materials)
    end

    test "returns true for decryption materials with key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, key)

      assert Behaviour.has_plaintext_data_key?(materials)
    end
  end
end
