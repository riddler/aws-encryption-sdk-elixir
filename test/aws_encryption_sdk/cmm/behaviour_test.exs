defmodule AwsEncryptionSdk.Cmm.BehaviourTest do
  use ExUnit.Case, async: true
  doctest AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Behaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  describe "reserved_encryption_context_key/0" do
    test "returns the reserved key" do
      assert Behaviour.reserved_encryption_context_key() == "aws-crypto-public-key"
    end
  end

  describe "default_algorithm_suite/1" do
    test "returns committed suite for require_encrypt_require_decrypt" do
      suite = Behaviour.default_algorithm_suite(:require_encrypt_require_decrypt)
      assert suite.id == 0x0578
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns committed suite for require_encrypt_allow_decrypt" do
      suite = Behaviour.default_algorithm_suite(:require_encrypt_allow_decrypt)
      assert suite.id == 0x0578
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns non-committed suite for forbid_encrypt_allow_decrypt" do
      suite = Behaviour.default_algorithm_suite(:forbid_encrypt_allow_decrypt)
      assert suite.id == 0x0378
      refute AlgorithmSuite.committed?(suite)
    end
  end

  describe "validate_commitment_policy_for_encrypt/2" do
    test "accepts committed suite with require_encrypt_require_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      assert :ok =
               Behaviour.validate_commitment_policy_for_encrypt(
                 suite,
                 :require_encrypt_require_decrypt
               )
    end

    test "accepts committed suite with require_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      assert :ok =
               Behaviour.validate_commitment_policy_for_encrypt(
                 suite,
                 :require_encrypt_allow_decrypt
               )
    end

    test "rejects non-committed suite with require_encrypt_require_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert {:error, :commitment_policy_requires_committed_suite} =
               Behaviour.validate_commitment_policy_for_encrypt(
                 suite,
                 :require_encrypt_require_decrypt
               )
    end

    test "rejects committed suite with forbid_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      assert {:error, :commitment_policy_forbids_committed_suite} =
               Behaviour.validate_commitment_policy_for_encrypt(
                 suite,
                 :forbid_encrypt_allow_decrypt
               )
    end

    test "accepts non-committed suite with forbid_encrypt_allow_decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok =
               Behaviour.validate_commitment_policy_for_encrypt(
                 suite,
                 :forbid_encrypt_allow_decrypt
               )
    end
  end

  describe "validate_commitment_policy_for_decrypt/2" do
    test "accepts any suite with require_encrypt_allow_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok =
               Behaviour.validate_commitment_policy_for_decrypt(
                 committed,
                 :require_encrypt_allow_decrypt
               )

      assert :ok =
               Behaviour.validate_commitment_policy_for_decrypt(
                 non_committed,
                 :require_encrypt_allow_decrypt
               )
    end

    test "accepts any suite with forbid_encrypt_allow_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok =
               Behaviour.validate_commitment_policy_for_decrypt(
                 committed,
                 :forbid_encrypt_allow_decrypt
               )

      assert :ok =
               Behaviour.validate_commitment_policy_for_decrypt(
                 non_committed,
                 :forbid_encrypt_allow_decrypt
               )
    end

    test "only accepts committed suite with require_encrypt_require_decrypt" do
      committed = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert :ok =
               Behaviour.validate_commitment_policy_for_decrypt(
                 committed,
                 :require_encrypt_require_decrypt
               )

      assert {:error, :commitment_policy_requires_committed_suite} =
               Behaviour.validate_commitment_policy_for_decrypt(
                 non_committed,
                 :require_encrypt_require_decrypt
               )
    end
  end

  describe "validate_encryption_materials/1" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3>>)

      %{suite: suite, key: key, edk: edk}
    end

    test "accepts valid materials", %{suite: suite, key: key, edk: edk} do
      materials = EncryptionMaterials.new(suite, %{}, [edk], key)
      assert :ok = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials without plaintext data key", %{suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :missing_plaintext_data_key} =
               Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials with wrong key length", %{suite: suite, edk: edk} do
      wrong_key = :crypto.strong_rand_bytes(16)
      materials = EncryptionMaterials.new(suite, %{}, [edk], wrong_key)

      assert {:error, :invalid_plaintext_data_key_length} =
               Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials without encrypted data keys", %{suite: suite, key: key} do
      materials = %EncryptionMaterials{
        algorithm_suite: suite,
        encryption_context: %{},
        encrypted_data_keys: [],
        plaintext_data_key: key
      }

      assert {:error, :missing_encrypted_data_keys} =
               Behaviour.validate_encryption_materials(materials)
    end

    test "rejects signed suite without signing key", %{key: key, edk: edk} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      materials = EncryptionMaterials.new(signed_suite, %{}, [edk], key)
      assert {:error, :missing_signing_key} = Behaviour.validate_encryption_materials(materials)
    end

    test "accepts signed suite with signing key", %{key: key, edk: edk} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      signing_key = :crypto.strong_rand_bytes(48)
      materials = EncryptionMaterials.new(signed_suite, %{}, [edk], key, signing_key: signing_key)
      assert :ok = Behaviour.validate_encryption_materials(materials)
    end

    test "rejects materials missing required context key", %{suite: suite, key: key, edk: edk} do
      materials =
        EncryptionMaterials.new(suite, %{}, [edk], key,
          required_encryption_context_keys: ["required_key"]
        )

      assert {:error, :missing_required_encryption_context_key} =
               Behaviour.validate_encryption_materials(materials)
    end

    test "accepts materials with required context keys present", %{
      suite: suite,
      key: key,
      edk: edk
    } do
      materials =
        EncryptionMaterials.new(suite, %{"required_key" => "value"}, [edk], key,
          required_encryption_context_keys: ["required_key"]
        )

      assert :ok = Behaviour.validate_encryption_materials(materials)
    end
  end

  describe "validate_decryption_materials/1" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      key = :crypto.strong_rand_bytes(32)

      %{suite: suite, key: key}
    end

    test "accepts valid materials", %{suite: suite, key: key} do
      materials = DecryptionMaterials.new(suite, %{}, key)
      assert :ok = Behaviour.validate_decryption_materials(materials)
    end

    test "rejects materials without plaintext data key", %{suite: suite} do
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, :missing_plaintext_data_key} =
               Behaviour.validate_decryption_materials(materials)
    end

    test "rejects materials with wrong key length", %{suite: suite} do
      wrong_key = :crypto.strong_rand_bytes(16)
      materials = DecryptionMaterials.new(suite, %{}, wrong_key)

      assert {:error, :invalid_plaintext_data_key_length} =
               Behaviour.validate_decryption_materials(materials)
    end

    test "rejects signed suite without verification key", %{key: key} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      materials = DecryptionMaterials.new(signed_suite, %{}, key)

      assert {:error, :missing_verification_key} =
               Behaviour.validate_decryption_materials(materials)
    end

    test "accepts signed suite with verification key", %{key: key} do
      signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      verification_key = :crypto.strong_rand_bytes(48)

      materials =
        DecryptionMaterials.new(signed_suite, %{}, key, verification_key: verification_key)

      assert :ok = Behaviour.validate_decryption_materials(materials)
    end
  end

  describe "validate_encryption_context_for_encrypt/1" do
    test "accepts context without reserved key" do
      assert :ok = Behaviour.validate_encryption_context_for_encrypt(%{"key" => "value"})
    end

    test "accepts empty context" do
      assert :ok = Behaviour.validate_encryption_context_for_encrypt(%{})
    end

    test "rejects context with reserved key" do
      context = %{"aws-crypto-public-key" => "some_value"}

      assert {:error, :reserved_encryption_context_key} =
               Behaviour.validate_encryption_context_for_encrypt(context)
    end
  end

  describe "validate_signing_context_consistency/2" do
    test "accepts unsigned suite without public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      assert :ok = Behaviour.validate_signing_context_consistency(suite, %{})
    end

    test "accepts signed suite with public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      context = %{"aws-crypto-public-key" => "base64_key"}
      assert :ok = Behaviour.validate_signing_context_consistency(suite, context)
    end

    test "rejects signed suite without public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      assert {:error, :missing_public_key_in_context} =
               Behaviour.validate_signing_context_consistency(suite, %{})
    end

    test "rejects unsigned suite with public key in context" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"aws-crypto-public-key" => "base64_key"}

      assert {:error, :unexpected_public_key_in_context} =
               Behaviour.validate_signing_context_consistency(suite, context)
    end
  end

  describe "validate_reproduced_context/2" do
    test "accepts nil reproduced context" do
      assert :ok = Behaviour.validate_reproduced_context(%{"key" => "value"}, nil)
    end

    test "accepts matching values for shared keys" do
      context = %{"key1" => "value1", "key2" => "value2"}
      reproduced = %{"key1" => "value1"}
      assert :ok = Behaviour.validate_reproduced_context(context, reproduced)
    end

    test "accepts reproduced with extra keys" do
      context = %{"key1" => "value1"}
      reproduced = %{"key1" => "value1", "key2" => "value2"}
      assert :ok = Behaviour.validate_reproduced_context(context, reproduced)
    end

    test "rejects mismatched values" do
      context = %{"key1" => "value1"}
      reproduced = %{"key1" => "different"}

      assert {:error, {:encryption_context_mismatch, "key1"}} =
               Behaviour.validate_reproduced_context(context, reproduced)
    end
  end

  describe "merge_reproduced_context/2" do
    test "returns context unchanged when reproduced is nil" do
      context = %{"key1" => "value1"}
      assert %{"key1" => "value1"} = Behaviour.merge_reproduced_context(context, nil)
    end

    test "merges reproduced keys not in context" do
      context = %{"key1" => "value1"}
      reproduced = %{"key2" => "value2"}
      result = Behaviour.merge_reproduced_context(context, reproduced)
      assert result == %{"key1" => "value1", "key2" => "value2"}
    end

    test "context values take precedence over reproduced" do
      context = %{"key1" => "context_value"}
      reproduced = %{"key1" => "reproduced_value"}
      result = Behaviour.merge_reproduced_context(context, reproduced)
      assert result == %{"key1" => "context_value"}
    end
  end
end
