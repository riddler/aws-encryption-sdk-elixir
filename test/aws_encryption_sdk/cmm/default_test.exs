defmodule AwsEncryptionSdk.Cmm.DefaultTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  # Helper to create a test keyring
  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "new/1" do
    test "creates CMM with keyring" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      assert %Default{keyring: ^keyring} = cmm
    end
  end

  describe "call_wrap_key/2" do
    test "dispatches to RawAes keyring" do
      keyring = create_test_keyring()
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      {:ok, result} = Default.call_wrap_key(keyring, materials)

      assert result.plaintext_data_key != nil
      assert length(result.encrypted_data_keys) == 1
    end
  end

  describe "call_unwrap_key/3" do
    test "dispatches to RawAes keyring" do
      keyring = create_test_keyring()
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # First wrap a key
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

      # Then unwrap it
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, result} = Default.call_unwrap_key(keyring, dec_materials, wrapped.encrypted_data_keys)

      assert result.plaintext_data_key == wrapped.plaintext_data_key
    end
  end

  describe "get_decryption_materials/2" do
    setup do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Create encryption materials to get valid EDKs
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

      {:ok,
       cmm: cmm,
       suite: suite,
       edks: wrapped.encrypted_data_keys,
       plaintext_key: wrapped.plaintext_data_key}
    end

    test "decrypts with committed suite and require policy", ctx do
      request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.edks,
        encryption_context: %{}
      }

      {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)

      assert materials.plaintext_data_key == ctx.plaintext_key
      assert materials.algorithm_suite == ctx.suite
      assert materials.encryption_context == %{}
    end

    test "decrypts with allow_decrypt policy", ctx do
      request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_allow_decrypt,
        encrypted_data_keys: ctx.edks,
        encryption_context: %{}
      }

      {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)
      assert materials.plaintext_data_key == ctx.plaintext_key
    end

    test "fails with non-committed suite and require_require policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      # Non-committed suite
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: [],
        encryption_context: %{}
      }

      assert {:error, :commitment_policy_requires_committed_suite} =
               Default.get_decryption_materials(cmm, request)
    end

    test "validates reproduced context matches", _ctx do
      # Create a test case with actual conflict between stored and reproduced context
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with a context value
      enc_materials =
        EncryptionMaterials.new_for_encrypt(suite, %{"key" => "value"})

      {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

      # Now try to decrypt claiming a different value was reproduced
      request2 = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: wrapped.encrypted_data_keys,
        encryption_context: %{"key" => "value"},
        reproduced_encryption_context: %{"key" => "different"}
      }

      assert {:error, {:encryption_context_mismatch, "key"}} =
               Default.get_decryption_materials(cmm, request2)
    end

    test "merges reproduced context", ctx do
      # Use the EDKs from setup which were encrypted with empty context
      # Add a reproduced context entry
      request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.edks,
        encryption_context: %{},
        reproduced_encryption_context: %{"reproduced" => "value"}
      }

      {:ok, materials} = Default.get_decryption_materials(ctx.cmm, request)

      # Should have the reproduced context merged in
      assert materials.encryption_context["reproduced"] == "value"
    end
  end

  describe "get_encryption_materials/2" do
    test "encrypts with default committed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      request = %{
        encryption_context: %{"purpose" => "test"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = Default.get_encryption_materials(cmm, request)

      # Default suite for require_* is committed with signing (0x0578)
      assert materials.algorithm_suite.id == 0x0578
      assert materials.plaintext_data_key != nil
      assert materials.encrypted_data_keys != []
      assert materials.encryption_context["purpose"] == "test"
      # Signing suite adds public key
      assert Map.has_key?(materials.encryption_context, "aws-crypto-public-key")
      assert materials.signing_key != nil
    end

    test "encrypts with specified non-signing suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials} = Default.get_encryption_materials(cmm, request)

      assert materials.algorithm_suite == suite
      assert materials.plaintext_data_key != nil
      assert materials.encrypted_data_keys != []
      # Non-signing suite should not have public key
      refute Map.has_key?(materials.encryption_context, "aws-crypto-public-key")
      assert materials.signing_key == nil
    end

    test "fails with non-committed suite and require policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      assert {:error, :commitment_policy_requires_committed_suite} =
               Default.get_encryption_materials(cmm, request)
    end

    test "fails with committed suite and forbid policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt,
        algorithm_suite: suite
      }

      assert {:error, :commitment_policy_forbids_committed_suite} =
               Default.get_encryption_materials(cmm, request)
    end

    test "fails when encryption context contains reserved key" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      request = %{
        encryption_context: %{"aws-crypto-public-key" => "malicious"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, :reserved_encryption_context_key} =
               Default.get_encryption_materials(cmm, request)
    end

    test "uses default non-committed suite for forbid policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt
      }

      {:ok, materials} = Default.get_encryption_materials(cmm, request)

      # Default for forbid is non-committed with signing (0x0378)
      assert materials.algorithm_suite.id == 0x0378
    end
  end

  describe "encrypt/decrypt round-trip" do
    test "round-trips with non-signing committed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt
      enc_request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      # Decrypt
      dec_request = %{
        algorithm_suite: enc_materials.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: enc_materials.encryption_context
      }

      {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

      assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
      assert dec_materials.verification_key == nil
    end

    test "round-trips with signing committed suite (0x0578)" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      # Encrypt
      enc_request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      assert enc_materials.signing_key != nil
      assert Map.has_key?(enc_materials.encryption_context, "aws-crypto-public-key")

      # Decrypt
      dec_request = %{
        algorithm_suite: enc_materials.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: enc_materials.encryption_context
      }

      {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

      assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
      assert dec_materials.verification_key != nil
    end

    test "round-trips with signing non-committed suite (0x0378)" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()

      # Encrypt
      enc_request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      # Decrypt
      dec_request = %{
        algorithm_suite: enc_materials.algorithm_suite,
        commitment_policy: :forbid_encrypt_allow_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: enc_materials.encryption_context
      }

      {:ok, dec_materials} = Default.get_decryption_materials(cmm, dec_request)

      assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
    end

    test "decryption fails when signing context missing for signed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      # Get encryption materials first
      enc_request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      # Remove the public key from context (simulating corrupted message)
      corrupted_context =
        Map.delete(enc_materials.encryption_context, "aws-crypto-public-key")

      dec_request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: corrupted_context
      }

      assert {:error, :missing_public_key_in_context} =
               Default.get_decryption_materials(cmm, dec_request)
    end

    test "decryption fails when non-signed suite has public key in context" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Get encryption materials
      enc_request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      # Add spurious public key to context
      corrupted_context =
        Map.put(enc_materials.encryption_context, "aws-crypto-public-key", "fake")

      dec_request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: corrupted_context
      }

      assert {:error, :unexpected_public_key_in_context} =
               Default.get_decryption_materials(cmm, dec_request)
    end
  end

  describe "error handling" do
    test "call_wrap_key fails with unsupported keyring type" do
      # Create a fake keyring struct
      fake_keyring = %{__struct__: FakeKeyring}
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, {:unsupported_keyring_type, FakeKeyring}} =
               Default.call_wrap_key(fake_keyring, materials)
    end

    test "call_unwrap_key fails with unsupported keyring type" do
      # Create a fake keyring struct
      fake_keyring = %{__struct__: FakeKeyring}
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, {:unsupported_keyring_type, FakeKeyring}} =
               Default.call_unwrap_key(fake_keyring, materials, [])
    end

    test "decryption fails with invalid base64 in verification key" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      # Create EDKs
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, wrapped} = Default.call_wrap_key(keyring, enc_materials)

      # Create a context with invalid base64 in the public key field
      corrupted_context = %{"aws-crypto-public-key" => "invalid-base64!!!"}

      request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: wrapped.encrypted_data_keys,
        encryption_context: corrupted_context
      }

      assert {:error, :invalid_base64} = Default.get_decryption_materials(cmm, request)
    end

    test "decryption fails when keyring cannot decrypt any EDK" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Create EDKs with a different keyring that this one can't decrypt
      other_key = :crypto.strong_rand_bytes(32)
      {:ok, other_keyring} = RawAes.new("other-namespace", "other-key", other_key, :aes_256_gcm)
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, wrapped} = Default.call_wrap_key(other_keyring, enc_materials)

      # Try to decrypt with the first keyring - should fail
      request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: wrapped.encrypted_data_keys,
        encryption_context: %{}
      }

      assert {:error, :unable_to_decrypt_data_key} =
               Default.get_decryption_materials(cmm, request)
    end
  end

  describe "with Multi-keyring" do
    test "encrypts with multi-keyring" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
      {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])

      cmm = Default.new(multi)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials} = Default.get_encryption_materials(cmm, request)

      # Should have 2 EDKs (one from each keyring)
      assert length(materials.encrypted_data_keys) == 2
    end

    test "decrypts with any keyring in multi-keyring" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
      {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])

      cmm = Default.new(multi)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with multi
      enc_request = %{
        encryption_context: %{},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Default.get_encryption_materials(cmm, enc_request)

      # Decrypt with single keyring (second one)
      single_cmm = Default.new(keyring2)

      dec_request = %{
        algorithm_suite: suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: enc_materials.encryption_context
      }

      {:ok, dec_materials} = Default.get_decryption_materials(single_cmm, dec_request)

      assert dec_materials.plaintext_data_key == enc_materials.plaintext_data_key
    end
  end
end
