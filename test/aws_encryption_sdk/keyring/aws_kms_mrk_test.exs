defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Default, as: DefaultCmm
  alias AwsEncryptionSdk.Keyring.{AwsKmsMrk, Multi}
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"
  @mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"
  @different_mrk "arn:aws:kms:us-west-2:123456789012:key/mrk-87654321876543218765432187654321"

  describe "new/3" do
    test "creates keyring with valid inputs" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsMrk.new(@kms_key_arn, mock)
      assert keyring.kms_key_id == @kms_key_arn
      assert keyring.kms_client == mock
      assert keyring.grant_tokens == []
    end

    test "creates keyring with MRK identifier" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      assert keyring.kms_key_id == @mrk_us_west
    end

    test "stores grant tokens" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrk.new(@kms_key_arn, mock, grant_tokens: ["token1", "token2"])
      assert keyring.grant_tokens == ["token1", "token2"]
    end

    test "rejects nil key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_required} = AwsKmsMrk.new(nil, mock)
    end

    test "rejects empty key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_empty} = AwsKmsMrk.new("", mock)
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKmsMrk.new(@kms_key_arn, nil)
    end

    test "rejects non-struct client" do
      assert {:error, :invalid_client_type} = AwsKmsMrk.new(@kms_key_arn, %{})
    end
  end

  describe "wrap_key/2 - GenerateDataKey path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})

      {:ok,
       keyring: keyring,
       materials: materials,
       plaintext_key: plaintext_key,
       ciphertext: ciphertext}
    end

    test "generates new data key when none exists", ctx do
      {:ok, result} = AwsKmsMrk.wrap_key(ctx.keyring, ctx.materials)

      assert result.plaintext_data_key == ctx.plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.key_provider_info == @mrk_us_west
      assert edk.ciphertext == ctx.ciphertext
    end

    test "returns error on KMS failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} =>
            {:error, {:kms_error, :access_denied, "Access denied"}}
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      assert {:error, {:kms_error, :access_denied, "Access denied"}} =
               AwsKmsMrk.wrap_key(keyring, ctx.materials)
    end

    test "validates plaintext length", ctx do
      # Return wrong length plaintext
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: :crypto.strong_rand_bytes(16),
            ciphertext: ctx.ciphertext,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      assert {:error, {:invalid_plaintext_length, expected: 32, actual: 16}} =
               AwsKmsMrk.wrap_key(keyring, ctx.materials)
    end
  end

  describe "wrap_key/2 - Encrypt path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @mrk_us_west} => %{
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      # Materials with existing plaintext key (multi-keyring scenario)
      materials =
        EncryptionMaterials.new(suite, %{"purpose" => "test"}, [], plaintext_key)

      {:ok,
       keyring: keyring,
       materials: materials,
       plaintext_key: plaintext_key,
       ciphertext: ciphertext}
    end

    test "encrypts existing key", ctx do
      {:ok, result} = AwsKmsMrk.wrap_key(ctx.keyring, ctx.materials)

      # Plaintext key unchanged
      assert result.plaintext_data_key == ctx.plaintext_key
      # EDK added
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.ciphertext == ctx.ciphertext
    end
  end

  describe "unwrap_key/3 - same region" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, keyring: keyring, materials: materials, edks: [edk], plaintext_key: plaintext_key}
    end

    test "decrypts matching EDK", ctx do
      {:ok, result} = AwsKmsMrk.unwrap_key(ctx.keyring, ctx.materials, ctx.edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "fails if plaintext key already set", ctx do
      {:ok, materials_with_key} =
        DecryptionMaterials.set_plaintext_data_key(ctx.materials, ctx.plaintext_key)

      assert {:error, :plaintext_data_key_already_set} =
               AwsKmsMrk.unwrap_key(ctx.keyring, materials_with_key, ctx.edks)
    end

    test "filters out non-aws-kms EDKs", ctx do
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKmsMrk.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "returns error when no EDKs provided", ctx do
      assert {:error, {:unable_to_decrypt_any_data_key, []}} =
               AwsKmsMrk.unwrap_key(ctx.keyring, ctx.materials, [])
    end
  end

  # Helper for setting up cross-region MRK test scenarios
  defp setup_cross_region_test(keyring_arn, edk_arn) do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_key = :crypto.strong_rand_bytes(32)
    ciphertext = :crypto.strong_rand_bytes(128)

    {:ok, mock} =
      Mock.new(%{
        {:decrypt, keyring_arn} => %{
          plaintext: plaintext_key,
          key_id: keyring_arn
        }
      })

    {:ok, keyring} = AwsKmsMrk.new(keyring_arn, mock)
    materials = DecryptionMaterials.new_for_decrypt(suite, %{})
    edk = EncryptedDataKey.new("aws-kms", edk_arn, ciphertext)

    {keyring, materials, edk, plaintext_key}
  end

  describe "unwrap_key/3 - cross-region MRK (KEY VALUE PROPOSITION)" do
    test "decrypts us-west-2 EDK with us-east-1 keyring" do
      # Keyring in us-east-1, EDK from us-west-2
      {keyring, materials, edk, plaintext_key} =
        setup_cross_region_test(@mrk_us_east, @mrk_us_west)

      # Should succeed! This is cross-region decryption.
      {:ok, result} = AwsKmsMrk.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "decrypts us-east-1 EDK with us-west-2 keyring" do
      # Keyring in us-west-2, EDK from us-east-1
      {keyring, materials, edk, plaintext_key} =
        setup_cross_region_test(@mrk_us_west, @mrk_us_east)

      # Should succeed! This is cross-region decryption.
      {:ok, result} = AwsKmsMrk.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "fails to decrypt different MRK (different key ID)" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new(%{})

      # Keyring configured with one MRK
      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK from a completely different MRK
      edk = EncryptedDataKey.new("aws-kms", @different_mrk, ciphertext)

      # Should fail - different key IDs don't match
      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrk.unwrap_key(keyring, materials, [edk])

      # Error should indicate key identifier mismatch
      assert [{:key_identifier_mismatch, @mrk_us_west, @different_mrk}] = errors
    end

    test "response key_id must MRK match configured key" do
      # Use helper to setup cross-region test
      {keyring, materials, edk, plaintext_key} =
        setup_cross_region_test(@mrk_us_east, @mrk_us_west)

      # Should succeed - response key_id MRK matches configured key
      {:ok, result} = AwsKmsMrk.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "round-trip encryption/decryption" do
    test "wrap_key then unwrap_key recovers original key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          },
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"test" => "data"})
      {:ok, enc_result} = AwsKmsMrk.wrap_key(keyring, enc_materials)

      assert enc_result.plaintext_data_key == plaintext_key
      assert [edk] = enc_result.encrypted_data_keys

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"test" => "data"})
      {:ok, dec_result} = AwsKmsMrk.unwrap_key(keyring, dec_materials, [edk])

      assert dec_result.plaintext_data_key == plaintext_key
      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "encrypt in us-west-2, decrypt in us-east-1 (cross-region)" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      # West mock - for encryption
      {:ok, west_mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          }
        })

      # East mock - for decryption
      {:ok, east_mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_east} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_east
          }
        })

      {:ok, west_keyring} = AwsKmsMrk.new(@mrk_us_west, west_mock)
      {:ok, east_keyring} = AwsKmsMrk.new(@mrk_us_east, east_mock)

      # Encrypt in us-west-2
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"test" => "data"})
      {:ok, enc_result} = AwsKmsMrk.wrap_key(west_keyring, enc_materials)
      assert [edk] = enc_result.encrypted_data_keys
      assert edk.key_provider_info == @mrk_us_west

      # Decrypt in us-east-1 (different region!)
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"test" => "data"})
      {:ok, dec_result} = AwsKmsMrk.unwrap_key(east_keyring, dec_materials, [edk])

      # Should recover the same plaintext key
      assert dec_result.plaintext_data_key == plaintext_key
      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end

  describe "integration with Default CMM" do
    test "can use AwsKmsMrk keyring with Default CMM" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          },
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      cmm = DefaultCmm.new(keyring)

      # Get encryption materials
      enc_request = %{
        encryption_context: %{"test" => "data"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, enc_materials} = DefaultCmm.get_encryption_materials(cmm, enc_request)
      assert enc_materials.plaintext_data_key == plaintext_key
      assert [edk] = enc_materials.encrypted_data_keys

      # Get decryption materials
      dec_request = %{
        algorithm_suite: suite,
        encrypted_data_keys: [edk],
        encryption_context: %{"test" => "data"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, dec_materials} = DefaultCmm.get_decryption_materials(cmm, dec_request)
      assert dec_materials.plaintext_data_key == plaintext_key
    end
  end

  describe "integration with Multi-keyring" do
    test "can use AwsKmsMrk as generator" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @mrk_us_west} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          }
        })

      {:ok, mrk_keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      {:ok, multi} = Multi.new(generator: mrk_keyring)

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, result} = Multi.wrap_key(multi, materials)

      assert result.plaintext_data_key == plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_info == @mrk_us_west
    end

    test "can use AwsKmsMrk as child" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @mrk_us_west} => %{
            ciphertext: ciphertext,
            key_id: @mrk_us_west
          }
        })

      {:ok, mrk_keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      {:ok, multi} = Multi.new(children: [mrk_keyring])

      # Materials with existing plaintext key
      materials = EncryptionMaterials.new(suite, %{}, [], plaintext_key)
      {:ok, result} = Multi.wrap_key(multi, materials)

      assert result.plaintext_data_key == plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_info == @mrk_us_west
    end

    test "can decrypt with AwsKmsMrk in multi-keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_west
          }
        })

      {:ok, mrk_keyring} = AwsKmsMrk.new(@mrk_us_west, mock)
      {:ok, multi} = Multi.new(children: [mrk_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "cross-region decryption in multi-keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      # Mock that can decrypt with us-east-1 keyring
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_east} => %{
            plaintext: plaintext_key,
            key_id: @mrk_us_east
          }
        })

      # Keyring configured for us-east-1
      {:ok, mrk_keyring} = AwsKmsMrk.new(@mrk_us_east, mock)
      {:ok, multi} = Multi.new(children: [mrk_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      # EDK from us-west-2 (different region!)
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      # Should succeed with cross-region MRK matching
      {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "behaviour callbacks" do
    test "on_encrypt returns error directing to wrap_key" do
      {:ok, mock} = Mock.new()
      {:ok, _keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, {:must_use_wrap_key, message}} = AwsKmsMrk.on_encrypt(materials)
      assert message =~ "wrap_key"
    end

    test "on_decrypt returns error directing to unwrap_key" do
      {:ok, mock} = Mock.new()
      {:ok, _keyring} = AwsKmsMrk.new(@mrk_us_west, mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edks = []

      assert {:error, {:must_use_unwrap_key, message}} =
               AwsKmsMrk.on_decrypt(materials, edks)

      assert message =~ "unwrap_key"
    end
  end
end
