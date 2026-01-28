defmodule AwsEncryptionSdk.Keyring.AwsKmsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @different_key_arn "arn:aws:kms:us-west-2:123456789012:key/different-key-id"

  describe "new/3" do
    test "creates keyring with valid inputs" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      assert keyring.kms_key_id == @kms_key_arn
      assert keyring.kms_client == mock
      assert keyring.grant_tokens == []
    end

    test "stores grant tokens" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock, grant_tokens: ["token1", "token2"])
      assert keyring.grant_tokens == ["token1", "token2"]
    end

    test "rejects nil key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_required} = AwsKms.new(nil, mock)
    end

    test "rejects empty key_id" do
      {:ok, mock} = Mock.new()
      assert {:error, :key_id_empty} = AwsKms.new("", mock)
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKms.new(@kms_key_arn, nil)
    end

    test "rejects non-struct client" do
      assert {:error, :invalid_client_type} = AwsKms.new(@kms_key_arn, %{})
    end
  end

  describe "wrap_key/2 - GenerateDataKey path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{"purpose" => "test"})

      {:ok,
       keyring: keyring,
       materials: materials,
       plaintext_key: plaintext_key,
       ciphertext: ciphertext}
    end

    test "generates new data key when none exists", ctx do
      {:ok, result} = AwsKms.wrap_key(ctx.keyring, ctx.materials)

      assert result.plaintext_data_key == ctx.plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.key_provider_info == @kms_key_arn
      assert edk.ciphertext == ctx.ciphertext
    end

    test "returns error on KMS failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} =>
            {:error, {:kms_error, :access_denied, "Access denied"}}
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:kms_error, :access_denied, "Access denied"}} =
               AwsKms.wrap_key(keyring, ctx.materials)
    end

    test "validates plaintext length", ctx do
      # Return wrong length plaintext
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: :crypto.strong_rand_bytes(16),
            ciphertext: ctx.ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:invalid_plaintext_length, expected: 32, actual: 16}} =
               AwsKms.wrap_key(keyring, ctx.materials)
    end

    test "validates response key_id is ARN", ctx do
      # Return invalid key_id (not an ARN)
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: ctx.plaintext_key,
            ciphertext: ctx.ciphertext,
            key_id: "not-an-arn"
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:invalid_response_key_id, _reason}} =
               AwsKms.wrap_key(keyring, ctx.materials)
    end
  end

  describe "wrap_key/2 - Encrypt path" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @kms_key_arn} => %{
            ciphertext: ciphertext,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

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
      {:ok, result} = AwsKms.wrap_key(ctx.keyring, ctx.materials)

      # Plaintext key unchanged
      assert result.plaintext_data_key == ctx.plaintext_key
      # EDK added
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "aws-kms"
      assert edk.ciphertext == ctx.ciphertext
    end

    test "returns error on KMS failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @kms_key_arn} => {:error, {:kms_error, :invalid_key, "Invalid key"}}
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      # Create materials with existing plaintext key
      materials =
        EncryptionMaterials.new(ctx.materials.algorithm_suite, %{}, [], ctx.plaintext_key)

      assert {:error, {:kms_error, :invalid_key, "Invalid key"}} =
               AwsKms.wrap_key(keyring, materials)
    end

    test "validates response key_id is ARN", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @kms_key_arn} => %{
            ciphertext: ctx.ciphertext,
            key_id: "not-an-arn"
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      # Create materials with existing plaintext key
      materials =
        EncryptionMaterials.new(ctx.materials.algorithm_suite, %{}, [], ctx.plaintext_key)

      assert {:error, {:invalid_response_key_id, _reason}} = AwsKms.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: plaintext_key,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})
      edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

      {:ok, keyring: keyring, materials: materials, edks: [edk], plaintext_key: plaintext_key}
    end

    test "decrypts matching EDK", ctx do
      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, ctx.edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "fails if plaintext key already set", ctx do
      {:ok, materials_with_key} =
        DecryptionMaterials.set_plaintext_data_key(ctx.materials, ctx.plaintext_key)

      assert {:error, :plaintext_data_key_already_set} =
               AwsKms.unwrap_key(ctx.keyring, materials_with_key, ctx.edks)
    end

    test "filters out non-aws-kms EDKs", ctx do
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out invalid ARN in provider info", ctx do
      invalid_edk = EncryptedDataKey.new("aws-kms", "not-an-arn", <<1, 2, 3>>)
      edks = [invalid_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out non-key resource types", ctx do
      alias_arn = "arn:aws:kms:us-west-2:123456789012:alias/my-alias"
      alias_edk = EncryptedDataKey.new("aws-kms", alias_arn, <<1, 2, 3>>)
      edks = [alias_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out non-matching key identifiers", ctx do
      other_edk = EncryptedDataKey.new("aws-kms", @different_key_arn, <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKms.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "collects errors when no EDK decrypts", ctx do
      # Remove the valid EDK
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKms.unwrap_key(ctx.keyring, ctx.materials, [other_edk])

      assert [{:provider_id_mismatch, "other-provider"}] = errors
    end

    test "returns error when no EDKs provided", ctx do
      assert {:error, {:unable_to_decrypt_any_data_key, []}} =
               AwsKms.unwrap_key(ctx.keyring, ctx.materials, [])
    end

    test "verifies response key_id matches configured key", ctx do
      # Mock returns different key_id
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: ctx.plaintext_key,
            key_id: @different_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKms.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:response_key_id_mismatch, @kms_key_arn, @different_key_arn}] = errors
    end

    test "validates decrypted plaintext length", ctx do
      # Mock returns wrong length plaintext
      wrong_length_key = :crypto.strong_rand_bytes(16)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: wrong_length_key,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKms.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:invalid_decrypted_length, expected: 32, actual: 16}] = errors
    end

    test "returns error on KMS decrypt failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => {:error, {:kms_error, :not_found, "Key not found"}}
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKms.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:kms_error, :not_found, "Key not found"}] = errors
    end
  end

  describe "MRK matching" do
    @mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"
    @mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"

    test "decrypts MRK EDK from different region" do
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

      # Keyring configured with us-west-2 MRK
      {:ok, keyring} = AwsKms.new(@mrk_us_west, mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK from us-east-1 MRK (same key, different region)
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKms.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "encrypts with MRK key" do
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

      {:ok, keyring} = AwsKms.new(@mrk_us_west, mock)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      {:ok, result} = AwsKms.wrap_key(keyring, materials)

      assert result.plaintext_data_key == plaintext_key
      assert [edk] = result.encrypted_data_keys
      assert edk.key_provider_info == @mrk_us_west
    end
  end

  describe "round-trip encryption/decryption" do
    test "wrap_key then unwrap_key recovers original key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @kms_key_arn} => %{
            plaintext: plaintext_key,
            ciphertext: ciphertext,
            key_id: @kms_key_arn
          },
          {:decrypt, @kms_key_arn} => %{
            plaintext: plaintext_key,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"test" => "data"})
      {:ok, enc_result} = AwsKms.wrap_key(keyring, enc_materials)

      assert enc_result.plaintext_data_key == plaintext_key
      assert [edk] = enc_result.encrypted_data_keys

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"test" => "data"})
      {:ok, dec_result} = AwsKms.unwrap_key(keyring, dec_materials, [edk])

      assert dec_result.plaintext_data_key == plaintext_key
      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end

  describe "behaviour callbacks" do
    test "on_encrypt returns error directing to wrap_key" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, {:must_use_wrap_key, message}} = AwsKms.on_encrypt(materials)
      assert message =~ "wrap_key"
    end

    test "on_decrypt returns error directing to unwrap_key" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKms.new(@kms_key_arn, mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edks = []

      assert {:error, {:must_use_unwrap_key, message}} = AwsKms.on_decrypt(materials, edks)
      assert message =~ "unwrap_key"
    end
  end
end
