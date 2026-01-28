defmodule AwsEncryptionSdk.Keyring.AwsKmsDiscoveryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @different_key_arn "arn:aws:kms:us-west-2:123456789012:key/different-key-id"

  describe "new/2" do
    test "creates keyring with valid client" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsDiscovery.new(mock)
      assert keyring.kms_client == mock
      assert keyring.discovery_filter == nil
      assert keyring.grant_tokens == []
    end

    test "stores grant tokens" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsDiscovery.new(mock, grant_tokens: ["token1", "token2"])
      assert keyring.grant_tokens == ["token1", "token2"]
    end

    test "stores valid discovery filter" do
      {:ok, mock} = Mock.new()
      filter = %{partition: "aws", accounts: ["123456789012"]}
      {:ok, keyring} = AwsKmsDiscovery.new(mock, discovery_filter: filter)
      assert keyring.discovery_filter == filter
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKmsDiscovery.new(nil)
    end

    test "rejects non-struct client" do
      assert {:error, :invalid_client_type} = AwsKmsDiscovery.new(%{})
    end

    test "rejects discovery filter missing partition" do
      {:ok, mock} = Mock.new()

      assert {:error, :invalid_discovery_filter} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{accounts: ["123"]})
    end

    test "rejects discovery filter missing accounts" do
      {:ok, mock} = Mock.new()

      assert {:error, :invalid_discovery_filter} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws"})
    end

    test "rejects discovery filter with empty accounts" do
      {:ok, mock} = Mock.new()

      assert {:error, :discovery_filter_accounts_empty} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws", accounts: []})
    end

    test "rejects discovery filter with non-string accounts" do
      {:ok, mock} = Mock.new()

      assert {:error, :invalid_account_ids} =
               AwsKmsDiscovery.new(mock, discovery_filter: %{partition: "aws", accounts: [123]})
    end
  end

  describe "wrap_key/2" do
    test "always fails - discovery keyrings cannot encrypt" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :discovery_keyring_cannot_encrypt} =
               AwsKmsDiscovery.wrap_key(keyring, materials)
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

      {:ok, keyring} = AwsKmsDiscovery.new(mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{"purpose" => "test"})
      edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

      {:ok, keyring: keyring, materials: materials, edks: [edk], plaintext_key: plaintext_key}
    end

    test "decrypts EDK using provider info as key_id", ctx do
      {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, ctx.edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "fails if plaintext key already set", ctx do
      {:ok, materials_with_key} =
        DecryptionMaterials.set_plaintext_data_key(ctx.materials, ctx.plaintext_key)

      assert {:error, :plaintext_data_key_already_set} =
               AwsKmsDiscovery.unwrap_key(ctx.keyring, materials_with_key, ctx.edks)
    end

    test "filters out non-aws-kms EDKs", ctx do
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)
      edks = [other_edk | ctx.edks]

      {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out invalid ARN in provider info", ctx do
      invalid_edk = EncryptedDataKey.new("aws-kms", "not-an-arn", <<1, 2, 3>>)
      edks = [invalid_edk | ctx.edks]

      {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filters out non-key resource types (alias)", ctx do
      alias_arn = "arn:aws:kms:us-west-2:123456789012:alias/my-alias"
      alias_edk = EncryptedDataKey.new("aws-kms", alias_arn, <<1, 2, 3>>)
      edks = [alias_edk | ctx.edks]

      {:ok, result} = AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, edks)
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "collects errors when no EDK decrypts", ctx do
      other_edk = EncryptedDataKey.new("other-provider", "info", <<1, 2, 3>>)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, [other_edk])

      assert [{:provider_id_mismatch, "other-provider"}] = errors
    end

    test "returns error when no EDKs provided", ctx do
      assert {:error, {:unable_to_decrypt_any_data_key, []}} =
               AwsKmsDiscovery.unwrap_key(ctx.keyring, ctx.materials, [])
    end

    test "verifies response key_id matches provider info exactly", ctx do
      # Mock returns different key_id (discovery keyring uses exact match, not MRK match)
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: ctx.plaintext_key,
            key_id: @different_key_arn
          }
        })

      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:response_key_id_mismatch, @kms_key_arn, @different_key_arn}] = errors
    end

    test "validates decrypted plaintext length", ctx do
      wrong_length_key = :crypto.strong_rand_bytes(16)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => %{
            plaintext: wrong_length_key,
            key_id: @kms_key_arn
          }
        })

      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:invalid_decrypted_length, expected: 32, actual: 16}] = errors
    end

    test "returns error on KMS decrypt failure", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @kms_key_arn} => {:error, {:kms_error, :access_denied, "Access denied"}}
        })

      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, ctx.materials, ctx.edks)

      assert [{:kms_error, :access_denied, "Access denied"}] = errors
    end

    test "tries multiple EDKs until one succeeds" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          # First key fails
          {:decrypt, @kms_key_arn} => {:error, {:kms_error, :access_denied, "Access denied"}},
          # Second key succeeds
          {:decrypt, @different_key_arn} => %{
            plaintext: plaintext_key,
            key_id: @different_key_arn
          }
        })

      {:ok, keyring} = AwsKmsDiscovery.new(mock)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      edk1 = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)
      edk2 = EncryptedDataKey.new("aws-kms", @different_key_arn, ciphertext)

      {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk1, edk2])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "unwrap_key/3 with discovery filter" do
    @aws_partition_key "arn:aws:kms:us-west-2:123456789012:key/abc123"
    @aws_cn_partition_key "arn:aws-cn:kms:cn-north-1:123456789012:key/abc123"

    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, suite: suite, plaintext_key: plaintext_key, ciphertext: ciphertext}
    end

    test "accepts EDK matching partition filter", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @aws_partition_key} => %{
            plaintext: ctx.plaintext_key,
            key_id: @aws_partition_key
          }
        })

      {:ok, keyring} =
        AwsKmsDiscovery.new(mock,
          discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

      {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "rejects EDK with mismatched partition", ctx do
      {:ok, mock} = Mock.new()

      {:ok, keyring} =
        AwsKmsDiscovery.new(mock,
          discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_cn_partition_key, ctx.ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:partition_mismatch, expected: "aws", actual: "aws-cn"}] = errors
    end

    test "accepts EDK with account in filter list", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @aws_partition_key} => %{
            plaintext: ctx.plaintext_key,
            key_id: @aws_partition_key
          }
        })

      {:ok, keyring} =
        AwsKmsDiscovery.new(mock,
          discovery_filter: %{
            partition: "aws",
            accounts: ["111111111111", "123456789012", "222222222222"]
          }
        )

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

      {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "rejects EDK with account not in filter list", ctx do
      {:ok, mock} = Mock.new()

      {:ok, keyring} =
        AwsKmsDiscovery.new(mock,
          discovery_filter: %{partition: "aws", accounts: ["111111111111"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:account_not_in_filter, account: "123456789012", allowed: ["111111111111"]}] =
               errors
    end

    test "no filter allows any partition and account", ctx do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @aws_cn_partition_key} => %{
            plaintext: ctx.plaintext_key,
            key_id: @aws_cn_partition_key
          }
        })

      {:ok, keyring} = AwsKmsDiscovery.new(mock)

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_cn_partition_key, ctx.ciphertext)

      {:ok, result} = AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == ctx.plaintext_key
    end

    test "filter is checked before KMS call", ctx do
      # Mock has no decrypt responses configured - if KMS is called, it will fail
      {:ok, mock} = Mock.new()

      {:ok, keyring} =
        AwsKmsDiscovery.new(mock,
          discovery_filter: %{partition: "aws-cn", accounts: ["123456789012"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(ctx.suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @aws_partition_key, ctx.ciphertext)

      # Should fail with partition mismatch, not a KMS error
      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:partition_mismatch, expected: "aws-cn", actual: "aws"}] = errors
    end
  end

  describe "integration with Default CMM" do
    alias AwsEncryptionSdk.Cmm.Default

    test "CMM decrypt uses discovery keyring" do
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

      {:ok, keyring} = AwsKmsDiscovery.new(mock)
      cmm = Default.new(keyring)

      edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

      request = %{
        algorithm_suite: suite,
        encryption_context: %{},
        encrypted_data_keys: [edk],
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = Default.get_decryption_materials(cmm, request)
      assert materials.plaintext_data_key == plaintext_key
    end

    test "CMM encrypt fails with discovery keyring" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsDiscovery.new(mock)
      cmm = Default.new(keyring)

      request = %{encryption_context: %{}, commitment_policy: :require_encrypt_require_decrypt}

      assert {:error, :discovery_keyring_cannot_encrypt} =
               Default.get_encryption_materials(cmm, request)
    end
  end

  describe "integration with Multi-keyring" do
    alias AwsEncryptionSdk.Keyring.Multi

    test "multi-keyring can use discovery keyring for decrypt" do
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

      {:ok, discovery_keyring} = AwsKmsDiscovery.new(mock)
      {:ok, multi} = Multi.new(children: [discovery_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @kms_key_arn, ciphertext)

      {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end
end
