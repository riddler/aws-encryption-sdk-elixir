defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkDiscoveryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Default, as: DefaultCmm
  alias AwsEncryptionSdk.Keyring.{AwsKmsMrkDiscovery, Multi}
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"
  @mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"
  @non_mrk_us_west "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"
  @non_mrk_us_east "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"

  describe "new/3" do
    test "creates keyring with valid inputs" do
      {:ok, mock} = Mock.new()
      assert {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      assert keyring.kms_client == mock
      assert keyring.region == "us-west-2"
      assert keyring.discovery_filter == nil
      assert keyring.grant_tokens == []
    end

    test "stores discovery filter and grant tokens" do
      {:ok, mock} = Mock.new()
      filter = %{partition: "aws", accounts: ["123456789012"]}

      {:ok, keyring} =
        AwsKmsMrkDiscovery.new(mock, "us-west-2",
          discovery_filter: filter,
          grant_tokens: ["token1"]
        )

      assert keyring.discovery_filter == filter
      assert keyring.grant_tokens == ["token1"]
    end

    test "rejects nil client" do
      assert {:error, :client_required} = AwsKmsMrkDiscovery.new(nil, "us-west-2")
    end

    test "rejects nil region" do
      {:ok, mock} = Mock.new()
      assert {:error, :region_required} = AwsKmsMrkDiscovery.new(mock, nil)
    end

    test "rejects empty region" do
      {:ok, mock} = Mock.new()
      assert {:error, :region_empty} = AwsKmsMrkDiscovery.new(mock, "")
    end

    test "rejects invalid discovery filter" do
      {:ok, mock} = Mock.new()

      assert {:error, :invalid_discovery_filter} =
               AwsKmsMrkDiscovery.new(mock, "us-west-2", discovery_filter: %{partition: "aws"})
    end

    test "rejects invalid client type (not a struct)" do
      assert {:error, :invalid_client_type} = AwsKmsMrkDiscovery.new("not-a-struct", "us-west-2")
    end

    test "rejects invalid region type (not a string)" do
      {:ok, mock} = Mock.new()
      assert {:error, :invalid_region_type} = AwsKmsMrkDiscovery.new(mock, 123)
    end

    test "rejects discovery filter with empty accounts list" do
      {:ok, mock} = Mock.new()

      assert {:error, :discovery_filter_accounts_empty} =
               AwsKmsMrkDiscovery.new(mock, "us-west-2",
                 discovery_filter: %{partition: "aws", accounts: []}
               )
    end

    test "rejects discovery filter with non-string account ids" do
      {:ok, mock} = Mock.new()

      assert {:error, :invalid_account_ids} =
               AwsKmsMrkDiscovery.new(mock, "us-west-2",
                 discovery_filter: %{partition: "aws", accounts: [123, 456]}
               )
    end
  end

  describe "wrap_key/2" do
    test "always fails - discovery keyrings cannot encrypt" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :discovery_keyring_cannot_encrypt} =
               AwsKmsMrkDiscovery.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3 - error cases" do
    test "fails when materials already have plaintext data key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")

      # Create materials that already have a plaintext data key
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, materials_with_key} =
        DecryptionMaterials.set_plaintext_data_key(materials, plaintext_key)

      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      assert {:error, :plaintext_data_key_already_set} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials_with_key, [edk])
    end

    test "fails when provider ID doesn't match" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK with wrong provider ID
      edk = EncryptedDataKey.new("wrong-provider", @mrk_us_west, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:provider_id_mismatch, "wrong-provider"}] = errors
    end

    test "fails when provider info is not a valid ARN" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK with invalid ARN as provider info
      edk = EncryptedDataKey.new("aws-kms", "not-an-arn", ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:invalid_provider_info_arn, _reason}] = errors
    end

    test "fails when resource type is alias instead of key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      # EDK with alias resource type
      alias_arn = "arn:aws:kms:us-west-2:123456789012:alias/my-alias"
      edk = EncryptedDataKey.new("aws-kms", alias_arn, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:invalid_resource_type, "alias"}] = errors
    end

    test "fails when partition doesn't match discovery filter" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()

      {:ok, keyring} =
        AwsKmsMrkDiscovery.new(mock, "us-west-2",
          discovery_filter: %{partition: "aws-cn", accounts: ["123456789012"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:partition_mismatch, expected: "aws-cn", actual: "aws"}] = errors
    end

    test "fails when KMS returns mismatched key ID" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      # KMS returns a different key ID than expected
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: "arn:aws:kms:us-west-2:123456789012:key/different-key-id"
          }
        })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:response_key_id_mismatch, @mrk_us_west, _actual}] = errors
    end

    test "fails when decrypted key has wrong length" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      # Return wrong length key (16 bytes instead of 32)
      wrong_length_key = :crypto.strong_rand_bytes(16)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @mrk_us_west} => %{
            plaintext: wrong_length_key,
            key_id: @mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:invalid_decrypted_length, expected: 32, actual: 16}] = errors
    end
  end

  describe "unwrap_key/3 - MRK same region" do
    test "decrypts MRK EDK when regions match" do
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

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "unwrap_key/3 - MRK cross-region (KEY VALUE PROPOSITION)" do
    test "decrypts us-east-1 MRK EDK with us-west-2 keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      # KMS in us-west-2 receives decrypt call with reconstructed ARN
      reconstructed_arn =
        "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, reconstructed_arn} => %{
            plaintext: plaintext_key,
            key_id: reconstructed_arn
          }
        })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      # EDK from us-east-1 (different region!)
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "decrypts us-west-2 MRK EDK with us-east-1 keyring" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn =
        "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, reconstructed_arn} => %{
            plaintext: plaintext_key,
            key_id: reconstructed_arn
          }
        })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-east-1")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "unwrap_key/3 - non-MRK region filtering" do
    test "decrypts non-MRK EDK when region matches" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @non_mrk_us_west} => %{
            plaintext: plaintext_key,
            key_id: @non_mrk_us_west
          }
        })

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @non_mrk_us_west, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end

    test "filters out non-MRK EDK from different region" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      # EDK from us-east-1 non-MRK
      edk = EncryptedDataKey.new("aws-kms", @non_mrk_us_east, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:non_mrk_region_mismatch, expected: "us-west-2", actual: "us-east-1"}] = errors
    end
  end

  describe "unwrap_key/3 - discovery filter with MRK" do
    test "applies filter before MRK reconstruction" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      ciphertext = :crypto.strong_rand_bytes(128)

      {:ok, mock} = Mock.new()

      {:ok, keyring} =
        AwsKmsMrkDiscovery.new(mock, "us-west-2",
          discovery_filter: %{partition: "aws", accounts: ["999999999999"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      assert {:error, {:unable_to_decrypt_any_data_key, errors}} =
               AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])

      assert [{:account_not_in_filter, account: "123456789012", allowed: ["999999999999"]}] =
               errors
    end

    test "MRK cross-region works with matching filter" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn =
        "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, reconstructed_arn} => %{
            plaintext: plaintext_key,
            key_id: reconstructed_arn
          }
        })

      {:ok, keyring} =
        AwsKmsMrkDiscovery.new(mock, "us-west-2",
          discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
        )

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = AwsKmsMrkDiscovery.unwrap_key(keyring, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end

  describe "integration with Default CMM" do
    test "CMM decrypt uses MRK discovery keyring" do
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

      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      cmm = DefaultCmm.new(keyring)

      edk = EncryptedDataKey.new("aws-kms", @mrk_us_west, ciphertext)

      request = %{
        algorithm_suite: suite,
        encryption_context: %{},
        encrypted_data_keys: [edk],
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = DefaultCmm.get_decryption_materials(cmm, request)
      assert materials.plaintext_data_key == plaintext_key
    end

    test "CMM encrypt fails with MRK discovery keyring" do
      {:ok, mock} = Mock.new()
      {:ok, keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      cmm = DefaultCmm.new(keyring)

      request = %{encryption_context: %{}, commitment_policy: :require_encrypt_require_decrypt}

      assert {:error, :discovery_keyring_cannot_encrypt} =
               DefaultCmm.get_encryption_materials(cmm, request)
    end
  end

  describe "integration with Multi-keyring" do
    test "multi-keyring can use MRK discovery keyring for decrypt" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_key = :crypto.strong_rand_bytes(32)
      ciphertext = :crypto.strong_rand_bytes(128)

      reconstructed_arn =
        "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678123456781234567812345678"

      {:ok, mock} =
        Mock.new(%{
          {:decrypt, reconstructed_arn} => %{
            plaintext: plaintext_key,
            key_id: reconstructed_arn
          }
        })

      {:ok, discovery_keyring} = AwsKmsMrkDiscovery.new(mock, "us-west-2")
      {:ok, multi} = Multi.new(children: [discovery_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      edk = EncryptedDataKey.new("aws-kms", @mrk_us_east, ciphertext)

      {:ok, result} = Multi.unwrap_key(multi, materials, [edk])
      assert result.plaintext_data_key == plaintext_key
    end
  end
end
