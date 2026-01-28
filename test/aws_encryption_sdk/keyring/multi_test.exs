defmodule AwsEncryptionSdk.Keyring.MultiTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite

  alias AwsEncryptionSdk.Keyring.{
    AwsKms,
    AwsKmsDiscovery,
    AwsKmsMrk,
    AwsKmsMrkDiscovery,
    Multi,
    RawAes
  }

  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  # Helper to create a test keyring
  defp create_aes_keyring(name \\ "test-key") do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", name, key, :aes_256_gcm)
    keyring
  end

  describe "new/1 generator validation" do
    test "rejects AwsKmsDiscovery as generator" do
      {:ok, client} = Mock.new(%{})
      {:ok, discovery} = AwsKmsDiscovery.new(client)

      assert {:error, :discovery_keyring_cannot_be_generator} =
               Multi.new(generator: discovery)
    end

    test "rejects AwsKmsMrkDiscovery as generator" do
      {:ok, client} = Mock.new(%{})
      {:ok, mrk_discovery} = AwsKmsMrkDiscovery.new(client, "us-west-2")

      assert {:error, :discovery_keyring_cannot_be_generator} =
               Multi.new(generator: mrk_discovery)
    end

    test "allows discovery keyrings as children" do
      {:ok, client} = Mock.new(%{})

      {:ok, kms} =
        AwsKms.new(
          "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
          client
        )

      {:ok, discovery} = AwsKmsDiscovery.new(client)

      assert {:ok, multi} = Multi.new(generator: kms, children: [discovery])
      assert multi.children == [discovery]
    end
  end

  describe "new/1" do
    test "creates multi-keyring with generator only" do
      generator = create_aes_keyring("generator")
      assert {:ok, multi} = Multi.new(generator: generator)
      assert multi.generator == generator
      assert multi.children == []
    end

    test "creates multi-keyring with children only" do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      assert {:ok, multi} = Multi.new(children: [child1, child2])
      assert multi.generator == nil
      assert multi.children == [child1, child2]
    end

    test "creates multi-keyring with generator and children" do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      assert {:ok, multi} = Multi.new(generator: generator, children: [child1])
      assert multi.generator == generator
      assert multi.children == [child1]
    end

    test "fails when no generator and no children" do
      assert {:error, :no_keyrings_provided} = Multi.new([])
      assert {:error, :no_keyrings_provided} = Multi.new(generator: nil, children: [])
    end

    test "accepts empty children list with generator" do
      generator = create_aes_keyring("generator")
      assert {:ok, multi} = Multi.new(generator: generator, children: [])
      assert multi.generator == generator
      assert multi.children == []
    end
  end

  describe "list_keyrings/1" do
    test "returns generator followed by children" do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      assert Multi.list_keyrings(multi) == [generator, child1, child2]
    end

    test "returns only children when no generator" do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      assert Multi.list_keyrings(multi) == [child1, child2]
    end

    test "returns only generator when no children" do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      assert Multi.list_keyrings(multi) == [generator]
    end
  end

  describe "unwrap_key/3" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "fails if materials already have plaintext key", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      existing_key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, existing_key)

      assert {:error, :plaintext_data_key_already_set} =
               Multi.unwrap_key(multi, materials, [])
    end

    test "decrypts with generator keyring", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      # Encrypt with the keyring
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(keyring, enc_materials)

      # Decrypt with multi-keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "decrypts with child keyring when generator fails", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(generator: generator, children: [child])

      # Encrypt with child keyring only
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(child, enc_materials)

      # Decrypt with multi-keyring - generator will fail, child will succeed
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "returns immediately on first success", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Encrypt with child1
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(child1, enc_materials)

      # Decrypt - should succeed with child1, never try child2
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "collects errors when all keyrings fail", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Create EDK that neither keyring can decrypt (from a different keyring)
      other_keyring = create_aes_keyring("other")
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawAes.wrap_key(other_keyring, enc_materials)

      # Decrypt - both should fail
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      result = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert {:error, {:all_keyrings_failed, errors}} = result
      assert length(errors) == 2
    end

    test "returns error when no EDKs provided", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      result = Multi.unwrap_key(multi, dec_materials, [])

      assert {:error, {:all_keyrings_failed, _errors}} = result
    end
  end

  describe "wrap_key/2" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "generates and wraps key with generator only", %{suite: suite} do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      {:ok, result} = Multi.wrap_key(multi, materials)

      assert is_binary(result.plaintext_data_key)
      assert byte_size(result.plaintext_data_key) == 32
      assert length(result.encrypted_data_keys) == 1
    end

    test "wraps existing key with children only", %{suite: suite} do
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(children: [child1, child2])

      # Pre-set plaintext data key (required when no generator)
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      {:ok, result} = Multi.wrap_key(multi, materials)

      assert result.plaintext_data_key == existing_key
      assert length(result.encrypted_data_keys) == 2
    end

    test "fails if no generator and no plaintext key", %{suite: suite} do
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(children: [child])

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      assert {:error, :no_plaintext_data_key} = Multi.wrap_key(multi, materials)
    end

    test "fails if materials have plaintext key when generator present", %{suite: suite} do
      generator = create_aes_keyring("generator")
      {:ok, multi} = Multi.new(generator: generator)

      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:error, :plaintext_data_key_already_set} = Multi.wrap_key(multi, materials)
    end

    test "generator followed by children adds multiple EDKs", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, result} = Multi.wrap_key(multi, materials)

      # Generator + 2 children = 3 EDKs
      assert length(result.encrypted_data_keys) == 3
    end

    test "round-trips encrypt/decrypt with generator only", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"context" => "test"})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"context" => "test"})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "round-trips encrypt/decrypt with generator and children", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child1 = create_aes_keyring("child1")
      child2 = create_aes_keyring("child2")
      {:ok, multi} = Multi.new(generator: generator, children: [child1, child2])

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Decrypt - any single keyring should work
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "can decrypt with subset of keyrings", %{suite: suite} do
      generator = create_aes_keyring("generator")
      child = create_aes_keyring("child")
      {:ok, encrypt_multi} = Multi.new(generator: generator, children: [child])

      # Encrypt with both
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(encrypt_multi, enc_materials)
      assert length(enc_result.encrypted_data_keys) == 2

      # Decrypt with only the child keyring
      {:ok, decrypt_multi} = Multi.new(children: [child])
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        Multi.unwrap_key(decrypt_multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end

  describe "edge cases" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "handles nested multi-keyrings", %{suite: suite} do
      inner_gen = create_aes_keyring("inner-gen")
      inner_child = create_aes_keyring("inner-child")
      {:ok, inner_multi} = Multi.new(generator: inner_gen, children: [inner_child])

      outer_child = create_aes_keyring("outer-child")
      {:ok, outer_multi} = Multi.new(generator: inner_multi, children: [outer_child])

      # Encrypt with nested multi-keyring
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(outer_multi, enc_materials)

      # Should have 3 EDKs: inner-gen + inner-child + outer-child
      assert length(enc_result.encrypted_data_keys) == 3

      # Decrypt with nested multi-keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        Multi.unwrap_key(outer_multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "preserves encryption context through wrap/unwrap", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      ec = %{"purpose" => "test", "user" => "alice"}

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "fails with wrong encryption context", %{suite: suite} do
      keyring = create_aes_keyring()
      {:ok, multi} = Multi.new(generator: keyring)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{"key" => "value1"})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{"key" => "value2"})
      result = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert {:error, {:all_keyrings_failed, _errors}} = result
    end

    test "single child keyring works", %{suite: suite} do
      child = create_aes_keyring("child")
      {:ok, multi} = Multi.new(children: [child])

      # Need existing plaintext key since no generator
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      {:ok, enc_result} = Multi.wrap_key(multi, materials)
      assert length(enc_result.encrypted_data_keys) == 1

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == existing_key
    end

    test "handles many children", %{suite: suite} do
      generator = create_aes_keyring("generator")
      children = for i <- 1..10, do: create_aes_keyring("child-#{i}")
      {:ok, multi} = Multi.new(generator: generator, children: children)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = Multi.wrap_key(multi, enc_materials)

      # Generator + 10 children = 11 EDKs
      assert length(enc_result.encrypted_data_keys) == 11

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      {:ok, dec_result} = Multi.unwrap_key(multi, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end

  describe "behaviour callbacks" do
    test "on_encrypt returns error directing to wrap_key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, {:must_use_wrap_key, _msg}} = Multi.on_encrypt(materials)
    end

    test "on_decrypt returns error directing to unwrap_key" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, {:must_use_unwrap_key, _msg}} = Multi.on_decrypt(materials, [])
    end
  end

  describe "new_with_kms_generator/4" do
    test "creates multi-keyring with KMS generator" do
      {:ok, client} = Mock.new(%{})

      assert {:ok, multi} =
               Multi.new_with_kms_generator(
                 "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                 client,
                 []
               )

      assert %AwsKms{} = multi.generator

      assert multi.generator.kms_key_id ==
               "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"

      assert multi.children == []
    end

    test "creates multi-keyring with KMS generator and children" do
      {:ok, client} = Mock.new(%{})
      child = create_aes_keyring("child")

      assert {:ok, multi} =
               Multi.new_with_kms_generator(
                 "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                 client,
                 [child]
               )

      assert %AwsKms{} = multi.generator
      assert multi.children == [child]
    end

    test "passes grant tokens to KMS keyring" do
      {:ok, client} = Mock.new(%{})

      assert {:ok, multi} =
               Multi.new_with_kms_generator(
                 "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                 client,
                 [],
                 grant_tokens: ["token1", "token2"]
               )

      assert multi.generator.grant_tokens == ["token1", "token2"]
    end

    test "returns error for invalid key_id" do
      {:ok, client} = Mock.new(%{})

      assert {:error, :key_id_required} = Multi.new_with_kms_generator(nil, client, [])
      assert {:error, :key_id_empty} = Multi.new_with_kms_generator("", client, [])
    end

    test "returns error for invalid client" do
      assert {:error, :client_required} =
               Multi.new_with_kms_generator(
                 "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
                 nil,
                 []
               )
    end
  end

  describe "new_mrk_aware/4" do
    test "creates MRK-aware multi-keyring with primary and replicas" do
      {:ok, primary_client} = Mock.new(%{})
      {:ok, east_client} = Mock.new(%{})
      {:ok, eu_client} = Mock.new(%{})

      assert {:ok, multi} =
               Multi.new_mrk_aware(
                 "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
                 primary_client,
                 [
                   {"us-east-1", east_client},
                   {"eu-west-1", eu_client}
                 ]
               )

      assert %AwsKmsMrk{} = multi.generator
      assert multi.generator.kms_key_id == "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123"
      assert length(multi.children) == 2

      [east_keyring, eu_keyring] = multi.children
      assert %AwsKmsMrk{} = east_keyring
      assert %AwsKmsMrk{} = eu_keyring
      assert east_keyring.kms_key_id == "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
      assert eu_keyring.kms_key_id == "arn:aws:kms:eu-west-1:123456789012:key/mrk-abc123"
    end

    test "creates MRK-aware multi-keyring with no replicas" do
      {:ok, client} = Mock.new(%{})

      assert {:ok, multi} =
               Multi.new_mrk_aware(
                 "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
                 client,
                 []
               )

      assert %AwsKmsMrk{} = multi.generator
      assert multi.children == []
    end

    test "passes grant tokens to all keyrings" do
      {:ok, primary_client} = Mock.new(%{})
      {:ok, replica_client} = Mock.new(%{})

      assert {:ok, multi} =
               Multi.new_mrk_aware(
                 "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
                 primary_client,
                 [{"us-east-1", replica_client}],
                 grant_tokens: ["token1"]
               )

      assert multi.generator.grant_tokens == ["token1"]
      [replica] = multi.children
      assert replica.grant_tokens == ["token1"]
    end

    test "returns error for non-ARN primary key" do
      {:ok, client} = Mock.new(%{})

      # Alias names can't be reconstructed for different regions
      assert {:error, {:invalid_replica_region, "us-east-1", :primary_key_must_be_arn}} =
               Multi.new_mrk_aware(
                 "alias/my-key",
                 client,
                 [{"us-east-1", client}]
               )
    end

    test "returns error for invalid primary client" do
      assert {:error, :client_required} =
               Multi.new_mrk_aware(
                 "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
                 nil,
                 []
               )
    end

    test "returns error for invalid replica client" do
      {:ok, primary_client} = Mock.new(%{})

      assert {:error, {:replica_keyring_failed, "us-east-1", :client_required}} =
               Multi.new_mrk_aware(
                 "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
                 primary_client,
                 [{"us-east-1", nil}]
               )
    end
  end

  describe "error handling" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, suite: suite}
    end

    test "wrap_key fails with unsupported keyring type", %{suite: suite} do
      # Create a struct that's not a valid keyring
      invalid_keyring = %{__struct__: FakeKeyring}
      {:ok, multi} = Multi.new(children: [invalid_keyring])

      # Pre-set plaintext data key since no generator
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:error, {:child_keyring_failed, 0, {:unsupported_keyring_type, FakeKeyring}}} =
               Multi.wrap_key(multi, materials)
    end

    test "unwrap_key fails with unsupported keyring type", %{suite: suite} do
      # Create a struct that's not a valid keyring
      invalid_keyring = %{__struct__: FakeKeyring}
      {:ok, multi} = Multi.new(children: [invalid_keyring])

      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, {:all_keyrings_failed, [{:unsupported_keyring_type, FakeKeyring}]}} =
               Multi.unwrap_key(multi, materials, [])
    end
  end
end
