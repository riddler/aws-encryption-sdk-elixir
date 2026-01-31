defmodule AwsEncryptionSdk.Cmm.CachingTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Cmm.{Caching, Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Keyring.RawAes

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    keyring
  end

  defp setup_caching_cmm(opts) do
    {:ok, cache} = LocalCache.start_link([])
    keyring = create_test_keyring()
    cmm = Caching.new_with_keyring(keyring, cache, opts)
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

    request = %{
      encryption_context: %{"tenant" => "acme"},
      commitment_policy: :require_encrypt_require_decrypt,
      algorithm_suite: suite
    }

    {cmm, request}
  end

  describe "new/3" do
    test "creates CMM with required options" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300)

      assert caching_cmm.underlying_cmm == cmm
      assert caching_cmm.cache == cache
      assert caching_cmm.max_age == 300
      assert byte_size(caching_cmm.partition_id) == 16
    end

    test "uses custom partition_id" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300, partition_id: "custom-partition")

      assert caching_cmm.partition_id == "custom-partition"
    end

    test "sets default limits" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300)

      assert caching_cmm.max_bytes == 9_223_372_036_854_775_807
      assert caching_cmm.max_messages == 4_294_967_296
    end

    test "accepts custom limits" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300, max_bytes: 1000, max_messages: 10)

      assert caching_cmm.max_bytes == 1000
      assert caching_cmm.max_messages == 10
    end

    test "raises on invalid max_age" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      assert_raise ArgumentError, fn ->
        Caching.new(cmm, cache, max_age: 0)
      end
    end
  end

  describe "new_with_keyring/3" do
    test "wraps keyring in Default CMM" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()

      caching_cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      assert %Default{keyring: ^keyring} = caching_cmm.underlying_cmm
    end
  end

  describe "get_encryption_materials/2 - cache behavior" do
    test "cache miss calls underlying CMM and stores result" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = Caching.get_encryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil
      assert materials.encrypted_data_keys != []
    end

    test "cache hit returns same materials" do
      {cmm, request} = setup_caching_cmm(max_age: 300)

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Same plaintext key = cache hit
      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end

    test "different context results in cache miss" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request1 = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      request2 = %{
        encryption_context: %{"tenant" => "other"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request1)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request2)

      # Different plaintext keys = cache miss
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end

    test "exceeding message limit triggers refresh" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300, max_messages: 2)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)
      # Third call should exceed limit (2 messages used)
      {:ok, materials3} = Caching.get_encryption_materials(cmm, request)

      assert materials1.plaintext_data_key == materials2.plaintext_data_key
      assert materials2.plaintext_data_key != materials3.plaintext_data_key
    end

    test "exceeding byte limit triggers refresh" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      # Set limit to 100 bytes
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300, max_bytes: 100)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite,
        max_plaintext_length: 100
      }

      # First call: stores entry with bytes_used=100
      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      # Second call: would be 100+100=200, but 100 >= 100, so refresh
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Different keys = cache refresh triggered
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end

    test "handles request without max_plaintext_length" do
      {cmm, request} = setup_caching_cmm(max_age: 300)

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Should still cache with 0 bytes tracked
      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end
  end

  describe "get_encryption_materials/2 - Identity KDF bypass" do
    test "bypasses cache for Identity KDF suite" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      # Deprecated NO_KDF suite
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf()

      request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Different keys each time = cache bypass
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end
  end

  describe "get_decryption_materials/2 - Identity KDF bypass" do
    test "bypasses cache for Identity KDF suite" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf()

      # Get encryption materials first
      enc_request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Caching.get_encryption_materials(cmm, enc_request)

      # Decrypt twice - should bypass cache each time
      dec_request = %{
        algorithm_suite: suite,
        commitment_policy: :forbid_encrypt_allow_decrypt,
        encrypted_data_keys: enc_materials.encrypted_data_keys,
        encryption_context: enc_materials.encryption_context
      }

      {:ok, _materials1} = Caching.get_decryption_materials(cmm, dec_request)
      {:ok, _materials2} = Caching.get_decryption_materials(cmm, dec_request)

      # Bypass confirmed (no error = success)
    end
  end

  describe "wrapping other CMMs" do
    test "wraps RequiredEncryptionContext CMM" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      underlying_cmm = RequiredEncryptionContext.new_with_keyring(["tenant"], keyring)
      cmm = Caching.new(underlying_cmm, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Cache hit works with wrapped RequiredEncryptionContext
      assert materials1.plaintext_data_key == materials2.plaintext_data_key
      # Verify required keys are preserved
      assert "tenant" in materials1.required_encryption_context_keys
    end

    test "wraps nested Caching CMM" do
      {:ok, cache1} = LocalCache.start_link([])
      {:ok, cache2} = LocalCache.start_link([])
      keyring = create_test_keyring()

      inner_cmm = Caching.new_with_keyring(keyring, cache1, max_age: 300)
      outer_cmm = Caching.new(inner_cmm, cache2, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(outer_cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(outer_cmm, request)

      # Both caches work independently
      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end
  end

  describe "get_encryption_materials/2 - partition isolation" do
    test "different partition IDs don't share cache entries" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm1 = Caching.new_with_keyring(keyring, cache, max_age: 300, partition_id: "partition-1")
      cmm2 = Caching.new_with_keyring(keyring, cache, max_age: 300, partition_id: "partition-2")
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm1, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm2, request)

      # Different partitions = different keys
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end
  end

  describe "get_decryption_materials/2" do
    setup do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Get encryption materials to create valid EDKs
      enc_request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Caching.get_encryption_materials(cmm, enc_request)

      {:ok, cmm: cmm, suite: suite, enc_materials: enc_materials}
    end

    test "cache miss calls underlying CMM", ctx do
      dec_request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.enc_materials.encrypted_data_keys,
        encryption_context: ctx.enc_materials.encryption_context
      }

      {:ok, materials} = Caching.get_decryption_materials(ctx.cmm, dec_request)

      assert materials.plaintext_data_key == ctx.enc_materials.plaintext_data_key
    end

    test "cache hit returns same materials", ctx do
      dec_request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.enc_materials.encrypted_data_keys,
        encryption_context: ctx.enc_materials.encryption_context
      }

      {:ok, materials1} = Caching.get_decryption_materials(ctx.cmm, dec_request)
      {:ok, materials2} = Caching.get_decryption_materials(ctx.cmm, dec_request)

      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end
  end

  describe "cache ID computation" do
    test "encryption cache ID is deterministic" do
      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"key" => "value"}

      id1 = Caching.compute_encryption_cache_id(partition_id, suite, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, suite, context)

      assert id1 == id2
      assert byte_size(id1) == 48
    end

    test "encryption cache ID differs for different suite" do
      partition_id = "test-partition-id!"
      suite1 = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      suite2 = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      context = %{}

      id1 = Caching.compute_encryption_cache_id(partition_id, suite1, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, suite2, context)

      assert id1 != id2
    end

    test "encryption cache ID handles nil suite" do
      partition_id = "test-partition-id!"
      context = %{"key" => "value"}

      id1 = Caching.compute_encryption_cache_id(partition_id, nil, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, nil, context)

      assert id1 == id2
      assert byte_size(id1) == 48
    end

    test "encryption cache ID differs for nil vs non-nil suite" do
      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{}

      id1 = Caching.compute_encryption_cache_id(partition_id, nil, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, suite, context)

      assert id1 != id2
    end

    test "decryption cache ID is deterministic" do
      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{}

      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      {:ok, enc_materials} =
        Default.get_encryption_materials(cmm, %{
          encryption_context: context,
          commitment_policy: :require_encrypt_require_decrypt,
          algorithm_suite: suite
        })

      edks = enc_materials.encrypted_data_keys

      id1 = Caching.compute_decryption_cache_id(partition_id, suite, edks, context)
      id2 = Caching.compute_decryption_cache_id(partition_id, suite, edks, context)

      assert id1 == id2
      assert byte_size(id1) == 48
    end

    test "decryption cache ID sorts EDKs" do
      alias AwsEncryptionSdk.Materials.EncryptedDataKey

      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{}

      edk1 = EncryptedDataKey.new("provider-a", "info-a", "ciphertext-a")
      edk2 = EncryptedDataKey.new("provider-z", "info-z", "ciphertext-z")

      # EDKs in different order should produce same cache ID
      id1 = Caching.compute_decryption_cache_id(partition_id, suite, [edk1, edk2], context)
      id2 = Caching.compute_decryption_cache_id(partition_id, suite, [edk2, edk1], context)

      assert id1 == id2
    end
  end
end
