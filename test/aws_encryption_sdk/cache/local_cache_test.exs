defmodule AwsEncryptionSdk.Cache.LocalCacheTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.{CacheEntry, LocalCache}
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  defp create_test_entry(max_age \\ 300) do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    CacheEntry.new(materials, max_age)
  end

  defp create_cache_id(data \\ "test") do
    :crypto.hash(:sha384, data)
  end

  describe "start_link/1" do
    test "starts cache process" do
      {:ok, cache} = LocalCache.start_link([])
      assert is_pid(cache)
    end

    test "starts with name" do
      {:ok, _cache} = LocalCache.start_link(name: :test_cache)
      assert Process.whereis(:test_cache) != nil
    after
      Process.whereis(:test_cache) && GenServer.stop(:test_cache)
    end
  end

  describe "put_cache_entry/3" do
    test "stores entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      assert :ok = LocalCache.put_cache_entry(cache, cache_id, entry)
    end

    test "replaces existing entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry1 = create_test_entry()
      entry2 = %{entry1 | messages_used: 99}

      LocalCache.put_cache_entry(cache, cache_id, entry1)
      LocalCache.put_cache_entry(cache, cache_id, entry2)

      {:ok, retrieved} = LocalCache.get_cache_entry(cache, cache_id)
      assert retrieved.messages_used == 99
    end
  end

  describe "get_cache_entry/2" do
    test "returns entry when found" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      {:ok, retrieved} = LocalCache.get_cache_entry(cache, cache_id)

      assert retrieved.materials == entry.materials
    end

    test "returns error when not found" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end

    test "returns error for expired entry and deletes it" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      # Create already expired entry
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      expired_entry = %CacheEntry{
        materials: materials,
        creation_time: System.monotonic_time(:second) - 400,
        expiry_time: System.monotonic_time(:second) - 100,
        messages_used: 0,
        bytes_used: 0
      }

      # Manually insert (bypassing normal put which would use current time)
      GenServer.call(cache, {:put, cache_id, expired_entry})

      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end
  end

  describe "delete_cache_entry/2" do
    test "deletes existing entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      assert :ok = LocalCache.delete_cache_entry(cache, cache_id)
      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end

    test "succeeds when entry doesn't exist" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert :ok = LocalCache.delete_cache_entry(cache, cache_id)
    end
  end

  describe "update_usage/4" do
    test "increments counters" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      LocalCache.update_usage(cache, cache_id, 1, 100)
      LocalCache.update_usage(cache, cache_id, 2, 200)

      {:ok, updated} = LocalCache.get_cache_entry(cache, cache_id)
      assert updated.messages_used == 3
      assert updated.bytes_used == 300
    end

    test "returns error when entry doesn't exist" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert {:error, :cache_miss} = LocalCache.update_usage(cache, cache_id, 1, 100)
    end
  end
end
