defmodule AwsEncryptionSdk.Cache.CacheEntryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.CacheEntry
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  defp create_test_materials do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    EncryptionMaterials.new_for_encrypt(suite, %{})
  end

  describe "new/2" do
    test "creates entry with correct fields" do
      materials = create_test_materials()
      entry = CacheEntry.new(materials, 300)

      assert entry.materials == materials
      assert entry.messages_used == 0
      assert entry.bytes_used == 0
      assert entry.expiry_time > entry.creation_time
    end
  end

  describe "expired?/1" do
    test "returns false for fresh entry" do
      materials = create_test_materials()
      entry = CacheEntry.new(materials, 300)

      refute CacheEntry.expired?(entry)
    end

    test "returns true for expired entry" do
      materials = create_test_materials()
      # Create entry that's already expired
      entry = %CacheEntry{
        materials: materials,
        creation_time: System.monotonic_time(:second) - 400,
        expiry_time: System.monotonic_time(:second) - 100,
        messages_used: 0,
        bytes_used: 0
      }

      assert CacheEntry.expired?(entry)
    end
  end

  describe "can_serve?/4" do
    defp entry_with(messages_used, bytes_used) do
      %CacheEntry{
        materials: create_test_materials(),
        creation_time: 0,
        expiry_time: 1000,
        messages_used: messages_used,
        bytes_used: bytes_used
      }
    end

    test "returns true when under limits" do
      assert CacheEntry.can_serve?(entry_with(10, 1000), 100, 100, 10_000)
    end

    test "returns false when messages are exhausted" do
      refute CacheEntry.can_serve?(entry_with(100, 0), 0, 100, 10_000)
    end

    test "returns true when the request lands exactly on the byte limit" do
      assert CacheEntry.can_serve?(entry_with(0, 9_900), 100, 100, 10_000)
    end

    test "returns false when the request would cross the byte limit" do
      refute CacheEntry.can_serve?(entry_with(0, 9_900), 101, 100, 10_000)
    end

    test "returns false when a single request exceeds the byte limit outright" do
      refute CacheEntry.can_serve?(entry_with(0, 0), 10_001, 100, 10_000)
    end

    test "zero-byte requests are governed by the message limit alone" do
      assert CacheEntry.can_serve?(entry_with(99, 10_000), 0, 100, 10_000)
      refute CacheEntry.can_serve?(entry_with(100, 0), 0, 100, 10_000)
    end
  end
end
