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

  describe "exceeded_limits?/3" do
    test "returns false when under limits" do
      materials = create_test_materials()

      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 10,
        bytes_used: 1000
      }

      refute CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end

    test "returns true when messages exceeded" do
      materials = create_test_materials()

      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 100,
        bytes_used: 0
      }

      assert CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end

    test "returns true when bytes exceeded" do
      materials = create_test_materials()

      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 0,
        bytes_used: 10_000
      }

      assert CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end
  end
end
