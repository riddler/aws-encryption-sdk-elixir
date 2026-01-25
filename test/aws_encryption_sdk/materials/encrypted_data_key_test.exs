defmodule AwsEncryptionSdk.Materials.EncryptedDataKeyTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "new/3" do
    test "creates an EDK struct" do
      edk = EncryptedDataKey.new("aws-kms", "arn:aws:kms:...", <<1, 2, 3>>)

      assert edk.key_provider_id == "aws-kms"
      assert edk.key_provider_info == "arn:aws:kms:..."
      assert edk.ciphertext == <<1, 2, 3>>
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "round-trips a simple EDK" do
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3, 4>>)
      serialized = EncryptedDataKey.serialize(edk)

      assert {:ok, ^edk, <<>>} = EncryptedDataKey.deserialize(serialized)
    end

    test "round-trips an EDK with empty provider_info" do
      edk = EncryptedDataKey.new("raw", <<>>, <<0::256>>)
      serialized = EncryptedDataKey.serialize(edk)

      assert {:ok, ^edk, <<>>} = EncryptedDataKey.deserialize(serialized)
    end

    test "preserves trailing bytes" do
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      serialized = EncryptedDataKey.serialize(edk)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, ^edk, <<99, 100>>} = EncryptedDataKey.deserialize(with_trailing)
    end

    test "produces correct binary format" do
      edk = EncryptedDataKey.new("ab", "cd", <<1, 2>>)
      serialized = EncryptedDataKey.serialize(edk)

      # provider_id_len (2) + "ab" + provider_info_len (2) + "cd" + ciphertext_len (2) + <<1,2>>
      assert serialized == <<0, 2, ?a, ?b, 0, 2, ?c, ?d, 0, 2, 1, 2>>
    end
  end

  describe "serialize_list/1 and deserialize_list/1" do
    test "round-trips a list of EDKs" do
      edks = [
        EncryptedDataKey.new("provider1", "info1", <<1>>),
        EncryptedDataKey.new("provider2", "info2", <<2>>)
      ]

      assert {:ok, serialized} = EncryptedDataKey.serialize_list(edks)
      assert {:ok, ^edks, <<>>} = EncryptedDataKey.deserialize_list(serialized)
    end

    test "rejects empty list" do
      assert {:error, :empty_edk_list} = EncryptedDataKey.serialize_list([])
    end

    test "rejects zero count in binary" do
      assert {:error, :empty_edk_list} = EncryptedDataKey.deserialize_list(<<0, 0>>)
    end

    test "deserialize returns error for insufficient data" do
      # Not enough data for a complete EDK
      assert {:error, :invalid_edk_format} = EncryptedDataKey.deserialize(<<0, 5>>)
    end

    test "deserialize_list preserves trailing bytes" do
      edk = EncryptedDataKey.new("test", "info", <<1, 2>>)
      {:ok, serialized} = EncryptedDataKey.serialize_list([edk])
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, [^edk], <<99, 100>>} = EncryptedDataKey.deserialize_list(with_trailing)
    end

    test "deserialize_list handles multiple EDKs correctly" do
      edk1 = EncryptedDataKey.new("p1", "i1", <<1>>)
      edk2 = EncryptedDataKey.new("p2", "i2", <<2>>)
      edk3 = EncryptedDataKey.new("p3", "i3", <<3>>)

      {:ok, serialized} = EncryptedDataKey.serialize_list([edk1, edk2, edk3])
      assert {:ok, edks, <<>>} = EncryptedDataKey.deserialize_list(serialized)
      assert length(edks) == 3
      assert Enum.at(edks, 0) == edk1
      assert Enum.at(edks, 1) == edk2
      assert Enum.at(edks, 2) == edk3
    end
  end
end
