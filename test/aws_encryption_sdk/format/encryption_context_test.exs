defmodule AwsEncryptionSdk.Format.EncryptionContextTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.EncryptionContext

  describe "validate/1" do
    test "accepts empty context" do
      assert :ok = EncryptionContext.validate(%{})
    end

    test "accepts context without reserved keys" do
      assert :ok = EncryptionContext.validate(%{"user-key" => "value", "another" => "val"})
    end

    test "rejects context with aws-crypto- prefix" do
      context = %{"aws-crypto-public-key" => "value"}

      assert {:error, {:reserved_keys, ["aws-crypto-public-key"]}} =
               EncryptionContext.validate(context)
    end

    test "returns all reserved keys found" do
      context = %{
        "aws-crypto-a" => "1",
        "aws-crypto-b" => "2",
        "valid-key" => "3"
      }

      assert {:error, {:reserved_keys, keys}} = EncryptionContext.validate(context)
      assert keys == ["aws-crypto-a", "aws-crypto-b"]
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "round-trips empty context" do
      assert <<>> = EncryptionContext.serialize(%{})
      assert {:ok, %{}, <<>>} = EncryptionContext.deserialize(<<>>)
    end

    test "round-trips single entry" do
      context = %{"key" => "value"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "round-trips multiple entries" do
      context = %{"a" => "1", "b" => "2", "c" => "3"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "sorts entries by key" do
      context = %{"z" => "last", "a" => "first", "m" => "middle"}
      serialized = EncryptionContext.serialize(context)

      # First entry should be "a" (0x61), not "m" (0x6d) or "z" (0x7a)
      <<_count::16-big, rest::binary>> = serialized
      <<key_len::16-big, first_key::binary-size(key_len), _rest::binary>> = rest

      assert first_key == "a"
    end

    test "handles UTF-8 keys correctly" do
      context = %{"café" => "coffee", "naïve" => "simple"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "preserves trailing bytes" do
      context = %{"k" => "v"}
      serialized = EncryptionContext.serialize(context)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, ^context, <<99, 100>>} = EncryptionContext.deserialize(with_trailing)
    end

    test "returns error for invalid format" do
      # Invalid: starts with non-zero count but has no data
      assert {:error, :invalid_encryption_context_format} = EncryptionContext.deserialize(<<1>>)
    end

    test "deserializes zero count correctly" do
      assert {:ok, %{}, <<1, 2, 3>>} = EncryptionContext.deserialize(<<0::16-big, 1, 2, 3>>)
    end
  end
end
