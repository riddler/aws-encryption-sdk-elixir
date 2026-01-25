defmodule AwsEncryptionSdk.Format.FooterTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.Footer

  describe "serialize/1 and deserialize/1" do
    test "round-trips a signature" do
      # Simulate a DER-encoded signature
      signature = :crypto.strong_rand_bytes(103)

      assert {:ok, serialized} = Footer.serialize(signature)
      assert {:ok, footer, <<>>} = Footer.deserialize(serialized)

      assert footer.signature == signature
    end

    test "encodes length as big-endian uint16" do
      signature = :crypto.strong_rand_bytes(72)

      assert {:ok, <<0, 72, _rest::binary>>} = Footer.serialize(signature)
    end

    test "preserves trailing bytes" do
      signature = <<1, 2, 3, 4, 5>>

      assert {:ok, serialized} = Footer.serialize(signature)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, %{signature: ^signature}, <<99, 100>>} = Footer.deserialize(with_trailing)
    end

    test "handles empty signature" do
      assert {:ok, <<0, 0>>} = Footer.serialize(<<>>)
      assert {:ok, %{signature: <<>>}, <<>>} = Footer.deserialize(<<0, 0>>)
    end

    test "returns error for incomplete footer" do
      # Length says 100 bytes, but only 5 present
      assert {:error, :incomplete_footer} = Footer.deserialize(<<0, 100, 1, 2, 3, 4, 5>>)
    end

    test "returns error for invalid footer" do
      assert {:error, :invalid_footer} = Footer.deserialize(<<0>>)
      assert {:error, :invalid_footer} = Footer.deserialize(<<>>)
    end
  end
end
