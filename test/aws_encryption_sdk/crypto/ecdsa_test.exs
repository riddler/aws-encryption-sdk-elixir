defmodule AwsEncryptionSdk.Crypto.ECDSATest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.ECDSA

  describe "generate_key_pair/1" do
    test "generates valid P-384 key pair" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      # P-384 private key is 48 bytes
      assert byte_size(private_key) == 48

      # P-384 uncompressed public key is 97 bytes (0x04 || x || y)
      assert byte_size(public_key) == 97
      assert :binary.first(public_key) == 0x04
    end

    test "generates unique key pairs" do
      {priv1, pub1} = ECDSA.generate_key_pair(:secp384r1)
      {priv2, pub2} = ECDSA.generate_key_pair(:secp384r1)

      refute priv1 == priv2
      refute pub1 == pub2
    end
  end

  describe "encode_public_key/1 and decode_public_key/1" do
    test "round-trips public key" do
      {_private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      encoded = ECDSA.encode_public_key(public_key)
      assert is_binary(encoded)
      assert String.printable?(encoded)

      {:ok, decoded} = ECDSA.decode_public_key(encoded)
      assert decoded == public_key
    end

    test "decode_public_key returns error for invalid base64" do
      assert {:error, :invalid_base64} = ECDSA.decode_public_key("not-valid-base64!!!")
    end
  end
end
