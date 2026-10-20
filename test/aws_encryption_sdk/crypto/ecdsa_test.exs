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
      assert ECDSA.normalize_public_key(decoded, :secp384r1) == public_key
    end

    # Sabotage: encode_public_key/1 returning Base.encode64(public_key) for
    # an uncompressed point (the form 1.0.x wrote) turns this test red.
    test "writes the SEC 1 compressed point: the parity prefix, then x" do
      for _round <- 1..20 do
        {_private_key, <<0x04, x::binary-size(48), y::binary-size(48)>> = public_key} =
          ECDSA.generate_key_pair(:secp384r1)

        {:ok, decoded} = public_key |> ECDSA.encode_public_key() |> ECDSA.decode_public_key()

        expected_prefix = if rem(:binary.last(y), 2) == 0, do: 0x02, else: 0x03
        assert decoded == <<expected_prefix, x::binary>>
        assert byte_size(ECDSA.encode_public_key(public_key)) == 68
      end
    end

    test "encodes an already compressed point as it is" do
      {_private_key, <<0x04, x::binary-size(48), _y::binary-size(48)>>} =
        ECDSA.generate_key_pair(:secp384r1)

      compressed = <<0x02, x::binary>>
      assert ECDSA.encode_public_key(compressed) == Base.encode64(compressed)
    end

    test "decode_public_key returns error for invalid base64" do
      assert {:error, :invalid_base64} = ECDSA.decode_public_key("not-valid-base64!!!")
    end
  end

  describe "sign/3" do
    test "generates a signature" do
      {private_key, _public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"

      signature = ECDSA.sign(message, private_key, :secp384r1)

      assert is_binary(signature)
      assert byte_size(signature) > 0
    end

    test "generates different signatures for different messages" do
      {private_key, _public_key} = ECDSA.generate_key_pair(:secp384r1)
      message1 = "test message 1"
      message2 = "test message 2"

      signature1 = ECDSA.sign(message1, private_key, :secp384r1)
      signature2 = ECDSA.sign(message2, private_key, :secp384r1)

      refute signature1 == signature2
    end
  end

  describe "verify/4" do
    test "verifies a valid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"

      signature = ECDSA.sign(message, private_key, :secp384r1)

      assert ECDSA.verify(message, signature, public_key, :secp384r1)
    end

    test "rejects an invalid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"

      signature = ECDSA.sign(message, private_key, :secp384r1)

      # Tamper with message
      tampered_message = "tampered message"

      refute ECDSA.verify(tampered_message, signature, public_key, :secp384r1)
    end

    test "rejects signature from different key" do
      {private_key1, _public_key1} = ECDSA.generate_key_pair(:secp384r1)
      {_private_key2, public_key2} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"

      signature = ECDSA.sign(message, private_key1, :secp384r1)

      refute ECDSA.verify(message, signature, public_key2, :secp384r1)
    end

    test "rejects tampered signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"

      signature = ECDSA.sign(message, private_key, :secp384r1)

      # Tamper with signature
      <<first_byte, rest::binary>> = signature
      tampered_signature = <<first_byte + 1, rest::binary>>

      refute ECDSA.verify(message, tampered_signature, public_key, :secp384r1)
    end

    # Sabotage: remove the rescue in ECDSA.verify/4 -> each case raises
    # ErlangError from :crypto instead of answering false.
    test "answers false for a public key that is not a point on the curve" do
      {private_key, _public_key} = ECDSA.generate_key_pair(:secp256r1)
      {_p384_private_key, p384_public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "test message"
      signature = ECDSA.sign(message, private_key, :secp256r1)

      # (1, 2) does not satisfy the P-256 curve equation
      off_curve = <<0x04, 1::256, 2::256>>

      # A raise becomes a value here, so that it fails the assertion
      answer = fn key, curve ->
        try do
          ECDSA.verify(message, signature, key, curve)
        rescue
          error -> {:raised, error.__struct__}
        end
      end

      assert answer.(off_curve, :secp256r1) == false
      assert answer.(p384_public_key, :secp256r1) == false
      assert answer.(<<1, 2, 3>>, :secp384r1) == false
    end
  end

  describe "check_signing_key!/2" do
    alias AwsEncryptionSdk.AlgorithmSuite

    # A raise becomes a value, so that it fails the assertion
    defp check(suite, key) do
      ECDSA.check_signing_key!(suite, key)
    rescue
      error -> {:raised, error.__struct__}
    end

    # Sabotage: in check_signing_key!/2, drop the `other != curve` condition
    # -> each signed suite's own key raises.
    test "accepts a private key on the suite's curve, and no key" do
      p256_suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()
      p384_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      {p256_key, _public_key} = ECDSA.generate_key_pair(:secp256r1)
      {p384_key, _public_key} = ECDSA.generate_key_pair(:secp384r1)

      assert :ok == check(p256_suite, p256_key)
      assert :ok == check(p384_suite, p384_key)
      assert :ok == check(p384_suite, nil)
    end

    test "accepts any key on an unsigned suite, which signs nothing" do
      unsigned = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {p256_key, _public_key} = ECDSA.generate_key_pair(:secp256r1)

      assert :ok == ECDSA.check_signing_key!(unsigned, p256_key)
    end

    # A key of neither curve's size is left to :crypto, as before.
    test "accepts a key of neither curve's size" do
      p384_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      assert :ok == ECDSA.check_signing_key!(p384_suite, :crypto.strong_rand_bytes(47))
    end

    test "raises naming the suite, its curve and the key's size" do
      p256_suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()
      p384_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      {p256_key, _public_key} = ECDSA.generate_key_pair(:secp256r1)
      {p384_key, _public_key} = ECDSA.generate_key_pair(:secp384r1)

      assert_raise ArgumentError,
                   "the signing key is not a secp256r1 private key, the curve algorithm " <>
                     "suite 0x0214 signs on: it is 48 bytes, the size of a secp384r1 private key",
                   fn -> ECDSA.check_signing_key!(p256_suite, p384_key) end

      assert_raise ArgumentError,
                   "the signing key is not a secp384r1 private key, the curve algorithm " <>
                     "suite 0x0578 signs on: it is 32 bytes, the size of a secp256r1 private key",
                   fn -> ECDSA.check_signing_key!(p384_suite, p256_key) end
    end
  end
end
