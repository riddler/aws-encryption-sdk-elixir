defmodule AwsEncryptionSdk.Stream.SignatureAccumulatorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  describe "init/0" do
    test "creates accumulator with hash context" do
      acc = SignatureAccumulator.init()
      assert %SignatureAccumulator{hash_ctx: ctx} = acc
      assert is_reference(ctx)
    end
  end

  describe "update/2" do
    test "accumulates data" do
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("hello")
        |> SignatureAccumulator.update(" world")

      digest = SignatureAccumulator.digest(acc)
      expected = :crypto.hash(:sha384, "hello world")
      assert digest == expected
    end

    test "handles empty data" do
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update(<<>>)
        |> SignatureAccumulator.update("data")

      digest = SignatureAccumulator.digest(acc)
      expected = :crypto.hash(:sha384, "data")
      assert digest == expected
    end
  end

  describe "sign/2 and verify/3" do
    test "produces valid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("header bytes")
        |> SignatureAccumulator.update("frame 1 bytes")
        |> SignatureAccumulator.update("frame 2 bytes")

      signature = SignatureAccumulator.sign(acc, private_key)
      assert is_binary(signature)

      # Verify with fresh accumulator (same data)
      verify_acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("header bytes")
        |> SignatureAccumulator.update("frame 1 bytes")
        |> SignatureAccumulator.update("frame 2 bytes")

      assert SignatureAccumulator.verify(verify_acc, signature, public_key)
    end

    test "rejects invalid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("original data")

      signature = SignatureAccumulator.sign(acc, private_key)

      # Different data should fail verification
      bad_acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("different data")

      refute SignatureAccumulator.verify(bad_acc, signature, public_key)
    end

    test "matches ECDSA.sign for complete message" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "complete message for signing"

      # Incremental signing
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update(message)

      incremental_sig = SignatureAccumulator.sign(acc, private_key)

      # Both should verify with the same public key
      assert ECDSA.verify(message, incremental_sig, public_key, :secp384r1)
    end
  end
end
