defmodule AwsEncryptionSdk.Crypto.AesGcmTest do
  use ExUnit.Case, async: true
  import Bitwise

  alias AwsEncryptionSdk.Crypto.AesGcm

  describe "encrypt/5 and decrypt/6" do
    test "round-trips data with AES-256-GCM" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      plaintext = "Hello, World!"
      aad = "additional data"

      {ciphertext, tag} = AesGcm.encrypt(:aes_256_gcm, key, iv, plaintext, aad)
      assert {:ok, ^plaintext} = AesGcm.decrypt(:aes_256_gcm, key, iv, ciphertext, aad, tag)
    end

    test "round-trips data with AES-128-GCM" do
      key = :crypto.strong_rand_bytes(16)
      iv = :crypto.strong_rand_bytes(12)
      plaintext = "Test data"
      aad = ""

      {ciphertext, tag} = AesGcm.encrypt(:aes_128_gcm, key, iv, plaintext, aad)
      assert {:ok, ^plaintext} = AesGcm.decrypt(:aes_128_gcm, key, iv, ciphertext, aad, tag)
    end

    test "fails with wrong key" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      plaintext = "Secret"
      aad = ""

      {ciphertext, tag} = AesGcm.encrypt(:aes_256_gcm, key1, iv, plaintext, aad)

      assert {:error, :authentication_failed} =
               AesGcm.decrypt(:aes_256_gcm, key2, iv, ciphertext, aad, tag)
    end

    test "fails with tampered ciphertext" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      plaintext = "Secret"
      aad = ""

      {ciphertext, tag} = AesGcm.encrypt(:aes_256_gcm, key, iv, plaintext, aad)
      # Flip first bit of ciphertext
      <<first_byte, rest::binary>> = ciphertext
      tampered = <<bxor(first_byte, 1), rest::binary>>

      assert {:error, :authentication_failed} =
               AesGcm.decrypt(:aes_256_gcm, key, iv, tampered, aad, tag)
    end

    test "fails with wrong AAD" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      plaintext = "Secret"

      {ciphertext, tag} = AesGcm.encrypt(:aes_256_gcm, key, iv, plaintext, "aad1")

      assert {:error, :authentication_failed} =
               AesGcm.decrypt(:aes_256_gcm, key, iv, ciphertext, "aad2", tag)
    end

    test "encrypts empty plaintext" do
      key = :crypto.strong_rand_bytes(32)
      iv = :crypto.strong_rand_bytes(12)
      aad = "header data"

      {ciphertext, tag} = AesGcm.encrypt(:aes_256_gcm, key, iv, <<>>, aad)
      assert ciphertext == <<>>
      assert byte_size(tag) == 16
      assert {:ok, <<>>} = AesGcm.decrypt(:aes_256_gcm, key, iv, ciphertext, aad, tag)
    end
  end

  describe "sequence_number_to_iv/1" do
    test "returns 12-byte IV" do
      iv = AesGcm.sequence_number_to_iv(1)
      assert byte_size(iv) == 12
    end

    test "sequence 1 produces correct IV" do
      assert AesGcm.sequence_number_to_iv(1) == <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1>>
    end

    test "sequence 256 produces correct IV" do
      assert AesGcm.sequence_number_to_iv(256) == <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0>>
    end
  end

  describe "zero_iv/0" do
    test "returns 12 zero bytes" do
      assert AesGcm.zero_iv() == <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
    end
  end

  describe "key_length/1" do
    test "returns 16 for aes_128_gcm" do
      assert AesGcm.key_length(:aes_128_gcm) == 16
    end

    test "returns 24 for aes_192_gcm" do
      assert AesGcm.key_length(:aes_192_gcm) == 24
    end

    test "returns 32 for aes_256_gcm" do
      assert AesGcm.key_length(:aes_256_gcm) == 32
    end
  end

  describe "iv_length/0" do
    test "returns 12" do
      assert AesGcm.iv_length() == 12
    end
  end

  describe "tag_length/0" do
    test "returns 16" do
      assert AesGcm.tag_length() == 16
    end
  end
end
