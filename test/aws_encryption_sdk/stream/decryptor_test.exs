defmodule AwsEncryptionSdk.Stream.DecryptorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Create test materials
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_data_key = :crypto.strong_rand_bytes(32)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: %{"purpose" => "test"},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: nil,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: %{"purpose" => "test"},
      verification_key: nil,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "init/1" do
    test "initializes decryptor" do
      get_materials = fn _header -> {:error, :not_implemented} end
      assert {:ok, dec} = Decryptor.init(get_materials: get_materials)
      assert dec.state == :init
    end
  end

  describe "update/2 with unsigned suite" do
    test "decrypts complete message in one chunk", ctx do
      plaintext = "Hello, streaming world!"

      # Encrypt
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Decrypt in one chunk
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, plaintexts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final} = Decryptor.finalize(dec)

      all_plaintexts = plaintexts ++ final
      result = all_plaintexts |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext

      # All should be verified (unsigned suite)
      assert Enum.all?(all_plaintexts, fn {_plaintext, status} -> status == :verified end)
    end

    test "decrypts message in multiple chunks", ctx do
      plaintext = :crypto.strong_rand_bytes(200)

      # Encrypt
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Decrypt in small chunks
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      chunks = chunk_binary(ciphertext, 30)

      {dec, all_plaintexts} =
        Enum.reduce(chunks, {dec, []}, fn chunk, {dec, acc} ->
          {:ok, dec, plaintexts} = Decryptor.update(dec, chunk)
          {dec, acc ++ plaintexts}
        end)

      {:ok, _dec, final} = Decryptor.finalize(dec)
      all_plaintexts = all_plaintexts ++ final

      result = all_plaintexts |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end

    test "releases plaintext incrementally", ctx do
      plaintext = :crypto.strong_rand_bytes(500)

      # Encrypt with small frames
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Feed header + first few frames
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # Split: header (~200 bytes) + some frames, then rest
      {:ok, dec, plaintexts1} = Decryptor.update(dec, binary_part(ciphertext, 0, 400))
      # Should have some plaintext already
      refute Enum.empty?(plaintexts1)

      {:ok, dec, plaintexts2} =
        Decryptor.update(dec, binary_part(ciphertext, 400, byte_size(ciphertext) - 400))

      {:ok, _dec, final} = Decryptor.finalize(dec)

      all = plaintexts1 ++ plaintexts2 ++ final
      result = all |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "finalize/1" do
    test "fails with trailing bytes", ctx do
      plaintext = "test"
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 100)
      # Add trailing garbage
      bad_ciphertext = ciphertext <> "garbage"

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, _plaintexts} = Decryptor.update(dec, bad_ciphertext)

      assert {:error, :trailing_bytes} = Decryptor.finalize(dec)
    end
  end

  describe "fail_on_signed option" do
    test "rejects signed suite when enabled" do
      # This would need a signed suite - placeholder test
      # The actual test requires signed materials setup
    end
  end

  # Helper functions

  defp encrypt_streaming(materials, plaintext, frame_length) do
    {:ok, enc} = Encryptor.init(materials, frame_length: frame_length)
    {:ok, enc, header} = Encryptor.start(enc)
    {:ok, enc, frames} = Encryptor.update(enc, plaintext)
    {:ok, _enc, final} = Encryptor.finalize(enc)
    header <> frames <> final
  end

  defp chunk_binary(binary, chunk_size) do
    chunk_binary_loop(binary, chunk_size, [])
  end

  defp chunk_binary_loop(<<>>, _chunk_size, acc), do: Enum.reverse(acc)

  defp chunk_binary_loop(binary, chunk_size, acc) when byte_size(binary) <= chunk_size do
    Enum.reverse([binary | acc])
  end

  defp chunk_binary_loop(binary, chunk_size, acc) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    chunk_binary_loop(rest, chunk_size, [chunk | acc])
  end
end
