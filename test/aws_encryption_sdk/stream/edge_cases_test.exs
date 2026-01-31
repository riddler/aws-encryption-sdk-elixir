defmodule AwsEncryptionSdk.Stream.EdgeCasesTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_data_key = :crypto.strong_rand_bytes(32)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: %{},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: nil,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: %{},
      verification_key: nil,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "empty plaintext" do
    test "produces single empty final frame", ctx do
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, <<>>)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Decrypt should produce empty plaintext
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == <<>>
    end
  end

  describe "single byte plaintext" do
    test "encrypts and decrypts correctly", ctx do
      plaintext = <<42>>

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "exact frame multiple" do
    test "handles plaintext = N * frame_length", ctx do
      # Exactly 3 frames worth
      plaintext = :crypto.strong_rand_bytes(300)

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "off-by-one" do
    test "handles plaintext = N * frame_length + 1", ctx do
      # 3 frames + 1 byte
      plaintext = :crypto.strong_rand_bytes(301)

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "byte-by-byte input" do
    test "handles one byte at a time", ctx do
      plaintext = "Hello!"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 3)
      {:ok, enc, header} = Encryptor.start(enc)

      # Feed one byte at a time
      {enc, frame_chunks} =
        plaintext
        |> String.graphemes()
        |> Enum.reduce({enc, []}, fn char, {enc, acc} ->
          {:ok, enc, bytes} = Encryptor.update(enc, char)
          {enc, [bytes | acc]}
        end)

      {:ok, _enc, final} = Encryptor.finalize(enc)

      frames = frame_chunks |> Enum.reverse() |> IO.iodata_to_binary()
      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end
end
