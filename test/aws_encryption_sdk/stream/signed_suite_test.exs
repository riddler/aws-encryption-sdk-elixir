defmodule AwsEncryptionSdk.Stream.SignedSuiteTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Create test materials with signed suite
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
    plaintext_data_key = :crypto.strong_rand_bytes(32)
    {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    # Add public key to encryption context (required for signed suites)
    enc_context = %{
      "purpose" => "test",
      "aws-crypto-public-key" => ECDSA.encode_public_key(public_key)
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: enc_context,
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: private_key,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: enc_context,
      verification_key: public_key,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "signed suite streaming" do
    test "encrypts and decrypts with signature", ctx do
      plaintext = :crypto.strong_rand_bytes(500)

      # Encrypt
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Verify footer exists (should have signature)
      # The final bytes should include 2-byte length + signature
      # Includes final frame + footer
      assert byte_size(final) > 100

      # Decrypt
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, plaintexts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_plaintexts} = Decryptor.finalize(dec)

      all = plaintexts ++ final_plaintexts

      # Regular frames should be unverified
      regular = Enum.filter(all, fn {_plaintext, status} -> status == :unverified end)
      refute Enum.empty?(regular)

      # Final frame should be verified (after signature check)
      final_frames = Enum.filter(all, fn {_plaintext, status} -> status == :verified end)
      assert length(final_frames) == 1

      result = all |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end

    test "fails on corrupted signature", ctx do
      plaintext = "test data"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Corrupt the last byte (signature)
      corrupted = binary_part(ciphertext, 0, byte_size(ciphertext) - 1) <> <<0xFF>>

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # update may return the error, or it could be returned by finalize
      case Decryptor.update(dec, corrupted) do
        {:ok, dec, _plaintexts} ->
          assert {:error, :signature_verification_failed} = Decryptor.finalize(dec)

        {:error, :signature_verification_failed} ->
          :ok
      end
    end

    test "fail_on_signed rejects signed suite", ctx do
      plaintext = "test"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials, fail_on_signed: true)

      assert {:error, :signed_algorithm_suite_not_allowed} = Decryptor.update(dec, ciphertext)
    end
  end
end
