defmodule AwsEncryptionSdk.Stream.ErrorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Setup for unsigned suite
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

    # Setup for signed suite
    signed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
    {pub_key, priv_key} = :crypto.generate_key(:ecdh, :secp384r1)

    signed_enc_materials = %EncryptionMaterials{
      algorithm_suite: signed_suite,
      encryption_context: %{},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: priv_key,
      required_encryption_context_keys: []
    }

    signed_dec_materials = %DecryptionMaterials{
      algorithm_suite: signed_suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: %{},
      verification_key: pub_key,
      required_encryption_context_keys: []
    }

    {:ok,
     enc_materials: enc_materials,
     dec_materials: dec_materials,
     signed_enc_materials: signed_enc_materials,
     signed_dec_materials: signed_dec_materials}
  end

  describe "fail_on_signed option" do
    test "fails immediately on signed algorithm suite", ctx do
      # Create a valid signed message
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.signed_enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Try to decrypt with fail_on_signed: true
      get_materials = fn _header -> {:ok, ctx.signed_dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials, fail_on_signed: true)

      assert {:error, :signed_algorithm_suite_not_allowed} = Decryptor.update(dec, ciphertext)
    end
  end

  describe "header authentication failure" do
    test "detects corrupted header auth tag", ctx do
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Corrupt the last byte of the header (the auth tag)
      header_size = byte_size(header)
      <<good_header::binary-size(header_size - 1), _last_byte, rest::binary>> = ciphertext
      corrupted = good_header <> <<0xFF>> <> rest

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      assert {:error, :header_authentication_failed} = Decryptor.update(dec, corrupted)
    end
  end

  describe "commitment mismatch" do
    test "detects commitment mismatch with wrong data key", ctx do
      # Encrypt with one key
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Try to decrypt with DIFFERENT materials (different data key)
      # This will pass header auth (same encrypted data key) but fail commitment
      wrong_data_key = :crypto.strong_rand_bytes(32)

      wrong_dec_materials = %DecryptionMaterials{
        algorithm_suite: ctx.dec_materials.algorithm_suite,
        plaintext_data_key: wrong_data_key,
        encryption_context: ctx.dec_materials.encryption_context,
        verification_key: nil,
        required_encryption_context_keys: []
      }

      get_materials = fn _header -> {:ok, wrong_dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # Should fail with commitment mismatch
      result = Decryptor.update(dec, ciphertext)

      assert match?({:error, :commitment_mismatch}, result),
             "Expected commitment_mismatch, got: #{inspect(result)}"
    end
  end

  describe "frame authentication failure" do
    test "detects corrupted frame auth tag", ctx do
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final
      header_size = byte_size(header)

      # Corrupt a byte in the frame section (skip header)
      <<header::binary-size(header_size), frame_data::binary>> = ciphertext

      # Find and corrupt the auth tag (last 16 bytes before sequence end marker)
      frame_size = byte_size(frame_data)

      <<frame_prefix::binary-size(frame_size - 16), _auth_tag::binary-size(16)>> = frame_data

      corrupted_auth_tag = :crypto.strong_rand_bytes(16)
      corrupted_frame = frame_prefix <> corrupted_auth_tag
      corrupted = header <> corrupted_frame

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      assert {:error, :body_authentication_failed} = Decryptor.update(dec, corrupted)
    end
  end

  describe "signature verification failure" do
    test "detects corrupted signature", ctx do
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.signed_enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Corrupt the last byte of the signature
      size = byte_size(ciphertext)
      <<good_part::binary-size(size - 1), _last_byte>> = ciphertext
      corrupted = good_part <> <<0xFF>>

      get_materials = fn _header -> {:ok, ctx.signed_dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # Process the corrupted message
      result = Decryptor.update(dec, corrupted)

      case result do
        {:ok, dec, _pts} ->
          # Signature verification happens in finalize
          assert {:error, :signature_verification_failed} = Decryptor.finalize(dec)

        {:error, :signature_verification_failed} ->
          # Or it might happen during update if we read the full footer
          :ok
      end
    end
  end

  describe "trailing bytes" do
    test "detects trailing bytes after message", ctx do
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Add trailing bytes
      ciphertext_with_trailing = ciphertext <> <<1, 2, 3, 4>>

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      {:ok, dec, _pts} = Decryptor.update(dec, ciphertext_with_trailing)
      assert {:error, :trailing_bytes} = Decryptor.finalize(dec)
    end
  end

  describe "incomplete message" do
    test "detects truncated ciphertext during finalize", ctx do
      plaintext = "test data that is long enough"
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Truncate the message (remove last 10 bytes)
      size = byte_size(ciphertext)
      <<truncated::binary-size(size - 10), _rest::binary>> = ciphertext

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      {:ok, dec, _pts} = Decryptor.update(dec, truncated)

      # Should fail with incomplete_message tuple containing the state
      assert {:error, {:incomplete_message, state}} = Decryptor.finalize(dec)
      assert state in [:reading_header, :decrypting, :reading_footer]
    end

    test "detects incomplete footer for signed suite", ctx do
      plaintext = "test data"
      {:ok, enc} = Encryptor.init(ctx.signed_enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Truncate during footer (signature)
      # Footer is at the end, after all frames
      size = byte_size(ciphertext)
      <<truncated::binary-size(size - 50), _rest::binary>> = ciphertext

      get_materials = fn _header -> {:ok, ctx.signed_dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      {:ok, dec, _pts} = Decryptor.update(dec, truncated)
      assert {:error, :incomplete_message} = Decryptor.finalize(dec)
    end
  end
end
