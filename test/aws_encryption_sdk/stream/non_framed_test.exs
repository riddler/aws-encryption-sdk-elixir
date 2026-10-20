defmodule AwsEncryptionSdk.Stream.NonFramedTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor

  # No encryptor in this package writes a non-framed message, so these tests
  # build one by hand (a header with content type non-framed, then one body:
  # IV, content length, ciphertext, tag), as other SDKs write it.

  describe "unsigned suite (0x0178)" do
    setup do
      materials(AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256())
    end

    # Sabotage: in Stream.Decryptor, drop the non-framed process_buffer
    # clause -> the body is read as a frame and update/2 answers
    # {:error, {:sequence_mismatch, 1, _}}.
    test "decrypts a non-framed message in one chunk", ctx do
      plaintext = :crypto.strong_rand_bytes(300)
      message = non_framed_message(ctx, plaintext)

      assert {:ok, dec, [{^plaintext, :verified}]} = Decryptor.update(init(ctx), message)
      assert {:ok, _dec, []} = Decryptor.finalize(dec)
    end

    # Sabotage: in decrypt_non_framed_body/2, serialize the AAD as
    # :final_frame -> the tag does not verify and update/2 answers
    # {:error, :body_authentication_failed}.
    test "decrypts a non-framed message fed in small chunks, released whole after the tag",
         ctx do
      plaintext = :crypto.strong_rand_bytes(300)
      message = non_framed_message(ctx, plaintext)
      chunks = chunk_binary(message, 7)
      {last, earlier} = List.pop_at(chunks, -1)

      dec =
        Enum.reduce(earlier, init(ctx), fn chunk, dec ->
          # Nothing is released before the tag has arrived and verified
          assert {:ok, dec, []} = Decryptor.update(dec, chunk)
          dec
        end)

      assert {:ok, dec, [{^plaintext, :verified}]} = Decryptor.update(dec, last)
      assert {:ok, _dec, []} = Decryptor.finalize(dec)
    end

    test "decrypts an empty non-framed body", ctx do
      message = non_framed_message(ctx, <<>>)

      assert {:ok, dec, [{<<>>, :verified}]} = Decryptor.update(init(ctx), message)
      assert {:ok, _dec, []} = Decryptor.finalize(dec)
    end

    test "a truncated body answers the streaming incomplete-message error", ctx do
      message = non_framed_message(ctx, :crypto.strong_rand_bytes(100))
      truncated = binary_part(message, 0, byte_size(message) - 1)

      assert {:ok, dec, []} = Decryptor.update(init(ctx), truncated)
      assert {:error, {:incomplete_message, :decrypting}} = Decryptor.finalize(dec)
    end

    # Sabotage: in decrypt_non_framed_body/2, return {:ok, body.ciphertext}
    # without AesGcm.decrypt -> the tampered message releases bytes.
    test "a tampered tag is refused and releases no plaintext", ctx do
      message = non_framed_message(ctx, :crypto.strong_rand_bytes(100))
      size = byte_size(message)
      <<head::binary-size(size - 1), last_byte>> = message
      tampered = head <> <<Bitwise.bxor(last_byte, 0x01)>>

      released =
        tampered
        |> chunk_binary(16)
        |> Enum.reduce_while({init(ctx), []}, fn chunk, {dec, acc} ->
          case Decryptor.update(dec, chunk) do
            {:ok, dec, plaintexts} -> {:cont, {dec, acc ++ plaintexts}}
            {:error, reason} -> {:halt, {:error, reason, acc}}
          end
        end)

      assert {:error, :body_authentication_failed, []} = released
    end

    test "bytes after the body are refused at finalize", ctx do
      message = non_framed_message(ctx, "data") <> "garbage"

      assert {:ok, dec, [{"data", :verified}]} = Decryptor.update(init(ctx), message)
      assert {:error, :trailing_bytes} = Decryptor.finalize(dec)
    end

    # The buffer is bounded by the declared length: a length above the
    # format's limit is refused as soon as the length field arrives.
    test "a declared content length above the limit is refused before buffering", ctx do
      message = non_framed_message(ctx, "data")
      {:ok, header_bin} = ctx |> header() |> Header.serialize()
      header_size = byte_size(header_bin)
      <<header_part::binary-size(header_size), iv::binary-size(12), _rest::binary>> = message

      too_long = header_part <> iv <> <<68_719_476_705::64-big>>

      assert {:error, :content_too_large} = Decryptor.update(init(ctx), too_long)
    end
  end

  describe "signed suite (0x0378)" do
    setup do
      materials(AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384())
    end

    # Sabotage: in process_non_framed_body/4, pass is_final = false to
    # handle_decrypted_frame/6 -> plaintext is released before the footer
    # arrives, so the body-only update no longer answers [].
    test "holds the plaintext until the signature verifies", ctx do
      plaintext = :crypto.strong_rand_bytes(300)
      message = non_framed_message(ctx, plaintext)
      footer_size = footer_size(message, ctx)
      body_end = byte_size(message) - footer_size

      assert {:ok, dec, []} = Decryptor.update(init(ctx), binary_part(message, 0, body_end))

      assert {:ok, dec, [{^plaintext, :verified}]} =
               Decryptor.update(dec, binary_part(message, body_end, footer_size))

      assert {:ok, _dec, []} = Decryptor.finalize(dec)
    end

    test "a bad signature is refused and releases no plaintext", ctx do
      message = non_framed_message(ctx, :crypto.strong_rand_bytes(100))
      size = byte_size(message)
      <<head::binary-size(size - 1), last_byte>> = message
      tampered = head <> <<Bitwise.bxor(last_byte, 0x01)>>

      assert {:error, :signature_verification_failed} = Decryptor.update(init(ctx), tampered)
    end
  end

  # Helpers

  defp materials(suite) do
    plaintext_data_key = :crypto.strong_rand_bytes(div(suite.data_key_length, 8))

    {signing_key, verification_key, context} =
      if AlgorithmSuite.signed?(suite) do
        {private_key, public_key} = ECDSA.generate_key_pair(ECDSA.curve_for_suite(suite))

        {private_key, public_key,
         %{"purpose" => "test", "aws-crypto-public-key" => ECDSA.encode_public_key(public_key)}}
      else
        {nil, nil, %{"purpose" => "test"}}
      end

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: context,
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: signing_key,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: context,
      verification_key: verification_key,
      required_encryption_context_keys: []
    }

    {:ok,
     enc_materials: enc_materials,
     dec_materials: dec_materials,
     message_id: Header.generate_message_id(suite.message_format_version)}
  end

  defp init(ctx) do
    {:ok, dec} = Decryptor.init(get_materials: fn _header -> {:ok, ctx.dec_materials} end)
    dec
  end

  # The non-committed HKDF derivation: salt nil, info = suite id || message id
  defp derived_key(ctx) do
    suite = ctx.enc_materials.algorithm_suite

    {:ok, key} =
      HKDF.derive(
        suite.kdf_hash,
        ctx.enc_materials.plaintext_data_key,
        nil,
        <<suite.id::16-big>> <> ctx.message_id,
        div(suite.data_key_length, 8)
      )

    key
  end

  defp header(ctx) do
    {:ok, header} = HeaderAuth.build_header(ctx.enc_materials, ctx.message_id, 4096, nil)
    header = %{header | content_type: :non_framed, frame_length: 0}

    {:ok, header} =
      HeaderAuth.compute_header_auth_tag(
        header,
        derived_key(ctx),
        ctx.enc_materials.encryption_context,
        []
      )

    header
  end

  defp non_framed_message(ctx, plaintext) do
    header = header(ctx)
    {:ok, header_bin} = Header.serialize(header)
    suite = ctx.enc_materials.algorithm_suite
    iv = :crypto.strong_rand_bytes(12)
    aad = BodyAad.serialize(ctx.message_id, :non_framed, 1, byte_size(plaintext))

    {ciphertext, tag} =
      AesGcm.encrypt(suite.encryption_algorithm, derived_key(ctx), iv, plaintext, aad)

    {:ok, body} = Body.serialize_non_framed(iv, ciphertext, tag)
    signed = header_bin <> body

    case ctx.enc_materials.signing_key do
      nil ->
        signed

      signing_key ->
        signature = ECDSA.sign(signed, signing_key, ECDSA.curve_for_suite(suite))
        signed <> <<byte_size(signature)::16-big, signature::binary>>
    end
  end

  # The footer is the last 2 + signature-length bytes; the signature length
  # varies, so read it from the message
  defp footer_size(message, ctx) do
    {:ok, header_bin} = ctx |> header() |> Header.serialize()
    header_size = byte_size(header_bin)

    <<_header::binary-size(header_size), _iv::binary-size(12), content_length::64-big,
      _rest::binary>> = message

    byte_size(message) - header_size - 12 - 8 - content_length - 16
  end

  defp chunk_binary(binary, size) when byte_size(binary) <= size, do: [binary]

  defp chunk_binary(binary, size) do
    <<chunk::binary-size(size), rest::binary>> = binary
    [chunk | chunk_binary(rest, size)]
  end
end
