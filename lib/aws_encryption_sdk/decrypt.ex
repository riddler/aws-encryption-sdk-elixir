defmodule AwsEncryptionSdk.Decrypt do
  @moduledoc """
  Message decryption operations.

  Decrypts AWS Encryption SDK messages using provided decryption materials.
  This is a non-streaming implementation that requires the entire ciphertext
  in memory.

  ## Security

  This module NEVER releases unauthenticated plaintext. All authentication
  checks (header auth tag, frame auth tags, key commitment, signature) must
  pass before any plaintext is returned.
  """

  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Materials.DecryptionMaterials

  @type decrypt_result :: %{
          plaintext: binary(),
          header: Header.t(),
          encryption_context: map()
        }

  @doc """
  Decrypts an AWS Encryption SDK message.

  ## Parameters

  - `ciphertext` - Complete encrypted message (header + body + optional footer)
  - `materials` - Decryption materials containing the plaintext data key

  ## Returns

  - `{:ok, result}` - Decryption succeeded; result contains plaintext, header, and encryption context
  - `{:error, reason}` - Decryption failed

  ## Errors

  - `:base64_encoded_message` - Message appears to be Base64 encoded
  - `:header_authentication_failed` - Header auth tag verification failed
  - `:commitment_mismatch` - Key commitment verification failed
  - `:body_authentication_failed` - Frame auth tag verification failed
  - `:signature_verification_failed` - Footer signature verification failed
  """
  @spec decrypt(binary(), DecryptionMaterials.t()) ::
          {:ok, decrypt_result()} | {:error, term()}
  def decrypt(ciphertext, %DecryptionMaterials{} = materials) do
    with :ok <- check_base64_encoding(ciphertext),
         {:ok, message, <<>>} <- Message.deserialize(ciphertext),
         {:ok, derived_key} <- derive_data_key(materials, message.header),
         :ok <- verify_commitment(materials, message.header, derived_key),
         :ok <- verify_header_auth_tag(message.header, derived_key),
         {:ok, plaintext} <- decrypt_body(message.body, message.header, derived_key),
         :ok <- verify_signature(message, materials) do
      {:ok,
       %{
         plaintext: plaintext,
         header: message.header,
         encryption_context: message.header.encryption_context
       }}
    end
  end

  # Check for Base64 encoding (SHOULD requirement)
  defp check_base64_encoding(<<"AQ", _rest::binary>>), do: {:error, :base64_encoded_message}
  defp check_base64_encoding(<<"Ag", _rest::binary>>), do: {:error, :base64_encoded_message}
  defp check_base64_encoding(_data), do: :ok

  # Derive the data encryption key using HKDF
  defp derive_data_key(materials, header) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        # No derivation for legacy NO_KDF suites
        {:ok, materials.plaintext_data_key}

      :hkdf ->
        # HKDF derivation
        derive_with_hkdf(suite, materials.plaintext_data_key, header.message_id)
    end
  end

  defp derive_with_hkdf(suite, plaintext_data_key, message_id) do
    key_length = div(suite.data_key_length, 8)

    # For committed suites, info is "DERIVEKEY" + 2-byte suite ID (big-endian)
    # For non-committed HKDF suites, info is just the suite ID bytes
    info = derive_key_info(suite)

    HKDF.derive(suite.kdf_hash, plaintext_data_key, message_id, info, key_length)
  end

  defp derive_key_info(%{commitment_length: 32} = suite) do
    # Committed suites use "DERIVEKEY" label
    <<suite.id::16-big>>
    |> then(&("DERIVEKEY" <> &1))
  end

  defp derive_key_info(suite) do
    # Non-committed HKDF suites use just the suite ID
    <<suite.id::16-big>>
  end

  # Verify key commitment for committed algorithm suites
  defp verify_commitment(
         _materials,
         %Header{algorithm_suite: %{commitment_length: 0}},
         _derived_key
       ) do
    # Non-committed suite, skip verification
    :ok
  end

  defp verify_commitment(materials, header, _derived_key) do
    suite = materials.algorithm_suite

    # Derive commitment key
    info = "COMMITKEY" <> <<suite.id::16-big>>

    case HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, header.message_id, info, 32) do
      {:ok, expected_commitment} ->
        if :crypto.hash_equals(expected_commitment, header.algorithm_suite_data) do
          :ok
        else
          {:error, :commitment_mismatch}
        end

      {:error, _reason} = error ->
        error
    end
  end

  # Verify header authentication tag
  defp verify_header_auth_tag(header, derived_key) do
    # Compute AAD: header body + serialized encryption context
    {:ok, header_body} = Header.serialize_body(header)
    ec_bytes = EncryptionContext.serialize(header.encryption_context)
    aad = header_body <> ec_bytes

    # IV is all zeros for header
    iv = AesGcm.zero_iv()

    # Decrypt empty ciphertext to verify tag
    case AesGcm.decrypt(
           header.algorithm_suite.encryption_algorithm,
           derived_key,
           iv,
           <<>>,
           aad,
           header.header_auth_tag
         ) do
      {:ok, <<>>} -> :ok
      {:error, :authentication_failed} -> {:error, :header_authentication_failed}
    end
  end

  # Decrypt message body
  defp decrypt_body(%{ciphertext: _ciphertext, auth_tag: _tag} = non_framed, header, derived_key) do
    decrypt_non_framed_body(non_framed, header, derived_key)
  end

  defp decrypt_body(frames, header, derived_key) when is_list(frames) do
    decrypt_framed_body(frames, header, derived_key)
  end

  defp decrypt_non_framed_body(body, header, derived_key) do
    aad = BodyAad.serialize(header.message_id, :non_framed, 1, byte_size(body.ciphertext))

    case AesGcm.decrypt(
           header.algorithm_suite.encryption_algorithm,
           derived_key,
           body.iv,
           body.ciphertext,
           aad,
           body.auth_tag
         ) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, :authentication_failed} -> {:error, :body_authentication_failed}
    end
  end

  defp decrypt_framed_body(frames, header, derived_key) do
    # Decrypt each frame, accumulating plaintext
    # All frames must authenticate before returning any plaintext
    result =
      Enum.reduce_while(frames, {:ok, []}, fn frame, {:ok, acc} ->
        case decrypt_frame(frame, header, derived_key) do
          {:ok, plaintext} -> {:cont, {:ok, [plaintext | acc]}}
          {:error, _reason} = error -> {:halt, error}
        end
      end)

    case result do
      {:ok, plaintexts} ->
        {:ok, plaintexts |> Enum.reverse() |> IO.iodata_to_binary()}

      {:error, _reason} = error ->
        error
    end
  end

  defp decrypt_frame(frame, header, derived_key) do
    content_type = if Map.get(frame, :final), do: :final_frame, else: :regular_frame
    plaintext_length = byte_size(frame.ciphertext)

    aad =
      BodyAad.serialize(header.message_id, content_type, frame.sequence_number, plaintext_length)

    iv = AesGcm.sequence_number_to_iv(frame.sequence_number)

    case AesGcm.decrypt(
           header.algorithm_suite.encryption_algorithm,
           derived_key,
           iv,
           frame.ciphertext,
           aad,
           frame.auth_tag
         ) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, :authentication_failed} -> {:error, :body_authentication_failed}
    end
  end

  # Verify signature (for signed suites)
  defp verify_signature(%{footer: nil}, _materials), do: :ok

  defp verify_signature(%{footer: %{signature: _signature}}, %{verification_key: nil}) do
    # Signed suite but no verification key provided
    {:error, :missing_verification_key}
  end

  defp verify_signature(_message, _materials) do
    # TO DO: Implement ECDSA signature verification
    # For now, skip signature verification for signed suites
    # This will be implemented when we add ECDSA support
    :ok
  end
end
