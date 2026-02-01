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
  alias AwsEncryptionSdk.Crypto.Commitment
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.BodyAad
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
         :ok <-
           verify_header_auth_tag(
             message.header,
             derived_key,
             materials.encryption_context,
             materials.required_encryption_context_keys
           ),
         {:ok, plaintext} <- decrypt_body(message.body, message.header, derived_key),
         :ok <- verify_signature(message, materials, ciphertext) do
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

    # Per spec, HKDF parameters differ between committed and non-committed suites:
    # - Committed suites: salt = message_id, info = "DERIVEKEY" + suite_id
    # - Non-committed suites: salt = nil (zeros), info = suite_id + message_id
    {salt, info} = derive_key_params(suite, message_id)

    HKDF.derive(suite.kdf_hash, plaintext_data_key, salt, info, key_length)
  end

  defp derive_key_params(%{commitment_length: 32} = suite, message_id) do
    # Committed suites: salt = message_id, info = suite_id + "DERIVEKEY"
    salt = message_id
    info = <<suite.id::16-big>> <> "DERIVEKEY"
    {salt, info}
  end

  defp derive_key_params(suite, message_id) do
    # Non-committed HKDF suites: salt = nil (zeros), info = suite_id + message_id
    salt = nil
    info = <<suite.id::16-big>> <> message_id
    {salt, info}
  end

  # Verify key commitment for committed algorithm suites
  defp verify_commitment(materials, header, _derived_key) do
    Commitment.verify_commitment(materials, header)
  end

  # Verify header authentication tag
  defp verify_header_auth_tag(header, derived_key, full_ec, required_ec_keys) do
    HeaderAuth.verify_header_auth_tag(header, derived_key, full_ec, required_ec_keys)
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
  defp verify_signature(%{footer: nil}, _materials, _ciphertext), do: :ok

  defp verify_signature(
         %{footer: %{signature: _signature}},
         %{verification_key: nil},
         _ciphertext
       ) do
    # Signed suite but no verification key provided
    {:error, :missing_verification_key}
  end

  defp verify_signature(
         %{footer: %{signature: signature}},
         %{algorithm_suite: suite, verification_key: verification_key},
         ciphertext
       )
       when is_binary(verification_key) do
    # Calculate header + body bytes from ciphertext
    # Footer format: signature_length (2 bytes) + signature
    # Signature is computed over header + body (everything before the footer)
    footer_len = 2 + byte_size(signature)
    message_len = byte_size(ciphertext) - footer_len
    <<message_bytes::binary-size(message_len), _footer::binary>> = ciphertext

    # Get the correct hash and curve from the algorithm suite
    {hash_algo, curve} = signature_params_from_suite(suite)

    # Normalize the public key (decompress if needed)
    normalized_key = ECDSA.normalize_public_key(verification_key, curve)

    # Compute hash and verify signature
    try do
      digest = :crypto.hash(hash_algo, message_bytes)

      if :crypto.verify(:ecdsa, hash_algo, {:digest, digest}, signature, [normalized_key, curve]) do
        :ok
      else
        {:error, :signature_verification_failed}
      end
    rescue
      _e ->
        # :crypto.verify raised an error
        {:error, :signature_verification_failed}
    end
  end

  # Get signature hash algorithm and curve from algorithm suite
  defp signature_params_from_suite(%{signature_algorithm: :ecdsa_p256}) do
    {:sha256, :secp256r1}
  end

  defp signature_params_from_suite(%{signature_algorithm: :ecdsa_p384}) do
    {:sha384, :secp384r1}
  end

  defp signature_params_from_suite(_suite) do
    # Default for backwards compatibility (shouldn't be reached for signed suites)
    {:sha384, :secp384r1}
  end
end
