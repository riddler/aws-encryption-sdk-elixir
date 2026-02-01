defmodule AwsEncryptionSdk.Encrypt do
  @moduledoc """
  Message encryption operations.

  Encrypts plaintext into AWS Encryption SDK message format using provided
  encryption materials. This is a non-streaming implementation that requires
  the entire plaintext in memory.

  ## Algorithm Suite Selection

  Uses the algorithm suite from the provided encryption materials. For committed
  suites (recommended), the message will use format version 2.
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  @default_frame_length 4096

  @type encrypt_result :: %{
          ciphertext: binary(),
          header: Header.t(),
          encryption_context: map(),
          algorithm_suite: AlgorithmSuite.t()
        }

  @type encrypt_opts :: [
          frame_length: pos_integer()
        ]

  @doc """
  Encrypts plaintext into an AWS Encryption SDK message.

  ## Parameters

  - `materials` - Encryption materials containing algorithm suite, data key, and EDKs
  - `plaintext` - Data to encrypt
  - `opts` - Options:
    - `:frame_length` - Frame size in bytes (default: 4096)

  ## Returns

  - `{:ok, result}` - Encryption succeeded; result contains ciphertext, header, etc.
  - `{:error, reason}` - Encryption failed
  """
  @spec encrypt(EncryptionMaterials.t(), binary(), encrypt_opts()) ::
          {:ok, encrypt_result()} | {:error, term()}
  def encrypt(%EncryptionMaterials{} = materials, plaintext, opts \\ [])
      when is_binary(plaintext) do
    frame_length = Keyword.get(opts, :frame_length, @default_frame_length)

    # Note: We don't validate encryption context here because the CMM may have
    # legitimately added reserved keys (e.g., aws-crypto-public-key for signed suites).
    # User-provided context validation should happen at the Client/CMM layer.
    with :ok <- validate_algorithm_suite(materials.algorithm_suite),
         {:ok, message_id} <- generate_message_id(materials.algorithm_suite),
         {:ok, derived_key, commitment_key} <- derive_keys(materials, message_id),
         {:ok, header} <- build_header(materials, message_id, frame_length, commitment_key),
         {:ok, header_with_tag} <-
           compute_header_auth_tag(
             header,
             derived_key,
             materials.encryption_context,
             materials.required_encryption_context_keys
           ),
         {:ok, body_binary} <-
           encrypt_body(plaintext, header_with_tag, derived_key, frame_length),
         {:ok, footer_binary} <- build_footer(materials, header_with_tag, body_binary) do
      {:ok, header_binary} = Header.serialize(header_with_tag)
      ciphertext = header_binary <> body_binary <> footer_binary

      {:ok,
       %{
         ciphertext: ciphertext,
         header: header_with_tag,
         encryption_context: materials.encryption_context,
         algorithm_suite: materials.algorithm_suite
       }}
    end
  end

  # Validate algorithm suite is allowed for encryption
  defp validate_algorithm_suite(suite) do
    if AlgorithmSuite.allows_encryption?(suite) do
      :ok
    else
      {:error, :deprecated_algorithm_suite}
    end
  end

  # Generate random message ID
  defp generate_message_id(suite) do
    {:ok, Header.generate_message_id(suite.message_format_version)}
  end

  # Derive data key and commitment key
  defp derive_keys(materials, message_id) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        {:ok, materials.plaintext_data_key, nil}

      :hkdf ->
        derive_with_hkdf(suite, materials.plaintext_data_key, message_id)
    end
  end

  defp derive_with_hkdf(suite, plaintext_data_key, message_id) do
    key_length = div(suite.data_key_length, 8)

    # Per spec, HKDF parameters differ between committed and non-committed suites:
    # - Committed suites: salt = message_id, info = "DERIVEKEY" + suite_id
    # - Non-committed suites: salt = nil (zeros), info = suite_id + message_id
    {salt, data_key_info} = derive_key_params(suite, message_id)

    {:ok, derived_key} =
      HKDF.derive(suite.kdf_hash, plaintext_data_key, salt, data_key_info, key_length)

    # Derive commitment key if needed (committed suites only)
    commitment_key =
      if suite.commitment_length > 0 do
        # Committed suites: salt = message_id, info = "COMMITKEY" (just the label, no suite_id)
        commit_info = "COMMITKEY"
        {:ok, key} = HKDF.derive(suite.kdf_hash, plaintext_data_key, message_id, commit_info, 32)
        key
      else
        nil
      end

    {:ok, derived_key, commitment_key}
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

  # Build header struct (without auth tag)
  defp build_header(materials, message_id, frame_length, commitment_key) do
    HeaderAuth.build_header(materials, message_id, frame_length, commitment_key)
  end

  # Compute header authentication tag
  defp compute_header_auth_tag(header, derived_key, full_ec, required_ec_keys) do
    HeaderAuth.compute_header_auth_tag(header, derived_key, full_ec, required_ec_keys)
  end

  # Encrypt body into frames
  defp encrypt_body(plaintext, header, derived_key, frame_length) do
    frames = chunk_plaintext(plaintext, frame_length)
    total_frames = length(frames)

    encrypted_frames =
      frames
      |> Enum.with_index(1)
      |> Enum.map(fn {chunk, seq_num} ->
        is_final = seq_num == total_frames
        encrypt_frame(chunk, header, derived_key, seq_num, is_final)
      end)

    {:ok, IO.iodata_to_binary(encrypted_frames)}
  end

  defp chunk_plaintext(<<>>, _frame_length), do: [<<>>]

  defp chunk_plaintext(plaintext, frame_length) do
    chunk_plaintext_loop(plaintext, frame_length, [])
  end

  defp chunk_plaintext_loop(<<>>, _frame_length, acc), do: Enum.reverse(acc)

  defp chunk_plaintext_loop(data, frame_length, acc) when byte_size(data) <= frame_length do
    Enum.reverse([data | acc])
  end

  defp chunk_plaintext_loop(data, frame_length, acc) do
    <<chunk::binary-size(frame_length), rest::binary>> = data
    chunk_plaintext_loop(rest, frame_length, [chunk | acc])
  end

  defp encrypt_frame(plaintext, header, derived_key, seq_num, is_final) do
    content_type = if is_final, do: :final_frame, else: :regular_frame
    aad = BodyAad.serialize(header.message_id, content_type, seq_num, byte_size(plaintext))
    iv = AesGcm.sequence_number_to_iv(seq_num)

    {ciphertext, auth_tag} =
      AesGcm.encrypt(
        header.algorithm_suite.encryption_algorithm,
        derived_key,
        iv,
        plaintext,
        aad
      )

    if is_final do
      Body.serialize_final_frame(seq_num, iv, ciphertext, auth_tag)
    else
      Body.serialize_regular_frame(seq_num, iv, ciphertext, auth_tag)
    end
  end

  # Build footer (for signed suites)
  defp build_footer(%{signing_key: nil}, _header, _body) do
    {:ok, <<>>}
  end

  defp build_footer(%{signing_key: private_key, algorithm_suite: suite}, header, body) do
    if AlgorithmSuite.signed?(suite) do
      # Serialize header to binary for signing
      {:ok, header_binary} = Header.serialize(header)

      # Sign header + body
      message_to_sign = header_binary <> body
      signature = ECDSA.sign(message_to_sign, private_key, :secp384r1)

      # Footer format: signature_length (2 bytes) + signature
      signature_length = byte_size(signature)
      footer = <<signature_length::16-big, signature::binary>>

      {:ok, footer}
    else
      {:ok, <<>>}
    end
  end
end
