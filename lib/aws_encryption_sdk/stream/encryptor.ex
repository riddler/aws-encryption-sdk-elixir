defmodule AwsEncryptionSdk.Stream.Encryptor do
  @moduledoc """
  Streaming encryptor state machine.

  Processes plaintext incrementally and emits ciphertext frames. Designed for
  use with Elixir's Stream functions.

  ## State Machine

  1. `:init` - Not started, awaiting first input
  2. `:encrypting` - Processing frames
  3. `:done` - Encryption complete

  ## Example

      # Initialize encryptor
      {:ok, enc} = Encryptor.init(materials, frame_length: 4096)

      # Process chunks, collecting output
      {enc, header_bytes} = Encryptor.start(enc)
      {enc, frame1_bytes} = Encryptor.update(enc, chunk1)
      {enc, frame2_bytes} = Encryptor.update(enc, chunk2)
      {enc, final_bytes} = Encryptor.finalize(enc)

  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  @default_frame_length 4096

  @type state :: :init | :encrypting | :done

  @type t :: %__MODULE__{
          state: state(),
          materials: EncryptionMaterials.t(),
          frame_length: pos_integer(),
          header: Header.t() | nil,
          derived_key: binary() | nil,
          sequence_number: pos_integer(),
          buffer: binary(),
          signature_acc: SignatureAccumulator.t() | nil
        }

  defstruct [
    :state,
    :materials,
    :frame_length,
    :header,
    :derived_key,
    :sequence_number,
    :buffer,
    :signature_acc
  ]

  @doc """
  Initializes a new streaming encryptor.

  ## Options

  - `:frame_length` - Frame size in bytes (default: 4096)
  """
  @spec init(EncryptionMaterials.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def init(%EncryptionMaterials{} = materials, opts \\ []) do
    frame_length = Keyword.get(opts, :frame_length, @default_frame_length)
    suite = materials.algorithm_suite

    if AlgorithmSuite.allows_encryption?(suite) do
      # Initialize signature accumulator for signed suites
      sig_acc = if AlgorithmSuite.signed?(suite), do: SignatureAccumulator.init(), else: nil

      {:ok,
       %__MODULE__{
         state: :init,
         materials: materials,
         frame_length: frame_length,
         header: nil,
         derived_key: nil,
         sequence_number: 1,
         buffer: <<>>,
         signature_acc: sig_acc
       }}
    else
      {:error, :deprecated_algorithm_suite}
    end
  end

  @doc """
  Starts encryption by generating header.

  Returns `{:ok, updated_encryptor, header_bytes}` on success.
  Must be called before `update/2`.
  """
  @spec start(t()) :: {:ok, t(), binary()} | {:error, term()}
  def start(%__MODULE__{state: :init} = enc) do
    with {:ok, message_id} <- generate_message_id(enc.materials.algorithm_suite),
         {:ok, derived_key, commitment_key} <- derive_keys(enc.materials, message_id),
         {:ok, header} <-
           build_header(enc.materials, message_id, enc.frame_length, commitment_key),
         {:ok, header_with_tag} <- compute_header_auth_tag(header, derived_key),
         {:ok, header_binary} <- Header.serialize(header_with_tag) do
      # Update signature accumulator with header
      sig_acc =
        if enc.signature_acc do
          SignatureAccumulator.update(enc.signature_acc, header_binary)
        else
          nil
        end

      {:ok,
       %{
         enc
         | state: :encrypting,
           header: header_with_tag,
           derived_key: derived_key,
           signature_acc: sig_acc
       }, header_binary}
    end
  end

  def start(%__MODULE__{state: state}) do
    {:error, {:invalid_state, state, :expected_init}}
  end

  @doc """
  Processes plaintext chunk.

  Buffers partial frames and emits complete frames. Returns `{:ok, updated_encryptor, frame_bytes}`
  where `frame_bytes` may be empty if not enough data for a complete frame.
  """
  @spec update(t(), binary()) :: {:ok, t(), binary()} | {:error, term()}
  def update(%__MODULE__{state: :encrypting} = enc, plaintext) when is_binary(plaintext) do
    # Add to buffer
    buffer = enc.buffer <> plaintext

    # Extract complete frames
    {frames, remaining_buffer, enc} = extract_frames(buffer, enc)

    # Serialize frames
    frame_bytes = IO.iodata_to_binary(frames)

    {:ok, %{enc | buffer: remaining_buffer}, frame_bytes}
  end

  def update(%__MODULE__{state: state}, _plaintext) do
    {:error, {:invalid_state, state, :expected_encrypting}}
  end

  @doc """
  Finalizes encryption.

  Encrypts any remaining buffered data as the final frame, optionally adds footer.
  Returns `{:ok, updated_encryptor, final_bytes}`.
  """
  @spec finalize(t()) :: {:ok, t(), binary()} | {:error, term()}
  def finalize(%__MODULE__{state: :encrypting} = enc) do
    # Encrypt remaining buffer as final frame
    final_frame = encrypt_frame(enc.buffer, enc, true)

    # Update signature accumulator
    sig_acc =
      if enc.signature_acc do
        SignatureAccumulator.update(enc.signature_acc, final_frame)
      else
        nil
      end

    # Build footer for signed suites
    footer_binary =
      if sig_acc do
        signature = SignatureAccumulator.sign(sig_acc, enc.materials.signing_key)
        signature_length = byte_size(signature)
        <<signature_length::16-big, signature::binary>>
      else
        <<>>
      end

    {:ok, %{enc | state: :done, buffer: <<>>, signature_acc: nil}, final_frame <> footer_binary}
  end

  def finalize(%__MODULE__{state: state}) do
    {:error, {:invalid_state, state, :expected_encrypting}}
  end

  @doc """
  Returns the current state of the encryptor.
  """
  @spec state(t()) :: state()
  def state(%__MODULE__{state: state}), do: state

  # Private functions

  defp generate_message_id(suite) do
    {:ok, Header.generate_message_id(suite.message_format_version)}
  end

  defp derive_keys(materials, message_id) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        {:ok, materials.plaintext_data_key, nil}

      :hkdf ->
        key_length = div(suite.data_key_length, 8)
        info = derive_key_info(suite)

        {:ok, derived_key} =
          HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, message_id, info, key_length)

        commitment_key =
          if suite.commitment_length > 0 do
            commit_info = "COMMITKEY" <> <<suite.id::16-big>>

            {:ok, key} =
              HKDF.derive(
                suite.kdf_hash,
                materials.plaintext_data_key,
                message_id,
                commit_info,
                32
              )

            key
          else
            nil
          end

        {:ok, derived_key, commitment_key}
    end
  end

  defp derive_key_info(%{commitment_length: 32} = suite) do
    "DERIVEKEY" <> <<suite.id::16-big>>
  end

  defp derive_key_info(suite) do
    <<suite.id::16-big>>
  end

  defp build_header(materials, message_id, frame_length, commitment_key) do
    HeaderAuth.build_header(materials, message_id, frame_length, commitment_key)
  end

  defp compute_header_auth_tag(header, derived_key) do
    HeaderAuth.compute_header_auth_tag(header, derived_key)
  end

  defp extract_frames(buffer, enc) when byte_size(buffer) < enc.frame_length do
    {[], buffer, enc}
  end

  defp extract_frames(buffer, enc) do
    extract_frames_loop(buffer, enc, [])
  end

  defp extract_frames_loop(buffer, enc, acc) when byte_size(buffer) < enc.frame_length do
    {Enum.reverse(acc), buffer, enc}
  end

  defp extract_frames_loop(buffer, enc, acc) do
    <<chunk::binary-size(enc.frame_length), rest::binary>> = buffer
    frame = encrypt_frame(chunk, enc, false)

    # Update signature accumulator
    sig_acc =
      if enc.signature_acc do
        SignatureAccumulator.update(enc.signature_acc, frame)
      else
        nil
      end

    new_enc = %{enc | sequence_number: enc.sequence_number + 1, signature_acc: sig_acc}
    extract_frames_loop(rest, new_enc, [frame | acc])
  end

  defp encrypt_frame(plaintext, enc, is_final) do
    content_type = if is_final, do: :final_frame, else: :regular_frame

    aad =
      BodyAad.serialize(
        enc.header.message_id,
        content_type,
        enc.sequence_number,
        byte_size(plaintext)
      )

    iv = AesGcm.sequence_number_to_iv(enc.sequence_number)

    {ciphertext, auth_tag} =
      AesGcm.encrypt(
        enc.header.algorithm_suite.encryption_algorithm,
        enc.derived_key,
        iv,
        plaintext,
        aad
      )

    if is_final do
      Body.serialize_final_frame(enc.sequence_number, iv, ciphertext, auth_tag)
    else
      Body.serialize_regular_frame(enc.sequence_number, iv, ciphertext, auth_tag)
    end
  end
end
