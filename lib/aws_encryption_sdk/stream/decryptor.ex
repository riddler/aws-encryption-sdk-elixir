defmodule AwsEncryptionSdk.Stream.Decryptor do
  @moduledoc """
  Streaming decryptor state machine for incremental ciphertext processing.

  ## When to Use Streaming

  Use `Stream.Decryptor` instead of `Client.decrypt/2` when:

  - Decrypting large files that don't fit in memory
  - Processing encrypted data from network streams
  - Working with ciphertext sources that produce chunks incrementally
  - Memory constraints require bounded memory usage

  For small messages (< 1MB), the simpler `Client.decrypt/2` API is recommended.

  ## Memory Efficiency

  The streaming decryptor maintains constant memory usage:

  - Buffers only data needed to parse the current frame
  - Emits plaintext incrementally after frame authentication
  - No need to load entire ciphertext into memory

  Memory usage is bounded by the frame size plus header size, regardless of
  total message size.

  ## Plaintext Verification Status

  Decrypted plaintext is tagged with verification status:

  - **`:verified`** - Plaintext is authenticated and safe to use
    - For unsigned suites: immediately after frame authentication
    - For signed suites: after signature verification completes

  - **`:unverified`** - Plaintext not yet cryptographically verified
    - Only for signed algorithm suites
    - Signature verification happens at end of stream
    - **Do not use unverified plaintext** until signature validates

  ### Handling Signed Suites

  For signed algorithm suites (ECDSA P-384), you must handle verification:

  **Option 1: Fail immediately** (safest):

      {:ok, dec} = Decryptor.init(
        get_materials: materials_fn,
        fail_on_signed: true
      )

  **Option 2: Buffer unverified plaintext** (for streaming):

      plaintexts = []
      for {plaintext, status} <- decrypted_chunks do
        case status do
          :verified -> use_plaintext(plaintext)
          :unverified -> plaintexts = [plaintext | plaintexts]
        end
      end
      # At end of stream, all buffered plaintext is verified

  **Option 3: Use high-level API** (recommended):

  Use `AwsEncryptionSdk.Stream.decrypt/3` which handles verification automatically.

  ## Integration with Elixir Streams

  Designed to work seamlessly with `Stream` module:

      File.stream!("encrypted.bin", [], 4096)
      |> AwsEncryptionSdk.Stream.decrypt(client)
      |> Stream.map(fn {plaintext, _status} -> plaintext end)
      |> Stream.into(File.stream!("decrypted.bin"))
      |> Stream.run()

  See `AwsEncryptionSdk.Stream` for high-level streaming API.

  ## State Machine

  The decryptor progresses through these states:

  1. `:init` - Not started, awaiting ciphertext
  2. `:reading_header` - Accumulating header bytes
  3. `:decrypting` - Processing frames
  4. `:reading_footer` - Accumulating footer (signed suites only)
  5. `:done` - Decryption complete

  ## Low-Level Example

  For custom streaming logic, use the state machine directly:

      get_materials = fn header ->
        # Obtain decryption materials from CMM
        cmm.get_decryption_materials(...)
      end

      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # Process ciphertext chunks
      {:ok, dec, plaintexts1} = Decryptor.update(dec, chunk1)
      {:ok, dec, plaintexts2} = Decryptor.update(dec, chunk2)
      {:ok, dec, final_plaintexts} = Decryptor.finalize(dec)

      # Each plaintexts is a list of {binary, :verified | :unverified} tuples

  ## Security

  - Never release unauthenticated plaintext to untrusted contexts
  - For signed suites, verify signature before using plaintext
  - The decryptor validates authentication tags before emitting plaintext
  - Commitment verification happens during header processing

  ## See Also

  - `AwsEncryptionSdk.Stream` - High-level streaming API
  - `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption
  - `AwsEncryptionSdk.Client` - Non-streaming decryption API
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.Commitment
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  @type state :: :init | :reading_header | :decrypting | :reading_footer | :done

  @type plaintext_status :: :verified | :unverified

  @type t :: %__MODULE__{
          state: state(),
          materials: DecryptionMaterials.t() | nil,
          get_materials: (Header.t() -> {:ok, DecryptionMaterials.t()} | {:error, term()}) | nil,
          header: Header.t() | nil,
          derived_key: binary() | nil,
          expected_sequence: pos_integer(),
          buffer: binary(),
          signature_acc: SignatureAccumulator.t() | nil,
          fail_on_signed: boolean(),
          final_frame_plaintext: binary() | nil
        }

  defstruct [
    :state,
    :materials,
    :get_materials,
    :header,
    :derived_key,
    :expected_sequence,
    :buffer,
    :signature_acc,
    :fail_on_signed,
    :final_frame_plaintext
  ]

  @doc """
  Initializes a new streaming decryptor.

  ## Options

  - `:get_materials` - Function `(header) -> {:ok, materials} | {:error, reason}` to obtain
    decryption materials after header is parsed. Required.
  - `:fail_on_signed` - If `true`, fails immediately when a signed algorithm suite is detected.
    Default: `false`.
  """
  @spec init(keyword()) :: {:ok, t()} | {:error, term()}
  def init(opts \\ []) do
    get_materials = Keyword.fetch!(opts, :get_materials)
    fail_on_signed = Keyword.get(opts, :fail_on_signed, false)

    {:ok,
     %__MODULE__{
       state: :init,
       materials: nil,
       get_materials: get_materials,
       header: nil,
       derived_key: nil,
       expected_sequence: 1,
       buffer: <<>>,
       signature_acc: nil,
       fail_on_signed: fail_on_signed,
       final_frame_plaintext: nil
     }}
  end

  @doc """
  Processes ciphertext chunk.

  Returns `{:ok, updated_decryptor, plaintexts}` where `plaintexts` is a list of
  `{plaintext_binary, status}` tuples. Status is `:verified` for unsigned suites
  or final frame after signature verification, `:unverified` otherwise.

  For unsigned suites, plaintext is released immediately after frame authentication.
  """
  @spec update(t(), binary()) ::
          {:ok, t(), [{binary(), plaintext_status()}]} | {:error, term()}
  def update(%__MODULE__{} = dec, ciphertext) when is_binary(ciphertext) do
    buffer = dec.buffer <> ciphertext
    process_buffer(%{dec | buffer: buffer}, [])
  end

  @doc """
  Finalizes decryption.

  Verifies no trailing bytes remain and completes signature verification for signed suites.
  Returns `{:ok, updated_decryptor, final_plaintexts}`.
  """
  @spec finalize(t()) :: {:ok, t(), [{binary(), plaintext_status()}]} | {:error, term()}
  def finalize(%__MODULE__{state: :done, buffer: <<>>} = dec) do
    {:ok, dec, []}
  end

  def finalize(%__MODULE__{state: :done, buffer: buffer}) when byte_size(buffer) > 0 do
    {:error, :trailing_bytes}
  end

  def finalize(%__MODULE__{state: :reading_footer} = dec) do
    # Try to parse footer
    case parse_footer(dec) do
      {:ok, dec, plaintexts} ->
        {:ok, dec, plaintexts}

      {:error, :incomplete_footer} ->
        {:error, :incomplete_message}

      error ->
        error
    end
  end

  def finalize(%__MODULE__{state: state}) do
    {:error, {:incomplete_message, state}}
  end

  @doc """
  Returns the parsed header, if available.
  """
  @spec header(t()) :: Header.t() | nil
  def header(%__MODULE__{header: header}), do: header

  @doc """
  Returns the current state.
  """
  @spec state(t()) :: state()
  def state(%__MODULE__{state: state}), do: state

  # Private: Process buffer based on current state

  defp process_buffer(%{state: :init} = dec, acc) do
    process_buffer(%{dec | state: :reading_header}, acc)
  end

  defp process_buffer(%{state: :reading_header} = dec, acc) do
    case Header.deserialize(dec.buffer) do
      {:ok, header, rest} ->
        process_header(dec, acc, header, rest)

      # Handle errors during header parsing
      # Real errors (not incomplete data) should be propagated
      {:error, {:unsupported_version, _version}} = error ->
        error

      {:error, {:invalid_content_type, _type}} = error ->
        error

      # All other errors during header parsing are treated as incomplete data
      # This is safe in streaming context - we just need more bytes
      {:error, _reason} ->
        {:ok, dec, Enum.reverse(acc)}
    end
  end

  defp process_buffer(%{state: :decrypting} = dec, acc) do
    case Body.deserialize_frame(dec.buffer, dec.header.frame_length) do
      {:ok, frame, rest} ->
        process_frame(dec, acc, frame, rest)

      # Incomplete frame data - need more bytes
      {:error, :incomplete_regular_frame} ->
        {:ok, dec, Enum.reverse(acc)}

      {:error, :incomplete_final_frame} ->
        {:ok, dec, Enum.reverse(acc)}

      {:error, :invalid_frame_format} ->
        {:ok, dec, Enum.reverse(acc)}
    end
  end

  defp process_buffer(%{state: :reading_footer} = dec, acc) do
    case parse_footer(dec) do
      {:ok, dec, plaintexts} ->
        {:ok, dec, Enum.reverse(acc) ++ plaintexts}

      {:error, :incomplete_footer} ->
        {:ok, dec, Enum.reverse(acc)}

      error ->
        error
    end
  end

  defp process_buffer(%{state: :done} = dec, acc) do
    {:ok, dec, Enum.reverse(acc)}
  end

  # Helper functions for processing header
  defp process_header(dec, acc, header, rest) do
    # Check for signed suite if fail_on_signed is set
    if dec.fail_on_signed and AlgorithmSuite.signed?(header.algorithm_suite) do
      {:error, :signed_algorithm_suite_not_allowed}
    else
      # Get materials and verify header
      with {:ok, materials} <- dec.get_materials.(header),
           {:ok, derived_key} <- derive_data_key(materials, header),
           :ok <- verify_commitment(materials, header),
           :ok <-
             verify_header_auth_tag(
               header,
               derived_key,
               materials.encryption_context,
               materials.required_encryption_context_keys
             ) do
        # Initialize signature accumulator for signed suites
        sig_acc = initialize_signature_accumulator(header)

        dec = %{
          dec
          | state: :decrypting,
            materials: materials,
            header: header,
            derived_key: derived_key,
            buffer: rest,
            signature_acc: sig_acc
        }

        process_buffer(dec, acc)
      end
    end
  end

  defp initialize_signature_accumulator(header) do
    if AlgorithmSuite.signed?(header.algorithm_suite) do
      {:ok, header_binary} = Header.serialize(header)

      SignatureAccumulator.init()
      |> SignatureAccumulator.update(header_binary)
    else
      nil
    end
  end

  # Helper functions for processing frames
  defp process_frame(dec, acc, frame, rest) do
    # Verify sequence number
    if frame.sequence_number != dec.expected_sequence do
      {:error, {:sequence_mismatch, dec.expected_sequence, frame.sequence_number}}
    else
      with {:ok, plaintext} <- decrypt_frame(frame, dec) do
        sig_acc = update_signature_accumulator(dec, rest)
        is_final = Map.get(frame, :final, false)

        handle_decrypted_frame(dec, acc, plaintext, rest, sig_acc, is_final)
      end
    end
  end

  defp update_signature_accumulator(%{signature_acc: nil}, _rest), do: nil

  defp update_signature_accumulator(%{signature_acc: sig_acc, buffer: buffer}, rest) do
    # Calculate how much we consumed
    consumed = byte_size(buffer) - byte_size(rest)
    frame_bytes = binary_part(buffer, 0, consumed)
    SignatureAccumulator.update(sig_acc, frame_bytes)
  end

  defp handle_decrypted_frame(dec, acc, plaintext, rest, sig_acc, is_final) do
    cond do
      is_final and sig_acc != nil ->
        # Signed suite: hold final frame, transition to reading_footer
        dec = %{
          dec
          | state: :reading_footer,
            buffer: rest,
            signature_acc: sig_acc,
            final_frame_plaintext: plaintext
        }

        process_buffer(dec, acc)

      is_final ->
        # Unsigned suite: done
        dec = %{dec | state: :done, buffer: rest}
        {:ok, dec, Enum.reverse([{plaintext, :verified} | acc])}

      sig_acc != nil ->
        # Signed suite, regular frame: release as unverified
        dec = %{
          dec
          | expected_sequence: dec.expected_sequence + 1,
            buffer: rest,
            signature_acc: sig_acc
        }

        process_buffer(dec, [{plaintext, :unverified} | acc])

      true ->
        # Unsigned suite, regular frame: release as verified
        dec = %{dec | expected_sequence: dec.expected_sequence + 1, buffer: rest}
        process_buffer(dec, [{plaintext, :verified} | acc])
    end
  end

  defp parse_footer(%{buffer: <<sig_len::16-big, rest::binary>>} = dec)
       when byte_size(rest) >= sig_len do
    <<signature::binary-size(sig_len), remaining::binary>> = rest

    # Verify signature
    if SignatureAccumulator.verify(dec.signature_acc, signature, dec.materials.verification_key) do
      dec = %{dec | state: :done, buffer: remaining, signature_acc: nil}
      {:ok, dec, [{dec.final_frame_plaintext, :verified}]}
    else
      {:error, :signature_verification_failed}
    end
  end

  defp parse_footer(_dec) do
    {:error, :incomplete_footer}
  end

  defp derive_data_key(materials, header) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        {:ok, materials.plaintext_data_key}

      :hkdf ->
        key_length = div(suite.data_key_length, 8)

        # Per spec, HKDF parameters differ between committed and non-committed suites:
        # - Committed suites: salt = message_id, info = suite_id + "DERIVEKEY"
        # - Non-committed suites: salt = nil (zeros), info = suite_id + message_id
        {salt, info} = derive_key_params(suite, header.message_id)

        HKDF.derive(
          suite.kdf_hash,
          materials.plaintext_data_key,
          salt,
          info,
          key_length
        )
    end
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

  defp verify_commitment(materials, header) do
    Commitment.verify_commitment(materials, header)
  end

  defp verify_header_auth_tag(header, derived_key, full_ec, required_ec_keys) do
    HeaderAuth.verify_header_auth_tag(header, derived_key, full_ec, required_ec_keys)
  end

  defp decrypt_frame(frame, dec) do
    content_type = if Map.get(frame, :final), do: :final_frame, else: :regular_frame
    plaintext_length = byte_size(frame.ciphertext)

    aad =
      BodyAad.serialize(
        dec.header.message_id,
        content_type,
        frame.sequence_number,
        plaintext_length
      )

    iv = AesGcm.sequence_number_to_iv(frame.sequence_number)

    case AesGcm.decrypt(
           dec.header.algorithm_suite.encryption_algorithm,
           dec.derived_key,
           iv,
           frame.ciphertext,
           aad,
           frame.auth_tag
         ) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, :authentication_failed} -> {:error, :body_authentication_failed}
    end
  end
end
