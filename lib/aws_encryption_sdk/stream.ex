defmodule AwsEncryptionSdk.Stream do
  @moduledoc """
  Streaming encryption and decryption APIs.

  Provides Stream-compatible functions for processing large data incrementally.

  ## Example

      # Encrypt a file stream
      File.stream!("input.bin", [], 4096)
      |> AwsEncryptionSdk.Stream.encrypt(client)
      |> Stream.into(File.stream!("output.encrypted"))
      |> Stream.run()

      # Decrypt a file stream
      File.stream!("output.encrypted", [], 4096)
      |> AwsEncryptionSdk.Stream.decrypt(client)
      |> Stream.map(fn {plaintext, _status} -> plaintext end)
      |> Stream.into(File.stream!("decrypted.bin"))
      |> Stream.run()

  """

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  @doc """
  Creates a stream that encrypts plaintext chunks.

  Returns a Stream that emits ciphertext binaries.

  ## Options

  - `:encryption_context` - Encryption context (default: `%{}`)
  - `:frame_length` - Frame size in bytes (default: 4096)
  - `:algorithm_suite` - Algorithm suite to use (default: from client)
  """
  @spec encrypt(Enumerable.t(), Client.t(), keyword()) :: Enumerable.t()
  def encrypt(plaintext_stream, %Client{} = client, opts \\ []) do
    case init_encryptor_for_stream(client, opts) do
      {:ok, enc} ->
        plaintext_stream
        |> Stream.transform(
          fn -> {:start, enc} end,
          &encrypt_chunk/2,
          &finalize_encryption/1,
          fn _acc -> :ok end
        )

      {:error, reason} ->
        raise "Encryption initialization failed: #{inspect(reason)}"
    end
  end

  @doc """
  Creates a stream that decrypts ciphertext chunks.

  Returns a Stream that emits `{plaintext, status}` tuples where status is
  `:verified` or `:unverified`.

  ## Options

  - `:encryption_context` - Reproduced context to validate (optional)
  - `:fail_on_signed` - Fail immediately on signed suites (default: false)
  """
  @spec decrypt(Enumerable.t(), Client.t(), keyword()) :: Enumerable.t()
  def decrypt(ciphertext_stream, %Client{} = client, opts \\ []) do
    {:ok, dec} = init_decryptor_for_stream(client, opts)

    ciphertext_stream
    |> Stream.transform(fn -> dec end, &decrypt_chunk/2, &finalize_decryption/1, fn _acc ->
      :ok
    end)
    |> Stream.flat_map(& &1)
  end

  # Private helpers for encryption

  defp init_encryptor_for_stream(client, opts) do
    encryption_context = Keyword.get(opts, :encryption_context, %{})
    frame_length = Keyword.get(opts, :frame_length, 4096)

    request = %{
      encryption_context: encryption_context,
      commitment_policy: client.commitment_policy
    }

    with {:ok, materials} <- call_cmm_get_encryption_materials(client.cmm, request) do
      Encryptor.init(materials, frame_length: frame_length)
    end
  end

  defp encrypt_chunk(plaintext_chunk, {:start, enc}) do
    case Encryptor.start(enc) do
      {:ok, enc, header} ->
        # Emit header, then process first chunk
        case Encryptor.update(enc, plaintext_chunk) do
          {:ok, enc, <<>>} ->
            {[header], enc}

          {:ok, enc, ciphertext} ->
            {[header, ciphertext], enc}

          # coveralls-ignore-start
          {:error, reason} ->
            raise "Encryption failed: #{inspect(reason)}"
            # coveralls-ignore-stop
        end

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Failed to generate header: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  defp encrypt_chunk(plaintext_chunk, enc) do
    case Encryptor.update(enc, plaintext_chunk) do
      {:ok, enc, <<>>} ->
        {[], enc}

      {:ok, enc, ciphertext} ->
        {[ciphertext], enc}

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Encryption failed: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  defp finalize_encryption({:start, enc}) do
    # Handle case where no plaintext chunks were provided
    case Encryptor.start(enc) do
      {:ok, enc, header} ->
        case Encryptor.finalize(enc) do
          {:ok, _enc, final} ->
            {[header, final], enc}

          # coveralls-ignore-start
          {:error, reason} ->
            raise "Finalization failed: #{inspect(reason)}"
            # coveralls-ignore-stop
        end

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Failed to generate header: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  defp finalize_encryption(enc) do
    case Encryptor.finalize(enc) do
      {:ok, _enc, final} ->
        {[final], enc}

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Finalization failed: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  # Private helpers for decryption

  defp init_decryptor_for_stream(client, opts) do
    fail_on_signed = Keyword.get(opts, :fail_on_signed, false)
    reproduced_context = Keyword.get(opts, :encryption_context, %{})

    get_materials = fn header ->
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: client.commitment_policy,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: reproduced_context
      }

      call_cmm_get_decryption_materials(client.cmm, request)
    end

    Decryptor.init(get_materials: get_materials, fail_on_signed: fail_on_signed)
  end

  defp decrypt_chunk(ciphertext_chunk, dec) do
    case Decryptor.update(dec, ciphertext_chunk) do
      {:ok, dec, []} ->
        {[], dec}

      {:ok, dec, plaintexts} ->
        {[plaintexts], dec}

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Decryption failed: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  defp finalize_decryption(dec) do
    case Decryptor.finalize(dec) do
      {:ok, _dec, final} ->
        {[final], dec}

      # coveralls-ignore-start
      {:error, reason} ->
        raise "Finalization failed: #{inspect(reason)}"
        # coveralls-ignore-stop
    end
  end

  # Dispatch get_encryption_materials to the appropriate CMM module
  defp call_cmm_get_encryption_materials(%Default{} = cmm, request) do
    Default.get_encryption_materials(cmm, request)
  end

  # coveralls-ignore-start
  defp call_cmm_get_encryption_materials(%RequiredEncryptionContext{} = cmm, request) do
    RequiredEncryptionContext.get_encryption_materials(cmm, request)
  end

  defp call_cmm_get_encryption_materials(%Caching{} = cmm, request) do
    Caching.get_encryption_materials(cmm, request)
  end

  defp call_cmm_get_encryption_materials(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  # coveralls-ignore-stop

  # Dispatch get_decryption_materials to the appropriate CMM module
  defp call_cmm_get_decryption_materials(%Default{} = cmm, request) do
    Default.get_decryption_materials(cmm, request)
  end

  # coveralls-ignore-start
  defp call_cmm_get_decryption_materials(%RequiredEncryptionContext{} = cmm, request) do
    RequiredEncryptionContext.get_decryption_materials(cmm, request)
  end

  defp call_cmm_get_decryption_materials(%Caching{} = cmm, request) do
    Caching.get_decryption_materials(cmm, request)
  end

  defp call_cmm_get_decryption_materials(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  # coveralls-ignore-stop
end
