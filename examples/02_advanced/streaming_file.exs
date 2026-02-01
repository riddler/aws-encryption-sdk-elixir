#!/usr/bin/env elixir
# Streaming File Encryption Example
#
# Demonstrates memory-efficient encryption of large files using the
# AWS Encryption SDK's streaming API. Instead of loading entire files
# into memory, data is processed in frames.
#
# Run with: mix run examples/streaming_file.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

defmodule StreamingDemo do
  @temp_dir System.tmp_dir!()
  @input_file Path.join(@temp_dir, "streaming_demo_input.bin")
  @encrypted_file Path.join(@temp_dir, "streaming_demo_encrypted.bin")
  @decrypted_file Path.join(@temp_dir, "streaming_demo_decrypted.bin")

  # 10MB file for demonstration
  @file_size 10 * 1024 * 1024
  @chunk_size 64 * 1024  # 64KB chunks for file I/O

  def run do
    IO.puts(String.duplicate("=", 60))
    IO.puts("Streaming File Encryption Example")
    IO.puts(String.duplicate("=", 60))
    IO.puts("")

    # Step 1: Set up encryption client
    IO.puts("Step 1: Setting up encryption client...")
    {client, _keyring} = setup_client()
    IO.puts("  ✓ Client ready with Raw AES keyring")
    IO.puts("")

    # Step 2: Generate test file
    IO.puts("Step 2: Generating #{format_size(@file_size)} test file...")
    generate_test_file()
    IO.puts("  ✓ Created: #{@input_file}")
    IO.puts("")

    # Step 3: Encrypt file using streaming
    IO.puts("Step 3: Encrypting file with streaming API...")
    IO.puts("  Frame size: 4096 bytes (default)")
    {encrypt_time, :ok} = :timer.tc(fn -> encrypt_file(client) end)
    encrypted_size = File.stat!(@encrypted_file).size
    IO.puts("  ✓ Encrypted in #{format_time(encrypt_time)}")
    IO.puts("  ✓ Output: #{@encrypted_file}")
    IO.puts("  ✓ Encrypted size: #{format_size(encrypted_size)} (includes header, frames, auth tags)")
    IO.puts("")

    # Step 4: Decrypt file using streaming
    IO.puts("Step 4: Decrypting file with streaming API...")
    {decrypt_time, :ok} = :timer.tc(fn -> decrypt_file(client) end)
    IO.puts("  ✓ Decrypted in #{format_time(decrypt_time)}")
    IO.puts("  ✓ Output: #{@decrypted_file}")
    IO.puts("")

    # Step 5: Verify integrity
    IO.puts("Step 5: Verifying file integrity...")
    verify_files()
    IO.puts("")

    # Step 6: Compare with non-streaming approach
    IO.puts("Step 6: Memory comparison (conceptual)...")
    IO.puts("  Non-streaming: Would load entire #{format_size(@file_size)} into memory")
    IO.puts("  Streaming: Processes ~4KB frames, constant memory usage")
    IO.puts("  ✓ Streaming is ideal for files larger than available memory")
    IO.puts("")

    # Cleanup
    IO.puts("Cleaning up temporary files...")
    cleanup()
    IO.puts("  ✓ Temporary files removed")
    IO.puts("")

    IO.puts(String.duplicate("=", 60))
    IO.puts("Streaming encryption completed successfully!")
    IO.puts(String.duplicate("=", 60))
  end

  defp setup_client do
    # Generate a random 256-bit AES key
    wrapping_key = :crypto.strong_rand_bytes(32)

    {:ok, keyring} = RawAes.new(
      "example",
      "streaming-demo-key",
      wrapping_key,
      :aes_256_gcm
    )

    cmm = Default.new(keyring)
    client = Client.new(cmm)

    {client, keyring}
  end

  defp generate_test_file do
    # Generate random data in chunks to avoid memory spike
    File.open!(@input_file, [:write, :binary], fn file ->
      chunks = div(@file_size, @chunk_size)

      for i <- 1..chunks do
        chunk = :crypto.strong_rand_bytes(@chunk_size)
        IO.binwrite(file, chunk)

        # Progress indicator every 10%
        if rem(i * 10, chunks) < 10 do
          percent = div(i * 100, chunks)
          IO.write("\r  Generating: #{percent}%")
        end
      end

      IO.puts("\r  Generating: 100%")
    end)
  end

  defp encrypt_file(client) do
    encryption_context = %{
      "purpose" => "streaming-demo",
      "file_type" => "binary"
    }

    # Stream from input file -> encrypt -> write to output file
    File.stream!(@input_file, [], @chunk_size)
    |> AwsEncryptionSdk.Stream.encrypt(client, encryption_context: encryption_context)
    |> Stream.into(File.stream!(@encrypted_file, [:write, :binary]))
    |> Stream.run()

    :ok
  end

  defp decrypt_file(client) do
    # Stream from encrypted file -> decrypt -> write to output file
    File.stream!(@encrypted_file, [], @chunk_size)
    |> AwsEncryptionSdk.Stream.decrypt(client)
    |> Stream.map(fn {plaintext, _status} -> plaintext end)
    |> Stream.into(File.stream!(@decrypted_file, [:write, :binary]))
    |> Stream.run()

    :ok
  end

  defp verify_files do
    # Compare file hashes
    input_hash = hash_file(@input_file)
    decrypted_hash = hash_file(@decrypted_file)

    if input_hash == decrypted_hash do
      IO.puts("  ✓ SHA-256 hashes match - decryption verified!")
      IO.puts("  Input:     #{Base.encode16(input_hash, case: :lower) |> String.slice(0, 16)}...")
      IO.puts("  Decrypted: #{Base.encode16(decrypted_hash, case: :lower) |> String.slice(0, 16)}...")
    else
      IO.puts("  ✗ Hash mismatch - decryption failed!")
      System.halt(1)
    end
  end

  defp hash_file(path) do
    File.stream!(path, [], 65536)
    |> Enum.reduce(:crypto.hash_init(:sha256), fn chunk, acc ->
      :crypto.hash_update(acc, chunk)
    end)
    |> :crypto.hash_final()
  end

  defp cleanup do
    File.rm(@input_file)
    File.rm(@encrypted_file)
    File.rm(@decrypted_file)
  end

  defp format_size(bytes) when bytes >= 1024 * 1024 do
    "#{Float.round(bytes / (1024 * 1024), 1)} MB"
  end
  defp format_size(bytes) when bytes >= 1024 do
    "#{Float.round(bytes / 1024, 1)} KB"
  end
  defp format_size(bytes), do: "#{bytes} bytes"

  defp format_time(microseconds) when microseconds >= 1_000_000 do
    "#{Float.round(microseconds / 1_000_000, 2)} seconds"
  end
  defp format_time(microseconds) do
    "#{Float.round(microseconds / 1000, 1)} ms"
  end
end

StreamingDemo.run()
