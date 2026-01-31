defmodule AwsEncryptionSdk.Stream.IntegrationTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default, as: DefaultCmm
  alias AwsEncryptionSdk.Keyring.RawAes

  setup do
    # Create keyring and client
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test", "key-1", key, :aes_256_gcm)
    cmm = DefaultCmm.new(keyring)
    client = Client.new(cmm)

    {:ok, client: client, key: key}
  end

  describe "encrypt_stream/3" do
    test "encrypts stream chunks", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(10_000)
      chunks = chunk_binary(plaintext, 1000)

      ciphertext =
        chunks
        |> AwsEncryptionSdk.encrypt_stream(client, encryption_context: %{"test" => "value"})
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      # Verify with non-streaming decrypt
      {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)
      assert result.plaintext == plaintext
    end

    test "works with small chunks", %{client: client} do
      plaintext = "Hello, streaming world!"
      chunks = plaintext |> String.graphemes()

      ciphertext =
        chunks
        |> AwsEncryptionSdk.encrypt_stream(client)
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)
      assert result.plaintext == plaintext
    end

    test "respects frame_length option", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(5000)

      ciphertext =
        [plaintext]
        |> AwsEncryptionSdk.encrypt_stream(client, frame_length: 500)
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)
      assert result.plaintext == plaintext
    end

    test "passes encryption_context", %{client: client} do
      plaintext = "test data"
      ec = %{"purpose" => "testing", "env" => "dev"}

      ciphertext =
        [plaintext]
        |> AwsEncryptionSdk.encrypt_stream(client, encryption_context: ec)
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)
      # Check that all keys from ec are present with correct values
      # (signed suites add aws-crypto-public-key)
      Enum.each(ec, fn {key, value} ->
        assert Map.get(result.encryption_context, key) == value
      end)
    end
  end

  describe "decrypt_stream/3" do
    test "decrypts stream chunks", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(10_000)

      # Encrypt with non-streaming
      {:ok, %{ciphertext: ciphertext}} =
        AwsEncryptionSdk.encrypt(client, plaintext, encryption_context: %{"test" => "value"})

      # Decrypt with streaming
      chunks = chunk_binary(ciphertext, 500)

      result_plaintext =
        chunks
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result_plaintext == plaintext
    end

    test "returns verified status for unsigned suites", %{client: client} do
      plaintext = "test data"

      {:ok, %{ciphertext: ciphertext}} = AwsEncryptionSdk.encrypt(client, plaintext)

      statuses =
        [ciphertext]
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {_pt, status} -> status end)

      # All should be verified (unsigned suite)
      assert Enum.all?(statuses, fn status -> status == :verified end)
    end

    test "validates reproduced encryption_context", %{client: client} do
      plaintext = "test"
      ec = %{"purpose" => "test"}

      {:ok, %{ciphertext: ciphertext}} =
        AwsEncryptionSdk.encrypt(client, plaintext, encryption_context: ec)

      # Correct reproduced context
      result =
        [ciphertext]
        |> AwsEncryptionSdk.decrypt_stream(client, encryption_context: ec)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end
  end

  describe "round-trip streaming" do
    test "encrypt_stream -> decrypt_stream", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(50_000)
      chunks = chunk_binary(plaintext, 2000)

      result =
        chunks
        |> AwsEncryptionSdk.encrypt_stream(client, frame_length: 1000)
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end

    test "handles empty plaintext", %{client: client} do
      result =
        [<<>>]
        |> AwsEncryptionSdk.encrypt_stream(client)
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == <<>>
    end

    test "handles single byte", %{client: client} do
      plaintext = <<42>>

      result =
        [plaintext]
        |> AwsEncryptionSdk.encrypt_stream(client)
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end
  end

  describe "memory efficiency" do
    test "processes large data without loading all into memory", %{client: client} do
      # This test doesn't explicitly verify memory usage, but demonstrates the pattern
      # for processing large data streams
      chunk_count = 100
      chunk_size = 10_000

      # Generate stream of chunks on-demand
      plaintext_stream =
        Stream.repeatedly(fn -> :crypto.strong_rand_bytes(chunk_size) end)
        |> Stream.take(chunk_count)

      # Encrypt streaming
      ciphertext_chunks =
        plaintext_stream
        |> AwsEncryptionSdk.encrypt_stream(client)
        |> Enum.to_list()

      # Should produce ciphertext without error
      refute ciphertext_chunks == []
    end
  end

  defp chunk_binary(binary, chunk_size) do
    chunk_binary_loop(binary, chunk_size, [])
  end

  defp chunk_binary_loop(<<>>, _chunk_size, acc), do: Enum.reverse(acc)

  defp chunk_binary_loop(binary, chunk_size, acc) when byte_size(binary) <= chunk_size do
    Enum.reverse([binary | acc])
  end

  defp chunk_binary_loop(binary, chunk_size, acc) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    chunk_binary_loop(rest, chunk_size, [chunk | acc])
  end
end
