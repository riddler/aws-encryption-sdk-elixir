defmodule AwsEncryptionSdk.Stream.CmmDispatchTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Stream

  describe "RequiredEncryptionContext CMM streaming" do
    test "encrypts and decrypts with RequiredEncryptionContext CMM" do
      # Create keyring
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      # Create RequiredEncryptionContext CMM
      default_cmm = Default.new(keyring)

      cmm = RequiredEncryptionContext.new(["purpose"], default_cmm)

      client = Client.new(cmm)

      # Encrypt with required key
      plaintext = "Hello, World!"

      ciphertext =
        [plaintext]
        |> Stream.encrypt(client, encryption_context: %{"purpose" => "test", "env" => "dev"})
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      # Decrypt - must provide required encryption context keys
      result =
        [ciphertext]
        |> Stream.decrypt(client, encryption_context: %{"purpose" => "test"})
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end
  end

  describe "Caching CMM streaming" do
    test "encrypts and decrypts with Caching CMM" do
      # Create keyring
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      # Create Caching CMM
      default_cmm = Default.new(keyring)
      {:ok, cache} = LocalCache.start_link([])

      cmm = Caching.new(default_cmm, cache, max_age: 60)

      client = Client.new(cmm)

      # Encrypt
      plaintext = "Hello, World!"

      ciphertext =
        [plaintext]
        |> Stream.encrypt(client, encryption_context: %{"purpose" => "test"})
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      # Decrypt
      result =
        [ciphertext]
        |> Stream.decrypt(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end

    test "uses cached materials for multiple encryptions" do
      # Create keyring
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      # Create Caching CMM
      default_cmm = Default.new(keyring)
      {:ok, cache} = LocalCache.start_link([])

      cmm = Caching.new(default_cmm, cache, max_age: 60, max_messages: 100)

      client = Client.new(cmm)

      # Encrypt multiple messages with same context (should use cache)
      ec = %{"purpose" => "test", "batch" => "1"}

      ciphertext1 =
        ["Message 1"]
        |> Stream.encrypt(client, encryption_context: ec)
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      ciphertext2 =
        ["Message 2"]
        |> Stream.encrypt(client, encryption_context: ec)
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      # Both should decrypt successfully
      result1 =
        [ciphertext1]
        |> Stream.decrypt(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      result2 =
        [ciphertext2]
        |> Stream.decrypt(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result1 == "Message 1"
      assert result2 == "Message 2"
    end

    test "without :plaintext_length the cache is bypassed and left empty" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      default_cmm = Default.new(keyring)
      {:ok, cache} = LocalCache.start_link([])

      cmm = Caching.new(default_cmm, cache, max_age: 60, partition_id: "stream-partition")
      client = Client.new(cmm)
      ec = %{"purpose" => "test"}

      for _round <- 1..2 do
        ["Message"]
        |> Stream.encrypt(client, encryption_context: ec)
        |> Enum.to_list()
      end

      # No length declared, so nothing was ever cached. The cache id is
      # derived from the request's context (before the CMM adds the signing
      # public key), so this probes exactly where an entry would have landed.
      cache_id = Caching.compute_encryption_cache_id("stream-partition", nil, ec)
      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end

    test "with :plaintext_length materials are cached and bytes_used accumulates" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      default_cmm = Default.new(keyring)
      {:ok, cache} = LocalCache.start_link([])

      cmm = Caching.new(default_cmm, cache, max_age: 60, partition_id: "stream-partition")
      client = Client.new(cmm)
      ec = %{"purpose" => "test"}
      plaintext = "Message"

      headers =
        for _round <- 1..2 do
          ciphertext =
            [plaintext]
            |> Stream.encrypt(client,
              encryption_context: ec,
              plaintext_length: byte_size(plaintext)
            )
            |> Enum.to_list()
            |> IO.iodata_to_binary()

          {:ok, header, _rest} = Header.deserialize(ciphertext)
          header
        end

      # Cache hit on the second stream reuses the stored materials, so both
      # messages carry identical EDKs
      [header1, header2] = headers
      assert header1.encrypted_data_keys == header2.encrypted_data_keys

      cache_id = Caching.compute_encryption_cache_id("stream-partition", nil, ec)

      {:ok, entry} = LocalCache.get_cache_entry(cache, cache_id)
      assert entry.messages_used == 2
      assert entry.bytes_used == 2 * byte_size(plaintext)
    end
  end

  describe "combined CMMs streaming" do
    test "encrypts and decrypts with RequiredEncryptionContext wrapping Caching" do
      # Create keyring
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key1", key, :aes_256_gcm)

      # Create nested CMMs: RequiredEncryptionContext -> Caching -> Default
      default_cmm = Default.new(keyring)
      {:ok, cache} = LocalCache.start_link([])

      caching_cmm = Caching.new(default_cmm, cache, max_age: 60)

      cmm = RequiredEncryptionContext.new(["purpose"], caching_cmm)

      client = Client.new(cmm)

      # Encrypt
      plaintext = "Hello, World!"

      ciphertext =
        [plaintext]
        |> Stream.encrypt(client,
          encryption_context: %{"purpose" => "test", "env" => "production"}
        )
        |> Enum.to_list()
        |> IO.iodata_to_binary()

      # Decrypt - must provide required encryption context keys
      result =
        [ciphertext]
        |> Stream.decrypt(client, encryption_context: %{"purpose" => "test"})
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end
  end
end
