defmodule AwsEncryptionSdk.Stream.CmmDispatchTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
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
