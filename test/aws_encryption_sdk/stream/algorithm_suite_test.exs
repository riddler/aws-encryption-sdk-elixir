defmodule AwsEncryptionSdk.Stream.AlgorithmSuiteTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Stream

  defp keyring do
    {:ok, keyring} = RawAes.new("test", "key1", :crypto.strong_rand_bytes(32), :aes_256_gcm)
    keyring
  end

  defp stream_encrypt(client, plaintext, opts) do
    [plaintext]
    |> Stream.encrypt(client, opts)
    |> Enum.to_list()
    |> IO.iodata_to_binary()
  end

  defp stream_decrypt(client, ciphertext) do
    [ciphertext]
    |> Stream.decrypt(client)
    |> Enum.map(fn {plaintext, _status} -> plaintext end)
    |> IO.iodata_to_binary()
  end

  defp header_suite_id(ciphertext) do
    {:ok, header, _rest} = Header.deserialize(ciphertext)
    header.algorithm_suite.id
  end

  describe "the :algorithm_suite option" do
    test "writes a 0x0214 header under a policy that permits it, and round-trips" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()

      client =
        Client.new(Default.new(keyring()), commitment_policy: :forbid_encrypt_allow_decrypt)

      plaintext = :crypto.strong_rand_bytes(10_000)

      ciphertext =
        stream_encrypt(client, plaintext,
          algorithm_suite: suite,
          encryption_context: %{"purpose" => "test"},
          frame_length: 1024
        )

      # The policy's default is 0x0378, so the header shows the option was read
      assert header_suite_id(ciphertext) == 0x0214

      assert stream_decrypt(client, ciphertext) == plaintext
      assert {:ok, %{plaintext: ^plaintext}} = Client.decrypt(client, ciphertext)
    end

    test "writes a committed non-default suite under the default policy" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      client = Client.new(Default.new(keyring()))

      ciphertext = stream_encrypt(client, "Hello, World!", algorithm_suite: suite)

      # The default policy's default is 0x0578
      assert header_suite_id(ciphertext) == 0x0478
      assert stream_decrypt(client, ciphertext) == "Hello, World!"
    end

    test "without the option the stream writes the policy's default suite" do
      client = Client.new(Default.new(keyring()))

      assert header_suite_id(stream_encrypt(client, "Hello", [])) == 0x0578
    end
  end

  describe "a suite the commitment policy forbids" do
    test "is refused under the default policy with the reason the one-shot returns" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()
      client = Client.new(Default.new(keyring()))

      assert {:error, :commitment_policy_requires_committed_suite} =
               Client.encrypt(client, "Hello", algorithm_suite: suite)

      assert_raise RuntimeError,
                   "Encryption initialization failed: :commitment_policy_requires_committed_suite",
                   fn -> Stream.encrypt(["Hello"], client, algorithm_suite: suite) end
    end

    test "is refused under the forbid policy with the reason the one-shot returns" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      client =
        Client.new(Default.new(keyring()), commitment_policy: :forbid_encrypt_allow_decrypt)

      assert {:error, :commitment_policy_forbids_committed_suite} =
               Client.encrypt(client, "Hello", algorithm_suite: suite)

      assert_raise RuntimeError,
                   "Encryption initialization failed: :commitment_policy_forbids_committed_suite",
                   fn -> Stream.encrypt(["Hello"], client, algorithm_suite: suite) end
    end

    test "is refused before a Caching CMM shared with a permitting client is consulted" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()
      {:ok, cache} = LocalCache.start_link([])
      cmm = Caching.new(Default.new(keyring()), cache, max_age: 60, partition_id: "shared")
      permitting = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      strict = Client.new(cmm)
      ec = %{"purpose" => "test"}

      _ciphertext =
        stream_encrypt(permitting, "Hello",
          algorithm_suite: suite,
          encryption_context: ec,
          plaintext_length: 5
        )

      cache_id = Caching.compute_encryption_cache_id("shared", suite, ec)
      assert {:ok, %{messages_used: 1}} = LocalCache.get_cache_entry(cache, cache_id)

      # The cached 0x0214 entry would answer the strict client's request; the
      # check runs first, so the entry is neither served nor counted
      assert_raise RuntimeError,
                   "Encryption initialization failed: :commitment_policy_requires_committed_suite",
                   fn ->
                     Stream.encrypt(["Hello"], strict,
                       algorithm_suite: suite,
                       encryption_context: ec,
                       plaintext_length: 5
                     )
                   end

      assert {:ok, %{messages_used: 1}} = LocalCache.get_cache_entry(cache, cache_id)
    end
  end

  describe "through the Caching CMM" do
    test "reads and writes the entry keyed on the requested suite" do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()
      {:ok, cache} = LocalCache.start_link([])
      cmm = Caching.new(Default.new(keyring()), cache, max_age: 60, partition_id: "suites")
      client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      ec = %{"purpose" => "test"}
      plaintext = "Message"

      [ciphertext1, ciphertext2] =
        for _round <- 1..2 do
          stream_encrypt(client, plaintext,
            algorithm_suite: suite,
            encryption_context: ec,
            plaintext_length: byte_size(plaintext)
          )
        end

      assert header_suite_id(ciphertext1) == 0x0214
      assert header_suite_id(ciphertext2) == 0x0214

      # The second stream was served from the suite's entry: the same EDKs
      {:ok, header1, _rest} = Header.deserialize(ciphertext1)
      {:ok, header2, _rest} = Header.deserialize(ciphertext2)
      assert header1.encrypted_data_keys == header2.encrypted_data_keys

      suite_id = Caching.compute_encryption_cache_id("suites", suite, ec)
      assert {:ok, entry} = LocalCache.get_cache_entry(cache, suite_id)
      assert entry.messages_used == 2
      assert entry.bytes_used == 2 * byte_size(plaintext)
      assert entry.materials.algorithm_suite.id == 0x0214

      # Nothing landed under the no-suite entry the stream used before
      default_id = Caching.compute_encryption_cache_id("suites", nil, ec)
      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, default_id)

      assert stream_decrypt(client, ciphertext2) == plaintext
    end
  end
end
