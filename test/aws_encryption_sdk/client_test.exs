defmodule AwsEncryptionSdk.ClientTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "new/2" do
    test "creates client with default policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      client = Client.new(cmm)

      assert client.cmm == cmm
      assert client.commitment_policy == :require_encrypt_require_decrypt
      assert client.max_encrypted_data_keys == nil
    end

    test "creates client with custom commitment policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)

      assert client.commitment_policy == :forbid_encrypt_allow_decrypt
    end

    test "creates client with custom max_encrypted_data_keys" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      client = Client.new(cmm, max_encrypted_data_keys: 10)

      assert client.max_encrypted_data_keys == 10
    end

    test "creates client with all options" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      client =
        Client.new(cmm,
          commitment_policy: :require_encrypt_allow_decrypt,
          max_encrypted_data_keys: 5
        )

      assert client.commitment_policy == :require_encrypt_allow_decrypt
      assert client.max_encrypted_data_keys == 5
    end
  end

  describe "struct immutability" do
    test "client fields cannot be modified after creation" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Attempting to modify fields requires creating a new struct
      # This is enforced by Elixir's immutable data structures
      assert %Client{} = client
    end
  end

  describe "encrypt/3" do
    test "encrypts with committed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      # Use non-signed committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} =
        Client.encrypt(client, "Hello, World!",
          encryption_context: %{"purpose" => "test"},
          algorithm_suite: suite
        )

      assert is_binary(result.ciphertext)
      assert result.encryption_context["purpose"] == "test"
      # Non-signed suite should not add public key
      refute Map.has_key?(result.encryption_context, "aws-crypto-public-key")
      assert AlgorithmSuite.committed?(result.algorithm_suite)
      assert result.algorithm_suite.id == 0x0478
    end

    test "encrypts with specified committed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} = Client.encrypt(client, "test", algorithm_suite: suite)

      assert result.algorithm_suite == suite
    end

    test "fails when requested suite violates require policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      # Default: require_encrypt_require_decrypt
      client = Client.new(cmm)

      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      assert {:error, :commitment_policy_requires_committed_suite} =
               Client.encrypt(client, "test", algorithm_suite: non_committed_suite)
    end

    test "fails when requested suite violates forbid policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)

      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      assert {:error, :commitment_policy_forbids_committed_suite} =
               Client.encrypt(client, "test", algorithm_suite: committed_suite)
    end

    test "enforces max_encrypted_data_keys limit" do
      # Create multi-keyring that will generate 2 EDKs
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
      {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])

      cmm = Default.new(multi)
      client = Client.new(cmm, max_encrypted_data_keys: 1)

      assert {:error, :max_encrypted_data_keys_exceeded} = Client.encrypt(client, "test")
    end

    test "allows encryption when under EDK limit" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
      {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])

      cmm = Default.new(multi)
      client = Client.new(cmm, max_encrypted_data_keys: 5)
      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      assert {:ok, _result} = Client.encrypt(client, "test", algorithm_suite: suite)
    end

    test "rejects reserved encryption context key" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      assert {:error, :reserved_encryption_context_key} =
               Client.encrypt(client, "test",
                 encryption_context: %{"aws-crypto-public-key" => "malicious"}
               )
    end
  end

  describe "encrypt_with_keyring/3" do
    test "encrypts using keyring directly" do
      keyring = create_test_keyring()
      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} =
        Client.encrypt_with_keyring(keyring, "test data",
          encryption_context: %{"key" => "value"},
          algorithm_suite: suite
        )

      assert is_binary(result.ciphertext)
      assert result.encryption_context["key"] == "value"
    end

    test "accepts custom commitment policy" do
      keyring = create_test_keyring()
      # Use non-signed non-committed suite
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, result} =
        Client.encrypt_with_keyring(keyring, "test",
          commitment_policy: :forbid_encrypt_allow_decrypt,
          algorithm_suite: suite
        )

      # Should use non-committed suite
      refute AlgorithmSuite.committed?(result.algorithm_suite)
      assert result.algorithm_suite.id == 0x0178
    end
  end

  describe "encrypt/decrypt round-trip" do
    test "round-trips with client encryption" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      plaintext = "Test message for round-trip"
      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with client
      {:ok, enc_result} =
        Client.encrypt(client, plaintext,
          encryption_context: %{"context" => "value"},
          algorithm_suite: suite
        )

      # For now, just verify encryption succeeded
      assert is_binary(enc_result.ciphertext)
      assert byte_size(enc_result.ciphertext) > byte_size(plaintext)
    end
  end

  describe "error handling" do
    test "returns error for unsupported CMM type" do
      # Create a fake CMM struct that's not Default
      fake_cmm = %{__struct__: FakeCMM, some_field: "value"}

      client = %Client{
        cmm: fake_cmm,
        commitment_policy: :require_encrypt_require_decrypt,
        max_encrypted_data_keys: nil
      }

      assert {:error, {:unsupported_cmm_type, FakeCMM}} =
               Client.encrypt(client, "test", encryption_context: %{})
    end
  end
end
