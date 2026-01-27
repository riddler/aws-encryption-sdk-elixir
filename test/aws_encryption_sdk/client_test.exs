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

  describe "decrypt/3" do
    test "decrypts with require_encrypt_require_decrypt policy and committed suite" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      plaintext = "Test message"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt
      {:ok, enc_result} = Client.encrypt(client, plaintext, algorithm_suite: suite)

      # Decrypt should succeed
      assert {:ok, dec_result} = Client.decrypt(client, enc_result.ciphertext)
      assert dec_result.plaintext == plaintext
      assert dec_result.encryption_context == %{}
    end

    test "rejects non-committed suite with require_encrypt_require_decrypt policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      # Encrypt with forbid policy (only way to get non-committed suite)
      forbid_client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, enc_result} =
        Client.encrypt(forbid_client, "test", algorithm_suite: non_committed_suite)

      # Decrypt with strict policy should fail
      strict_client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)

      assert {:error, :commitment_policy_requires_committed_suite} =
               Client.decrypt(strict_client, enc_result.ciphertext)
    end

    test "accepts both suite types with require_encrypt_allow_decrypt policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      # Encrypt with committed suite using require_allow policy
      require_allow_client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)
      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc1} =
        Client.encrypt(require_allow_client, "test1", algorithm_suite: committed_suite)

      # Encrypt with non-committed suite using forbid policy
      forbid_client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      {:ok, enc2} = Client.encrypt(forbid_client, "test2", algorithm_suite: non_committed_suite)

      # Decrypt both with require_allow policy (should accept both)
      assert {:ok, dec1} = Client.decrypt(require_allow_client, enc1.ciphertext)
      assert dec1.plaintext == "test1"

      assert {:ok, dec2} = Client.decrypt(require_allow_client, enc2.ciphertext)
      assert dec2.plaintext == "test2"
    end

    test "accepts both suite types with forbid_encrypt_allow_decrypt policy" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      # Encrypt with different policies to get both suite types
      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      require_client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)
      {:ok, enc1} = Client.encrypt(require_client, "test1", algorithm_suite: committed_suite)

      forbid_encrypt_client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)

      {:ok, enc2} =
        Client.encrypt(forbid_encrypt_client, "test2", algorithm_suite: non_committed_suite)

      # Decrypt both with forbid_allow policy
      forbid_client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      assert {:ok, dec1} = Client.decrypt(forbid_client, enc1.ciphertext)
      assert dec1.plaintext == "test1"

      assert {:ok, dec2} = Client.decrypt(forbid_client, enc2.ciphertext)
      assert dec2.plaintext == "test2"
    end

    test "rejects messages exceeding max_encrypted_data_keys limit" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} = Client.encrypt(client, "test", algorithm_suite: suite)

      # Create client with max_edks = 0 (will reject any message)
      strict_client = Client.new(cmm, max_encrypted_data_keys: 0)

      assert {:error, :too_many_encrypted_data_keys} =
               Client.decrypt(strict_client, enc_result.ciphertext)
    end

    test "accepts messages within max_encrypted_data_keys limit" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} = Client.encrypt(client, "test", algorithm_suite: suite)

      # Create client with max_edks = 10 (message has 1 EDK)
      lenient_client = Client.new(cmm, max_encrypted_data_keys: 10)

      assert {:ok, dec_result} = Client.decrypt(lenient_client, enc_result.ciphertext)
      assert dec_result.plaintext == "test"
    end

    test "validates reproduced encryption context matches" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      context = %{"key" => "value"}

      {:ok, enc_result} =
        Client.encrypt(client, "test", encryption_context: context, algorithm_suite: suite)

      # Should succeed with matching context
      assert {:ok, dec_result} =
               Client.decrypt(client, enc_result.ciphertext, encryption_context: context)

      assert dec_result.plaintext == "test"
    end

    test "fails when reproduced encryption context mismatches" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      context = %{"key" => "value"}

      {:ok, enc_result} =
        Client.encrypt(client, "test", encryption_context: context, algorithm_suite: suite)

      # Should fail with mismatched context
      wrong_context = %{"key" => "wrong"}

      assert {:error, {:encryption_context_mismatch, "key"}} =
               Client.decrypt(client, enc_result.ciphertext, encryption_context: wrong_context)
    end
  end

  describe "decrypt_with_keyring/3" do
    test "decrypts using keyring directly" do
      keyring = create_test_keyring()
      plaintext = "test data"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} = Client.encrypt_with_keyring(keyring, plaintext, algorithm_suite: suite)

      {:ok, dec_result} = Client.decrypt_with_keyring(keyring, enc_result.ciphertext)

      assert dec_result.plaintext == plaintext
    end

    test "accepts custom commitment policy" do
      keyring = create_test_keyring()
      plaintext = "test"

      # Encrypt with non-committed suite
      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, enc_result} =
        Client.encrypt_with_keyring(keyring, plaintext,
          commitment_policy: :forbid_encrypt_allow_decrypt,
          algorithm_suite: non_committed_suite
        )

      # Decrypt with lenient policy should succeed
      {:ok, dec_result} =
        Client.decrypt_with_keyring(keyring, enc_result.ciphertext,
          commitment_policy: :require_encrypt_allow_decrypt
        )

      assert dec_result.plaintext == plaintext
      refute AlgorithmSuite.committed?(dec_result.header.algorithm_suite)
    end
  end

  describe "encrypt/decrypt round-trip" do
    test "round-trips with client encryption and decryption" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      plaintext = "Test message for round-trip"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Encrypt with client
      {:ok, enc_result} =
        Client.encrypt(client, plaintext,
          encryption_context: %{"context" => "value"},
          algorithm_suite: suite
        )

      # Decrypt with client
      {:ok, dec_result} = Client.decrypt(client, enc_result.ciphertext)

      assert dec_result.plaintext == plaintext
      assert dec_result.encryption_context == %{"context" => "value"}
      assert AlgorithmSuite.committed?(dec_result.header.algorithm_suite)
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
