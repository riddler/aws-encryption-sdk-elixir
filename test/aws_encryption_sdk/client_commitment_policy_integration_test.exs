defmodule AwsEncryptionSdk.ClientCommitmentPolicyIntegrationTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.{AlgorithmSuite, Client, Cmm}
  alias AwsEncryptionSdk.Keyring.RawAes

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "require_encrypt_require_decrypt policy (strictest)" do
    test "rejects non-committed suite messages" do
      keyring = create_test_keyring()

      # Encrypt with lenient policy and non-committed suite
      lenient_client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :forbid_encrypt_allow_decrypt)

      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, enc_result} =
        Client.encrypt(lenient_client, "test data", algorithm_suite: non_committed_suite)

      # Attempt to decrypt with strict policy
      strict_client =
        Client.new(Cmm.Default.new(keyring),
          commitment_policy: :require_encrypt_require_decrypt
        )

      assert {:error, :commitment_policy_requires_committed_suite} =
               Client.decrypt(strict_client, enc_result.ciphertext)
    end

    test "accepts committed suite messages" do
      keyring = create_test_keyring()

      # Encrypt with committed suite
      client =
        Client.new(Cmm.Default.new(keyring),
          commitment_policy: :require_encrypt_require_decrypt
        )

      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} =
        Client.encrypt(client, "test data", algorithm_suite: committed_suite)

      # Should decrypt successfully with strict policy
      {:ok, dec_result} = Client.decrypt(client, enc_result.ciphertext)

      assert dec_result.plaintext == "test data"
    end
  end

  describe "require_encrypt_allow_decrypt policy (transitional)" do
    test "accepts non-committed suite messages" do
      keyring = create_test_keyring()

      # Encrypt with lenient policy and non-committed suite
      lenient_client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :forbid_encrypt_allow_decrypt)

      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, enc_result} =
        Client.encrypt(lenient_client, "test data", algorithm_suite: non_committed_suite)

      # Should decrypt successfully with transitional policy
      transitional_client =
        Client.new(Cmm.Default.new(keyring),
          commitment_policy: :require_encrypt_allow_decrypt
        )

      {:ok, dec_result} = Client.decrypt(transitional_client, enc_result.ciphertext)

      assert dec_result.plaintext == "test data"
    end

    test "accepts committed suite messages" do
      keyring = create_test_keyring()

      client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :require_encrypt_allow_decrypt)

      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} =
        Client.encrypt(client, "test data", algorithm_suite: committed_suite)

      # Should decrypt successfully
      {:ok, dec_result} = Client.decrypt(client, enc_result.ciphertext)

      assert dec_result.plaintext == "test data"
    end
  end

  describe "forbid_encrypt_allow_decrypt policy (legacy)" do
    test "accepts non-committed suite messages" do
      keyring = create_test_keyring()

      client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :forbid_encrypt_allow_decrypt)

      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, enc_result} =
        Client.encrypt(client, "test data", algorithm_suite: non_committed_suite)

      # Should decrypt successfully with legacy policy
      {:ok, dec_result} = Client.decrypt(client, enc_result.ciphertext)

      assert dec_result.plaintext == "test data"
    end

    test "accepts committed suite messages for decrypt" do
      keyring = create_test_keyring()

      # Encrypt with committed suite using transitional policy
      enc_client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :require_encrypt_allow_decrypt)

      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} =
        Client.encrypt(enc_client, "test data", algorithm_suite: committed_suite)

      # Decrypt with legacy policy (allows all suites for decrypt)
      dec_client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :forbid_encrypt_allow_decrypt)

      {:ok, dec_result} = Client.decrypt(dec_client, enc_result.ciphertext)

      assert dec_result.plaintext == "test data"
    end
  end

  describe "cross-policy compatibility" do
    test "message encrypted with one policy can be decrypted with compatible policy" do
      keyring = create_test_keyring()

      # Encrypt with transitional policy (uses committed suite)
      enc_client =
        Client.new(Cmm.Default.new(keyring), commitment_policy: :require_encrypt_allow_decrypt)

      {:ok, enc_result} = Client.encrypt(enc_client, "cross-policy test")

      # Decrypt with strict policy (accepts committed suites)
      dec_client_strict =
        Client.new(Cmm.Default.new(keyring),
          commitment_policy: :require_encrypt_require_decrypt
        )

      {:ok, dec_result} = Client.decrypt(dec_client_strict, enc_result.ciphertext)

      assert dec_result.plaintext == "cross-policy test"
    end
  end

  describe "max_encrypted_data_keys enforcement" do
    test "rejects messages exceeding EDK limit" do
      keyring = create_test_keyring()
      cmm = Cmm.Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} = Client.encrypt(client, "test", algorithm_suite: suite)

      # Create client with max_edks = 0 (will reject any message)
      strict_client = Client.new(cmm, max_encrypted_data_keys: 0)

      assert {:error, :too_many_encrypted_data_keys} =
               Client.decrypt(strict_client, enc_result.ciphertext)
    end

    test "accepts messages within EDK limit" do
      keyring = create_test_keyring()
      cmm = Cmm.Default.new(keyring)
      client = Client.new(cmm)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, enc_result} = Client.encrypt(client, "test", algorithm_suite: suite)

      # Create client with max_edks = 10 (message has 1 EDK)
      lenient_client = Client.new(cmm, max_encrypted_data_keys: 10)

      {:ok, dec_result} = Client.decrypt(lenient_client, enc_result.ciphertext)

      assert dec_result.plaintext == "test"
    end
  end
end
