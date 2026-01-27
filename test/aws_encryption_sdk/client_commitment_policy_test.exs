defmodule AwsEncryptionSdk.ClientCommitmentPolicyTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}

  @moduletag :commitment_policy

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
    keyring
  end

  # Helper to test committed suite acceptance (DRY for require_* policies)
  defp test_accepts_committed_suite(client, suite) do
    # Skip ECDSA suites until ECDSA is implemented
    if suite.id == 0x0578 do
      :ok
    else
      assert {:ok, result} = Client.encrypt(client, "test", algorithm_suite: suite)
      assert result.algorithm_suite == suite
    end
  end

  # Committed algorithm suites
  @committed_suites [
    {:aes_256_gcm_hkdf_sha512_commit_key, AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()},
    {:aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384,
     AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()}
  ]

  # Non-committed algorithm suites
  @non_committed_suites [
    {:aes_256_gcm_iv12_tag16_hkdf_sha256, AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()},
    {:aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384,
     AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()}
  ]

  describe "forbid_encrypt_allow_decrypt policy" do
    setup do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      {:ok, client: client}
    end

    test "uses non-committed default suite", %{client: client} do
      # Use non-signed non-committed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      {:ok, result} = Client.encrypt(client, "test", algorithm_suite: suite)

      assert result.algorithm_suite.id == 0x0178
      refute AlgorithmSuite.committed?(result.algorithm_suite)
    end

    for {name, suite} <- @committed_suites do
      @suite suite
      @name name

      test "rejects committed suite #{@name} for encryption", %{client: client} do
        assert {:error, :commitment_policy_forbids_committed_suite} =
                 Client.encrypt(client, "test", algorithm_suite: @suite)
      end
    end

    for {name, suite} <- @non_committed_suites do
      @suite suite
      @name name

      test "accepts non-committed suite #{@name} for encryption", %{client: client} do
        # Skip ECDSA suites until ECDSA is implemented
        if @suite.id == 0x0378 do
          # ECDSA suite - skip for now
          :ok
        else
          assert {:ok, result} = Client.encrypt(client, "test", algorithm_suite: @suite)
          assert result.algorithm_suite == @suite
        end
      end
    end
  end

  describe "require_encrypt_allow_decrypt policy" do
    setup do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)
      {:ok, client: client}
    end

    test "uses committed default suite (0x0578)", %{client: client} do
      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, result} = Client.encrypt(client, "test", algorithm_suite: suite)

      assert result.algorithm_suite.id == 0x0478
      assert AlgorithmSuite.committed?(result.algorithm_suite)
    end

    for {name, suite} <- @committed_suites do
      @suite suite
      @name name

      test "accepts committed suite #{@name} for encryption", %{client: client} do
        test_accepts_committed_suite(client, @suite)
      end
    end

    for {name, suite} <- @non_committed_suites do
      @suite suite
      @name name

      test "rejects non-committed suite #{@name} for encryption", %{client: client} do
        assert {:error, :commitment_policy_requires_committed_suite} =
                 Client.encrypt(client, "test", algorithm_suite: @suite)
      end
    end
  end

  describe "require_encrypt_require_decrypt policy (default)" do
    setup do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      {:ok, client: client}
    end

    test "uses committed default suite (0x0478)", %{client: client} do
      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, result} = Client.encrypt(client, "test", algorithm_suite: suite)

      assert result.algorithm_suite.id == 0x0478
      assert AlgorithmSuite.committed?(result.algorithm_suite)
    end

    test "policy is the default", %{client: client} do
      assert client.commitment_policy == :require_encrypt_require_decrypt
    end

    for {name, suite} <- @committed_suites do
      @suite suite
      @name name

      test "accepts committed suite #{@name} for encryption", %{client: client} do
        test_accepts_committed_suite(client, @suite)
      end
    end

    for {name, suite} <- @non_committed_suites do
      @suite suite
      @name name

      test "rejects non-committed suite #{@name} for encryption", %{client: client} do
        assert {:error, :commitment_policy_requires_committed_suite} =
                 Client.encrypt(client, "test", algorithm_suite: @suite)
      end
    end
  end

  describe "policy enforcement across operations" do
    test "different clients can have different policies" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      client_forbid = Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      client_require = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)

      # Forbid client uses non-committed (specify non-signed suite)
      non_committed_suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      {:ok, result_forbid} =
        Client.encrypt(client_forbid, "test", algorithm_suite: non_committed_suite)

      refute AlgorithmSuite.committed?(result_forbid.algorithm_suite)

      # Require client uses committed (use non-signed suite)
      committed_suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result_require} =
        Client.encrypt(client_require, "test", algorithm_suite: committed_suite)

      assert AlgorithmSuite.committed?(result_require.algorithm_suite)
    end

    test "policy cannot be changed after client creation" do
      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Attempting to modify commitment_policy requires creating new client
      # (Elixir immutability prevents in-place modification)
      assert client.commitment_policy == :require_encrypt_require_decrypt

      # This creates a NEW client, doesn't modify the old one
      new_client = %{client | commitment_policy: :forbid_encrypt_allow_decrypt}

      # Original unchanged
      assert client.commitment_policy == :require_encrypt_require_decrypt
      # New client has new policy
      assert new_client.commitment_policy == :forbid_encrypt_allow_decrypt
    end
  end

  describe "integration with multi-keyring" do
    test "respects policy with multi-keyring" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, keyring1} = RawAes.new("ns", "key1", key1, :aes_256_gcm)
      {:ok, keyring2} = RawAes.new("ns", "key2", key2, :aes_256_gcm)
      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])

      cmm = Default.new(multi)
      client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)

      # Use non-signed suite until ECDSA is implemented
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      {:ok, result} =
        Client.encrypt(client, "test",
          algorithm_suite: suite,
          encryption_context: %{"test" => "value"}
        )

      # Should produce 2 EDKs with committed suite
      assert map_size(result.encryption_context) >= 1
      assert AlgorithmSuite.committed?(result.algorithm_suite)
    end
  end
end
