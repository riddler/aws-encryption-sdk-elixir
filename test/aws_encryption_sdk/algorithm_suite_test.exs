defmodule AwsEncryptionSdk.AlgorithmSuiteTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias AwsEncryptionSdk.AlgorithmSuite

  describe "default/0" do
    test "returns the recommended suite 0x0578" do
      suite = AlgorithmSuite.default()

      assert suite.id == 0x0578
      assert suite.name == "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"
      assert suite.message_format_version == 2
      assert suite.encryption_algorithm == :aes_256_gcm
      assert suite.data_key_length == 256
      assert suite.kdf_type == :hkdf
      assert suite.kdf_hash == :sha512
      assert suite.signature_algorithm == :ecdsa_p384
      assert suite.commitment_length == 32
    end
  end

  describe "by_id/1" do
    test "returns error for reserved ID 0x0000" do
      assert {:error, :reserved_suite_id} = AlgorithmSuite.by_id(0x0000)
    end

    test "returns error for unknown ID" do
      assert {:error, :unknown_suite_id} = AlgorithmSuite.by_id(0x9999)
    end

    test "returns committed suite 0x0578" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert suite.id == 0x0578
      assert suite.commitment_length == 32
    end

    test "returns committed suite 0x0478" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      assert suite.id == 0x0478
      assert suite.commitment_length == 32
      assert suite.signature_algorithm == nil
    end

    test "returns legacy suite 0x0378" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      assert suite.id == 0x0378
      assert suite.message_format_version == 1
      assert suite.signature_algorithm == :ecdsa_p384
    end

    test "returns legacy suite 0x0178" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      assert suite.id == 0x0178
      assert suite.kdf_hash == :sha256
      assert suite.signature_algorithm == nil
    end
  end

  describe "committed?/1" do
    test "returns true for committed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert AlgorithmSuite.committed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns false for non-committed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      refute AlgorithmSuite.committed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      refute AlgorithmSuite.committed?(suite)
    end
  end

  describe "signed?/1" do
    test "returns true for signed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert AlgorithmSuite.signed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      assert AlgorithmSuite.signed?(suite)
    end

    test "returns false for unsigned suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      refute AlgorithmSuite.signed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      refute AlgorithmSuite.signed?(suite)
    end
  end

  describe "allows_encryption?/1 and deprecated?/1" do
    test "non-deprecated suites allow encryption" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      refute AlgorithmSuite.deprecated?(suite)
      assert AlgorithmSuite.allows_encryption?(suite)
    end
  end

  describe "all ESDK suites" do
    @all_suite_ids [
      0x0578,
      0x0478,
      0x0378,
      0x0346,
      0x0214,
      0x0178,
      0x0146,
      0x0114,
      0x0078,
      0x0046,
      0x0014
    ]

    test "all 11 ESDK suites are accessible via by_id/1" do
      capture_log(fn ->
        for suite_id <- @all_suite_ids do
          assert {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          assert suite.id == suite_id
        end
      end)
    end

    test "all suites have required fields" do
      capture_log(fn ->
        for suite_id <- @all_suite_ids do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)

          assert is_integer(suite.id)
          assert is_binary(suite.name)
          assert suite.message_format_version in [1, 2]
          assert suite.encryption_algorithm in [:aes_128_gcm, :aes_192_gcm, :aes_256_gcm]
          assert suite.data_key_length in [128, 192, 256]
          assert suite.iv_length == 12
          assert suite.auth_tag_length == 16
          assert suite.kdf_type in [:hkdf, :identity]
        end
      end)
    end

    test "all suites have consistent iv_length of 12" do
      capture_log(fn ->
        for suite_id <- @all_suite_ids do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          assert suite.iv_length == 12
        end
      end)
    end

    test "all suites have consistent auth_tag_length of 16" do
      capture_log(fn ->
        for suite_id <- @all_suite_ids do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          assert suite.auth_tag_length == 16
        end
      end)
    end
  end

  describe "committed suites" do
    @committed_suite_ids [0x0578, 0x0478]

    test "only 0x0578 and 0x0478 are committed" do
      for suite_id <- @committed_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert AlgorithmSuite.committed?(suite)
        assert suite.commitment_length == 32
        assert suite.suite_data_length == 32
        assert suite.message_format_version == 2
      end
    end
  end

  describe "signed suites" do
    @signed_suite_ids [0x0578, 0x0378, 0x0346, 0x0214]
    @unsigned_suite_ids [0x0478, 0x0178, 0x0146, 0x0114, 0x0078, 0x0046, 0x0014]

    test "signed suites have signature algorithm" do
      for suite_id <- @signed_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert AlgorithmSuite.signed?(suite)
        assert suite.signature_algorithm in [:ecdsa_p256, :ecdsa_p384]
        assert suite.signature_hash in [:sha256, :sha384]
      end
    end

    test "unsigned suites have no signature algorithm" do
      capture_log(fn ->
        for suite_id <- @unsigned_suite_ids do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          refute AlgorithmSuite.signed?(suite)
          assert suite.signature_algorithm == nil
          assert suite.signature_hash == nil
        end
      end)
    end
  end

  describe "deprecated (NO_KDF) suites" do
    @deprecated_suite_ids [0x0078, 0x0046, 0x0014]
    @non_deprecated_suite_ids [0x0578, 0x0478, 0x0378, 0x0346, 0x0214, 0x0178, 0x0146, 0x0114]

    test "NO_KDF suites are deprecated" do
      capture_log(fn ->
        for suite_id <- @deprecated_suite_ids do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          assert AlgorithmSuite.deprecated?(suite)
          refute AlgorithmSuite.allows_encryption?(suite)
          assert suite.kdf_type == :identity
          assert suite.kdf_hash == nil
        end
      end)
    end

    test "HKDF suites are not deprecated" do
      for suite_id <- @non_deprecated_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        refute AlgorithmSuite.deprecated?(suite)
        assert AlgorithmSuite.allows_encryption?(suite)
        assert suite.kdf_type == :hkdf
        assert suite.kdf_hash != nil
      end
    end

    test "accessing deprecated suite logs warning" do
      log =
        capture_log(fn ->
          {:ok, _suite} = AlgorithmSuite.by_id(0x0014)
        end)

      assert log =~ "deprecated"
      assert log =~ "0x14"
    end
  end

  describe "data key length consistency" do
    test "encryption algorithm matches data_key_length" do
      {:ok, suite_256} = AlgorithmSuite.by_id(0x0578)
      assert suite_256.encryption_algorithm == :aes_256_gcm
      assert suite_256.data_key_length == 256

      {:ok, suite_192} = AlgorithmSuite.by_id(0x0346)
      assert suite_192.encryption_algorithm == :aes_192_gcm
      assert suite_192.data_key_length == 192

      {:ok, suite_128} = AlgorithmSuite.by_id(0x0214)
      assert suite_128.encryption_algorithm == :aes_128_gcm
      assert suite_128.data_key_length == 128
    end

    test "kdf_input_length matches data_key_length in bytes" do
      capture_log(fn ->
        for suite_id <- [0x0578, 0x0478, 0x0378, 0x0178, 0x0078] do
          {:ok, suite} = AlgorithmSuite.by_id(suite_id)
          assert suite.kdf_input_length == div(suite.data_key_length, 8)
        end
      end)
    end
  end

  describe "direct suite functions" do
    test "each suite has a direct accessor function" do
      assert AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384().id == 0x0578
      assert AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key().id == 0x0478
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384().id == 0x0378
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384().id == 0x0346
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256().id == 0x0214
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256().id == 0x0178
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_hkdf_sha256().id == 0x0146
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256().id == 0x0114
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf().id == 0x0078
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_no_kdf().id == 0x0046
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_no_kdf().id == 0x0014
    end
  end
end
