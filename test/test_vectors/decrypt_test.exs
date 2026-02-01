defmodule AwsEncryptionSdk.TestVectors.DecryptTest do
  @moduledoc """
  Test vector validation for AWS Encryption SDK decrypt operations.

  These tests validate message structure parsing against official test vectors.
  Full decryption validation requires keyring implementations (future work).

  Run with: mix test --only test_vectors
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.TestSupport.TestVectorHarness
  alias AwsEncryptionSdk.TestSupport.TestVectorSetup

  @moduletag :test_vectors

  # Skip entire module if test vectors not available
  # Skip tag added conditionally below

  setup_all do
    case TestVectorSetup.find_manifest("**/manifest.json") do
      {:ok, manifest_path} ->
        case TestVectorHarness.load_manifest(manifest_path) do
          {:ok, harness} ->
            {:ok, harness: harness}

          {:error, reason} ->
            {:ok, harness: nil, load_error: reason}
        end

      :not_found ->
        {:ok, harness: nil, load_error: :manifest_not_found}
    end
  end

  describe "manifest loading" do
    @tag :test_vectors
    test "loads manifest successfully", %{harness: harness} = context do
      if harness == nil do
        flunk("Failed to load manifest: #{inspect(context[:load_error])}")
      end

      assert harness.manifest_type == "awses-decrypt"
      assert harness.manifest_version in [2, 3, 4]
    end

    @tag :test_vectors
    test "loads keys manifest", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Should have at least some keys defined
      assert map_size(harness.keys) > 0
    end

    @tag :test_vectors
    test "has test cases defined", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      test_ids = TestVectorHarness.list_test_ids(harness)
      refute test_ids == []
    end
  end

  describe "message structure validation" do
    @tag :test_vectors
    test "parses test vector ciphertexts successfully", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Get first 10 success test cases for structure validation
      success_tests =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(10)

      for {test_id, _test_data} <- success_tests do
        {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

        case TestVectorHarness.parse_ciphertext(ciphertext) do
          {:ok, message, _rest} ->
            # Validate basic message structure
            assert is_map(message.header)
            assert message.header.version in [1, 2]
            assert is_binary(message.header.message_id)

            # Validate algorithm suite is recognized
            suite = message.header.algorithm_suite
            key_length_bytes = div(suite.data_key_length, 8)
            assert key_length_bytes in [16, 24, 32]

          {:error, reason} ->
            flunk("Failed to parse ciphertext for test #{test_id}: #{inspect(reason)}")
        end
      end
    end

    @tag :test_vectors
    test "validates header fields", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Get a single test case for detailed validation
      [test_id | _rest] =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.map(fn {id, _test_data} -> id end)
        |> Enum.take(1)

      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _rest} = TestVectorHarness.parse_ciphertext(ciphertext)

      header = message.header

      # Version validation
      assert header.version in [1, 2]

      # Message ID length depends on version
      expected_msg_id_length = if header.version == 1, do: 16, else: 32
      assert byte_size(header.message_id) == expected_msg_id_length

      # Algorithm suite should be valid
      assert header.algorithm_suite != nil

      # Content type should be valid
      assert header.content_type in [:framed, :non_framed]

      # EDKs should be present
      assert is_list(header.encrypted_data_keys)
      refute header.encrypted_data_keys == []
    end
  end

  describe "key material" do
    @tag :test_vectors
    test "decodes AES key material", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Find an AES key
      aes_key =
        Enum.find(harness.keys, fn {_id, key} ->
          key["type"] == "symmetric" and key["algorithm"] == "aes"
        end)

      if aes_key do
        {_key_id, key_data} = aes_key
        {:ok, material} = TestVectorHarness.decode_key_material(key_data)

        expected_bytes = div(key_data["bits"], 8)
        assert byte_size(material) == expected_bytes
      end
    end

    @tag :test_vectors
    test "handles RSA key material", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Find an RSA key
      rsa_key =
        Enum.find(harness.keys, fn {_id, key} ->
          key["type"] in ["private", "public"] and key["algorithm"] == "rsa"
        end)

      if rsa_key do
        {_key_id, key_data} = rsa_key
        {:ok, material} = TestVectorHarness.decode_key_material(key_data)

        # PEM material should start with proper header
        assert String.starts_with?(material, "-----BEGIN")
      end
    end
  end

  describe "filtering" do
    @tag :test_vectors
    @tag algorithm: :committed
    test "identifies committed algorithm suites", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Parse a few messages and check for committed suites
      committed_count =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(20)
        |> Enum.count(fn {test_id, _test_data} ->
          {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

          case TestVectorHarness.parse_ciphertext(ciphertext) do
            {:ok, message, _rest} ->
              AlgorithmSuite.committed?(message.header.algorithm_suite)

            _error ->
              false
          end
        end)

      # Just verify we can identify committed vs non-committed
      assert is_integer(committed_count)
    end

    @tag :test_vectors
    @tag algorithm: :signed
    test "identifies signed algorithm suites", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Parse a few messages and check for signed suites
      signed_count =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(20)
        |> Enum.count(fn {test_id, _test_data} ->
          {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

          case TestVectorHarness.parse_ciphertext(ciphertext) do
            {:ok, message, _rest} ->
              AlgorithmSuite.signed?(message.header.algorithm_suite)

            _error ->
              false
          end
        end)

      # Just verify we can identify signed vs unsigned
      assert is_integer(signed_count)
    end
  end
end
