defmodule AwsEncryptionSdk.TestVectors.FullDecryptTest do
  @moduledoc """
  Full end-to-end decrypt validation against AWS Encryption SDK test vectors.

  These tests execute the complete `Client.decrypt_with_keyring/3` flow and validate
  that decrypted plaintext matches expected output byte-for-byte.

  Run with: mix test --only full_test_vectors
  Run specific category: mix test --only full_test_vectors:raw_aes
  """

  # credo:disable-for-this-file Credo.Check.Refactor.IoPuts
  # credo:disable-for-this-file Credo.Check.Refactor.Nesting
  # credo:disable-for-this-file Credo.Check.Design.DuplicatedCode

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes, RawRsa}
  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

  @moduletag :test_vectors
  @moduletag :full_test_vectors

  # Only skip if test vectors are not available
  if not TestVectorSetup.vectors_available?() do
    @moduletag :skip
  end

  setup_all do
    case TestVectorSetup.find_manifest("**/manifest.json") do
      {:ok, manifest_path} ->
        {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
        {:ok, harness: harness}

      :not_found ->
        {:ok, harness: nil}
    end
  end

  # ==========================================================================
  # Test Helper Functions
  # ==========================================================================

  @doc """
  Runs a full decrypt test for a single test vector.

  Returns :ok on success, {:error, reason} on failure.
  """
  @spec run_full_decrypt_test(TestVectorHarness.t(), String.t()) :: :ok | {:error, term()}
  def run_full_decrypt_test(harness, test_id) do
    with {:ok, test} <- TestVectorHarness.get_test(harness, test_id),
         {:ok, ciphertext} <- TestVectorHarness.load_ciphertext(harness, test_id),
         {:ok, message, _rest} <- TestVectorHarness.parse_ciphertext(ciphertext),
         {:ok, keyring} <-
           build_keyring_from_master_keys(
             harness,
             test.master_keys,
             message.header.encrypted_data_keys
           ),
         {:ok, expected} <- TestVectorHarness.load_expected_plaintext(harness, test_id) do
      # Execute full decrypt with appropriate commitment policy
      # Use :require_encrypt_allow_decrypt to handle legacy non-committed vectors
      case Client.decrypt_with_keyring(keyring, ciphertext,
             commitment_policy: :require_encrypt_allow_decrypt
           ) do
        {:ok, %{plaintext: ^expected}} ->
          :ok

        {:ok, %{plaintext: actual}} ->
          {:error,
           {:plaintext_mismatch, expected: byte_size(expected), actual: byte_size(actual)}}

        {:error, reason} ->
          {:error, {:decrypt_failed, reason}}
      end
    end
  end

  @doc """
  Builds a keyring (or multi-keyring) from test vector master keys and EDKs.

  Extracts key names from EDK provider_info to ensure exact matching.
  """
  @spec build_keyring_from_master_keys(TestVectorHarness.t(), list(), list()) ::
          {:ok, term()} | {:error, term()}
  def build_keyring_from_master_keys(harness, [single_key], edks) do
    build_single_keyring(harness, single_key, edks)
  end

  def build_keyring_from_master_keys(harness, master_keys, edks) when length(master_keys) > 1 do
    keyrings =
      master_keys
      |> Enum.map(fn mk -> build_single_keyring(harness, mk, edks) end)
      |> Enum.filter(fn
        {:ok, _keyring} -> true
        _error -> false
      end)
      |> Enum.map(fn {:ok, kr} -> kr end)

    if keyrings == [] do
      {:error, :no_usable_keyrings}
    else
      Multi.new(children: keyrings)
    end
  end

  defp build_single_keyring(
         harness,
         %{"type" => "raw", "encryption-algorithm" => "aes"} = mk,
         edks
       ) do
    key_id = mk["key"]

    with {:ok, key_data} <- TestVectorHarness.get_key(harness, key_id),
         {:ok, key_bytes} <- TestVectorHarness.decode_key_material(key_data),
         {:ok, key_name} <- extract_aes_key_name(edks, mk["provider-id"]) do
      provider_id = mk["provider-id"]

      wrapping_algorithm =
        case key_data["bits"] do
          128 -> :aes_128_gcm
          192 -> :aes_192_gcm
          256 -> :aes_256_gcm
        end

      RawAes.new(provider_id, key_name, key_bytes, wrapping_algorithm)
    end
  end

  defp build_single_keyring(
         harness,
         %{"type" => "raw", "encryption-algorithm" => "rsa"} = mk,
         edks
       ) do
    key_id = mk["key"]

    with {:ok, key_data} <- TestVectorHarness.get_key(harness, key_id),
         true <- key_data["decrypt"] == true,
         {:ok, pem} <- TestVectorHarness.decode_key_material(key_data),
         {:ok, private_key} <- RawRsa.load_private_key_pem(pem),
         {:ok, key_name} <- extract_rsa_key_name(edks, mk["provider-id"]) do
      provider_id = mk["provider-id"]
      padding = parse_rsa_padding(mk)

      RawRsa.new(provider_id, key_name, padding, private_key: private_key)
    else
      false -> {:error, :key_cannot_decrypt}
      error -> error
    end
  end

  defp build_single_keyring(_harness, %{"type" => "aws-kms"}, _edks) do
    {:error, :aws_kms_not_supported}
  end

  defp build_single_keyring(_harness, mk, _edks) do
    {:error, {:unsupported_master_key, mk}}
  end

  # Extract key name from AES EDK provider_info
  # Format: key_name + tag_len(4) + iv_len(4) + iv(12)
  defp extract_aes_key_name(edks, provider_id) do
    case Enum.find(edks, fn edk -> edk.key_provider_id == provider_id end) do
      nil ->
        {:error, :no_matching_edk}

      edk ->
        # Key name length = total - 4 - 4 - 12
        key_name_len = byte_size(edk.key_provider_info) - 20
        <<key_name::binary-size(key_name_len), _rest::binary>> = edk.key_provider_info
        {:ok, key_name}
    end
  end

  # Extract key name from RSA EDK provider_info
  # For RSA, provider_info is just the key name
  defp extract_rsa_key_name(edks, provider_id) do
    case Enum.find(edks, fn edk -> edk.key_provider_id == provider_id end) do
      nil -> {:error, :no_matching_edk}
      edk -> {:ok, edk.key_provider_info}
    end
  end

  defp parse_rsa_padding(%{"padding-algorithm" => "pkcs1"}), do: :pkcs1_v1_5

  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha1"}),
    do: {:oaep, :sha1}

  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha256"}),
    do: {:oaep, :sha256}

  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha384"}),
    do: {:oaep, :sha384}

  defp parse_rsa_padding(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => "sha512"}),
    do: {:oaep, :sha512}

  # ==========================================================================
  # Smoke Tests (Quick Validation)
  # ==========================================================================

  describe "smoke tests" do
    @tag :smoke
    test "decrypts AES-256 vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "83928d8e-9f97-4861-8f70-ab1eaa6930ea")
    end

    @tag :smoke
    test "decrypts RSA PKCS1 vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "d20b31a6-200d-4fdb-819d-7ded46c99d10")
    end

    @tag :smoke
    test "decrypts multi-keyring vector", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :ok == run_full_decrypt_test(harness, "8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e")
    end
  end

  defp skip_if_no_harness(nil), do: :ok
  defp skip_if_no_harness(_harness), do: :ok

  # ==========================================================================
  # Raw AES Full Test Suite
  # ==========================================================================

  describe "raw AES success tests" do
    @tag :full_test_vectors
    @tag :raw_aes
    @tag timeout: 600_000
    # 10 minutes
    test "all raw AES success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to raw AES success tests
      raw_aes_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.by_encryption_algorithm("aes")
        |> TestVectorHarness.single_key_tests()

      total = length(raw_aes_tests)
      IO.puts("\nRunning #{total} Raw AES success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        raw_aes_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 100) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Raw AES: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")

        failed
        |> Enum.take(10)
        |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} Raw AES tests failed"
    end
  end

  # ==========================================================================
  # Raw RSA Full Test Suite
  # ==========================================================================

  describe "raw RSA success tests" do
    @tag :full_test_vectors
    @tag :raw_rsa
    @tag timeout: 900_000
    # 15 minutes (RSA is slower)
    test "all raw RSA success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to raw RSA success tests with decrypt capability
      raw_rsa_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.by_encryption_algorithm("rsa")
        |> TestVectorHarness.single_key_tests()
        |> filter_decryptable_rsa(harness)

      total = length(raw_rsa_tests)
      IO.puts("\nRunning #{total} Raw RSA success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        raw_rsa_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 200) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Raw RSA: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")

        failed
        |> Enum.take(10)
        |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} Raw RSA tests failed"
    end
  end

  # ==========================================================================
  # Multi-Keyring Full Test Suite
  # ==========================================================================

  describe "multi-keyring success tests" do
    @tag :full_test_vectors
    @tag :multi_keyring
    @tag timeout: 300_000
    # 5 minutes
    test "all multi-keyring success vectors", %{harness: harness} do
      skip_if_no_harness(harness)

      # Filter to multi-keyring success tests (raw keys only)
      multi_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()
        |> TestVectorHarness.multi_key_tests()

      total = length(multi_tests)
      IO.puts("\nRunning #{total} multi-keyring success tests...")

      # Run all tests and collect failures
      {passed, failed} =
        multi_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, _test}, idx}, {pass_count, failures} ->
          if rem(idx, 50) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_full_decrypt_test(harness, test_id) do
            :ok -> {pass_count + 1, failures}
            {:error, reason} -> {pass_count, [{test_id, reason} | failures]}
          end
        end)

      IO.puts("Multi-keyring: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")

        failed
        |> Enum.take(10)
        |> Enum.each(fn {id, reason} ->
          IO.puts("  #{id}: #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} multi-keyring tests failed"
    end
  end

  # ==========================================================================
  # Coverage Report
  # ==========================================================================

  describe "coverage report" do
    @tag :full_test_vectors
    @tag :coverage_report
    test "algorithm suite coverage", %{harness: harness} do
      skip_if_no_harness(harness)

      # Get all raw key success tests
      raw_tests =
        harness
        |> TestVectorHarness.success_tests()
        |> TestVectorHarness.raw_key_tests()

      # Sample tests to determine algorithm suite coverage
      suite_counts =
        raw_tests
        |> Enum.reduce(%{}, fn {test_id, _test}, acc ->
          case TestVectorHarness.load_ciphertext(harness, test_id) do
            {:ok, ciphertext} ->
              case TestVectorHarness.parse_ciphertext(ciphertext) do
                {:ok, message, _rest} ->
                  suite_id = message.header.algorithm_suite.id
                  Map.update(acc, suite_id, 1, &(&1 + 1))

                _error ->
                  acc
              end

            _error ->
              acc
          end
        end)

      IO.puts("\n" <> String.duplicate("=", 60))
      IO.puts("Algorithm Suite Coverage Report")
      IO.puts(String.duplicate("=", 60))

      suite_counts
      |> Enum.sort_by(fn {_id, count} -> -count end)
      |> Enum.each(fn {suite_id, count} ->
        hex_id = "0x" <> String.pad_leading(Integer.to_string(suite_id, 16), 4, "0")
        IO.puts("  #{hex_id}: #{count} tests")
      end)

      IO.puts(String.duplicate("=", 60))
      IO.puts("Total: #{length(raw_tests)} raw key success tests")
      IO.puts(String.duplicate("=", 60))

      # Just verify we have coverage data
      assert map_size(suite_counts) > 0
    end
  end

  # ==========================================================================
  # Helper Functions
  # ==========================================================================

  # Filter RSA tests to only those where we have a private key (can decrypt)
  defp filter_decryptable_rsa(tests, harness) do
    Enum.filter(tests, fn {_test_id, test} ->
      Enum.all?(test.master_keys, fn mk ->
        key_id = mk["key"]

        case TestVectorHarness.get_key(harness, key_id) do
          {:ok, %{"decrypt" => true}} -> true
          _error -> false
        end
      end)
    end)
  end
end
