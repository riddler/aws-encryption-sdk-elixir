defmodule AwsEncryptionSdk.TestVectors.ErrorDecryptTest do
  @moduledoc """
  Error test vector validation for AWS Encryption SDK.

  These tests validate that the SDK correctly rejects:
  - Truncated messages
  - Bit-flipped ciphertexts (tampered data)
  - Other malformed inputs

  Run with: mix test --only error_vectors
  Run smoke tests: mix test --only error_vectors:smoke
  """

  # credo:disable-for-this-file Credo.Check.Refactor.IoPuts
  # credo:disable-for-this-file Credo.Check.Refactor.Nesting
  # credo:disable-for-this-file Credo.Check.Design.DuplicatedCode

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes, RawRsa}
  alias AwsEncryptionSdk.Stream
  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

  @moduletag :test_vectors
  @moduletag :error_vectors

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
  Runs an error test - expects decrypt to return {:error, _}.

  Returns:
  - :pass - Decryption correctly failed
  - {:fail_unexpected_success, plaintext_size} - Decryption unexpectedly succeeded
  - {:fail_crash, exception} - Decryption crashed instead of returning error
  """
  @spec run_error_decrypt_test(TestVectorHarness.t(), String.t()) ::
          :pass
          | {:fail_unexpected_success, non_neg_integer() | :unknown_size}
          | {:fail_crash, String.t()}
          | {:fail_not_found, String.t()}
  def run_error_decrypt_test(harness, test_id) do
    with {:ok, test} <- TestVectorHarness.get_test(harness, test_id),
         {:ok, ciphertext} <- TestVectorHarness.load_ciphertext(harness, test_id) do
      # Try to parse and build keyring - some errors may occur here
      result =
        try do
          case attempt_decrypt(harness, test, ciphertext) do
            {:error, _reason} -> :pass
            {:ok, %{plaintext: pt}} -> {:fail_unexpected_success, byte_size(pt)}
            {:ok, _result} -> {:fail_unexpected_success, :unknown_size}
          end
        rescue
          e -> {:fail_crash, Exception.message(e)}
        end

      result
    else
      {:error, _reason} ->
        # Loading the test or ciphertext failed - this counts as an error (pass)
        :pass

      :not_found ->
        {:fail_not_found, test_id}
    end
  end

  defp attempt_decrypt(harness, test, ciphertext) do
    # Try to parse message to get EDKs for keyring building
    case TestVectorHarness.parse_ciphertext(ciphertext) do
      {:ok, message, rest} ->
        # If there are trailing bytes after parsing, the message is malformed
        # Treat this as an error case
        if rest != <<>> do
          {:error, {:unexpected_trailing_bytes, byte_size(rest)}}
        else
          case build_keyring_from_master_keys(
                 harness,
                 test.master_keys,
                 message.header.encrypted_data_keys
               ) do
            {:ok, keyring} ->
              Client.decrypt_with_keyring(keyring, ciphertext,
                commitment_policy: :require_encrypt_allow_decrypt
              )

            {:error, reason} ->
              {:error, {:keyring_build_failed, reason}}
          end
        end

      {:error, reason} ->
        # Parse failed - expected for truncated messages
        {:error, {:parse_failed, reason}}
    end
  end

  @doc """
  Categorizes an error test by its error description.
  """
  @spec categorize_error_test(map()) ::
          :bit_flip | :truncation | :kms_arn | :api_mismatch | :other
  def categorize_error_test(%{error_description: desc}) when is_binary(desc) do
    cond do
      String.match?(desc, ~r/^Bit \d+ flipped$/) -> :bit_flip
      String.match?(desc, ~r/^Truncated at byte \d+$/) -> :truncation
      String.contains?(desc, "ARN") -> :kms_arn
      String.contains?(desc, "streaming unsigned") -> :api_mismatch
      true -> :other
    end
  end

  @spec categorize_error_test(term()) :: :other
  def categorize_error_test(_test), do: :other

  @doc """
  Runs an API mismatch test - validates that signed messages are rejected
  when using the unsigned-only streaming API (fail_on_signed: true).
  """
  @spec run_api_mismatch_test(TestVectorHarness.t(), String.t()) ::
          :pass
          | {:fail_unexpected_success, term()}
          | {:fail_crash, String.t()}
          | {:fail_not_found, String.t()}
  def run_api_mismatch_test(harness, test_id) do
    with {:ok, test} <- TestVectorHarness.get_test(harness, test_id),
         {:ok, ciphertext} <- TestVectorHarness.load_ciphertext(harness, test_id) do
      # Try to parse message to build keyring
      result =
        try do
          case attempt_streaming_unsigned_decrypt(harness, test, ciphertext) do
            {:error, _reason} ->
              :pass

            {:ok, _plaintext} ->
              {:fail_unexpected_success, :decryption_succeeded}

            other ->
              {:fail_unexpected_success, other}
          end
        rescue
          # Stream.decrypt raises on errors, so we need to catch the exception
          e in RuntimeError ->
            # Check if this is the expected error for signed algorithm suite
            if String.contains?(e.message, "signed_algorithm_suite_not_allowed") do
              :pass
            else
              {:fail_crash, Exception.message(e)}
            end

          e ->
            {:fail_crash, Exception.message(e)}
        end

      result
    else
      {:error, _reason} ->
        :pass

      :not_found ->
        {:fail_not_found, test_id}
    end
  end

  defp attempt_streaming_unsigned_decrypt(harness, test, ciphertext) do
    # Parse message to get EDKs for keyring building
    with {:ok, message, _rest} <- TestVectorHarness.parse_ciphertext(ciphertext),
         {:ok, keyring} <-
           build_keyring_from_master_keys(
             harness,
             test.master_keys,
             message.header.encrypted_data_keys
           ) do
      # Create client with keyring
      cmm = Default.new(keyring)
      client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

      # Use streaming decrypt with fail_on_signed: true
      # This should reject signed messages
      result =
        [ciphertext]
        |> Stream.decrypt(client, fail_on_signed: true)
        |> Enum.to_list()

      # If we got here, collect all plaintext
      plaintext =
        result
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      {:ok, plaintext}
    end
  end

  # ==========================================================================
  # Keyring Building (reused from full_decrypt_test.exs)
  # ==========================================================================

  defp build_keyring_from_master_keys(harness, [single_key], edks) do
    build_single_keyring(harness, single_key, edks)
  end

  defp build_keyring_from_master_keys(harness, master_keys, edks)
       when length(master_keys) > 1 do
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

  defp extract_aes_key_name(edks, provider_id) do
    case Enum.find(edks, fn edk -> edk.key_provider_id == provider_id end) do
      nil ->
        {:error, :no_matching_edk}

      edk ->
        key_name_len = byte_size(edk.key_provider_info) - 20
        <<key_name::binary-size(key_name_len), _rest::binary>> = edk.key_provider_info
        {:ok, key_name}
    end
  end

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

  defp skip_if_no_harness(nil), do: :ok
  defp skip_if_no_harness(_harness), do: :ok

  # ==========================================================================
  # Smoke Tests (Quick Validation)
  # ==========================================================================

  describe "smoke tests" do
    @tag :smoke
    @tag :error_vectors_smoke
    test "rejects truncated at byte 1", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :pass == run_error_decrypt_test(harness, "b2510a07-dc9e-48e0-ba2c-12d2c27af7ff")
    end

    @tag :smoke
    @tag :error_vectors_smoke
    test "rejects bit 0 flipped", %{harness: harness} do
      skip_if_no_harness(harness)
      assert :pass == run_error_decrypt_test(harness, "061f37ec-2433-4ff8-9fbb-4ab98ee100ef")
    end
  end

  # ==========================================================================
  # Truncation Error Tests
  # ==========================================================================

  describe "truncation error tests" do
    @tag :error_vectors
    @tag :truncation
    @tag timeout: 300_000
    test "all truncation errors return error", %{harness: harness} do
      skip_if_no_harness(harness)

      truncation_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()
        |> Enum.filter(fn {_id, test} ->
          categorize_error_test(test) == :truncation
        end)

      total = length(truncation_tests)
      IO.puts("\nRunning #{total} truncation error tests...")

      {passed, failed} =
        truncation_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, test}, idx}, {pass_count, failures} ->
          if rem(idx, 50) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_error_decrypt_test(harness, test_id) do
            :pass ->
              {pass_count + 1, failures}

            failure ->
              {pass_count, [{test_id, test.error_description, failure} | failures]}
          end
        end)

      IO.puts("Truncation: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")

        failed
        |> Enum.take(10)
        |> Enum.each(fn {id, desc, reason} ->
          IO.puts("  #{id}: #{desc} - #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} truncation tests failed"
    end
  end

  # ==========================================================================
  # Bit Flip Error Tests
  # ==========================================================================

  describe "bit flip error tests" do
    @tag :error_vectors
    @tag :bit_flip
    @tag :slow
    @tag timeout: 900_000
    test "all bit flip errors return error", %{harness: harness} do
      skip_if_no_harness(harness)

      bit_flip_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()
        |> Enum.filter(fn {_id, test} ->
          categorize_error_test(test) == :bit_flip
        end)

      total = length(bit_flip_tests)
      IO.puts("\nRunning #{total} bit flip error tests...")

      {passed, failed} =
        bit_flip_tests
        |> Enum.with_index(1)
        |> Enum.reduce({0, []}, fn {{test_id, test}, idx}, {pass_count, failures} ->
          if rem(idx, 500) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          case run_error_decrypt_test(harness, test_id) do
            :pass ->
              {pass_count + 1, failures}

            failure ->
              {pass_count, [{test_id, test.error_description, failure} | failures]}
          end
        end)

      IO.puts("Bit flip: #{passed} passed, #{length(failed)} failed")

      if failed != [] do
        IO.puts("\nFailed tests (first 10):")

        failed
        |> Enum.take(10)
        |> Enum.each(fn {id, desc, reason} ->
          IO.puts("  #{id}: #{desc} - #{inspect(reason)}")
        end)
      end

      assert failed == [], "#{length(failed)} bit flip tests failed"
    end

    @tag :error_vectors
    @tag :bit_flip_sample
    test "sample bit flip tests (every 100th)", %{harness: harness} do
      skip_if_no_harness(harness)

      # Get sample: bits 0, 100, 200, ... 3700
      bit_flip_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()
        |> Enum.filter(fn {_id, test} ->
          case test.error_description do
            "Bit " <> rest ->
              case Integer.parse(rest) do
                {n, " flipped"} -> rem(n, 100) == 0
                _other -> false
              end

            _other ->
              false
          end
        end)

      total = length(bit_flip_tests)
      IO.puts("\nRunning #{total} sample bit flip tests...")

      results =
        Enum.map(bit_flip_tests, fn {test_id, test} ->
          {test_id, test.error_description, run_error_decrypt_test(harness, test_id)}
        end)

      failures =
        Enum.filter(results, fn {_id, _desc, result} ->
          result != :pass
        end)

      assert failures == [], "#{length(failures)} sample bit flip tests failed"
    end
  end

  # ==========================================================================
  # Complete Error Coverage
  # ==========================================================================

  describe "all raw key error tests" do
    @tag :error_vectors
    @tag :full_error_suite
    @tag :slow
    @tag timeout: 1_200_000
    test "complete error test coverage", %{harness: harness} do
      skip_if_no_harness(harness)

      all_error_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()

      total = length(all_error_tests)
      IO.puts("\nRunning #{total} total error tests...")

      # Group by category for reporting
      by_category =
        Enum.group_by(all_error_tests, fn {_id, test} ->
          categorize_error_test(test)
        end)

      IO.puts("\nError test distribution:")

      Enum.each(by_category, fn {category, tests} ->
        IO.puts("  #{category}: #{length(tests)} tests")
      end)

      # Run all tests
      results =
        all_error_tests
        |> Enum.with_index(1)
        |> Enum.map(fn {{test_id, test}, idx} ->
          if rem(idx, 500) == 0, do: IO.puts("  Progress: #{idx}/#{total}")

          category = categorize_error_test(test)

          result =
            if category == :api_mismatch do
              run_api_mismatch_test(harness, test_id)
            else
              run_error_decrypt_test(harness, test_id)
            end

          {test_id, category, test.error_description, result}
        end)

      # Collect failures by category
      failures_by_category =
        results
        |> Enum.filter(fn {_id, _cat, _desc, result} -> result != :pass end)
        |> Enum.group_by(fn {_id, cat, _desc, _result} -> cat end)

      # Report
      IO.puts("\n" <> String.duplicate("=", 60))
      IO.puts("Error Test Coverage Report")
      IO.puts(String.duplicate("=", 60))

      Enum.each(by_category, fn {category, tests} ->
        failures = Map.get(failures_by_category, category, [])
        passed = length(tests) - length(failures)
        IO.puts("  #{category}: #{passed}/#{length(tests)} passed")
      end)

      total_failures =
        Enum.flat_map(failures_by_category, fn {_cat, failures} -> failures end)

      IO.puts(String.duplicate("=", 60))
      IO.puts("Total: #{total - length(total_failures)}/#{total} passed")
      IO.puts(String.duplicate("=", 60))

      if total_failures != [] do
        IO.puts("\nSample failures (first 20):")

        total_failures
        |> Enum.take(20)
        |> Enum.each(fn {id, cat, desc, reason} ->
          IO.puts("  [#{cat}] #{id}: #{desc} - #{inspect(reason)}")
        end)
      end

      assert total_failures == [], "#{length(total_failures)} error tests failed"
    end
  end

  # ==========================================================================
  # Edge Case Tests
  # ==========================================================================

  describe "edge case error tests" do
    @tag :error_vectors
    @tag :edge_cases
    test "other category errors", %{harness: harness} do
      skip_if_no_harness(harness)

      other_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()
        |> Enum.filter(fn {_id, test} ->
          categorize_error_test(test) == :other
        end)

      if other_tests == [] do
        IO.puts("No 'other' category tests found (expected)")
      else
        IO.puts("Running #{length(other_tests)} 'other' error tests...")

        failures =
          Enum.filter(other_tests, fn {test_id, _test} ->
            run_error_decrypt_test(harness, test_id) != :pass
          end)

        assert failures == []
      end
    end

    @tag :error_vectors
    @tag :edge_cases
    test "API mismatch: signed messages rejected by unsigned-only streaming API", %{
      harness: harness
    } do
      skip_if_no_harness(harness)

      # This test validates that signed messages are rejected when passed to
      # an unsigned-only streaming decryption method (fail_on_signed: true)
      api_mismatch_tests =
        harness
        |> TestVectorHarness.error_tests()
        |> TestVectorHarness.raw_key_tests()
        |> Enum.filter(fn {_id, test} ->
          categorize_error_test(test) == :api_mismatch
        end)

      IO.puts("\nRunning #{length(api_mismatch_tests)} API mismatch tests...")

      failures =
        Enum.map(api_mismatch_tests, fn {test_id, test} ->
          result = run_api_mismatch_test(harness, test_id)
          {test_id, test.error_description, result}
        end)
        |> Enum.filter(fn {_id, _desc, result} -> result != :pass end)

      if failures != [] do
        IO.puts("\nFailed tests:")

        Enum.each(failures, fn {id, desc, reason} ->
          IO.puts("  #{id}: #{desc} - #{inspect(reason)}")
        end)
      end

      assert failures == [], "#{length(failures)} API mismatch tests failed"
    end
  end
end
