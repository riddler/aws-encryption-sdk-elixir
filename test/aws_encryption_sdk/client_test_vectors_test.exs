defmodule AwsEncryptionSdk.ClientTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}

  @moduletag :test_vectors

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

  describe "test vector compatibility" do
    test "can parse algorithm suites from test vectors", %{harness: harness} do
      # Pick a known test vector
      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"

      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

      # Parse algorithm suite from header
      <<version::8, suite_id::16-big, _rest::binary>> = ciphertext

      assert version in [1, 2]
      assert suite_id > 0
    end

    test "analyze test vector algorithm suites", %{harness: harness} do
      # Get all test IDs
      test_ids = Map.keys(harness.tests)

      # Parse each to categorize by algorithm suite
      suites_found =
        Enum.reduce(test_ids, %{committed: [], non_committed: []}, fn test_id, acc ->
          case TestVectorHarness.load_ciphertext(harness, test_id) do
            {:ok, ciphertext} when byte_size(ciphertext) >= 3 ->
              <<_version::8, suite_id::16-big, _rest::binary>> = ciphertext

              # Categorize: committed (0x0478, 0x0578) vs non-committed
              committed = suite_id in [0x0478, 0x0578]

              suite_hex = "0x" <> String.upcase(Integer.to_string(suite_id, 16))

              if committed do
                %{acc | committed: [{test_id, suite_hex} | acc.committed]}
              else
                %{acc | non_committed: [{test_id, suite_hex} | acc.non_committed]}
              end

            _other ->
              # Skip invalid or too-short ciphertext
              acc
          end
        end)

      # Verify we have test vectors for testing
      has_committed = suites_found.committed != []
      has_non_committed = suites_found.non_committed != []

      assert has_committed or has_non_committed
    end
  end
end
