defmodule AwsEncryptionSdk.Keyring.RawAesTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
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

  describe "AES-256 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 83928d8e-9f97-4861-8f70-ab1eaa6930ea", %{harness: harness} do
      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"
      run_decrypt_test(harness, test_id)
    end

    @tag timeout: 120_000
    test "decrypts test vector 917a3a40-3b92-48f7-9cbe-231c9bde6222", %{harness: harness} do
      test_id = "917a3a40-3b92-48f7-9cbe-231c9bde6222"
      run_decrypt_test(harness, test_id)
    end
  end

  describe "AES-128 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 4be2393c-2916-4668-ae7a-d26ddb8de593", %{harness: harness} do
      test_id = "4be2393c-2916-4668-ae7a-d26ddb8de593"
      run_decrypt_test(harness, test_id)
    end
  end

  describe "AES-192 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1", %{harness: harness} do
      test_id = "a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1"
      run_decrypt_test(harness, test_id)
    end
  end

  defp run_decrypt_test(nil, _test_id), do: :ok

  defp run_decrypt_test(harness, test_id) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _remainder} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Get key material for raw AES keyring
    [master_key | _rest_master_keys] = test.master_keys
    assert master_key["type"] == "raw"

    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    {:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)

    # Extract EDKs from message header
    edks = message.header.encrypted_data_keys
    [edk | _rest_edks] = edks

    # Extract key name from provider info
    # Format: key_name + tag_len(4) + iv_len(4) + iv(12)
    # So key_name length = total_length - 4 - 4 - 12
    key_name_len = byte_size(edk.key_provider_info) - 4 - 4 - 12
    <<key_name::binary-size(key_name_len), _rest::binary>> = edk.key_provider_info

    # Create keyring with info from test vector
    provider_id = master_key["provider-id"]
    wrapping_algorithm = cipher_for_key_bits(key_data["bits"])

    {:ok, keyring} = RawAes.new(provider_id, key_name, raw_key, wrapping_algorithm)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key
    {:ok, result} = RawAes.unwrap_key(keyring, materials, edks)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end

  defp cipher_for_key_bits(128), do: :aes_128_gcm
  defp cipher_for_key_bits(192), do: :aes_192_gcm
  defp cipher_for_key_bits(256), do: :aes_256_gcm
end
