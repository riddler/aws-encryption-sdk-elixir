defmodule AwsEncryptionSdk.Keyring.MultiTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.{Multi, RawRsa}
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

  describe "Multi-RSA decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts 8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e (PKCS1 + OAEP-SHA256)", %{
      harness: harness
    } do
      run_multi_rsa_decrypt_test(harness, "8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e")
    end

    @tag timeout: 120_000
    test "decrypts 6b8d3386-9824-46db-8764-8d58d8086f77 (OAEP-SHA256 x2)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "6b8d3386-9824-46db-8764-8d58d8086f77")
    end
  end

  describe "Multi-RSA decrypt vectors - extended" do
    @tag timeout: 120_000
    test "decrypts afb2ba6d-e8b7-4c74-99ff-f7925485a868", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "afb2ba6d-e8b7-4c74-99ff-f7925485a868")
    end

    @tag timeout: 120_000
    test "decrypts bca8fe01-878d-4705-9ee4-8ea9faf6328b (OAEP-SHA1 + SHA256)", %{
      harness: harness
    } do
      run_multi_rsa_decrypt_test(harness, "bca8fe01-878d-4705-9ee4-8ea9faf6328b")
    end

    @tag timeout: 120_000
    test "decrypts 1aa68ab1-3752-48e8-af6b-cea6650df263 (OAEP-SHA384 + SHA256)", %{
      harness: harness
    } do
      run_multi_rsa_decrypt_test(harness, "1aa68ab1-3752-48e8-af6b-cea6650df263")
    end

    @tag timeout: 120_000
    test "decrypts aba06ffc-a839-4639-967c-a739d8626adc (OAEP-SHA512 + SHA256)", %{
      harness: harness
    } do
      run_multi_rsa_decrypt_test(harness, "aba06ffc-a839-4639-967c-a739d8626adc")
    end

    @tag timeout: 120_000
    test "decrypts e05108d7-cde8-42ae-8901-ee7d39af0eae (OAEP-SHA256 x2)", %{harness: harness} do
      run_multi_rsa_decrypt_test(harness, "e05108d7-cde8-42ae-8901-ee7d39af0eae")
    end
  end

  defp run_multi_rsa_decrypt_test(nil, _test_id), do: :ok

  defp run_multi_rsa_decrypt_test(harness, test_id) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _remainder} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Build keyrings for each master key
    keyrings =
      build_keyrings_from_master_keys(
        harness,
        test.master_keys,
        message.header.encrypted_data_keys
      )

    # Create multi-keyring with all keyrings as children (no generator)
    {:ok, multi} = Multi.new(children: keyrings)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key using multi-keyring
    {:ok, result} = Multi.unwrap_key(multi, materials, message.header.encrypted_data_keys)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end

  defp build_keyrings_from_master_keys(harness, master_keys, edks) do
    master_keys
    |> Enum.with_index()
    |> Enum.map(fn {mk, idx} ->
      build_keyring(harness, mk, Enum.at(edks, idx))
    end)
    |> Enum.filter(&(&1 != nil))
  end

  defp build_keyring(harness, %{"type" => "raw", "encryption-algorithm" => "rsa"} = mk, edk) do
    key_id = mk["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)

    # Only build keyring if we can decrypt (need private key)
    case key_data do
      %{"decrypt" => true} ->
        {:ok, pem_material} = TestVectorHarness.decode_key_material(key_data)
        {:ok, private_key} = RawRsa.load_private_key_pem(pem_material)

        padding_scheme = parse_padding_scheme(mk)
        provider_id = mk["provider-id"]
        # For RSA, provider_info in EDK is the key name
        key_name = if edk, do: edk.key_provider_info, else: mk["key"]

        {:ok, keyring} =
          RawRsa.new(provider_id, key_name, padding_scheme, private_key: private_key)

        keyring

      _other_key_data ->
        # Can't decrypt with this key (public-only or KMS)
        nil
    end
  end

  defp build_keyring(_harness, _master_key, _edk), do: nil

  defp parse_padding_scheme(%{"padding-algorithm" => "pkcs1"}), do: :pkcs1_v1_5

  defp parse_padding_scheme(%{"padding-algorithm" => "oaep-mgf1", "padding-hash" => hash}) do
    {:oaep, String.to_atom(hash)}
  end
end
