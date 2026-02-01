defmodule AwsEncryptionSdk.Keyring.RawRsaTestVectorsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.RawRsa
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

  describe "RSA PKCS1 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector d20b31a6-200d-4fdb-819d-7ded46c99d10", %{harness: harness} do
      run_rsa_decrypt_test(harness, "d20b31a6-200d-4fdb-819d-7ded46c99d10", :pkcs1_v1_5)
    end
  end

  describe "RSA OAEP-SHA256 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 24088ba0-bf47-4d06-bb12-f6ba40956bd6", %{harness: harness} do
      run_rsa_decrypt_test(harness, "24088ba0-bf47-4d06-bb12-f6ba40956bd6", {:oaep, :sha256})
    end
  end

  describe "RSA OAEP-SHA1 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 7c640f28-9fa1-4ff9-9179-196149f8c346", %{harness: harness} do
      run_rsa_decrypt_test(harness, "7c640f28-9fa1-4ff9-9179-196149f8c346", {:oaep, :sha1})
    end
  end

  describe "RSA OAEP-SHA384 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector 0ad7c010-79ad-4710-876b-21c677c97b19", %{harness: harness} do
      run_rsa_decrypt_test(harness, "0ad7c010-79ad-4710-876b-21c677c97b19", {:oaep, :sha384})
    end
  end

  describe "RSA OAEP-SHA512 decrypt vectors" do
    @tag timeout: 120_000
    test "decrypts test vector a2adc73f-6885-4a1c-a2bb-3294d48766b4", %{harness: harness} do
      run_rsa_decrypt_test(harness, "a2adc73f-6885-4a1c-a2bb-3294d48766b4", {:oaep, :sha512})
    end
  end

  defp run_rsa_decrypt_test(nil, _test_id, _padding), do: :ok

  defp run_rsa_decrypt_test(harness, test_id, padding_scheme) do
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    assert test.result == :success, "Test vector should be a success case"

    # Load ciphertext and parse message
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _remainder} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Get key material for raw RSA keyring
    [master_key | _rest_master_keys] = test.master_keys
    assert master_key["type"] == "raw"

    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    {:ok, pem_material} = TestVectorHarness.decode_key_material(key_data)

    # Load private key from PEM
    {:ok, private_key} = RawRsa.load_private_key_pem(pem_material)

    # Extract EDKs from message header
    edks = message.header.encrypted_data_keys
    [edk | _rest_edks] = edks

    # For RSA, provider_info is just the key name (unlike AES which has structured format)
    provider_id = master_key["provider-id"]
    key_name = edk.key_provider_info

    # Create keyring
    {:ok, keyring} = RawRsa.new(provider_id, key_name, padding_scheme, private_key: private_key)

    # Create decryption materials
    suite = message.header.algorithm_suite
    ec = message.header.encryption_context
    materials = DecryptionMaterials.new_for_decrypt(suite, ec)

    # Unwrap key
    {:ok, result} = RawRsa.unwrap_key(keyring, materials, edks)

    assert is_binary(result.plaintext_data_key)
    assert byte_size(result.plaintext_data_key) == div(suite.data_key_length, 8)
  end
end
