defmodule AwsEncryptionSdk.Cmm.DefaultTestVectorsTest do
  # credo:disable-for-this-file Credo.Check.Design.DuplicatedCode

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Keyring.{RawAes, RawRsa}
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

  describe "get_decryption_materials with test vectors" do
    @tag :test_vectors
    test "decrypts AES-256 committed suite", %{harness: harness} do
      skip_if_no_harness(harness)

      test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"
      {:ok, test} = TestVectorHarness.get_test(harness, test_id)
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _remaining_bytes} = Message.deserialize(ciphertext)

      # Create keyring from test vector key
      [master_key | _rest_keys] = test.master_keys
      keyring = create_keyring_from_test(harness, master_key, message.header.encrypted_data_keys)

      # Create CMM and get decryption materials
      cmm = Default.new(keyring)

      request = %{
        algorithm_suite: message.header.algorithm_suite,
        commitment_policy: :require_encrypt_allow_decrypt,
        encrypted_data_keys: message.header.encrypted_data_keys,
        encryption_context: message.header.encryption_context
      }

      {:ok, materials} = Default.get_decryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil

      assert byte_size(materials.plaintext_data_key) ==
               message.header.algorithm_suite.kdf_input_length
    end

    @tag :test_vectors
    test "decrypts AES-192 committed suite", %{harness: harness} do
      skip_if_no_harness(harness)

      test_id = "a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1"
      {:ok, test} = TestVectorHarness.get_test(harness, test_id)
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _remaining_bytes} = Message.deserialize(ciphertext)

      # Create keyring from test vector key
      [master_key | _rest_keys] = test.master_keys
      keyring = create_keyring_from_test(harness, master_key, message.header.encrypted_data_keys)

      # Create CMM and get decryption materials
      cmm = Default.new(keyring)

      request = %{
        algorithm_suite: message.header.algorithm_suite,
        commitment_policy: :require_encrypt_allow_decrypt,
        encrypted_data_keys: message.header.encrypted_data_keys,
        encryption_context: message.header.encryption_context
      }

      {:ok, materials} = Default.get_decryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil

      assert byte_size(materials.plaintext_data_key) ==
               message.header.algorithm_suite.kdf_input_length
    end

    @tag :test_vectors
    test "decrypts RSA PKCS1 legacy suite", %{harness: harness} do
      skip_if_no_harness(harness)

      test_id = "d20b31a6-200d-4fdb-819d-7ded46c99d10"
      {:ok, test} = TestVectorHarness.get_test(harness, test_id)
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _remaining_bytes} = Message.deserialize(ciphertext)

      # Create keyring from test vector key
      [master_key | _rest_keys] = test.master_keys
      keyring = create_keyring_from_test(harness, master_key, message.header.encrypted_data_keys)

      # Create CMM and get decryption materials
      cmm = Default.new(keyring)

      request = %{
        algorithm_suite: message.header.algorithm_suite,
        commitment_policy: :require_encrypt_allow_decrypt,
        encrypted_data_keys: message.header.encrypted_data_keys,
        encryption_context: message.header.encryption_context
      }

      {:ok, materials} = Default.get_decryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil

      assert byte_size(materials.plaintext_data_key) ==
               message.header.algorithm_suite.kdf_input_length
    end
  end

  defp skip_if_no_harness(nil), do: ExUnit.configure(exclude: [:test_vectors])
  defp skip_if_no_harness(_harness), do: :ok

  defp create_keyring_from_test(harness, master_key, edks) do
    key_id = master_key["key"]
    {:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
    provider_id = master_key["provider-id"]

    case key_data["algorithm"] do
      "aes" ->
        {:ok, key_bytes} = TestVectorHarness.decode_key_material(key_data)

        # Extract key name from EDK provider_info
        {:ok, key_name} = extract_aes_key_name(edks, provider_id)

        wrapping_algorithm =
          case byte_size(key_bytes) do
            16 -> :aes_128_gcm
            24 -> :aes_192_gcm
            32 -> :aes_256_gcm
          end

        {:ok, keyring} = RawAes.new(provider_id, key_name, key_bytes, wrapping_algorithm)
        keyring

      "rsa" ->
        {:ok, pem} = TestVectorHarness.decode_key_material(key_data)
        {:ok, private_key} = RawRsa.load_private_key_pem(pem)

        # Extract key name from EDK provider_info
        {:ok, key_name} = extract_rsa_key_name(edks, provider_id)

        padding = parse_rsa_padding(master_key["padding-algorithm"])

        {:ok, keyring} = RawRsa.new(provider_id, key_name, padding, private_key: private_key)
        keyring
    end
  end

  # Extract key name from AES EDK provider_info
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

  # Extract key name from RSA EDK provider_info
  defp extract_rsa_key_name(edks, provider_id) do
    case Enum.find(edks, fn edk -> edk.key_provider_id == provider_id end) do
      nil -> {:error, :no_matching_edk}
      edk -> {:ok, edk.key_provider_info}
    end
  end

  defp parse_rsa_padding("pkcs1"), do: :pkcs1_v1_5
  defp parse_rsa_padding("oaep-mgf1-sha256"), do: {:oaep, :sha256}
  defp parse_rsa_padding("oaep-mgf1-sha1"), do: {:oaep, :sha1}
  defp parse_rsa_padding("oaep-mgf1-sha384"), do: {:oaep, :sha384}
  defp parse_rsa_padding("oaep-mgf1-sha512"), do: {:oaep, :sha512}
end
