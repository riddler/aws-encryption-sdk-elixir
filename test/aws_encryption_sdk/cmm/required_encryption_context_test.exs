defmodule AwsEncryptionSdk.Cmm.RequiredEncryptionContextTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.{Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Keyring.RawAes

  describe "new/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      default_cmm = Default.new(keyring)
      %{default_cmm: default_cmm}
    end

    test "creates CMM with required keys and underlying CMM", %{default_cmm: default_cmm} do
      cmm = RequiredEncryptionContext.new(["tenant-id", "purpose"], default_cmm)

      assert cmm.required_encryption_context_keys == ["tenant-id", "purpose"]
      assert cmm.underlying_cmm == default_cmm
    end

    test "accepts empty required keys list", %{default_cmm: default_cmm} do
      cmm = RequiredEncryptionContext.new([], default_cmm)
      assert cmm.required_encryption_context_keys == []
    end
  end

  describe "new_with_keyring/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      %{keyring: keyring}
    end

    test "creates CMM wrapping keyring in Default CMM", %{keyring: keyring} do
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)

      assert cmm.required_encryption_context_keys == ["tenant-id"]
      assert %Default{} = cmm.underlying_cmm
      assert cmm.underlying_cmm.keyring == keyring
    end
  end

  describe "get_encryption_materials/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      %{cmm: cmm}
    end

    test "succeeds when all required keys present", %{cmm: cmm} do
      request = %{
        encryption_context: %{"tenant-id" => "acme", "other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
      assert "tenant-id" in materials.required_encryption_context_keys
    end

    test "fails when required key missing from context", %{cmm: cmm} do
      request = %{
        encryption_context: %{"other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_encryption_materials(cmm, request)
    end

    test "fails when multiple required keys missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)

      request = %{
        encryption_context: %{"other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, missing}} =
               RequiredEncryptionContext.get_encryption_materials(cmm, request)

      assert "tenant-id" in missing
      assert "purpose" in missing
    end

    test "merges with existing required keys in request", %{cmm: cmm} do
      request = %{
        encryption_context: %{"tenant-id" => "acme", "existing-required" => "value"},
        commitment_policy: :require_encrypt_require_decrypt,
        required_encryption_context_keys: ["existing-required"]
      }

      assert {:ok, materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
      assert "tenant-id" in materials.required_encryption_context_keys
      assert "existing-required" in materials.required_encryption_context_keys
    end

    test "succeeds with empty required keys (pass-through)" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring([], keyring)

      request = %{
        encryption_context: %{"any" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, _materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
    end
  end

  describe "get_decryption_materials/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      client = Client.new(cmm)

      # Create a valid ciphertext to decrypt
      {:ok, result} =
        Client.encrypt(client, "test plaintext",
          encryption_context: %{"tenant-id" => "acme", "other" => "value"}
        )

      %{cmm: cmm, keyring: keyring, ciphertext: result.ciphertext, header: result.header}
    end

    test "succeeds when required keys in reproduced context", %{cmm: cmm, header: header} do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: %{"tenant-id" => "acme"}
      }

      assert {:ok, _materials} = RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when required key missing from reproduced context", %{cmm: cmm, header: header} do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: %{"other" => "value"}
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when reproduced context is nil and required keys configured", %{
      cmm: cmm,
      header: header
    } do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: nil
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when reproduced context not provided and required keys configured", %{
      cmm: cmm,
      header: header
    } do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end
  end

  describe "nested CMMs" do
    test "validates both layers of required keys" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      # Inner CMM requires "inner-key"
      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)

      # Outer CMM requires "outer-key"
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      # Must have both keys
      request = %{
        encryption_context: %{"inner-key" => "value1", "outer-key" => "value2"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, materials} =
               RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)

      assert "inner-key" in materials.required_encryption_context_keys
      assert "outer-key" in materials.required_encryption_context_keys
    end

    test "fails if outer required key missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      request = %{
        encryption_context: %{"inner-key" => "value1"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, ["outer-key"]}} =
               RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)
    end

    test "fails if inner required key missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      request = %{
        encryption_context: %{"outer-key" => "value2"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      # Outer validation passes, but inner validation fails
      assert {:error, {:missing_required_encryption_context_keys, ["inner-key"]}} =
               RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)
    end
  end

  describe "Client integration" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      client = Client.new(cmm)
      %{client: client}
    end

    test "encrypt succeeds with required keys", %{client: client} do
      {:ok, result} =
        Client.encrypt(client, "secret data", encryption_context: %{"tenant-id" => "acme"})

      assert is_binary(result.ciphertext)
    end

    test "encrypt fails without required keys", %{client: client} do
      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.encrypt(client, "secret data", encryption_context: %{"other" => "value"})
    end

    test "decrypt succeeds with required keys in reproduced context", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data", encryption_context: %{"tenant-id" => "acme"})

      {:ok, decrypted} =
        Client.decrypt(client, encrypted.ciphertext, encryption_context: %{"tenant-id" => "acme"})

      assert decrypted.plaintext == "secret data"
    end

    test "decrypt fails without required keys in reproduced context", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data", encryption_context: %{"tenant-id" => "acme"})

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.decrypt(client, encrypted.ciphertext,
                 encryption_context: %{"other" => "value"}
               )
    end

    test "decrypt fails when no reproduced context provided", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data", encryption_context: %{"tenant-id" => "acme"})

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.decrypt(client, encrypted.ciphertext)
    end

    test "round-trip with multiple required keys" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)
      client = Client.new(cmm)

      context = %{"tenant-id" => "acme", "purpose" => "backup", "extra" => "data"}

      {:ok, encrypted} = Client.encrypt(client, "multi-key test", encryption_context: context)

      {:ok, decrypted} =
        Client.decrypt(client, encrypted.ciphertext,
          encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
        )

      assert decrypted.plaintext == "multi-key test"
    end
  end
end
