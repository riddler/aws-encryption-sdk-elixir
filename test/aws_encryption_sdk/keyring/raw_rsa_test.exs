defmodule AwsEncryptionSdk.Keyring.RawRsaTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Keyring.RawRsa
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  # Generate test RSA key pair for unit tests
  setup_all do
    # Generate 2048-bit RSA key pair for testing
    private_key = :public_key.generate_key({:rsa, 2048, 65_537})

    # Extract public key from private
    {:RSAPrivateKey, _version, modulus, public_exp, _private_exp, _prime1, _prime2, _exp1, _exp2,
     _coef, _other} = private_key

    public_key = {:RSAPublicKey, modulus, public_exp}

    {:ok, private_key: private_key, public_key: public_key}
  end

  describe "new/4" do
    test "creates keyring with public key only", %{public_key: pub} do
      assert {:ok, keyring} = RawRsa.new("my-ns", "my-key", {:oaep, :sha256}, public_key: pub)
      assert keyring.key_namespace == "my-ns"
      assert keyring.key_name == "my-key"
      assert keyring.padding_scheme == {:oaep, :sha256}
      assert keyring.public_key == pub
      assert keyring.private_key == nil
    end

    test "creates keyring with private key only", %{private_key: priv} do
      assert {:ok, keyring} = RawRsa.new("ns", "key", :pkcs1_v1_5, private_key: priv)
      assert keyring.private_key == priv
      assert keyring.public_key == nil
    end

    test "creates keyring with both keys", %{public_key: pub, private_key: priv} do
      assert {:ok, keyring} =
               RawRsa.new("ns", "key", {:oaep, :sha1}, public_key: pub, private_key: priv)

      assert keyring.public_key == pub
      assert keyring.private_key == priv
    end

    test "supports all padding schemes", %{public_key: pub} do
      for scheme <- [
            :pkcs1_v1_5,
            {:oaep, :sha1},
            {:oaep, :sha256},
            {:oaep, :sha384},
            {:oaep, :sha512}
          ] do
        assert {:ok, _keyring} = RawRsa.new("ns", "key", scheme, public_key: pub),
               "Failed to create keyring with #{inspect(scheme)}"
      end
    end

    test "rejects reserved provider ID", %{public_key: pub} do
      assert {:error, :reserved_provider_id} =
               RawRsa.new("aws-kms", "key", {:oaep, :sha256}, public_key: pub)

      assert {:error, :reserved_provider_id} =
               RawRsa.new("aws-kms-mrk", "key", {:oaep, :sha256}, public_key: pub)
    end

    test "rejects invalid padding scheme", %{public_key: pub} do
      assert {:error, :invalid_padding_scheme} =
               RawRsa.new("ns", "key", :invalid, public_key: pub)

      assert {:error, :invalid_padding_scheme} =
               RawRsa.new("ns", "key", {:oaep, :md5}, public_key: pub)
    end

    test "rejects when no keys provided" do
      assert {:error, :no_keys_provided} = RawRsa.new("ns", "key", {:oaep, :sha256})
      assert {:error, :no_keys_provided} = RawRsa.new("ns", "key", {:oaep, :sha256}, [])
    end
  end

  describe "wrap_key/2" do
    setup %{public_key: pub, private_key: priv} do
      {:ok, keyring} =
        RawRsa.new("test-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "generates data key when not present", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      assert materials.plaintext_data_key == nil

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert is_binary(result.plaintext_data_key)
      assert byte_size(result.plaintext_data_key) == 32
    end

    test "wraps existing data key", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      materials = EncryptionMaterials.set_plaintext_data_key(materials, existing_key)

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert result.plaintext_data_key == existing_key
    end

    test "adds EDK to materials", %{keyring: keyring, suite: suite} do
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:ok, result} = RawRsa.wrap_key(keyring, materials)
      assert length(result.encrypted_data_keys) == 1

      [edk] = result.encrypted_data_keys
      assert edk.key_provider_id == "test-ns"
      assert edk.key_provider_info == "test-key"
      assert is_binary(edk.ciphertext)
    end

    test "fails when no public key configured", %{private_key: priv, suite: suite} do
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, private_key: priv)
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :no_public_key} = RawRsa.wrap_key(keyring, materials)
    end

    test "handles encryption failure with invalid key" do
      # Create an invalid/corrupted public key structure that will cause encryption to fail
      invalid_public_key = {:RSAPublicKey, 12_345, 65_537}
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: invalid_public_key)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, :encryption_failed} = RawRsa.wrap_key(keyring, materials)
    end
  end

  describe "unwrap_key/3" do
    setup %{public_key: pub, private_key: priv} do
      {:ok, keyring} =
        RawRsa.new("test-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, keyring: keyring, suite: suite}
    end

    test "decrypts EDK created by same keyring", %{keyring: keyring, suite: suite} do
      ec = %{"context" => "test"}

      # Encrypt
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      # Decrypt
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      {:ok, dec_result} =
        RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "fails if plaintext data key already set", %{keyring: keyring, suite: suite} do
      existing_key = :crypto.strong_rand_bytes(32)
      materials = DecryptionMaterials.new(suite, %{}, existing_key)

      assert {:error, :plaintext_data_key_already_set} = RawRsa.unwrap_key(keyring, materials, [])
    end

    test "skips EDKs with wrong provider ID", %{
      keyring: keyring,
      suite: suite,
      public_key: pub,
      private_key: priv
    } do
      ec = %{}

      # Create EDK with different provider
      {:ok, other_keyring} =
        RawRsa.new("other-ns", "test-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:error, :unable_to_decrypt_data_key} =
               RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "skips EDKs with wrong key name", %{
      keyring: keyring,
      suite: suite,
      public_key: pub,
      private_key: priv
    } do
      ec = %{}

      # Create EDK with different key name
      {:ok, other_keyring} =
        RawRsa.new("test-ns", "other-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, enc_result} = RawRsa.wrap_key(other_keyring, enc_materials)

      # Try to decrypt with original keyring
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:error, :unable_to_decrypt_data_key} =
               RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)
    end

    test "fails when no private key configured", %{public_key: pub, suite: suite} do
      {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, :no_private_key} = RawRsa.unwrap_key(keyring, materials, [])
    end

    test "returns error when no EDKs provided", %{keyring: keyring, suite: suite} do
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})
      assert {:error, :unable_to_decrypt_data_key} = RawRsa.unwrap_key(keyring, materials, [])
    end

    test "handles decryption failure with corrupted ciphertext", %{keyring: keyring, suite: suite} do
      ec = %{}

      # Create an EDK with corrupted ciphertext that will fail to decrypt
      alias AwsEncryptionSdk.Materials.EncryptedDataKey
      corrupted_edk = EncryptedDataKey.new("test-ns", "test-key", <<0, 1, 2, 3, 4, 5>>)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)

      assert {:error, :unable_to_decrypt_data_key} =
               RawRsa.unwrap_key(keyring, dec_materials, [corrupted_edk])
    end

    test "handles decryption failure with invalid private key" do
      # Create an invalid/corrupted private key that will cause decryption to fail
      invalid_private_key = {:RSAPrivateKey, 0, 12_345, 65_537, 1, 1, 1, 1, 1, 1, :asn1_NOVALUE}

      {:ok, keyring} =
        RawRsa.new("test-ns", "test-key", {:oaep, :sha256}, private_key: invalid_private_key)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      alias AwsEncryptionSdk.Materials.EncryptedDataKey
      edk = EncryptedDataKey.new("test-ns", "test-key", :crypto.strong_rand_bytes(256))

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, :unable_to_decrypt_data_key} =
               RawRsa.unwrap_key(keyring, dec_materials, [edk])
    end
  end

  describe "round-trip all padding schemes" do
    setup %{public_key: pub, private_key: priv} do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, public_key: pub, private_key: priv, suite: suite}
    end

    test "round-trips with PKCS1 v1.5", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, :pkcs1_v1_5, suite)
    end

    test "round-trips with OAEP-SHA1", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha1}, suite)
    end

    test "round-trips with OAEP-SHA256", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha256}, suite)
    end

    test "round-trips with OAEP-SHA384", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha384}, suite)
    end

    test "round-trips with OAEP-SHA512", %{public_key: pub, private_key: priv, suite: suite} do
      assert_round_trip(pub, priv, {:oaep, :sha512}, suite)
    end

    defp assert_round_trip(pub, priv, scheme, suite) do
      {:ok, keyring} = RawRsa.new("ns", "key", scheme, public_key: pub, private_key: priv)

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key,
             "Round-trip failed for #{inspect(scheme)}"
    end
  end

  describe "edge cases" do
    test "handles unicode key names", %{public_key: pub, private_key: priv} do
      {:ok, keyring} =
        RawRsa.new("namespace-日本語", "キー名-🔑", {:oaep, :sha256}, public_key: pub, private_key: priv)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end

    test "handles empty encryption context", %{public_key: pub, private_key: priv} do
      {:ok, keyring} =
        RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      enc_materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      {:ok, enc_result} = RawRsa.wrap_key(keyring, enc_materials)

      dec_materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      {:ok, dec_result} =
        RawRsa.unwrap_key(keyring, dec_materials, enc_result.encrypted_data_keys)

      assert dec_result.plaintext_data_key == enc_result.plaintext_data_key
    end
  end

  describe "PEM loading" do
    setup do
      # Generate keys for PEM export
      private_key = :public_key.generate_key({:rsa, 2048, 65_537})

      {:RSAPrivateKey, _version, modulus, public_exp, _private_exp, _prime1, _prime2, _exp1,
       _exp2, _coef, _other} = private_key

      public_key = {:RSAPublicKey, modulus, public_exp}

      {:ok, private_key: private_key, public_key: public_key}
    end

    test "load_public_key_pem loads SubjectPublicKeyInfo format", %{public_key: pub} do
      # Use pem_entry_encode to properly encode the public key
      pem_entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, pub)
      pem = :public_key.pem_encode([pem_entry])

      assert {:ok, loaded_key} = RawRsa.load_public_key_pem(pem)
      # SubjectPublicKeyInfo decodes to a tuple containing the algorithm and key
      assert is_tuple(loaded_key)
      assert elem(loaded_key, 0) == :SubjectPublicKeyInfo
    end

    test "load_public_key_pem loads RSAPublicKey format", %{public_key: pub} do
      # Use pem_entry_encode for RSAPublicKey format
      pem_entry = :public_key.pem_entry_encode(:RSAPublicKey, pub)
      pem = :public_key.pem_encode([pem_entry])

      assert {:ok, loaded_key} = RawRsa.load_public_key_pem(pem)
      assert loaded_key == pub
    end

    test "load_private_key_pem loads PrivateKeyInfo format", %{private_key: priv} do
      # Use pem_entry_encode for PrivateKeyInfo (PKCS#8)
      pem_entry = :public_key.pem_entry_encode(:PrivateKeyInfo, priv)
      pem = :public_key.pem_encode([pem_entry])

      assert {:ok, loaded_key} = RawRsa.load_private_key_pem(pem)
      # PrivateKeyInfo wraps the key, so we need to extract it
      assert is_tuple(loaded_key)
    end

    test "load_private_key_pem loads RSAPrivateKey format", %{private_key: priv} do
      # Use pem_entry_encode for RSAPrivateKey format
      pem_entry = :public_key.pem_entry_encode(:RSAPrivateKey, priv)
      pem = :public_key.pem_encode([pem_entry])

      assert {:ok, loaded_key} = RawRsa.load_private_key_pem(pem)
      assert loaded_key == priv
    end

    test "load_public_key_pem handles invalid PEM" do
      assert {:error, :invalid_pem_format} = RawRsa.load_public_key_pem("")
      assert {:error, :invalid_pem_format} = RawRsa.load_public_key_pem("not a pem")
    end

    test "load_public_key_pem handles unsupported key types" do
      # Create a PEM with an unsupported entry type (like ECPrivateKey)
      pem = """
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIIGlJW+9vLRPD4uz/T8JT8rKj3ac0z1FzEDhLTE0f0fPoAoGCCqGSM49
      AwEHoUQDQgAEm0O3tKlLqVH5p4X9V3X+VIJ5e3Qn1j6W5n3Gp5tUq+9K1N9F0D1t
      T0C3q1P1z9J1N0F1D1t1T0C3q1P1z9J1Nw==
      -----END EC PRIVATE KEY-----
      """

      assert {:error, :unsupported_key_type} = RawRsa.load_public_key_pem(pem)
    end

    test "load_private_key_pem handles invalid PEM" do
      assert {:error, :invalid_pem_format} = RawRsa.load_private_key_pem("")
      assert {:error, :invalid_pem_format} = RawRsa.load_private_key_pem("not a pem")
    end

    test "load_private_key_pem handles unsupported key types" do
      # Create a PEM with an unsupported entry type
      pem = """
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIIGlJW+9vLRPD4uz/T8JT8rKj3ac0z1FzEDhLTE0f0fPoAoGCCqGSM49
      AwEHoUQDQgAEm0O3tKlLqVH5p4X9V3X+VIJ5e3Qn1j6W5n3Gp5tUq+9K1N9F0D1t
      T0C3q1P1z9J1N0F1D1t1T0C3q1P1z9J1Nw==
      -----END EC PRIVATE KEY-----
      """

      assert {:error, :unsupported_key_type} = RawRsa.load_private_key_pem(pem)
    end

    test "load_public_key_pem handles malformed PEM that causes decode error" do
      # A PEM-like structure that will cause :public_key.pem_decode to raise
      malformed = """
      -----BEGIN PUBLIC KEY-----
      !!!INVALID BASE64 CONTENT!!!
      -----END PUBLIC KEY-----
      """

      assert {:error, :pem_decode_failed} = RawRsa.load_public_key_pem(malformed)
    end

    test "load_private_key_pem handles malformed PEM that causes decode error" do
      # A PEM-like structure that will cause :public_key.pem_decode to raise
      malformed = """
      -----BEGIN PRIVATE KEY-----
      !!!INVALID BASE64 CONTENT!!!
      -----END PRIVATE KEY-----
      """

      assert {:error, :pem_decode_failed} = RawRsa.load_private_key_pem(malformed)
    end
  end

  describe "behaviour callbacks" do
    test "on_encrypt returns helpful error" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})

      assert {:error, {:must_use_wrap_key, message}} = RawRsa.on_encrypt(materials)
      assert message =~ "wrap_key"
    end

    test "on_decrypt returns helpful error" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = DecryptionMaterials.new_for_decrypt(suite, %{})

      assert {:error, {:must_use_unwrap_key, message}} = RawRsa.on_decrypt(materials, [])
      assert message =~ "unwrap_key"
    end
  end
end
