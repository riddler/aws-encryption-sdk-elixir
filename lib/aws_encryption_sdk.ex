defmodule AwsEncryptionSdk do
  @moduledoc """
  AWS Encryption SDK for Elixir.

  This module provides client-side encryption following the official AWS Encryption
  SDK Specification, enabling interoperability with AWS Encryption SDK implementations
  in other languages (Python, Java, JavaScript, C, CLI).

  ## Quick Start with Client

  The recommended API uses the Client module for commitment policy enforcement:

  ```elixir
  # Create a keyring
  key = :crypto.strong_rand_bytes(32)
  {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("namespace", "key-name", key, :aes_256_gcm)

  # Create a CMM
  cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)

  # Create a client (defaults to strictest commitment policy)
  client = AwsEncryptionSdk.Client.new(cmm)

  # Encrypt
  {:ok, result} = AwsEncryptionSdk.encrypt(client, "secret data",
    encryption_context: %{"purpose" => "example"}
  )

  # Decrypt (when Client.decrypt is implemented)
  # {:ok, plaintext} = AwsEncryptionSdk.decrypt(client, result.ciphertext)
  ```

  ## Client-Based API

  - `encrypt/3` - Encrypts plaintext using client configuration
  - `encrypt_with_keyring/3` - Convenience function with keyring

  ## Materials-Based API (Advanced)

  For advanced use cases or testing, you can use the materials-based API:

  - `encrypt_with_materials/3` - Direct encryption with pre-assembled materials
  - `decrypt_with_materials/2` - Direct decryption with pre-assembled materials

  ## Security

  The SDK follows the AWS Encryption SDK specification security requirements:

  - Never releases unauthenticated plaintext
  - Supports key commitment for enhanced security (recommended)
  - Validates all authentication tags before returning data
  - Enforces encryption context validation
  - Commitment policy prevents algorithm downgrade attacks

  ## Current Limitations

  This is a non-streaming implementation that requires the entire plaintext/ciphertext
  in memory. Streaming support will be added in a future release.
  """

  alias AwsEncryptionSdk.Client

  @doc """
  Encrypts plaintext using a client configuration.

  This is the recommended encryption API that enforces commitment policy and
  integrates with the CMM layer.

  For backward compatibility, also accepts EncryptionMaterials as the first argument
  (delegates to `encrypt_with_materials/3`).

  ## Parameters

  - `client` - Client with CMM and commitment policy configuration
  - `plaintext` - Binary data to encrypt
  - `opts` - Options (see `Client.encrypt/3`)

  ## Returns

  - `{:ok, result}` - Encryption succeeded
  - `{:error, reason}` - Encryption failed

  ## Examples

      # Create client and encrypt
      keyring = create_keyring()
      cmm = Cmm.Default.new(keyring)
      client = Client.new(cmm)

      {:ok, result} = AwsEncryptionSdk.encrypt(client, "secret data",
        encryption_context: %{"purpose" => "example"}
      )

  """
  @spec encrypt(Client.t(), binary(), Client.encrypt_opts()) ::
          {:ok, AwsEncryptionSdk.Encrypt.encrypt_result()} | {:error, term()}
  @spec encrypt(AwsEncryptionSdk.Materials.EncryptionMaterials.t(), binary(), keyword()) ::
          {:ok, AwsEncryptionSdk.Encrypt.encrypt_result()} | {:error, term()}
  def encrypt(client_or_materials, plaintext, opts \\ [])

  def encrypt(%Client{} = client, plaintext, opts) do
    Client.encrypt(client, plaintext, opts)
  end

  def encrypt(materials, plaintext, opts) do
    encrypt_with_materials(materials, plaintext, opts)
  end

  @doc """
  Encrypts plaintext using a keyring directly.

  Convenience function that creates a Default CMM and Client automatically.

  ## Parameters

  - `keyring` - A keyring struct (RawAes, RawRsa, or Multi)
  - `plaintext` - Binary data to encrypt
  - `opts` - Options (see `Client.encrypt_with_keyring/3`)

  ## Examples

      keyring = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

      {:ok, result} = AwsEncryptionSdk.encrypt_with_keyring(keyring, "secret",
        encryption_context: %{"purpose" => "test"}
      )

  """
  defdelegate encrypt_with_keyring(keyring, plaintext, opts \\ []), to: Client

  @doc """
  Encrypts plaintext using pre-assembled encryption materials.

  This is an advanced API for testing or specialized use cases. Most applications
  should use `encrypt/3` with a Client instead.

  ## Parameters

  - `materials` - Encryption materials containing algorithm suite, data key, and EDKs
  - `plaintext` - Data to encrypt
  - `opts` - Options (see `AwsEncryptionSdk.Encrypt.encrypt/3`)

  ## Returns

  - `{:ok, result}` - Encryption succeeded
  - `{:error, reason}` - Encryption failed

  ## Examples

      # Advanced: manually assemble materials
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      plaintext_data_key = :crypto.strong_rand_bytes(32)
      edk = EncryptedDataKey.new("provider", "key-info", plaintext_data_key)

      materials = EncryptionMaterials.new(suite, %{"key" => "value"}, [edk], plaintext_data_key)

      {:ok, result} = AwsEncryptionSdk.encrypt_with_materials(materials, "data")

  """
  @spec encrypt_with_materials(
          AwsEncryptionSdk.Materials.EncryptionMaterials.t(),
          binary(),
          keyword()
        ) ::
          {:ok, AwsEncryptionSdk.Encrypt.encrypt_result()} | {:error, term()}
  def encrypt_with_materials(materials, plaintext, opts \\ []) do
    AwsEncryptionSdk.Encrypt.encrypt(materials, plaintext, opts)
  end

  @doc """
  Decrypts an AWS Encryption SDK message using pre-assembled decryption materials.

  This is an advanced API for testing or specialized use cases. In the future,
  use `decrypt/2` with a Client instead.

  ## Parameters

  - `ciphertext` - Complete encrypted message
  - `materials` - Decryption materials containing the plaintext data key

  ## Returns

  - `{:ok, result}` - Decryption succeeded
  - `{:error, reason}` - Decryption failed
  """
  @spec decrypt_with_materials(binary(), AwsEncryptionSdk.Materials.DecryptionMaterials.t()) ::
          {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
  def decrypt_with_materials(ciphertext, materials) do
    AwsEncryptionSdk.Decrypt.decrypt(ciphertext, materials)
  end

  @doc """
  Decrypts an AWS Encryption SDK message.

  For backward compatibility, accepts DecryptionMaterials as the second argument
  (delegates to `decrypt_with_materials/2`).

  In the future, will accept a Client as the first argument for policy enforcement.

  ## Parameters

  - `ciphertext` - Complete encrypted message
  - `materials` - Decryption materials containing the plaintext data key

  ## Returns

  - `{:ok, result}` - Decryption succeeded
  - `{:error, reason}` - Decryption failed
  """
  @spec decrypt(binary(), AwsEncryptionSdk.Materials.DecryptionMaterials.t()) ::
          {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
  def decrypt(ciphertext, materials) do
    decrypt_with_materials(ciphertext, materials)
  end
end
