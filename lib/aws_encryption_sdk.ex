defmodule AwsEncryptionSdk do
  @moduledoc """
  AWS Encryption SDK for Elixir.

  This module provides client-side encryption following the official AWS Encryption
  SDK Specification, enabling interoperability with AWS Encryption SDK implementations
  in other languages (Python, Java, JavaScript, C, CLI).

  ## Quick Start

  The SDK provides two main operations:

  - `encrypt/3` - Encrypts plaintext using encryption materials
  - `decrypt/2` - Decrypts AWS Encryption SDK messages

  ## Example

  ```elixir
  # Create encryption materials (typically from a keyring/CMM)
  suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
  plaintext_data_key = :crypto.strong_rand_bytes(32)
  edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("provider", "key-info", plaintext_data_key)

  enc_materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new(
    suite,
    %{"purpose" => "example"},
    [edk],
    plaintext_data_key
  )

  # Encrypt
  {:ok, result} = AwsEncryptionSdk.encrypt(enc_materials, "secret data")

  # Decrypt
  dec_materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new(
    suite,
    result.encryption_context,
    plaintext_data_key
  )

  {:ok, decrypted} = AwsEncryptionSdk.decrypt(result.ciphertext, dec_materials)
  ```

  ## Security

  The SDK follows the AWS Encryption SDK specification security requirements:

  - Never releases unauthenticated plaintext
  - Supports key commitment for enhanced security
  - Validates all authentication tags before returning data
  - Enforces encryption context validation

  ## Current Limitations

  This is a non-streaming implementation that requires the entire plaintext/ciphertext
  in memory. Streaming support will be added in a future release.
  """

  @doc """
  Encrypts plaintext using the provided materials.

  This is a convenience wrapper around `AwsEncryptionSdk.Encrypt.encrypt/3`.

  ## Parameters

  - `materials` - Encryption materials containing algorithm suite, data key, and EDKs
  - `plaintext` - Data to encrypt
  - `opts` - Options (see `AwsEncryptionSdk.Encrypt.encrypt/3`)

  ## Returns

  - `{:ok, result}` - Encryption succeeded
  - `{:error, reason}` - Encryption failed
  """
  defdelegate encrypt(materials, plaintext, opts \\ []), to: AwsEncryptionSdk.Encrypt

  @doc """
  Decrypts an AWS Encryption SDK message using the provided materials.

  This is a convenience wrapper around `AwsEncryptionSdk.Decrypt.decrypt/2`.

  ## Parameters

  - `ciphertext` - Complete encrypted message
  - `materials` - Decryption materials containing the plaintext data key

  ## Returns

  - `{:ok, result}` - Decryption succeeded
  - `{:error, reason}` - Decryption failed
  """
  defdelegate decrypt(ciphertext, materials), to: AwsEncryptionSdk.Decrypt
end
