defmodule AwsEncryptionSdk.Keyring.KmsClient do
  @moduledoc """
  Behaviour for AWS KMS client implementations.

  This module defines the interface for KMS operations required by AWS KMS keyrings.
  Implementations must provide `generate_data_key/5`, `encrypt/5`, and `decrypt/5`.

  ## Implementations

  - `AwsEncryptionSdk.Keyring.KmsClient.ExAws` - Production client using ExAws
  - `AwsEncryptionSdk.Keyring.KmsClient.Mock` - Test mock for unit testing

  ## Example

      # Using ExAws client
      {:ok, client} = KmsClient.ExAws.new(region: "us-east-1")
      {:ok, result} = KmsClient.ExAws.generate_data_key(
        client,
        "arn:aws:kms:us-east-1:123456789012:key/abc123",
        32,
        %{"purpose" => "encryption"},
        []
      )
  """

  # ============================================================================
  # Types
  # ============================================================================

  @typedoc "AWS KMS key identifier (ARN, alias ARN, alias name, or key ID)"
  @type key_id :: String.t()

  @typedoc "Encryption context - key-value pairs for additional authenticated data"
  @type encryption_context :: %{String.t() => String.t()}

  @typedoc "Grant tokens for temporary permissions"
  @type grant_tokens :: [String.t()]

  @typedoc """
  Result of GenerateDataKey operation.

  - `:plaintext` - The plaintext data key (unencrypted)
  - `:ciphertext` - The encrypted data key (ciphertext blob)
  - `:key_id` - The ARN of the KMS key that was used
  """
  @type generate_data_key_result :: %{
          plaintext: binary(),
          ciphertext: binary(),
          key_id: String.t()
        }

  @typedoc """
  Result of Encrypt operation.

  - `:ciphertext` - The encrypted data (ciphertext blob)
  - `:key_id` - The ARN of the KMS key that was used
  """
  @type encrypt_result :: %{
          ciphertext: binary(),
          key_id: String.t()
        }

  @typedoc """
  Result of Decrypt operation.

  - `:plaintext` - The decrypted data
  - `:key_id` - The ARN of the KMS key that was used
  """
  @type decrypt_result :: %{
          plaintext: binary(),
          key_id: String.t()
        }

  @typedoc "KMS operation error with descriptive information"
  @type kms_error ::
          {:kms_error, atom(), String.t()}
          | {:http_error, integer(), String.t()}
          | {:connection_error, term()}

  # ============================================================================
  # Callbacks
  # ============================================================================

  @doc """
  Generates a unique data key for encryption.

  Calls the AWS KMS GenerateDataKey API to create a new data key. Returns both
  the plaintext key (for immediate use) and the encrypted key (for storage).

  ## Parameters

  - `client` - The KMS client struct
  - `key_id` - KMS key identifier (ARN, alias, or key ID)
  - `number_of_bytes` - Length of the data key in bytes (typically 32 for AES-256)
  - `encryption_context` - Key-value pairs bound to the ciphertext
  - `grant_tokens` - Optional grant tokens for temporary permissions

  ## Returns

  - `{:ok, result}` with plaintext, ciphertext, and key_id
  - `{:error, reason}` on failure
  """
  @callback generate_data_key(
              client :: struct(),
              key_id :: key_id(),
              number_of_bytes :: pos_integer(),
              encryption_context :: encryption_context(),
              grant_tokens :: grant_tokens()
            ) :: {:ok, generate_data_key_result()} | {:error, kms_error()}

  @doc """
  Encrypts data using a KMS key.

  Calls the AWS KMS Encrypt API to encrypt the provided plaintext.

  ## Parameters

  - `client` - The KMS client struct
  - `key_id` - KMS key identifier (ARN, alias, or key ID)
  - `plaintext` - Data to encrypt (max 4096 bytes for direct encryption)
  - `encryption_context` - Key-value pairs bound to the ciphertext
  - `grant_tokens` - Optional grant tokens for temporary permissions

  ## Returns

  - `{:ok, result}` with ciphertext and key_id
  - `{:error, reason}` on failure
  """
  @callback encrypt(
              client :: struct(),
              key_id :: key_id(),
              plaintext :: binary(),
              encryption_context :: encryption_context(),
              grant_tokens :: grant_tokens()
            ) :: {:ok, encrypt_result()} | {:error, kms_error()}

  @doc """
  Decrypts data that was encrypted with a KMS key.

  Calls the AWS KMS Decrypt API to decrypt the provided ciphertext.

  ## Parameters

  - `client` - The KMS client struct
  - `key_id` - KMS key identifier (must match the key used for encryption)
  - `ciphertext` - Encrypted data (ciphertext blob from Encrypt or GenerateDataKey)
  - `encryption_context` - Must match the context used during encryption
  - `grant_tokens` - Optional grant tokens for temporary permissions

  ## Returns

  - `{:ok, result}` with plaintext and key_id
  - `{:error, reason}` on failure
  """
  @callback decrypt(
              client :: struct(),
              key_id :: key_id(),
              ciphertext :: binary(),
              encryption_context :: encryption_context(),
              grant_tokens :: grant_tokens()
            ) :: {:ok, decrypt_result()} | {:error, kms_error()}
end
