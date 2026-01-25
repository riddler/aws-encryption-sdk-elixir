defmodule AwsEncryptionSdk.AlgorithmSuite do
  @moduledoc """
  Algorithm suite definitions for the AWS Encryption SDK.

  Each algorithm suite defines the cryptographic algorithms and parameters used for
  encryption and decryption operations. The SDK supports 11 ESDK algorithm suites
  across three categories:

  - **Committed suites** (recommended): 0x0578, 0x0478 - Include key commitment
  - **Legacy HKDF suites**: 0x0378, 0x0346, 0x0214, 0x0178, 0x0146, 0x0114
  - **Deprecated NO_KDF suites** (decrypt only): 0x0078, 0x0046, 0x0014

  ## Default Suite

  The default and recommended suite is `0x0578`
  (AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384), which provides:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation
  - Key commitment for enhanced security
  - ECDSA P-384 message signing
  """

  require Logger

  @typedoc "Algorithm suite identifier (2-byte big-endian integer)"
  @type suite_id :: non_neg_integer()

  @typedoc "Encryption algorithm for AES-GCM operations"
  @type encryption_algorithm :: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm

  @typedoc "Key derivation function type"
  @type kdf_type :: :hkdf | :identity

  @typedoc "Hash algorithm for KDF operations"
  @type kdf_hash :: :sha256 | :sha384 | :sha512 | nil

  @typedoc "ECDSA signature algorithm"
  @type signature_algorithm :: :ecdsa_p256 | :ecdsa_p384 | nil

  @typedoc "Hash algorithm for signature operations"
  @type signature_hash :: :sha256 | :sha384 | nil

  @typedoc """
  Algorithm suite struct containing all cryptographic parameters.

  ## Fields

  - `:id` - Suite identifier (e.g., 0x0578)
  - `:name` - Human-readable name
  - `:message_format_version` - Message format version (1 or 2)
  - `:encryption_algorithm` - AES-GCM variant for Erlang :crypto
  - `:data_key_length` - Data key length in bits (128, 192, or 256)
  - `:iv_length` - Initialization vector length in bytes (always 12)
  - `:auth_tag_length` - Authentication tag length in bytes (always 16)
  - `:kdf_type` - Key derivation function (:hkdf or :identity)
  - `:kdf_hash` - Hash algorithm for HKDF (nil for identity KDF)
  - `:kdf_input_length` - KDF input key length in bytes
  - `:signature_algorithm` - ECDSA curve (nil if unsigned)
  - `:signature_hash` - Hash for signatures (nil if unsigned)
  - `:suite_data_length` - Suite data in header (32 for committed, 0 otherwise)
  - `:commitment_length` - Commitment key length (32 for committed, 0 otherwise)
  """
  @type t :: %__MODULE__{
          id: suite_id(),
          name: String.t(),
          message_format_version: 1 | 2,
          encryption_algorithm: encryption_algorithm(),
          data_key_length: 128 | 192 | 256,
          iv_length: 12,
          auth_tag_length: 16,
          kdf_type: kdf_type(),
          kdf_hash: kdf_hash(),
          kdf_input_length: pos_integer(),
          signature_algorithm: signature_algorithm(),
          signature_hash: signature_hash(),
          suite_data_length: 0 | 32,
          commitment_length: 0 | 32
        }

  @enforce_keys [
    :id,
    :name,
    :message_format_version,
    :encryption_algorithm,
    :data_key_length,
    :iv_length,
    :auth_tag_length,
    :kdf_type,
    :kdf_hash,
    :kdf_input_length,
    :signature_algorithm,
    :signature_hash,
    :suite_data_length,
    :commitment_length
  ]

  defstruct @enforce_keys

  # Suite ID constants
  @aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384 0x0578
  @aes_256_gcm_hkdf_sha512_commit_key 0x0478
  @aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 0x0378
  @aes_256_gcm_iv12_tag16_hkdf_sha256 0x0178

  # Additional HKDF suites (192-bit and 128-bit)
  @aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 0x0346
  @aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256 0x0214
  @aes_192_gcm_iv12_tag16_hkdf_sha256 0x0146
  @aes_128_gcm_iv12_tag16_hkdf_sha256 0x0114

  # Deprecated NO_KDF suites (decrypt only)
  @aes_256_gcm_iv12_tag16_no_kdf 0x0078
  @aes_192_gcm_iv12_tag16_no_kdf 0x0046
  @aes_128_gcm_iv12_tag16_no_kdf 0x0014

  @doc """
  Returns the default algorithm suite (0x0578).

  The default suite is AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, which provides
  the highest level of security with key commitment and message signing.
  """
  @spec default() :: t()
  def default do
    aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
  end

  @doc """
  Returns the AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 suite (0x0578).

  This is the recommended suite providing:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation with 32-byte input
  - Key commitment (32 bytes)
  - ECDSA P-384 message signing
  """
  @spec aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384() :: t()
  def aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384 do
    %__MODULE__{
      id: @aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384,
      name: "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
      message_format_version: 2,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha512,
      kdf_input_length: 32,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 32,
      commitment_length: 32
    }
  end

  @doc """
  Returns the AES_256_GCM_HKDF_SHA512_COMMIT_KEY suite (0x0478).

  A committed suite without message signing:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation with 32-byte input
  - Key commitment (32 bytes)
  - No message signing
  """
  @spec aes_256_gcm_hkdf_sha512_commit_key() :: t()
  def aes_256_gcm_hkdf_sha512_commit_key do
    %__MODULE__{
      id: @aes_256_gcm_hkdf_sha512_commit_key,
      name: "AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
      message_format_version: 2,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha512,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 32,
      commitment_length: 32
    }
  end

  @doc """
  Returns the AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 suite (0x0378).

  A legacy suite with message signing (no commitment):
  - AES-256-GCM encryption
  - HKDF-SHA384 key derivation
  - No key commitment
  - ECDSA P-384 message signing
  """
  @spec aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384() :: t()
  def aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384,
      name: "AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha384,
      kdf_input_length: 32,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_256_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0178).

  A common legacy suite without signing or commitment:
  - AES-256-GCM encryption
  - HKDF-SHA256 key derivation
  - No key commitment
  - No message signing
  """
  @spec aes_256_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_256_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_256_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 suite (0x0346).

  A legacy 192-bit suite with message signing.
  """
  @spec aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384() :: t()
  def aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384,
      name: "AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha384,
      kdf_input_length: 24,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 suite (0x0214).

  A legacy 128-bit suite with ECDSA P-256 message signing.
  """
  @spec aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256() :: t()
  def aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256 do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256,
      name: "AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 16,
      signature_algorithm: :ecdsa_p256,
      signature_hash: :sha256,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_192_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0146).

  A legacy 192-bit suite without message signing.
  """
  @spec aes_192_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_192_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_192_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 24,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0114).

  A legacy 128-bit suite without message signing.
  """
  @spec aes_128_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_128_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_128_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 16,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_256_GCM_IV12_TAG16_NO_KDF suite (0x0078).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_256_gcm_iv12_tag16_no_kdf() :: t()
  def aes_256_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_no_kdf,
      name: "AES_256_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_192_GCM_IV12_TAG16_NO_KDF suite (0x0046).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_192_gcm_iv12_tag16_no_kdf() :: t()
  def aes_192_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_no_kdf,
      name: "AES_192_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 24,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_NO_KDF suite (0x0014).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_128_gcm_iv12_tag16_no_kdf() :: t()
  def aes_128_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_no_kdf,
      name: "AES_128_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 16,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Looks up an algorithm suite by its ID.

  Returns `{:ok, suite}` if found, or `{:error, reason}` if the ID is invalid
  or reserved.

  ## Examples

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x0578)
      {:ok, %AwsEncryptionSdk.AlgorithmSuite{id: 0x0578}}

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x0000)
      {:error, :reserved_suite_id}

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x9999)
      {:error, :unknown_suite_id}

  Note: Accessing deprecated suites (NO_KDF) will log a warning.
  """
  @spec by_id(suite_id()) :: {:ok, t()} | {:error, :reserved_suite_id | :unknown_suite_id}
  def by_id(0x0000), do: {:error, :reserved_suite_id}

  def by_id(@aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384) do
    {:ok, aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()}
  end

  def by_id(@aes_256_gcm_hkdf_sha512_commit_key) do
    {:ok, aes_256_gcm_hkdf_sha512_commit_key()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384) do
    {:ok, aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_256_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(@aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384) do
    {:ok, aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256) do
    {:ok, aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()}
  end

  def by_id(@aes_192_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_192_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_128_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_256_gcm_iv12_tag16_no_kdf)
    {:ok, aes_256_gcm_iv12_tag16_no_kdf()}
  end

  def by_id(@aes_192_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_192_gcm_iv12_tag16_no_kdf)
    {:ok, aes_192_gcm_iv12_tag16_no_kdf()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_128_gcm_iv12_tag16_no_kdf)
    {:ok, aes_128_gcm_iv12_tag16_no_kdf()}
  end

  def by_id(_unknown_id), do: {:error, :unknown_suite_id}

  @doc """
  Returns true if the suite uses key commitment.

  Committed suites (0x0478, 0x0578) use message format version 2 and include
  a 32-byte commitment value that binds the data key to the message.
  """
  @spec committed?(t()) :: boolean()
  def committed?(%__MODULE__{commitment_length: length}), do: length > 0

  @doc """
  Returns true if the suite uses message signing.

  Signed suites include an ECDSA signature in the message footer that
  authenticates the entire message.
  """
  @spec signed?(t()) :: boolean()
  def signed?(%__MODULE__{signature_algorithm: nil}), do: false
  def signed?(%__MODULE__{signature_algorithm: _algorithm}), do: true

  @doc """
  Returns true if the suite can be used for encryption.

  Deprecated suites (NO_KDF) should only be used for decryption of existing
  messages, not for encrypting new messages.
  """
  @spec allows_encryption?(t()) :: boolean()
  def allows_encryption?(%__MODULE__{} = suite), do: not deprecated?(suite)

  @doc """
  Returns true if the suite is deprecated.

  Deprecated suites are the NO_KDF suites (0x0014, 0x0046, 0x0078) which do not
  use key derivation. These should only be used for decrypting legacy messages.
  """
  @spec deprecated?(t()) :: boolean()
  def deprecated?(%__MODULE__{kdf_type: :identity}), do: true
  def deprecated?(%__MODULE__{kdf_type: _kdf_type}), do: false

  @spec log_deprecation_warning(suite_id()) :: :ok
  defp log_deprecation_warning(suite_id) do
    Logger.warning(
      "Algorithm suite 0x#{Integer.to_string(suite_id, 16)} (NO_KDF) is deprecated. " <>
        "Use a committed algorithm suite for new encryptions."
    )
  end
end
