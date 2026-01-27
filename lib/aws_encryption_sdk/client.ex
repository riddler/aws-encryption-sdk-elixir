defmodule AwsEncryptionSdk.Client do
  @moduledoc """
  Client configuration for AWS Encryption SDK operations.

  The Client holds configuration that controls encryption and decryption behavior,
  including the commitment policy and maximum number of encrypted data keys.

  ## Commitment Policy

  The commitment policy controls which algorithm suites can be used:

  - `:forbid_encrypt_allow_decrypt` - Legacy: encrypt with non-committed suites only
  - `:require_encrypt_allow_decrypt` - Transitional: encrypt with committed suites, decrypt any
  - `:require_encrypt_require_decrypt` - Strictest (default): encrypt and decrypt committed only

  ## Example

      # Create with default policy (strictest)
      keyring = RawAes.new("namespace", "key", key_bytes, :aes_256_gcm)
      cmm = Cmm.Default.new(keyring)
      client = Client.new(cmm)

      # Or specify policy explicitly
      client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

      # Limit encrypted data keys
      client = Client.new(cmm, max_encrypted_data_keys: 3)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Decrypt
  alias AwsEncryptionSdk.Encrypt
  alias AwsEncryptionSdk.Format.Header

  @typedoc "Commitment policy for algorithm suite selection"
  @type commitment_policy :: CmmBehaviour.commitment_policy()

  @typedoc """
  Client configuration struct.

  ## Fields

  - `:cmm` - Cryptographic Materials Manager for obtaining encryption/decryption materials
  - `:commitment_policy` - Policy controlling algorithm suite usage (default: `:require_encrypt_require_decrypt`)
  - `:max_encrypted_data_keys` - Maximum number of EDKs allowed (default: `nil` for unlimited)
  """
  @type t :: %__MODULE__{
          cmm: CmmBehaviour.t(),
          commitment_policy: commitment_policy(),
          max_encrypted_data_keys: non_neg_integer() | nil
        }

  @enforce_keys [:cmm]

  defstruct [
    :cmm,
    commitment_policy: :require_encrypt_require_decrypt,
    max_encrypted_data_keys: nil
  ]

  @doc """
  Creates a new Client with the given CMM and options.

  ## Parameters

  - `cmm` - A Cryptographic Materials Manager (required)
  - `opts` - Options (optional):
    - `:commitment_policy` - One of `:forbid_encrypt_allow_decrypt`,
      `:require_encrypt_allow_decrypt`, `:require_encrypt_require_decrypt`
      (default: `:require_encrypt_require_decrypt`)
    - `:max_encrypted_data_keys` - Maximum number of EDKs allowed
      (default: `nil` for unlimited)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> client = AwsEncryptionSdk.Client.new(cmm)
      iex> client.commitment_policy
      :require_encrypt_require_decrypt

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> client = AwsEncryptionSdk.Client.new(cmm, commitment_policy: :forbid_encrypt_allow_decrypt)
      iex> client.commitment_policy
      :forbid_encrypt_allow_decrypt

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> client = AwsEncryptionSdk.Client.new(cmm, max_encrypted_data_keys: 5)
      iex> client.max_encrypted_data_keys
      5

  """
  @spec new(CmmBehaviour.t(), keyword()) :: t()
  def new(cmm, opts \\ []) do
    %__MODULE__{
      cmm: cmm,
      commitment_policy: Keyword.get(opts, :commitment_policy, :require_encrypt_require_decrypt),
      max_encrypted_data_keys: Keyword.get(opts, :max_encrypted_data_keys)
    }
  end

  @type encrypt_opts :: [
          encryption_context: %{String.t() => String.t()},
          algorithm_suite: AlgorithmSuite.t(),
          frame_length: pos_integer()
        ]

  @doc """
  Encrypts plaintext using the client's CMM and commitment policy.

  This is the primary encryption API that enforces commitment policy and
  integrates with the CMM to obtain encryption materials.

  ## Parameters

  - `client` - Client configuration with CMM and policy
  - `plaintext` - Binary data to encrypt
  - `opts` - Options:
    - `:encryption_context` - Key-value pairs for AAD (default: `%{}`)
    - `:algorithm_suite` - Override default suite (validated against policy)
    - `:frame_length` - Frame size in bytes (default: 4096)

  ## Returns

  - `{:ok, result}` - Encryption succeeded
  - `{:error, reason}` - Encryption failed

  ## Errors

  - `:commitment_policy_requires_committed_suite` - Non-committed suite with require policy
  - `:commitment_policy_forbids_committed_suite` - Committed suite with forbid policy
  - `:max_encrypted_data_keys_exceeded` - Too many EDKs generated
  - Other errors from CMM or encryption operations

  ## Examples

      # Encrypt with default committed suite
      {:ok, result} = Client.encrypt(client, "secret data",
        encryption_context: %{"purpose" => "example"}
      )

      # Encrypt with specific algorithm suite (must match policy)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      {:ok, result} = Client.encrypt(client, "data",
        algorithm_suite: suite
      )

  """
  @spec encrypt(t(), binary(), encrypt_opts()) ::
          {:ok, Encrypt.encrypt_result()} | {:error, term()}
  def encrypt(%__MODULE__{} = client, plaintext, opts \\ []) when is_binary(plaintext) do
    encryption_context = Keyword.get(opts, :encryption_context, %{})
    requested_suite = Keyword.get(opts, :algorithm_suite)
    frame_length = Keyword.get(opts, :frame_length, 4096)

    with :ok <- validate_encryption_context_for_client(encryption_context),
         :ok <- maybe_validate_requested_suite(requested_suite, client.commitment_policy),
         {:ok, materials} <-
           get_encryption_materials(client, encryption_context, requested_suite),
         :ok <- validate_materials_suite(materials.algorithm_suite, client.commitment_policy),
         :ok <- validate_edk_limit(materials.encrypted_data_keys, client.max_encrypted_data_keys) do
      Encrypt.encrypt(materials, plaintext, frame_length: frame_length)
    end
  end

  @doc """
  Encrypts plaintext using a keyring directly.

  Convenience function that wraps the keyring in a Default CMM before encrypting.
  Equivalent to creating a client with `Cmm.Default.new(keyring)`.

  ## Parameters

  - `keyring` - A keyring struct (RawAes, RawRsa, or Multi)
  - `plaintext` - Binary data to encrypt
  - `opts` - Same options as `encrypt/3`, plus:
    - `:commitment_policy` - Override default policy
    - `:max_encrypted_data_keys` - Override default limit

  ## Examples

      keyring = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

      {:ok, result} = Client.encrypt_with_keyring(keyring, "secret",
        encryption_context: %{"purpose" => "test"},
        commitment_policy: :require_encrypt_allow_decrypt
      )

  """
  @spec encrypt_with_keyring(Default.keyring(), binary(), encrypt_opts()) ::
          {:ok, Encrypt.encrypt_result()} | {:error, term()}
  def encrypt_with_keyring(keyring, plaintext, opts \\ []) do
    commitment_policy =
      Keyword.get(opts, :commitment_policy, :require_encrypt_require_decrypt)

    max_edks = Keyword.get(opts, :max_encrypted_data_keys)

    cmm = Default.new(keyring)

    client =
      new(cmm,
        commitment_policy: commitment_policy,
        max_encrypted_data_keys: max_edks
      )

    # Remove client-specific opts before passing to encrypt
    encrypt_opts = Keyword.drop(opts, [:commitment_policy, :max_encrypted_data_keys])
    encrypt(client, plaintext, encrypt_opts)
  end

  @type decrypt_opts :: [
          encryption_context: %{String.t() => String.t()}
        ]

  @doc """
  Decrypts ciphertext using the client's CMM and commitment policy.

  This is the primary decryption API that enforces commitment policy and
  integrates with the CMM to obtain decryption materials.

  ## Parameters

  - `client` - Client configuration with CMM and policy
  - `ciphertext` - Complete encrypted message (header + body + footer)
  - `opts` - Options:
    - `:encryption_context` - Reproduced context to validate against (default: `nil`)

  ## Returns

  - `{:ok, result}` - Decryption succeeded with `%{plaintext: binary, encryption_context: map, algorithm_suite: AlgorithmSuite.t(), header: Header.t()}`
  - `{:error, reason}` - Decryption failed

  ## Errors

  - `:commitment_policy_requires_committed_suite` - Non-committed suite with strict policy
  - `:too_many_encrypted_data_keys` - EDK count exceeds limit
  - `:base64_encoded_message` - Message appears to be Base64 encoded
  - Other errors from CMM, keyring, or decryption operations

  ## Examples

      # Decrypt with default strict policy
      {:ok, result} = Client.decrypt(client, ciphertext)

      # Decrypt with reproduced encryption context validation
      {:ok, result} = Client.decrypt(client, ciphertext,
        encryption_context: %{"purpose" => "example"}
      )

  """
  @spec decrypt(t(), binary(), decrypt_opts()) ::
          {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
  def decrypt(%__MODULE__{} = client, ciphertext, opts \\ []) when is_binary(ciphertext) do
    reproduced_context = Keyword.get(opts, :encryption_context)

    with {:ok, header, _rest} <- Header.deserialize(ciphertext),
         :ok <-
           validate_algorithm_suite_for_decrypt(header.algorithm_suite, client.commitment_policy),
         :ok <- validate_edk_count_for_decrypt(header, client.max_encrypted_data_keys),
         {:ok, materials} <- get_decryption_materials(client, header, reproduced_context) do
      Decrypt.decrypt(ciphertext, materials)
    end
  end

  @doc """
  Decrypts ciphertext using a keyring directly.

  Convenience function that wraps the keyring in a Default CMM before decrypting.
  Equivalent to creating a client with `Cmm.Default.new(keyring)`.

  ## Parameters

  - `keyring` - A keyring struct (RawAes, RawRsa, or Multi)
  - `ciphertext` - Complete encrypted message
  - `opts` - Same options as `decrypt/3`, plus:
    - `:commitment_policy` - Override default policy
    - `:max_encrypted_data_keys` - Override default limit

  ## Examples

      keyring = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)

      {:ok, result} = Client.decrypt_with_keyring(keyring, ciphertext,
        encryption_context: %{"purpose" => "test"},
        commitment_policy: :require_encrypt_allow_decrypt
      )

  """
  @spec decrypt_with_keyring(Default.keyring(), binary(), decrypt_opts()) ::
          {:ok, AwsEncryptionSdk.Decrypt.decrypt_result()} | {:error, term()}
  def decrypt_with_keyring(keyring, ciphertext, opts \\ []) do
    commitment_policy =
      Keyword.get(opts, :commitment_policy, :require_encrypt_require_decrypt)

    max_edks = Keyword.get(opts, :max_encrypted_data_keys)

    cmm = Default.new(keyring)

    client =
      new(cmm,
        commitment_policy: commitment_policy,
        max_encrypted_data_keys: max_edks
      )

    # Remove client-specific opts before passing to decrypt
    decrypt_opts = Keyword.drop(opts, [:commitment_policy, :max_encrypted_data_keys])
    decrypt(client, ciphertext, decrypt_opts)
  end

  # Private helpers

  defp validate_encryption_context_for_client(context) do
    CmmBehaviour.validate_encryption_context_for_encrypt(context)
  end

  defp maybe_validate_requested_suite(nil, _policy), do: :ok

  defp maybe_validate_requested_suite(suite, policy) do
    CmmBehaviour.validate_commitment_policy_for_encrypt(suite, policy)
  end

  defp get_encryption_materials(client, encryption_context, requested_suite) do
    request = %{
      encryption_context: encryption_context,
      commitment_policy: client.commitment_policy,
      algorithm_suite: requested_suite
    }

    # Dispatch to the CMM module based on struct type
    call_cmm_get_encryption_materials(client.cmm, request)
  end

  # Dispatch get_encryption_materials to the appropriate CMM module
  defp call_cmm_get_encryption_materials(%Default{} = cmm, request) do
    Default.get_encryption_materials(cmm, request)
  end

  # Add support for other CMM types as they are implemented
  defp call_cmm_get_encryption_materials(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  defp validate_materials_suite(suite, policy) do
    CmmBehaviour.validate_commitment_policy_for_encrypt(suite, policy)
  end

  defp validate_edk_limit(_edks, nil), do: :ok

  defp validate_edk_limit(edks, max_edks) when is_integer(max_edks) do
    if length(edks) <= max_edks do
      :ok
    else
      {:error, :max_encrypted_data_keys_exceeded}
    end
  end

  # Validates algorithm suite against commitment policy for decryption
  defp validate_algorithm_suite_for_decrypt(suite, policy) do
    CmmBehaviour.validate_commitment_policy_for_decrypt(suite, policy)
  end

  # Validates that EDK count doesn't exceed configured maximum
  defp validate_edk_count_for_decrypt(_header, nil), do: :ok

  defp validate_edk_count_for_decrypt(header, max_edks) when is_integer(max_edks) do
    edk_count = length(header.encrypted_data_keys)

    if edk_count <= max_edks do
      :ok
    else
      {:error, :too_many_encrypted_data_keys}
    end
  end

  # Builds request and dispatches to CMM to get decryption materials
  defp get_decryption_materials(client, header, reproduced_context) do
    request = %{
      algorithm_suite: header.algorithm_suite,
      commitment_policy: client.commitment_policy,
      encrypted_data_keys: header.encrypted_data_keys,
      encryption_context: header.encryption_context,
      reproduced_encryption_context: reproduced_context
    }

    # Dispatch to the CMM module based on struct type
    call_cmm_get_decryption_materials(client.cmm, request)
  end

  # Dispatch get_decryption_materials to the appropriate CMM module
  defp call_cmm_get_decryption_materials(%Default{} = cmm, request) do
    Default.get_decryption_materials(cmm, request)
  end

  # Add support for other CMM types as they are implemented
  defp call_cmm_get_decryption_materials(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end
end
