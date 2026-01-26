defmodule AwsEncryptionSdk.Cmm.Behaviour do
  @moduledoc """
  Behaviour for Cryptographic Materials Manager (CMM) implementations.

  The CMM is responsible for assembling cryptographic materials for encryption
  and decryption operations. It sits between the encrypt/decrypt APIs and keyrings,
  managing algorithm suite selection, encryption context handling, and orchestrating
  keyring operations.

  ## Callbacks

  - `get_encryption_materials/2` - Obtain materials for encryption
  - `get_decryption_materials/2` - Obtain materials for decryption

  ## Commitment Policy

  The commitment policy controls which algorithm suites can be used:

  - `:forbid_encrypt_allow_decrypt` - Forbid committed suites for encrypt, allow all for decrypt
  - `:require_encrypt_allow_decrypt` - Require committed suites for encrypt, allow all for decrypt
  - `:require_encrypt_require_decrypt` - Require committed suites for both (strictest, recommended)

  ## Reserved Encryption Context Key

  The key `"aws-crypto-public-key"` is reserved for storing the signature verification
  key in the encryption context. CMMs MUST:

  - Add this key when the algorithm suite includes signing
  - Fail if the caller already provided this key
  - Extract the verification key from this key during decryption

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @typedoc "CMM implementation struct (opaque to the behaviour)"
  @type t :: term()

  @typedoc """
  Commitment policy for algorithm suite selection.

  - `:forbid_encrypt_allow_decrypt` - Non-committed suites only for encrypt
  - `:require_encrypt_allow_decrypt` - Committed suites required for encrypt
  - `:require_encrypt_require_decrypt` - Committed suites required for both (default)
  """
  @type commitment_policy ::
          :forbid_encrypt_allow_decrypt
          | :require_encrypt_allow_decrypt
          | :require_encrypt_require_decrypt

  @typedoc """
  Request for encryption materials.

  ## Required Fields

  - `:encryption_context` - Key-value pairs for AAD (may be empty map)
  - `:commitment_policy` - Policy controlling algorithm suite selection

  ## Optional Fields

  - `:algorithm_suite` - Requested algorithm suite (CMM may use default)
  - `:required_encryption_context_keys` - Keys that must be in final context
  - `:max_plaintext_length` - Maximum plaintext length hint
  """
  @type encryption_materials_request :: %{
          required(:encryption_context) => %{String.t() => String.t()},
          required(:commitment_policy) => commitment_policy(),
          optional(:algorithm_suite) => AlgorithmSuite.t() | nil,
          optional(:required_encryption_context_keys) => [String.t()],
          optional(:max_plaintext_length) => non_neg_integer() | nil
        }

  @typedoc """
  Request for decryption materials.

  ## Required Fields

  - `:algorithm_suite` - Algorithm suite from message header
  - `:commitment_policy` - Policy controlling algorithm suite selection
  - `:encrypted_data_keys` - EDKs from message header
  - `:encryption_context` - Encryption context from message header

  ## Optional Fields

  - `:reproduced_encryption_context` - Context to validate against
  """
  @type decrypt_materials_request :: %{
          required(:algorithm_suite) => AlgorithmSuite.t(),
          required(:commitment_policy) => commitment_policy(),
          required(:encrypted_data_keys) => [EncryptedDataKey.t()],
          required(:encryption_context) => %{String.t() => String.t()},
          optional(:reproduced_encryption_context) => %{String.t() => String.t()} | nil
        }

  @doc """
  Obtains encryption materials for an encryption operation.

  The CMM assembles encryption materials by:
  1. Selecting an algorithm suite (using requested or default)
  2. Validating the algorithm suite against commitment policy
  3. Delegating to keyring(s) to generate/encrypt data key
  4. Adding signing key if algorithm suite requires signing
  5. Validating the assembled materials

  ## Parameters

  - `cmm` - CMM implementation struct
  - `request` - Encryption materials request

  ## Returns

  - `{:ok, %EncryptionMaterials{}}` - Valid encryption materials
  - `{:error, term()}` - Failed to assemble materials

  ## Spec Requirements

  The returned materials MUST:
  - Include a non-NULL plaintext data key
  - Include at least one encrypted data key
  - Include signing key if algorithm suite has signing algorithm
  - Have required_encryption_context_keys as superset of request
  """
  @callback get_encryption_materials(cmm :: t(), request :: encryption_materials_request()) ::
              {:ok, EncryptionMaterials.t()} | {:error, term()}

  @doc """
  Obtains decryption materials for a decryption operation.

  The CMM assembles decryption materials by:
  1. Validating the algorithm suite against commitment policy
  2. Validating encryption context against reproduced context (if provided)
  3. Delegating to keyring(s) to decrypt a data key
  4. Extracting verification key if algorithm suite requires signing
  5. Validating the assembled materials

  ## Parameters

  - `cmm` - CMM implementation struct
  - `request` - Decryption materials request

  ## Returns

  - `{:ok, %DecryptionMaterials{}}` - Valid decryption materials
  - `{:error, term()}` - Failed to assemble materials

  ## Spec Requirements

  The returned materials MUST:
  - Include a non-NULL plaintext data key
  - Include verification key if algorithm suite has signing algorithm
  - Have all required_encryption_context_keys present in encryption context
  """
  @callback get_decryption_materials(cmm :: t(), request :: decrypt_materials_request()) ::
              {:ok, DecryptionMaterials.t()} | {:error, term()}

  # Reserved encryption context key for signature verification
  @reserved_ec_key "aws-crypto-public-key"

  @doc """
  Returns the reserved encryption context key for signature verification.

  This key is used to store the base64-encoded public key in the encryption
  context for signed algorithm suites.
  """
  @spec reserved_encryption_context_key() :: String.t()
  def reserved_encryption_context_key, do: @reserved_ec_key

  @doc """
  Returns the default algorithm suite for a commitment policy.

  ## Examples

      iex> suite = AwsEncryptionSdk.Cmm.Behaviour.default_algorithm_suite(:require_encrypt_require_decrypt)
      iex> suite.id
      0x0578

      iex> suite = AwsEncryptionSdk.Cmm.Behaviour.default_algorithm_suite(:forbid_encrypt_allow_decrypt)
      iex> suite.id
      0x0378

  """
  @spec default_algorithm_suite(commitment_policy()) :: AlgorithmSuite.t()
  def default_algorithm_suite(:forbid_encrypt_allow_decrypt) do
    # Non-committed suite with signing
    AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()
  end

  def default_algorithm_suite(_policy) do
    # Committed suite (default for require_* policies)
    AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
  end

  @doc """
  Validates an algorithm suite against a commitment policy for encryption.

  ## Rules

  - `:forbid_encrypt_allow_decrypt` - Suite MUST NOT be committed
  - `:require_encrypt_allow_decrypt` - Suite MUST be committed
  - `:require_encrypt_require_decrypt` - Suite MUST be committed

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_encrypt(suite, :require_encrypt_require_decrypt)
      {:error, :commitment_policy_requires_committed_suite}

  """
  @spec validate_commitment_policy_for_encrypt(AlgorithmSuite.t(), commitment_policy()) ::
          :ok
          | {:error,
             :commitment_policy_requires_committed_suite
             | :commitment_policy_forbids_committed_suite}
  def validate_commitment_policy_for_encrypt(suite, :forbid_encrypt_allow_decrypt) do
    if AlgorithmSuite.committed?(suite) do
      {:error, :commitment_policy_forbids_committed_suite}
    else
      :ok
    end
  end

  def validate_commitment_policy_for_encrypt(suite, policy)
      when policy in [:require_encrypt_allow_decrypt, :require_encrypt_require_decrypt] do
    if AlgorithmSuite.committed?(suite) do
      :ok
    else
      {:error, :commitment_policy_requires_committed_suite}
    end
  end

  @doc """
  Validates an algorithm suite against a commitment policy for decryption.

  ## Rules

  - `:forbid_encrypt_allow_decrypt` - Any suite allowed
  - `:require_encrypt_allow_decrypt` - Any suite allowed
  - `:require_encrypt_require_decrypt` - Suite MUST be committed

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_decrypt(suite, :require_encrypt_allow_decrypt)
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_commitment_policy_for_decrypt(suite, :require_encrypt_require_decrypt)
      {:error, :commitment_policy_requires_committed_suite}

  """
  @spec validate_commitment_policy_for_decrypt(AlgorithmSuite.t(), commitment_policy()) ::
          :ok | {:error, :commitment_policy_requires_committed_suite}
  def validate_commitment_policy_for_decrypt(_suite, policy)
      when policy in [:forbid_encrypt_allow_decrypt, :require_encrypt_allow_decrypt] do
    :ok
  end

  def validate_commitment_policy_for_decrypt(suite, :require_encrypt_require_decrypt) do
    if AlgorithmSuite.committed?(suite) do
      :ok
    else
      {:error, :commitment_policy_requires_committed_suite}
    end
  end

  @doc """
  Validates that encryption materials are complete and valid.

  Checks:
  1. Plaintext data key is present and correct length
  2. At least one encrypted data key exists
  3. Signing key present if algorithm suite has signing
  4. Required encryption context keys are present in context

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> edk = AwsEncryptionSdk.Materials.EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new(suite, %{}, [edk], key)
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_materials(materials)
      :ok

  """
  @spec validate_encryption_materials(EncryptionMaterials.t()) ::
          :ok
          | {:error,
             :missing_plaintext_data_key
             | :invalid_plaintext_data_key_length
             | :missing_encrypted_data_keys
             | :missing_signing_key
             | :missing_required_encryption_context_key}
  def validate_encryption_materials(%EncryptionMaterials{} = materials) do
    with :ok <- validate_plaintext_data_key(materials),
         :ok <- validate_encrypted_data_keys(materials),
         :ok <- validate_signing_key(materials) do
      validate_required_context_keys(materials)
    end
  end

  defp validate_plaintext_data_key(%{plaintext_data_key: nil}) do
    {:error, :missing_plaintext_data_key}
  end

  defp validate_plaintext_data_key(%{plaintext_data_key: key, algorithm_suite: suite})
       when is_binary(key) do
    expected_length = suite.kdf_input_length

    if byte_size(key) == expected_length do
      :ok
    else
      {:error, :invalid_plaintext_data_key_length}
    end
  end

  defp validate_encrypted_data_keys(%{encrypted_data_keys: []}) do
    {:error, :missing_encrypted_data_keys}
  end

  defp validate_encrypted_data_keys(%{encrypted_data_keys: edks}) when is_list(edks) do
    :ok
  end

  defp validate_signing_key(%{algorithm_suite: suite, signing_key: signing_key}) do
    if AlgorithmSuite.signed?(suite) and is_nil(signing_key) do
      {:error, :missing_signing_key}
    else
      :ok
    end
  end

  defp validate_required_context_keys(%{
         encryption_context: context,
         required_encryption_context_keys: required_keys
       }) do
    missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, :missing_required_encryption_context_key}
    end
  end

  @doc """
  Validates that decryption materials are complete and valid.

  Checks:
  1. Plaintext data key is present and correct length
  2. Verification key present if algorithm suite has signing
  3. Required encryption context keys are present in context

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> key = :crypto.strong_rand_bytes(32)
      iex> materials = AwsEncryptionSdk.Materials.DecryptionMaterials.new(suite, %{}, key)
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_decryption_materials(materials)
      :ok

  """
  @spec validate_decryption_materials(DecryptionMaterials.t()) ::
          :ok
          | {:error,
             :missing_plaintext_data_key
             | :invalid_plaintext_data_key_length
             | :missing_verification_key
             | :missing_required_encryption_context_key}
  def validate_decryption_materials(%DecryptionMaterials{} = materials) do
    with :ok <- validate_decryption_plaintext_key(materials),
         :ok <- validate_verification_key(materials) do
      validate_decryption_required_context_keys(materials)
    end
  end

  defp validate_decryption_plaintext_key(%{plaintext_data_key: nil}) do
    {:error, :missing_plaintext_data_key}
  end

  defp validate_decryption_plaintext_key(%{plaintext_data_key: key, algorithm_suite: suite})
       when is_binary(key) do
    expected_length = suite.kdf_input_length

    if byte_size(key) == expected_length do
      :ok
    else
      {:error, :invalid_plaintext_data_key_length}
    end
  end

  defp validate_verification_key(%{algorithm_suite: suite, verification_key: verification_key}) do
    if AlgorithmSuite.signed?(suite) and is_nil(verification_key) do
      {:error, :missing_verification_key}
    else
      :ok
    end
  end

  defp validate_decryption_required_context_keys(%{
         encryption_context: context,
         required_encryption_context_keys: required_keys
       }) do
    missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, :missing_required_encryption_context_key}
    end
  end

  @doc """
  Validates that encryption context does not contain reserved keys.

  The caller MUST NOT provide the reserved key `aws-crypto-public-key`.
  This key is reserved for the CMM to store the signature verification key.

  ## Examples

      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_context_for_encrypt(%{"key" => "value"})
      :ok

      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_encryption_context_for_encrypt(%{"aws-crypto-public-key" => "value"})
      {:error, :reserved_encryption_context_key}

  """
  @spec validate_encryption_context_for_encrypt(%{String.t() => String.t()}) ::
          :ok | {:error, :reserved_encryption_context_key}
  def validate_encryption_context_for_encrypt(context) when is_map(context) do
    if Map.has_key?(context, @reserved_ec_key) do
      {:error, :reserved_encryption_context_key}
    else
      :ok
    end
  end

  @doc """
  Validates encryption context consistency with algorithm suite signing requirement.

  For decryption, validates that:
  - If algorithm suite has signing, `aws-crypto-public-key` SHOULD be present
  - If algorithm suite has no signing, `aws-crypto-public-key` SHOULD NOT be present

  ## Examples

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_signing_context_consistency(suite, %{})
      :ok

      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_signing_context_consistency(suite, %{})
      {:error, :missing_public_key_in_context}

  """
  @spec validate_signing_context_consistency(AlgorithmSuite.t(), %{String.t() => String.t()}) ::
          :ok | {:error, :missing_public_key_in_context | :unexpected_public_key_in_context}
  def validate_signing_context_consistency(suite, context) do
    is_signed = AlgorithmSuite.signed?(suite)
    has_public_key = Map.has_key?(context, @reserved_ec_key)

    cond do
      is_signed and not has_public_key ->
        {:error, :missing_public_key_in_context}

      not is_signed and has_public_key ->
        {:error, :unexpected_public_key_in_context}

      true ->
        :ok
    end
  end

  @doc """
  Validates encryption context against reproduced encryption context.

  For any key that exists in both contexts, the values MUST be equal.
  Keys that exist only in one context are allowed.

  ## Examples

      iex> context = %{"key1" => "value1", "key2" => "value2"}
      iex> reproduced = %{"key1" => "value1"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_reproduced_context(context, reproduced)
      :ok

      iex> context = %{"key1" => "value1"}
      iex> reproduced = %{"key1" => "different"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.validate_reproduced_context(context, reproduced)
      {:error, {:encryption_context_mismatch, "key1"}}

  """
  @spec validate_reproduced_context(
          %{String.t() => String.t()},
          %{String.t() => String.t()} | nil
        ) :: :ok | {:error, {:encryption_context_mismatch, String.t()}}
  def validate_reproduced_context(_context, nil), do: :ok

  def validate_reproduced_context(context, reproduced) when is_map(reproduced) do
    # Find any key where both contexts have a value but they differ
    mismatched_key =
      Enum.find(reproduced, fn {key, reproduced_value} ->
        case Map.fetch(context, key) do
          {:ok, context_value} -> context_value != reproduced_value
          :error -> false
        end
      end)

    case mismatched_key do
      nil -> :ok
      {key, _value} -> {:error, {:encryption_context_mismatch, key}}
    end
  end

  @doc """
  Merges reproduced encryption context into decryption context.

  Keys from reproduced context that are not in the original context
  are appended to the decryption materials context.

  ## Examples

      iex> context = %{"key1" => "value1"}
      iex> reproduced = %{"key1" => "value1", "key2" => "value2"}
      iex> AwsEncryptionSdk.Cmm.Behaviour.merge_reproduced_context(context, reproduced)
      %{"key1" => "value1", "key2" => "value2"}

  """
  @spec merge_reproduced_context(
          %{String.t() => String.t()},
          %{String.t() => String.t()} | nil
        ) :: %{String.t() => String.t()}
  def merge_reproduced_context(context, nil), do: context

  def merge_reproduced_context(context, reproduced) when is_map(reproduced) do
    Map.merge(reproduced, context)
  end
end
