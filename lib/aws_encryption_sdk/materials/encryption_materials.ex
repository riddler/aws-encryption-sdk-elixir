defmodule AwsEncryptionSdk.Materials.EncryptionMaterials do
  @moduledoc """
  Materials required for encryption operations.

  These materials are typically provided by a Cryptographic Materials Manager (CMM)
  or can be constructed directly for testing purposes.
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  @type t :: %__MODULE__{
          algorithm_suite: AlgorithmSuite.t(),
          encryption_context: %{String.t() => String.t()},
          encrypted_data_keys: [EncryptedDataKey.t()],
          plaintext_data_key: binary(),
          signing_key: binary() | nil,
          required_encryption_context_keys: [String.t()]
        }

  @enforce_keys [
    :algorithm_suite,
    :encryption_context,
    :encrypted_data_keys,
    :plaintext_data_key
  ]

  defstruct [
    :algorithm_suite,
    :encryption_context,
    :encrypted_data_keys,
    :plaintext_data_key,
    :signing_key,
    required_encryption_context_keys: []
  ]

  @doc """
  Creates new encryption materials.

  ## Parameters

  - `algorithm_suite` - Algorithm suite to use
  - `encryption_context` - Encryption context map
  - `encrypted_data_keys` - List of encrypted data keys
  - `plaintext_data_key` - Raw data key bytes
  - `opts` - Optional fields (:signing_key, :required_encryption_context_keys)
  """
  @spec new(AlgorithmSuite.t(), map(), [EncryptedDataKey.t()], binary(), keyword()) :: t()
  def new(
        algorithm_suite,
        encryption_context,
        encrypted_data_keys,
        plaintext_data_key,
        opts \\ []
      ) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      encrypted_data_keys: encrypted_data_keys,
      plaintext_data_key: plaintext_data_key,
      signing_key: Keyword.get(opts, :signing_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end
end
