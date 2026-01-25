defmodule AwsEncryptionSdk.Materials.DecryptionMaterials do
  @moduledoc """
  Materials required for decryption operations.

  These materials are typically provided by a Cryptographic Materials Manager (CMM)
  or can be constructed directly for testing purposes.
  """

  alias AwsEncryptionSdk.AlgorithmSuite

  @type t :: %__MODULE__{
          algorithm_suite: AlgorithmSuite.t(),
          encryption_context: %{String.t() => String.t()},
          plaintext_data_key: binary(),
          verification_key: binary() | nil,
          required_encryption_context_keys: [String.t()]
        }

  @enforce_keys [
    :algorithm_suite,
    :encryption_context,
    :plaintext_data_key
  ]

  defstruct [
    :algorithm_suite,
    :encryption_context,
    :plaintext_data_key,
    :verification_key,
    required_encryption_context_keys: []
  ]

  @doc """
  Creates new decryption materials.

  ## Parameters

  - `algorithm_suite` - Algorithm suite from message header
  - `encryption_context` - Encryption context from message header
  - `plaintext_data_key` - Decrypted data key
  - `opts` - Optional fields (:verification_key, :required_encryption_context_keys)
  """
  @spec new(AlgorithmSuite.t(), map(), binary(), keyword()) :: t()
  def new(algorithm_suite, encryption_context, plaintext_data_key, opts \\ []) do
    %__MODULE__{
      algorithm_suite: algorithm_suite,
      encryption_context: encryption_context,
      plaintext_data_key: plaintext_data_key,
      verification_key: Keyword.get(opts, :verification_key),
      required_encryption_context_keys: Keyword.get(opts, :required_encryption_context_keys, [])
    }
  end
end
