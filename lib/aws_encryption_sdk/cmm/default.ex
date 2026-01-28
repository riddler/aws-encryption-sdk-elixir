defmodule AwsEncryptionSdk.Cmm.Default do
  @moduledoc """
  Default Cryptographic Materials Manager implementation.

  The Default CMM wraps a keyring and provides the standard CMM behavior for
  encryption and decryption operations. It handles:

  - Algorithm suite selection and validation against commitment policy
  - Signing key generation for signed algorithm suites
  - Keyring orchestration for data key generation/encryption/decryption
  - Materials validation

  ## Example

      # Create a keyring
      {:ok, keyring} = RawAes.new("namespace", "key-name", key_bytes, :aes_256_gcm)

      # Create the CMM
      cmm = Default.new(keyring)

      # Get encryption materials
      {:ok, materials} = Default.get_encryption_materials(cmm, %{
        encryption_context: %{"purpose" => "example"},
        commitment_policy: :require_encrypt_require_decrypt
      })

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
  """

  @behaviour AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, Multi, RawAes, RawRsa}
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type keyring :: RawAes.t() | RawRsa.t() | Multi.t() | AwsKms.t() | AwsKmsDiscovery.t()

  @type t :: %__MODULE__{
          keyring: keyring()
        }

  defstruct [:keyring]

  @doc """
  Creates a new Default CMM wrapping the given keyring.

  ## Parameters

  - `keyring` - A keyring struct (RawAes, RawRsa, or Multi)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, aes_keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.Default.new(aes_keyring)
      iex> is_struct(cmm, AwsEncryptionSdk.Cmm.Default)
      true

  """
  @spec new(keyring()) :: t()
  def new(keyring) do
    %__MODULE__{keyring: keyring}
  end

  # Keyring dispatch helpers - reuse pattern from Multi-keyring

  @doc false
  @spec call_wrap_key(keyring(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def call_wrap_key(%RawAes{} = keyring, materials) do
    RawAes.wrap_key(keyring, materials)
  end

  def call_wrap_key(%RawRsa{} = keyring, materials) do
    RawRsa.wrap_key(keyring, materials)
  end

  def call_wrap_key(%Multi{} = keyring, materials) do
    Multi.wrap_key(keyring, materials)
  end

  def call_wrap_key(%AwsKms{} = keyring, materials) do
    AwsKms.wrap_key(keyring, materials)
  end

  def call_wrap_key(%AwsKmsDiscovery{} = keyring, materials) do
    AwsKmsDiscovery.wrap_key(keyring, materials)
  end

  def call_wrap_key(keyring, _materials) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  @doc false
  @spec call_unwrap_key(keyring(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def call_unwrap_key(%RawAes{} = keyring, materials, edks) do
    RawAes.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%RawRsa{} = keyring, materials, edks) do
    RawRsa.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%Multi{} = keyring, materials, edks) do
    Multi.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%AwsKms{} = keyring, materials, edks) do
    AwsKms.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(%AwsKmsDiscovery{} = keyring, materials, edks) do
    AwsKmsDiscovery.unwrap_key(keyring, materials, edks)
  end

  def call_unwrap_key(keyring, _materials, _edks) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  # Implementation

  @impl CmmBehaviour
  def get_encryption_materials(%__MODULE__{keyring: keyring}, request) do
    %{
      encryption_context: context,
      commitment_policy: policy
    } = request

    requested_suite = Map.get(request, :algorithm_suite)
    required_keys = Map.get(request, :required_encryption_context_keys, [])

    with :ok <- CmmBehaviour.validate_encryption_context_for_encrypt(context),
         suite = select_algorithm_suite(requested_suite, policy),
         :ok <- CmmBehaviour.validate_commitment_policy_for_encrypt(suite, policy),
         {:ok, context_with_signing, signing_key} <- maybe_add_signing_context(suite, context),
         initial_materials =
           create_initial_encryption_materials(
             suite,
             context_with_signing,
             signing_key,
             required_keys
           ),
         {:ok, materials} <- call_wrap_key(keyring, initial_materials),
         :ok <- CmmBehaviour.validate_encryption_materials(materials) do
      {:ok, materials}
    end
  end

  defp select_algorithm_suite(nil, policy) do
    CmmBehaviour.default_algorithm_suite(policy)
  end

  defp select_algorithm_suite(suite, _policy) do
    suite
  end

  defp maybe_add_signing_context(suite, context) do
    if AlgorithmSuite.signed?(suite) do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      encoded_public_key = ECDSA.encode_public_key(public_key)
      reserved_key = CmmBehaviour.reserved_encryption_context_key()
      updated_context = Map.put(context, reserved_key, encoded_public_key)
      {:ok, updated_context, private_key}
    else
      {:ok, context, nil}
    end
  end

  defp create_initial_encryption_materials(suite, context, signing_key, required_keys) do
    EncryptionMaterials.new_for_encrypt(suite, context,
      signing_key: signing_key,
      required_encryption_context_keys: required_keys
    )
  end

  @impl CmmBehaviour
  def get_decryption_materials(%__MODULE__{keyring: keyring}, request) do
    %{
      algorithm_suite: suite,
      commitment_policy: policy,
      encrypted_data_keys: edks,
      encryption_context: context
    } = request

    reproduced_context = Map.get(request, :reproduced_encryption_context)

    with :ok <- CmmBehaviour.validate_commitment_policy_for_decrypt(suite, policy),
         :ok <- CmmBehaviour.validate_reproduced_context(context, reproduced_context),
         :ok <- CmmBehaviour.validate_signing_context_consistency(suite, context),
         {:ok, verification_key} <- extract_verification_key(suite, context),
         # Use ORIGINAL context for keyring (for AAD validation)
         initial_materials =
           create_initial_decryption_materials(suite, context, verification_key),
         {:ok, materials} <- call_unwrap_key(keyring, initial_materials, edks),
         # Merge reproduced context AFTER decryption
         final_materials = merge_reproduced_into_materials(materials, reproduced_context),
         :ok <- CmmBehaviour.validate_decryption_materials(final_materials) do
      {:ok, final_materials}
    end
  end

  defp extract_verification_key(suite, context) do
    if AlgorithmSuite.signed?(suite) do
      reserved_key = CmmBehaviour.reserved_encryption_context_key()

      case Map.fetch(context, reserved_key) do
        {:ok, encoded_key} ->
          ECDSA.decode_public_key(encoded_key)

        :error ->
          # This should have been caught by validate_signing_context_consistency
          {:error, :missing_verification_key}
      end
    else
      {:ok, nil}
    end
  end

  defp create_initial_decryption_materials(suite, context, verification_key) do
    DecryptionMaterials.new_for_decrypt(suite, context, verification_key: verification_key)
  end

  defp merge_reproduced_into_materials(materials, nil), do: materials

  defp merge_reproduced_into_materials(materials, reproduced_context) do
    merged_context =
      CmmBehaviour.merge_reproduced_context(materials.encryption_context, reproduced_context)

    %{materials | encryption_context: merged_context}
  end
end
