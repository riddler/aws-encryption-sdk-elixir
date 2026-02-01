defmodule AwsEncryptionSdk.Cmm.RequiredEncryptionContext do
  @moduledoc """
  Required Encryption Context CMM implementation.

  This CMM wraps another CMM and enforces that specific encryption context keys
  are present throughout encryption and decryption operations. It provides:

  - **Encryption validation**: Ensures required keys exist in caller's encryption context
  - **Decryption validation**: Ensures required keys exist in reproduced encryption context
  - **Key propagation**: Marks required keys in materials for downstream tracking
  - **Security enforcement**: Prevents accidental removal of critical AAD components

  ## Example

      # Create with a keyring (auto-wraps in Default CMM)
      {:ok, keyring} = RawAes.new("namespace", "key-name", key_bytes, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)

      # Or wrap an existing CMM
      default_cmm = Default.new(keyring)
      cmm = RequiredEncryptionContext.new(["tenant-id"], default_cmm)

      # Use with Client
      client = Client.new(cmm)

      # Encrypt - will fail if context missing required keys
      {:ok, result} = Client.encrypt(client, plaintext,
        encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
      )

      # Decrypt - must provide required keys in reproduced context
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext,
        encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
      )

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md
  """

  @behaviour AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Cmm.Default

  @type t :: %__MODULE__{
          required_encryption_context_keys: [String.t()],
          underlying_cmm: CmmBehaviour.t()
        }

  defstruct [:required_encryption_context_keys, :underlying_cmm]

  @doc """
  Creates a new Required Encryption Context CMM wrapping an existing CMM.

  ## Parameters

  - `required_keys` - List of encryption context keys that must be present
  - `underlying_cmm` - The CMM to wrap (e.g., Default CMM)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> default_cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new(["tenant-id"], default_cmm)
      iex> cmm.required_encryption_context_keys
      ["tenant-id"]

  """
  @spec new([String.t()], CmmBehaviour.t()) :: t()
  def new(required_keys, underlying_cmm)
      when is_list(required_keys) do
    %__MODULE__{
      required_encryption_context_keys: required_keys,
      underlying_cmm: underlying_cmm
    }
  end

  @doc """
  Creates a new Required Encryption Context CMM from a keyring.

  The keyring is automatically wrapped in a Default CMM.

  ## Parameters

  - `required_keys` - List of encryption context keys that must be present
  - `keyring` - A keyring struct (RawAes, RawRsa, Multi, AwsKms, etc.)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      iex> cmm.required_encryption_context_keys
      ["tenant-id"]

  """
  @spec new_with_keyring([String.t()], Default.keyring()) :: t()
  def new_with_keyring(required_keys, keyring)
      when is_list(required_keys) do
    underlying_cmm = Default.new(keyring)
    new(required_keys, underlying_cmm)
  end

  @impl CmmBehaviour
  def get_encryption_materials(%__MODULE__{} = cmm, request) do
    %{encryption_context: context} = request

    with :ok <- validate_required_keys_in_context(cmm.required_encryption_context_keys, context),
         updated_request = add_required_keys_to_request(cmm, request),
         {:ok, materials} <- call_underlying_cmm_encrypt(cmm.underlying_cmm, updated_request),
         :ok <-
           validate_required_keys_in_materials(cmm.required_encryption_context_keys, materials) do
      # Update materials to include required encryption context keys for header auth
      # Merge with any existing required keys from underlying CMM
      all_required_keys =
        (materials.required_encryption_context_keys ++ cmm.required_encryption_context_keys)
        |> Enum.uniq()

      updated_materials = %{
        materials
        | required_encryption_context_keys: all_required_keys
      }

      {:ok, updated_materials}
    end
  end

  @impl CmmBehaviour
  def get_decryption_materials(%__MODULE__{} = cmm, request) do
    reproduced_context = Map.get(request, :reproduced_encryption_context) || %{}

    with :ok <-
           validate_required_keys_in_reproduced_context(
             cmm.required_encryption_context_keys,
             reproduced_context
           ),
         {:ok, materials} <- call_underlying_cmm_decrypt(cmm.underlying_cmm, request),
         :ok <-
           validate_required_keys_in_decryption_materials(
             cmm.required_encryption_context_keys,
             materials
           ) do
      # Update materials to include required encryption context keys for header auth
      # Merge with any existing required keys from underlying CMM
      all_required_keys =
        (materials.required_encryption_context_keys ++ cmm.required_encryption_context_keys)
        |> Enum.uniq()

      updated_materials = %{
        materials
        | required_encryption_context_keys: all_required_keys
      }

      {:ok, updated_materials}
    end
  end

  # Validates that all required keys exist in the encryption context
  defp validate_required_keys_in_context(required_keys, context) do
    missing_keys =
      required_keys
      |> Enum.reject(&Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, {:missing_required_encryption_context_keys, missing_keys}}
    end
  end

  # Merges configured required keys with any existing required keys in request
  defp add_required_keys_to_request(cmm, request) do
    existing_required = Map.get(request, :required_encryption_context_keys, [])

    merged_required =
      (existing_required ++ cmm.required_encryption_context_keys)
      |> Enum.uniq()

    Map.put(request, :required_encryption_context_keys, merged_required)
  end

  # Dispatches to underlying CMM based on struct type
  defp call_underlying_cmm_encrypt(%Default{} = cmm, request) do
    Default.get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(%__MODULE__{} = cmm, request) do
    get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(%Caching{} = cmm, request) do
    Caching.get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  # Validates that returned materials have all required keys marked as required
  defp validate_required_keys_in_materials(required_keys, materials) do
    materials_required_keys = materials.required_encryption_context_keys
    missing_keys = required_keys -- materials_required_keys

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, {:required_keys_not_in_materials, missing_keys}}
    end
  end

  # Validates that all required keys exist in the reproduced encryption context
  defp validate_required_keys_in_reproduced_context(required_keys, reproduced_context) do
    missing_keys =
      required_keys
      |> Enum.reject(&Map.has_key?(reproduced_context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, {:missing_required_encryption_context_keys, missing_keys}}
    end
  end

  # Dispatches to underlying CMM based on struct type
  defp call_underlying_cmm_decrypt(%Default{} = cmm, request) do
    Default.get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(%__MODULE__{} = cmm, request) do
    get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(%Caching{} = cmm, request) do
    Caching.get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  # Validates that returned materials have all required keys in encryption context
  defp validate_required_keys_in_decryption_materials(required_keys, materials) do
    context = materials.encryption_context
    missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

    if Enum.empty?(missing_keys) do
      :ok
    else
      {:error, {:required_keys_not_in_decryption_context, missing_keys}}
    end
  end
end
