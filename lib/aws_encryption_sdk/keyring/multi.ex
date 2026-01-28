defmodule AwsEncryptionSdk.Keyring.Multi do
  @moduledoc """
  Multi-Keyring implementation.

  Composes multiple keyrings together, enabling encryption with multiple keys
  and flexible decryption with any available key.

  ## Use Cases

  - **Redundancy**: Encrypt with multiple keys so any one can decrypt
  - **Key rotation**: Include both old and new keys during transitions
  - **Multi-party access**: Different parties can decrypt with their respective keys

  ## Encryption Behavior

  - Generator keyring (if provided) generates and wraps the plaintext data key
  - Each child keyring wraps the plaintext data key (adding additional EDKs)
  - All keyrings must succeed (fail-fast)
  - EDKs accumulate through the pipeline

  ## Decryption Behavior

  - Attempts decryption with generator first (if provided), then children
  - Each keyring receives the original, unmodified materials
  - Returns immediately on first successful decryption
  - Fails only if all keyrings fail to decrypt

  ## Security Note

  Any keyring in the multi-keyring can decrypt data encrypted with this keyring.
  Users should understand the security implications of their keyring composition.

  ## Example

      # Create keyrings
      {:ok, aes_keyring} = RawAes.new("ns", "aes-key", aes_key, :aes_256_gcm)
      {:ok, rsa_keyring} = RawRsa.new("ns", "rsa-key", {:oaep, :sha256}, public_key: pub, private_key: priv)

      # Create multi-keyring with generator and child
      {:ok, multi} = Multi.new(generator: aes_keyring, children: [rsa_keyring])

      # Encrypt - AES generates key, both keyrings wrap it
      {:ok, enc_materials} = Multi.wrap_key(multi, materials)

      # Decrypt - tries AES first, then RSA
      {:ok, dec_materials} = Multi.unwrap_key(multi, materials, edks)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.{AwsKms, RawAes, RawRsa}
  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type keyring :: struct()

  @type t :: %__MODULE__{
          generator: keyring() | nil,
          children: [keyring()]
        }

  defstruct [:generator, children: []]

  @doc """
  Creates a new Multi-Keyring.

  ## Options

  - `:generator` - Optional keyring that generates the plaintext data key during encryption
  - `:children` - List of keyrings that wrap the data key (default: `[]`)

  At least one of generator or children must be provided.
  If children is empty, generator is required.

  ## Returns

  - `{:ok, multi_keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :no_keyrings_provided}` - Neither generator nor children provided
  - `{:error, :generator_required_when_no_children}` - Children empty but no generator

  ## Examples

      # Generator with children
      {:ok, multi} = Multi.new(generator: aes_keyring, children: [rsa_keyring])

      # Generator only
      {:ok, multi} = Multi.new(generator: aes_keyring)

      # Children only (materials must already have plaintext data key for encryption)
      {:ok, multi} = Multi.new(children: [rsa_keyring_1, rsa_keyring_2])

  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts \\ []) when is_list(opts) do
    generator = Keyword.get(opts, :generator)
    children = Keyword.get(opts, :children, [])

    with :ok <- validate_at_least_one_keyring(generator, children),
         :ok <- validate_generator_when_no_children(generator, children) do
      {:ok, %__MODULE__{generator: generator, children: children}}
    end
  end

  defp validate_at_least_one_keyring(nil, []), do: {:error, :no_keyrings_provided}
  defp validate_at_least_one_keyring(_generator, _children), do: :ok

  defp validate_generator_when_no_children(nil, []),
    do: {:error, :generator_required_when_no_children}

  defp validate_generator_when_no_children(_generator, _children), do: :ok

  @doc """
  Returns the list of all keyrings in this multi-keyring.

  Useful for understanding which keyrings will be used for encryption/decryption.

  ## Examples

      {:ok, multi} = Multi.new(generator: gen, children: [child1, child2])
      Multi.list_keyrings(multi)
      # => [gen, child1, child2]

  """
  @spec list_keyrings(t()) :: [keyring()]
  def list_keyrings(%__MODULE__{generator: nil, children: children}), do: children
  def list_keyrings(%__MODULE__{generator: gen, children: children}), do: [gen | children]

  # Placeholder implementations - will be completed in Phases 2 and 3

  @doc """
  Wraps a data key using all keyrings in the multi-keyring.

  If a generator is present, it generates and wraps the plaintext data key.
  Each child keyring then wraps the same plaintext data key, adding additional EDKs.

  All keyrings must succeed (fail-fast on any error).

  ## Returns

  - `{:ok, materials}` - Data key wrapped by all keyrings
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key (with generator)
  - `{:error, :no_plaintext_data_key}` - No generator and materials have no plaintext key
  - `{:error, {:generator_failed, reason}}` - Generator keyring failed
  - `{:error, {:generator_did_not_produce_key}}` - Generator didn't set plaintext key
  - `{:error, {:child_keyring_failed, index, reason}}` - Child keyring failed

  ## Examples

      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])
      enc_materials = EncryptionMaterials.new_for_encrypt(suite, ec)
      {:ok, result} = Multi.wrap_key(multi, enc_materials)

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    with {:ok, materials} <- maybe_call_generator(keyring.generator, materials),
         {:ok, materials} <- validate_has_plaintext_key(keyring.generator, materials) do
      wrap_with_children(keyring.children, materials)
    end
  end

  # When generator is present, call it first
  defp maybe_call_generator(nil, materials), do: {:ok, materials}

  defp maybe_call_generator(generator, materials) do
    # Spec: MUST fail if materials already have plaintext key when generator present
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      case call_wrap_key(generator, materials) do
        {:ok, result} -> {:ok, result}
        {:error, reason} -> {:error, {:generator_failed, reason}}
      end
    end
  end

  # Validate that we have a plaintext key after generator (or before children if no generator)
  defp validate_has_plaintext_key(_generator, materials) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:ok, materials}
    else
      {:error, :no_plaintext_data_key}
    end
  end

  # Call each child keyring in sequence, chaining outputs
  defp wrap_with_children(children, materials) do
    children
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, materials}, fn {child, index}, {:ok, acc_materials} ->
      case call_wrap_key(child, acc_materials) do
        {:ok, result} ->
          {:cont, {:ok, result}}

        {:error, reason} ->
          {:halt, {:error, {:child_keyring_failed, index, reason}}}
      end
    end)
  end

  # Dispatch to the appropriate wrap_key function based on keyring type
  defp call_wrap_key(%RawAes{} = keyring, materials) do
    RawAes.wrap_key(keyring, materials)
  end

  defp call_wrap_key(%RawRsa{} = keyring, materials) do
    RawRsa.wrap_key(keyring, materials)
  end

  defp call_wrap_key(%AwsKms{} = keyring, materials) do
    AwsKms.wrap_key(keyring, materials)
  end

  defp call_wrap_key(%__MODULE__{} = keyring, materials) do
    # Nested multi-keyring
    wrap_key(keyring, materials)
  end

  defp call_wrap_key(keyring, _materials) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  @doc """
  Unwraps a data key using the keyrings in the multi-keyring.

  Attempts decryption with generator first (if present), then each child keyring
  in order. Returns immediately when any keyring successfully decrypts.

  Each keyring receives the original, unmodified materials (not chained).

  ## Returns

  - `{:ok, materials}` - Data key successfully unwrapped by one of the keyrings
  - `{:error, :plaintext_data_key_already_set}` - Materials already have a key
  - `{:error, {:all_keyrings_failed, [reasons]}}` - All keyrings failed to decrypt

  ## Examples

      {:ok, multi} = Multi.new(generator: keyring1, children: [keyring2])
      dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      {:ok, result} = Multi.unwrap_key(multi, dec_materials, edks)

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      keyrings = list_keyrings(keyring)
      attempt_decryption(keyrings, materials, edks, [])
    end
  end

  defp attempt_decryption([], _materials, _edks, errors) do
    # All keyrings failed - return collected errors
    {:error, {:all_keyrings_failed, Enum.reverse(errors)}}
  end

  defp attempt_decryption([keyring | rest], materials, edks, errors) do
    # Call the keyring's unwrap_key with unmodified materials
    case call_unwrap_key(keyring, materials, edks) do
      {:ok, result_materials} ->
        # Success - return immediately
        {:ok, result_materials}

      {:error, reason} ->
        # Collect error and continue to next keyring
        attempt_decryption(rest, materials, edks, [reason | errors])
    end
  end

  # Dispatch to the appropriate unwrap_key function based on keyring type
  defp call_unwrap_key(%RawAes{} = keyring, materials, edks) do
    RawAes.unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(%RawRsa{} = keyring, materials, edks) do
    RawRsa.unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(%AwsKms{} = keyring, materials, edks) do
    AwsKms.unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(%__MODULE__{} = keyring, materials, edks) do
    # Nested multi-keyring
    unwrap_key(keyring, materials, edks)
  end

  defp call_unwrap_key(keyring, _materials, _edks) do
    {:error, {:unsupported_keyring_type, keyring.__struct__}}
  end

  # Behaviour callbacks - follow existing pattern of directing to explicit functions
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call Multi.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call Multi.unwrap_key(keyring, materials, edks) instead"}}
  end
end
