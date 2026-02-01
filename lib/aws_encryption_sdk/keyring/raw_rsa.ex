defmodule AwsEncryptionSdk.Keyring.RawRsa do
  @moduledoc """
  Raw RSA Keyring implementation.

  Uses locally-provided RSA key pairs to wrap and unwrap data keys using
  asymmetric encryption. Supports multiple padding schemes.

  ## Example

      iex> {:ok, public_key} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem_string)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawRsa.new("my-ns", "my-key", {:oaep, :sha256}, public_key: public_key)
      iex> is_struct(keyring, AwsEncryptionSdk.Keyring.RawRsa)
      true

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.Behaviour, as: KeyringBehaviour
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @typedoc "RSA padding scheme"
  @type padding_scheme ::
          :pkcs1_v1_5
          | {:oaep, :sha1}
          | {:oaep, :sha256}
          | {:oaep, :sha384}
          | {:oaep, :sha512}

  @typedoc "RSA public key in Erlang format"
  @type rsa_public_key :: {:RSAPublicKey, integer(), integer()}

  @typedoc "RSA private key in Erlang format"
  @type rsa_private_key :: tuple()

  @type t :: %__MODULE__{
          key_namespace: String.t(),
          key_name: String.t(),
          padding_scheme: padding_scheme(),
          public_key: rsa_public_key() | nil,
          private_key: rsa_private_key() | nil
        }

  @enforce_keys [:key_namespace, :key_name, :padding_scheme]
  defstruct [:key_namespace, :key_name, :padding_scheme, :public_key, :private_key]

  @valid_padding_schemes [
    :pkcs1_v1_5,
    {:oaep, :sha1},
    {:oaep, :sha256},
    {:oaep, :sha384},
    {:oaep, :sha512}
  ]

  @doc """
  Creates a new Raw RSA Keyring.

  ## Parameters

  - `key_namespace` - Key provider ID (must not start with "aws-kms")
  - `key_name` - Unique identifier for the key pair
  - `padding_scheme` - One of `:pkcs1_v1_5`, `{:oaep, :sha1}`, `{:oaep, :sha256}`, `{:oaep, :sha384}`, `{:oaep, :sha512}`
  - `opts` - Keyword list with `:public_key` and/or `:private_key` (at least one required)

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :reserved_provider_id}` - key_namespace starts with "aws-kms"
  - `{:error, :invalid_padding_scheme}` - unsupported padding scheme
  - `{:error, :no_keys_provided}` - neither public nor private key provided

  ## Examples

      iex> {:ok, pub} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
      iex> keyring.padding_scheme
      {:oaep, :sha256}

  """
  @spec new(String.t(), String.t(), padding_scheme(), keyword()) ::
          {:ok, t()} | {:error, term()}
  def new(key_namespace, key_name, padding_scheme, opts \\ [])
      when is_binary(key_namespace) and is_binary(key_name) and is_list(opts) do
    public_key = Keyword.get(opts, :public_key)
    private_key = Keyword.get(opts, :private_key)

    with :ok <- KeyringBehaviour.validate_provider_id(key_namespace),
         :ok <- validate_padding_scheme(padding_scheme),
         :ok <- validate_at_least_one_key(public_key, private_key) do
      {:ok,
       %__MODULE__{
         key_namespace: key_namespace,
         key_name: key_name,
         padding_scheme: padding_scheme,
         public_key: public_key,
         private_key: private_key
       }}
    end
  end

  defp validate_padding_scheme(scheme) when scheme in @valid_padding_schemes, do: :ok
  defp validate_padding_scheme(_scheme), do: {:error, :invalid_padding_scheme}

  defp validate_at_least_one_key(nil, nil), do: {:error, :no_keys_provided}
  defp validate_at_least_one_key(_public, _private), do: :ok

  @doc false
  @spec padding_options(padding_scheme()) :: list()
  def padding_options(:pkcs1_v1_5), do: [{:rsa_padding, :rsa_pkcs1_padding}]

  def padding_options({:oaep, :sha1}) do
    [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha}, {:rsa_mgf1_md, :sha}]
  end

  def padding_options({:oaep, :sha256}) do
    [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha256}, {:rsa_mgf1_md, :sha256}]
  end

  def padding_options({:oaep, :sha384}) do
    [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha384}, {:rsa_mgf1_md, :sha384}]
  end

  def padding_options({:oaep, :sha512}) do
    [{:rsa_padding, :rsa_pkcs1_oaep_padding}, {:rsa_oaep_md, :sha512}, {:rsa_mgf1_md, :sha512}]
  end

  @doc """
  Wraps a data key using this keyring's public key.

  If materials don't have a plaintext data key, one will be generated.
  The wrapped key is added to the materials as an EDK.

  ## Examples

      iex> {:ok, pub} = RawRsa.load_public_key_pem(pem)
      iex> {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, public_key: pub)
      iex> suite = AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      iex> materials = AwsEncryptionSdk.Materials.EncryptionMaterials.new_for_encrypt(suite, %{})
      iex> {:ok, result} = RawRsa.wrap_key(keyring, materials)
      iex> length(result.encrypted_data_keys) == 1
      true

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{public_key: nil}, _materials) do
    {:error, :no_public_key}
  end

  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    with {:ok, materials} <- ensure_data_key(keyring, materials),
         {:ok, edk} <- encrypt_data_key(keyring, materials.plaintext_data_key) do
      {:ok, EncryptionMaterials.add_encrypted_data_key(materials, edk)}
    end
  end

  defp ensure_data_key(_keyring, materials) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:ok, materials}
    else
      key = KeyringBehaviour.generate_data_key(materials.algorithm_suite)
      {:ok, EncryptionMaterials.set_plaintext_data_key(materials, key)}
    end
  end

  defp encrypt_data_key(%__MODULE__{} = keyring, plaintext_key) do
    padding_opts = padding_options(keyring.padding_scheme)

    try do
      ciphertext = :public_key.encrypt_public(plaintext_key, keyring.public_key, padding_opts)

      # For RSA, provider_info is just the key_name (no additional structure like AES)
      edk = EncryptedDataKey.new(keyring.key_namespace, keyring.key_name, ciphertext)
      {:ok, edk}
    rescue
      _error -> {:error, :encryption_failed}
    end
  end

  @doc """
  Unwraps a data key using this keyring's private key.

  Iterates through EDKs to find one that:
  1. Has matching key_provider_id (key_namespace)
  2. Has matching key_provider_info (key_name)
  3. Successfully decrypts with this keyring's private key

  ## Returns

  - `{:ok, materials}` - Data key successfully unwrapped and set
  - `{:error, :no_private_key}` - No private key configured
  - `{:error, :plaintext_data_key_already_set}` - Materials already have a key
  - `{:error, :unable_to_decrypt_data_key}` - No matching EDK could be decrypted

  ## Examples

      iex> {:ok, priv} = RawRsa.load_private_key_pem(pem)
      iex> {:ok, keyring} = RawRsa.new("ns", "key", {:oaep, :sha256}, private_key: priv)
      iex> dec_materials = DecryptionMaterials.new_for_decrypt(suite, ec)
      iex> {:ok, result} = RawRsa.unwrap_key(keyring, dec_materials, edks)
      iex> is_binary(result.plaintext_data_key)
      true

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{private_key: nil}, _materials, _edks) do
    {:error, :no_private_key}
  end

  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    if KeyringBehaviour.has_plaintext_data_key?(materials) do
      {:error, :plaintext_data_key_already_set}
    else
      try_decrypt_edks(keyring, materials, edks)
    end
  end

  defp try_decrypt_edks(keyring, materials, edks) do
    result =
      Enum.reduce_while(edks, :no_match, fn edk, _acc ->
        case try_decrypt_edk(keyring, edk) do
          {:ok, plaintext_key} -> {:halt, {:ok, plaintext_key}}
          {:error, _reason} -> {:cont, :no_match}
        end
      end)

    case result do
      {:ok, plaintext_key} ->
        DecryptionMaterials.set_plaintext_data_key(materials, plaintext_key)

      :no_match ->
        {:error, :unable_to_decrypt_data_key}
    end
  end

  defp try_decrypt_edk(keyring, edk) do
    with :ok <- match_provider_id(keyring, edk),
         :ok <- match_key_name(keyring, edk) do
      decrypt_with_private_key(keyring, edk.ciphertext)
    end
  end

  defp match_provider_id(keyring, edk) do
    if edk.key_provider_id == keyring.key_namespace do
      :ok
    else
      {:error, :provider_id_mismatch}
    end
  end

  defp match_key_name(keyring, edk) do
    if edk.key_provider_info == keyring.key_name do
      :ok
    else
      {:error, :key_name_mismatch}
    end
  end

  defp decrypt_with_private_key(keyring, ciphertext) do
    padding_opts = padding_options(keyring.padding_scheme)

    try do
      plaintext = :public_key.decrypt_private(ciphertext, keyring.private_key, padding_opts)
      {:ok, plaintext}
    rescue
      _error -> {:error, :decryption_failed}
    end
  end

  @doc """
  Loads an RSA public key from PEM-encoded string.

  Supports X.509 SubjectPublicKeyInfo and RSAPublicKey formats.

  ## Examples

      iex> pem = "-----BEGIN PUBLIC KEY-----\\n..."
      iex> {:ok, key} = AwsEncryptionSdk.Keyring.RawRsa.load_public_key_pem(pem)

  """
  @spec load_public_key_pem(String.t()) :: {:ok, rsa_public_key()} | {:error, term()}
  def load_public_key_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{type, _der, _not_encrypted} = entry]
      when type in [:SubjectPublicKeyInfo, :RSAPublicKey] ->
        {:ok, :public_key.pem_entry_decode(entry)}

      [] ->
        {:error, :invalid_pem_format}

      _other ->
        {:error, :unsupported_key_type}
    end
  rescue
    _error -> {:error, :pem_decode_failed}
  end

  @doc """
  Loads an RSA private key from PEM-encoded string.

  Supports PKCS#8 PrivateKeyInfo and RSAPrivateKey formats.

  ## Examples

      iex> pem = "-----BEGIN PRIVATE KEY-----\\n..."
      iex> {:ok, key} = AwsEncryptionSdk.Keyring.RawRsa.load_private_key_pem(pem)

  """
  @spec load_private_key_pem(String.t()) :: {:ok, rsa_private_key()} | {:error, term()}
  def load_private_key_pem(pem_string) when is_binary(pem_string) do
    case :public_key.pem_decode(pem_string) do
      [{type, _der, _not_encrypted} = entry] when type in [:PrivateKeyInfo, :RSAPrivateKey] ->
        {:ok, :public_key.pem_entry_decode(entry)}

      [] ->
        {:error, :invalid_pem_format}

      _other ->
        {:error, :unsupported_key_type}
    end
  rescue
    _error -> {:error, :pem_decode_failed}
  end

  # Behaviour callbacks (Phases 2-3 will add wrap_key/unwrap_key)
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call RawRsa.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error, {:must_use_unwrap_key, "Call RawRsa.unwrap_key(keyring, materials, edks) instead"}}
  end
end
