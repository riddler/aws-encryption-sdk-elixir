defmodule AwsEncryptionSdk.Cmm.Caching do
  @moduledoc """
  Caching Cryptographic Materials Manager implementation.

  The Caching CMM wraps another CMM and caches cryptographic materials to reduce
  expensive calls to key providers. It provides:

  - **Performance**: Caches generated data keys and EDKs
  - **Security**: Enforces key rotation via TTL and usage limits
  - **Sharing**: Multiple Caching CMMs can share cache via Partition IDs

  ## Example

      # Create cache
      {:ok, cache} = LocalCache.start_link([])

      # Create caching CMM with keyring
      {:ok, keyring} = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      # Or wrap an existing CMM
      default_cmm = Default.new(keyring)
      cmm = Caching.new(default_cmm, cache, max_age: 300)

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md
  """

  @behaviour AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.{CacheEntry, LocalCache}
  alias AwsEncryptionSdk.Cmm.{Behaviour, Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  # Default limits per spec
  @default_max_bytes 9_223_372_036_854_775_807
  @default_max_messages 4_294_967_296

  @type cache :: LocalCache.t()

  @type t :: %__MODULE__{
          underlying_cmm: Behaviour.t(),
          cache: cache(),
          partition_id: binary(),
          max_age: pos_integer(),
          max_bytes: non_neg_integer(),
          max_messages: non_neg_integer()
        }

  @enforce_keys [:underlying_cmm, :cache, :partition_id, :max_age]
  defstruct [
    :underlying_cmm,
    :cache,
    :partition_id,
    :max_age,
    max_bytes: @default_max_bytes,
    max_messages: @default_max_messages
  ]

  @doc """
  Creates a new Caching CMM wrapping an existing CMM.

  ## Parameters

  - `underlying_cmm` - The CMM to wrap (Default, RequiredEncryptionContext, etc.)
  - `cache` - A CMC implementation (e.g., LocalCache pid)
  - `opts` - Options:
    - `:max_age` - Required. TTL in seconds (must be > 0)
    - `:partition_id` - Optional. UUID for cache partitioning (auto-generated if omitted)
    - `:max_bytes` - Optional. Maximum bytes to encrypt per entry (default: 2^63-1)
    - `:max_messages` - Optional. Maximum messages per entry (default: 2^32)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> default_cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> {:ok, cache} = AwsEncryptionSdk.Cache.LocalCache.start_link([])
      iex> cmm = AwsEncryptionSdk.Cmm.Caching.new(default_cmm, cache, max_age: 300)
      iex> is_struct(cmm, AwsEncryptionSdk.Cmm.Caching)
      true

  """
  @spec new(Behaviour.t(), cache(), keyword()) :: t()
  def new(underlying_cmm, cache, opts) do
    max_age = Keyword.fetch!(opts, :max_age)

    if max_age <= 0 do
      raise ArgumentError, "max_age must be greater than 0"
    end

    partition_id = Keyword.get_lazy(opts, :partition_id, &generate_partition_id/0)
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)
    max_messages = Keyword.get(opts, :max_messages, @default_max_messages)

    %__MODULE__{
      underlying_cmm: underlying_cmm,
      cache: cache,
      partition_id: partition_id,
      max_age: max_age,
      max_bytes: max_bytes,
      max_messages: max_messages
    }
  end

  @doc """
  Creates a new Caching CMM from a keyring.

  The keyring is automatically wrapped in a Default CMM.

  ## Parameters

  - `keyring` - A keyring struct
  - `cache` - A CMC implementation
  - `opts` - Same as `new/3`

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> {:ok, cache} = AwsEncryptionSdk.Cache.LocalCache.start_link([])
      iex> cmm = AwsEncryptionSdk.Cmm.Caching.new_with_keyring(keyring, cache, max_age: 300)
      iex> is_struct(cmm, AwsEncryptionSdk.Cmm.Caching)
      true

  """
  @spec new_with_keyring(Default.keyring(), cache(), keyword()) :: t()
  def new_with_keyring(keyring, cache, opts) do
    underlying_cmm = Default.new(keyring)
    new(underlying_cmm, cache, opts)
  end

  # CMM Behaviour Implementation

  @impl Behaviour
  def get_encryption_materials(%__MODULE__{} = cmm, request) do
    algorithm_suite = Map.get(request, :algorithm_suite)
    encryption_context = request.encryption_context

    # Identity KDF bypass - never cache deprecated suites
    if identity_kdf?(algorithm_suite) do
      call_underlying_cmm_encrypt(cmm.underlying_cmm, request)
    else
      cache_id =
        compute_encryption_cache_id(cmm.partition_id, algorithm_suite, encryption_context)

      handle_encryption_cache_lookup(cmm, cache_id, request)
    end
  end

  @impl Behaviour
  def get_decryption_materials(%__MODULE__{} = cmm, request) do
    algorithm_suite = request.algorithm_suite
    encryption_context = request.encryption_context
    edks = request.encrypted_data_keys

    # Identity KDF bypass - never cache deprecated suites
    if identity_kdf?(algorithm_suite) do
      call_underlying_cmm_decrypt(cmm.underlying_cmm, request)
    else
      cache_id =
        compute_decryption_cache_id(cmm.partition_id, algorithm_suite, edks, encryption_context)

      handle_decryption_cache_lookup(cmm, cache_id, request)
    end
  end

  # Cache ID Computation (Appendix A formulas)

  @doc false
  @spec compute_encryption_cache_id(binary(), AlgorithmSuite.t() | nil, map()) :: binary()
  def compute_encryption_cache_id(partition_id, algorithm_suite, encryption_context) do
    serialized_context = EncryptionContext.serialize(encryption_context)

    data =
      case algorithm_suite do
        nil ->
          # No suite specified: 0x01 || 0x00 || 0x01 || 0x00 || partition_id || 0x00 || 0x00 || 0x00 || context
          <<0x01, 0x00, 0x01, 0x00>> <>
            partition_id <> <<0x00, 0x00, 0x00>> <> serialized_context

        suite ->
          # Suite specified: includes partition_id, suite_id, and context
          <<0x01, 0x00, 0x01, 0x00>> <>
            partition_id <>
            <<0x00, 0x01, 0x00, suite.id::16-big, 0x00>> <> serialized_context
      end

    :crypto.hash(:sha384, data)
  end

  @doc false
  @spec compute_decryption_cache_id(binary(), AlgorithmSuite.t(), [EncryptedDataKey.t()], map()) ::
          binary()
  def compute_decryption_cache_id(partition_id, algorithm_suite, edks, encryption_context) do
    # Sort EDKs lexicographically by serialized form
    sorted_edks =
      edks
      |> Enum.map(&EncryptedDataKey.serialize/1)
      |> Enum.sort()
      |> IO.iodata_to_binary()

    serialized_context = EncryptionContext.serialize(encryption_context)

    # 0x01 || 0x00 || 0x02 || 0x00 || partition_id || 0x00 || suite_id || 0x00 || sorted_edks || 0x00 || context
    data =
      <<0x01, 0x00, 0x02, 0x00>> <>
        partition_id <>
        <<0x00, algorithm_suite.id::16-big, 0x00>> <>
        sorted_edks <> <<0x00>> <> serialized_context

    :crypto.hash(:sha384, data)
  end

  # Private Helpers

  defp generate_partition_id do
    # Generate UUID v4 as 16 bytes
    <<a::48, _version::4, b::12, _variant::2, c::62>> = :crypto.strong_rand_bytes(16)
    <<a::48, 4::4, b::12, 2::2, c::62>>
  end

  defp identity_kdf?(nil), do: false
  defp identity_kdf?(%AlgorithmSuite{kdf_type: :identity}), do: true
  defp identity_kdf?(_suite), do: false

  defp handle_encryption_cache_lookup(cmm, cache_id, request) do
    case LocalCache.get_cache_entry(cmm.cache, cache_id) do
      {:ok, entry} ->
        if CacheEntry.exceeded_limits?(entry, cmm.max_messages, cmm.max_bytes) do
          # Limits exceeded, fetch fresh materials
          fetch_and_cache_encryption_materials(cmm, cache_id, request)
        else
          # Cache hit - update usage and return materials
          bytes = Map.get(request, :max_plaintext_length, 0)
          LocalCache.update_usage(cmm.cache, cache_id, 1, bytes)
          {:ok, entry.materials}
        end

      {:error, :cache_miss} ->
        fetch_and_cache_encryption_materials(cmm, cache_id, request)
    end
  end

  defp fetch_and_cache_encryption_materials(cmm, cache_id, request) do
    with {:ok, materials} <- call_underlying_cmm_encrypt(cmm.underlying_cmm, request) do
      # Store in cache with initial usage
      entry = CacheEntry.new(materials, cmm.max_age)
      bytes = Map.get(request, :max_plaintext_length, 0)
      entry = %{entry | messages_used: 1, bytes_used: bytes}
      LocalCache.put_cache_entry(cmm.cache, cache_id, entry)
      {:ok, materials}
    end
  end

  defp handle_decryption_cache_lookup(cmm, cache_id, request) do
    case LocalCache.get_cache_entry(cmm.cache, cache_id) do
      {:ok, entry} ->
        # Decryption doesn't track usage limits
        {:ok, entry.materials}

      {:error, :cache_miss} ->
        fetch_and_cache_decryption_materials(cmm, cache_id, request)
    end
  end

  defp fetch_and_cache_decryption_materials(cmm, cache_id, request) do
    with {:ok, materials} <- call_underlying_cmm_decrypt(cmm.underlying_cmm, request) do
      # Store in cache
      entry = CacheEntry.new(materials, cmm.max_age)
      LocalCache.put_cache_entry(cmm.cache, cache_id, entry)
      {:ok, materials}
    end
  end

  # CMM Dispatch (same pattern as RequiredEncryptionContext)

  defp call_underlying_cmm_encrypt(%Default{} = cmm, request) do
    Default.get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(%RequiredEncryptionContext{} = cmm, request) do
    RequiredEncryptionContext.get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(%__MODULE__{} = cmm, request) do
    get_encryption_materials(cmm, request)
  end

  defp call_underlying_cmm_encrypt(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end

  defp call_underlying_cmm_decrypt(%Default{} = cmm, request) do
    Default.get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(%RequiredEncryptionContext{} = cmm, request) do
    RequiredEncryptionContext.get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(%__MODULE__{} = cmm, request) do
    get_decryption_materials(cmm, request)
  end

  defp call_underlying_cmm_decrypt(cmm, _request) do
    {:error, {:unsupported_cmm_type, cmm.__struct__}}
  end
end
