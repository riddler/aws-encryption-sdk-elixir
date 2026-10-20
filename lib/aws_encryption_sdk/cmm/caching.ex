defmodule AwsEncryptionSdk.Cmm.Caching do
  @moduledoc """
  Caching Cryptographic Materials Manager implementation.

  The Caching CMM wraps another CMM and caches cryptographic materials to reduce
  expensive calls to key providers. It provides:

  - **Performance**: Caches generated data keys and EDKs
  - **Security**: Enforces key rotation via TTL and usage limits
  - **Sharing**: Multiple Caching CMMs can share cache via Partition IDs,
    when their materials-shaping configuration matches (see Cache identity)

  ## Example

      # Create cache
      {:ok, cache} = LocalCache.start_link([])

      # Create caching CMM with keyring
      {:ok, keyring} = RawAes.new("ns", "key", key_bytes, :aes_256_gcm)
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      # Or wrap an existing CMM
      default_cmm = Default.new(keyring)
      cmm = Caching.new(default_cmm, cache, max_age: 300)

  ## Cache identity

  A cache entry is shared only by requests that a cold read would answer
  the same way. The cache key includes the materials-shaping
  configuration: the partition id; the underlying CMM chain (each CMM's
  kind, and the keys each `AwsEncryptionSdk.Cmm.RequiredEncryptionContext`
  in it requires); the request's commitment policy; and, on encrypt, the
  required encryption context keys the request carries. A differently
  configured CMM sharing the cache and partition id misses and refetches,
  so a hit always answers as a cold read would.

  The keyring is not part of the cache key: Caching CMMs that share a cache
  and a partition id share entries across their keyrings, so share a
  partition id only between Caching CMMs whose keyrings hold the same keys.

  ## Usage limits

  Each cache entry tracks how many messages and plaintext bytes it has served.
  An entry is refreshed (fresh materials fetched and cached) rather than
  reused when serving the request would exceed `max_messages` or push the
  entry's cumulative bytes past `max_bytes`, so no entry ever serves more
  than `max_bytes` bytes. The one exception is a single request larger than
  `max_bytes` on its own: it is served once with fresh materials by design,
  and the entry is refreshed on the next request.

  The byte limit is enforced against the request's `:max_plaintext_length`.
  `AwsEncryptionSdk.Client.encrypt/3` sets it automatically from the
  plaintext size. Streaming callers must pass `:plaintext_length` to
  `AwsEncryptionSdk.Stream.encrypt/3` when they know the total size; when a
  request carries no length, the byte limit cannot be enforced, so this CMM
  bypasses the cache entirely for that request (the underlying CMM is called
  and the result is not cached). Decryption is unaffected - usage limits are
  encrypt-only per the spec.

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

    cond do
      # Identity KDF bypass - never cache deprecated suites
      identity_kdf?(algorithm_suite) ->
        call_underlying_cmm_encrypt(cmm.underlying_cmm, request)

      # Unknown plaintext length bypass - max_bytes cannot be enforced
      # without a declared length, so the result is never cached
      not is_integer(Map.get(request, :max_plaintext_length)) ->
        call_underlying_cmm_encrypt(cmm.underlying_cmm, request)

      true ->
        handle_encryption_cache_lookup(cmm, encryption_cache_id(cmm, request), request)
    end
  end

  @impl Behaviour
  def get_decryption_materials(%__MODULE__{} = cmm, request) do
    # Identity KDF bypass - never cache deprecated suites
    if identity_kdf?(request.algorithm_suite) do
      call_underlying_cmm_decrypt(cmm.underlying_cmm, request)
    else
      handle_decryption_cache_lookup(cmm, decryption_cache_id(cmm, request), request)
    end
  end

  # Cache identity
  #
  # The Appendix A formulas below hash a partition id with the request's
  # suite, encrypted data keys and stored context. Nothing else in a request
  # or in this CMM's configuration reaches them, yet more than that shapes
  # the materials a cold read returns:
  #
  #   * the underlying CMM chain: each CMM's kind, and each required-context
  #     CMM's configured keys (it refuses a read without them, and adds them
  #     to the materials' required set, which shapes the header a message
  #     is written with and the header-authentication AAD it is read with);
  #   * the request's commitment policy (with no suite requested, the
  #     default CMM picks the suite by policy; on decrypt it refuses a suite
  #     the policy forbids);
  #   * on encrypt, the required keys the request carries (a required-context
  #     CMM wrapping this one adds its keys there).
  #
  # The keyring is not part of it: Caching CMMs that share a cache and a
  # partition id share entries across their keyrings (the moduledoc says
  # so).
  #
  # So the partition the formulas hash is derived from the configured
  # partition id AND that configuration. A Caching CMM configured
  # differently computes a different cache id, misses, and fetches fresh
  # materials from its own chain, so a hit answers as a cold read would.

  @doc false
  @spec encryption_cache_id(t(), map()) :: binary()
  def encryption_cache_id(%__MODULE__{} = cmm, request) do
    shape =
      {:encrypt, Map.get(request, :commitment_policy),
       Map.get(request, :required_encryption_context_keys) || []}

    compute_encryption_cache_id(
      effective_partition_id(cmm, shape),
      Map.get(request, :algorithm_suite),
      request.encryption_context
    )
  end

  @doc false
  @spec decryption_cache_id(t(), map()) :: binary()
  def decryption_cache_id(%__MODULE__{} = cmm, request) do
    shape = {:decrypt, Map.get(request, :commitment_policy)}

    compute_decryption_cache_id(
      effective_partition_id(cmm, shape),
      request.algorithm_suite,
      request.encrypted_data_keys,
      request.encryption_context
    )
  end

  defp effective_partition_id(cmm, request_shape) do
    identity = {:v1, cmm.partition_id, cmm_chain_identity(cmm.underlying_cmm), request_shape}
    :crypto.hash(:sha384, :erlang.term_to_binary(identity, [:deterministic]))
  end

  defp cmm_chain_identity(%Default{}), do: :default

  defp cmm_chain_identity(%RequiredEncryptionContext{} = cmm),
    do:
      {:required_encryption_context, cmm.required_encryption_context_keys,
       cmm_chain_identity(cmm.underlying_cmm)}

  defp cmm_chain_identity(%__MODULE__{} = cmm),
    do: {:caching, cmm_chain_identity(cmm.underlying_cmm)}

  defp cmm_chain_identity(%module{}), do: {:unsupported, module}

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
    request_bytes = Map.fetch!(request, :max_plaintext_length)

    case LocalCache.get_cache_entry(cmm.cache, cache_id) do
      {:ok, entry} ->
        if CacheEntry.can_serve?(entry, request_bytes, cmm.max_messages, cmm.max_bytes) do
          # Cache hit - update usage and return materials
          LocalCache.update_usage(cmm.cache, cache_id, 1, request_bytes)
          {:ok, entry.materials}
        else
          # Limits would be exceeded, fetch fresh materials
          fetch_and_cache_encryption_materials(cmm, cache_id, request, request_bytes)
        end

      {:error, :cache_miss} ->
        fetch_and_cache_encryption_materials(cmm, cache_id, request, request_bytes)
    end
  end

  defp fetch_and_cache_encryption_materials(cmm, cache_id, request, request_bytes) do
    with {:ok, materials} <- call_underlying_cmm_encrypt(cmm.underlying_cmm, request) do
      # Store in cache with initial usage. The limit is deliberately not
      # re-checked here: a request larger than max_bytes is served once rather
      # than looping on refetch, and is refused on the next lookup.
      entry = CacheEntry.new(materials, cmm.max_age)
      entry = %{entry | messages_used: 1, bytes_used: request_bytes}
      LocalCache.put_cache_entry(cmm.cache, cache_id, entry)
      {:ok, materials}
    end
  end

  defp handle_decryption_cache_lookup(cmm, cache_id, request) do
    case LocalCache.get_cache_entry(cmm.cache, cache_id) do
      {:ok, entry} ->
        # Decryption doesn't track usage limits
        if bound_context_agrees?(entry.materials, request) do
          {:ok, entry.materials}
        else
          fetch_and_cache_decryption_materials(cmm, cache_id, request)
        end

      {:error, :cache_miss} ->
        fetch_and_cache_decryption_materials(cmm, cache_id, request)
    end
  end

  # The decryption cache id hashes the STORED context only, so a key a
  # message does not store is not part of it: readers that reproduce
  # different values for such a key, or different keys, share one entry.
  # A hit is served only when the request agrees with everything the entry
  # bound:
  #
  #   * every reproduced value for a stored key equals the stored value;
  #   * every key in the entry's required set, stored or not, is reproduced
  #     (a cold read through the default CMM or a required-context CMM
  #     refuses or fails without it). The entry was filled through this
  #     CMM's own chain (the chain is part of the cache identity), so that
  #     set already holds every key a required-context CMM in the chain
  #     configures;
  #   * the reproduced pairs the header does not store are exactly the
  #     pairs the cached entry bound outside the header (its required keys
  #     absent from the stored context, with their values).
  #
  # Otherwise the hit is not served and the request goes the cache-miss way:
  # the cold read decides, and on success replaces the entry. So a failed
  # read that populated the cache (a keyring that does not bind the context
  # unwraps under any claim; header authentication fails later) never makes
  # a correct reader fail, and a disagreeing reader is refused by the same
  # unwrap or header authentication as on a cold read.
  defp bound_context_agrees?(materials, request) do
    reproduced = Map.get(request, :reproduced_encryption_context) || %{}
    stored = request.encryption_context

    stored_agrees? =
      Enum.all?(Map.take(reproduced, Map.keys(stored)), fn {k, v} -> stored[k] == v end)

    bound_outside_header =
      Map.take(
        materials.encryption_context,
        (materials.required_encryption_context_keys || []) -- Map.keys(stored)
      )

    required_reproduced? =
      Enum.all?(materials.required_encryption_context_keys || [], &Map.has_key?(reproduced, &1))

    stored_agrees? and required_reproduced? and
      Map.drop(reproduced, Map.keys(stored)) == bound_outside_header
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
