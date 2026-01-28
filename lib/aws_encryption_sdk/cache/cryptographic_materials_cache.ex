defmodule AwsEncryptionSdk.Cache.CryptographicMaterialsCache do
  @moduledoc """
  Behaviour for Cryptographic Materials Cache implementations.

  The CMC provides a caching layer for cryptographic materials, allowing the
  Caching CMM to reuse data keys across multiple encryption operations.

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md
  """

  alias AwsEncryptionSdk.Cache.CacheEntry

  @typedoc "Cache implementation module or process reference"
  @type cache :: module() | pid() | atom()

  @typedoc "48-byte SHA-384 cache identifier"
  @type cache_id :: binary()

  @doc """
  Stores a cache entry.

  If an entry with the given cache ID already exists, it MUST be replaced.
  This operation MUST NOT return the inserted entry.

  ## Parameters

  - `cache` - Cache implementation
  - `cache_id` - 48-byte cache identifier
  - `entry` - Cache entry to store
  """
  @callback put_cache_entry(cache(), cache_id(), CacheEntry.t()) :: :ok

  @doc """
  Retrieves a cache entry.

  Returns `{:ok, entry}` if found and not expired, `{:error, :cache_miss}` otherwise.
  Expired entries MUST NOT be returned and SHOULD be removed.

  ## Parameters

  - `cache` - Cache implementation
  - `cache_id` - 48-byte cache identifier
  """
  @callback get_cache_entry(cache(), cache_id()) ::
              {:ok, CacheEntry.t()} | {:error, :cache_miss}

  @doc """
  Removes a cache entry.

  This operation MUST succeed even if no entry exists for the cache ID.

  ## Parameters

  - `cache` - Cache implementation
  - `cache_id` - 48-byte cache identifier
  """
  @callback delete_cache_entry(cache(), cache_id()) :: :ok

  @doc """
  Updates usage statistics for a cache entry.

  Increments messages_used and bytes_used counters atomically.
  Returns `{:error, :cache_miss}` if entry doesn't exist.

  ## Parameters

  - `cache` - Cache implementation
  - `cache_id` - 48-byte cache identifier
  - `messages` - Number of messages to add
  - `bytes` - Number of bytes to add
  """
  @callback update_usage(cache(), cache_id(), pos_integer(), non_neg_integer()) ::
              :ok | {:error, :cache_miss}
end
