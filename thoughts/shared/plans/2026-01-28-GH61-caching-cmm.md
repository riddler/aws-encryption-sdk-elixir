# Caching CMM Implementation Plan

## Overview

Implement the Caching Cryptographic Materials Manager (CMM) that wraps another CMM and caches cryptographic materials to reduce expensive calls to key providers like AWS KMS.

**Issue**: #61
**Research**: `thoughts/shared/research/2026-01-28-GH61-caching-cmm.md`

## Specification Requirements

### Source Documents
- [caching-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md) - Caching CMM specification
- [cryptographic-materials-cache.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md) - CMC interface specification

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Mandatory: cache, max_age | caching-cmm.md#initialization | MUST |
| CMM or Keyring (mutually exclusive) | caching-cmm.md#initialization | MUST |
| Auto-generate partition ID | caching-cmm.md#initialization | MUST |
| Default limits (bytes, messages) | caching-cmm.md#initialization | MUST |
| Identity KDF bypass | caching-cmm.md#get-encryption-materials | MUST |
| Cache ID formulas (SHA-384) | caching-cmm.md#appendix-a | MUST |
| TTL enforcement | cryptographic-materials-cache.md | MUST |
| Usage stats tracking | caching-cmm.md#get-encryption-materials | MUST |
| Atomic usage updates | cryptographic-materials-cache.md#usage-metadata | SHOULD |
| Background cleanup | cryptographic-materials-cache.md#background-processing | SHOULD (deferred) |

## Test Vectors

### Validation Strategy
No dedicated test vectors exist for Caching CMM in official repositories. This is because caching is an implementation-specific optimization layer that cannot be validated through static ciphertext test vectors.

Testing approach:
1. **Unit tests** - Primary method for testing cache behavior (hit/miss, TTL, limits)
2. **Integration tests** - Verify Caching CMM produces identical results to Default CMM
3. **Round-trip tests** - Encrypt/decrypt cycles work correctly with caching

## Current State Analysis

### Existing Code
| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk/cmm/behaviour.ex` | CMM behaviour with callbacks |
| `lib/aws_encryption_sdk/cmm/default.ex` | Default CMM wrapping keyrings |
| `lib/aws_encryption_sdk/cmm/required_encryption_context.ex` | CMM wrapping pattern example |
| `lib/aws_encryption_sdk/format/encryption_context.ex` | Context serialization (sorted key-value) |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EDK serialization |
| `lib/aws_encryption_sdk/algorithm_suite.ex` | Identity KDF detection via `kdf_type: :identity` |

### Key Discoveries
- CMM dispatch uses explicit pattern matching on struct types (`%Default{}`, `%RequiredEncryptionContext{}`)
- CMM wrapping pattern stores `underlying_cmm` field
- `new_with_keyring/2` helper wraps keyring in `Default.new/1`
- Encryption context serialize produces sorted binary representation
- EDK serialize produces length-prefixed binary format

## Desired End State

After this plan is complete:

1. **New Modules Created**:
   - `AwsEncryptionSdk.Cache.CryptographicMaterialsCache` - CMC behaviour
   - `AwsEncryptionSdk.Cache.CacheEntry` - Cache entry struct
   - `AwsEncryptionSdk.Cache.LocalCache` - ETS-based CMC implementation
   - `AwsEncryptionSdk.Cmm.Caching` - Caching CMM implementation

2. **Functionality**:
   - Cache encryption materials on first encrypt, return cached on subsequent
   - Cache decryption materials based on EDKs + context
   - Enforce TTL expiration (entries not returned after max_age)
   - Enforce usage limits (messages and bytes encrypted)
   - Bypass cache for Identity KDF (deprecated NO_KDF suites)
   - Support multiple Caching CMMs sharing a cache via partition IDs

3. **Verification**:
   - `mix quality` passes
   - All new tests pass
   - Round-trip encrypt/decrypt works with Caching CMM

## What We're NOT Doing

- Background cleanup task (deferred SHOULD requirement)
- Max entries limit (TTL and usage limits are sufficient)
- Cache persistence (ETS is in-memory only)
- Distributed caching (LocalCache is process-local)

## Implementation Approach

Four phases building incrementally:
1. **CMC Infrastructure** - Define behaviour and cache entry struct
2. **LocalCache** - ETS-based implementation with atomic counters
3. **Caching CMM Core** - Cache ID computation and cache lookup/store
4. **Limits & Bypass** - TTL, usage limits, Identity KDF bypass

---

## Phase 1: CMC Infrastructure

### Overview
Create the Cryptographic Materials Cache (CMC) behaviour and CacheEntry struct that define the caching interface.

### Spec Requirements Addressed
- "the caller MUST provide the following values: [Underlying Cryptographic Materials Cache (CMC)]"
- "track usage statistics" - CacheEntry includes usage counters

### Changes Required

#### 1. Cache Entry Struct
**File**: `lib/aws_encryption_sdk/cache/cache_entry.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Cache.CacheEntry do
  @moduledoc """
  Cache entry containing cryptographic materials with usage metadata.

  ## Fields

  - `:materials` - EncryptionMaterials or DecryptionMaterials
  - `:creation_time` - Monotonic time when entry was created (seconds)
  - `:expiry_time` - Monotonic time when entry expires (seconds)
  - `:messages_used` - Number of messages encrypted with this entry
  - `:bytes_used` - Number of bytes encrypted with this entry
  """

  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptionMaterials}

  @type materials :: EncryptionMaterials.t() | DecryptionMaterials.t()

  @type t :: %__MODULE__{
          materials: materials(),
          creation_time: integer(),
          expiry_time: integer(),
          messages_used: non_neg_integer(),
          bytes_used: non_neg_integer()
        }

  @enforce_keys [:materials, :creation_time, :expiry_time]
  defstruct [
    :materials,
    :creation_time,
    :expiry_time,
    messages_used: 0,
    bytes_used: 0
  ]

  @doc """
  Creates a new cache entry with the given materials and TTL.

  ## Parameters

  - `materials` - EncryptionMaterials or DecryptionMaterials
  - `max_age` - TTL in seconds

  ## Examples

      iex> materials = %EncryptionMaterials{...}
      iex> entry = CacheEntry.new(materials, 300)
      iex> entry.messages_used
      0
  """
  @spec new(materials(), pos_integer()) :: t()
  def new(materials, max_age) when is_integer(max_age) and max_age > 0 do
    now = System.monotonic_time(:second)

    %__MODULE__{
      materials: materials,
      creation_time: now,
      expiry_time: now + max_age,
      messages_used: 0,
      bytes_used: 0
    }
  end

  @doc """
  Checks if the cache entry has expired.

  ## Examples

      iex> entry = CacheEntry.new(materials, 300)
      iex> CacheEntry.expired?(entry)
      false
  """
  @spec expired?(t()) :: boolean()
  def expired?(%__MODULE__{expiry_time: expiry_time}) do
    System.monotonic_time(:second) >= expiry_time
  end

  @doc """
  Checks if the cache entry has exceeded usage limits.

  ## Parameters

  - `entry` - The cache entry
  - `max_messages` - Maximum messages allowed
  - `max_bytes` - Maximum bytes allowed

  ## Examples

      iex> entry = %CacheEntry{messages_used: 100, bytes_used: 1000, ...}
      iex> CacheEntry.exceeded_limits?(entry, 50, 10000)
      true
  """
  @spec exceeded_limits?(t(), non_neg_integer(), non_neg_integer()) :: boolean()
  def exceeded_limits?(%__MODULE__{} = entry, max_messages, max_bytes) do
    entry.messages_used >= max_messages or entry.bytes_used >= max_bytes
  end
end
```

#### 2. CMC Behaviour
**File**: `lib/aws_encryption_sdk/cache/cryptographic_materials_cache.ex`
**Changes**: New file

```elixir
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
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix quality --quick` passes
- [x] New modules load without errors

#### Manual Verification:
- [x] Struct creation works in IEx:
  ```elixir
  alias AwsEncryptionSdk.Cache.CacheEntry
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.AlgorithmSuite
  suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
  materials = EncryptionMaterials.new_for_encrypt(suite, %{})
  entry = CacheEntry.new(materials, 300)
  CacheEntry.expired?(entry)  # false
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: LocalCache Implementation

### Overview
Implement an ETS-based local cache that satisfies the CMC behaviour.

### Spec Requirements Addressed
- "Put removes existing" - Overwrite on put
- "Put no return" - Returns `:ok`
- "Delete idempotent" - Returns `:ok` even if not found
- "TTL enforcement" - Check expiry on get
- "Atomic usage updates" (SHOULD) - Use ETS update_counter

### Changes Required

#### 1. LocalCache GenServer
**File**: `lib/aws_encryption_sdk/cache/local_cache.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Cache.LocalCache do
  @moduledoc """
  ETS-based local implementation of the Cryptographic Materials Cache.

  This cache stores materials in an ETS table owned by a GenServer process.
  Multiple Caching CMMs can share the same LocalCache instance.

  ## Example

      {:ok, cache} = LocalCache.start_link([])
      LocalCache.put_cache_entry(cache, cache_id, entry)
      {:ok, entry} = LocalCache.get_cache_entry(cache, cache_id)

  ## Options

  - `:name` - Optional registered name for the cache process
  """

  use GenServer

  @behaviour AwsEncryptionSdk.Cache.CryptographicMaterialsCache

  alias AwsEncryptionSdk.Cache.CacheEntry

  @type t :: pid() | atom()

  # Client API

  @doc """
  Starts a new LocalCache process.

  ## Options

  - `:name` - Optional registered name
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def put_cache_entry(cache, cache_id, %CacheEntry{} = entry)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:put, cache_id, entry})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def get_cache_entry(cache, cache_id)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:get, cache_id})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def delete_cache_entry(cache, cache_id)
      when is_binary(cache_id) and byte_size(cache_id) == 48 do
    GenServer.call(cache, {:delete, cache_id})
  end

  @impl AwsEncryptionSdk.Cache.CryptographicMaterialsCache
  def update_usage(cache, cache_id, messages, bytes)
      when is_binary(cache_id) and byte_size(cache_id) == 48 and
             is_integer(messages) and messages > 0 and
             is_integer(bytes) and bytes >= 0 do
    GenServer.call(cache, {:update_usage, cache_id, messages, bytes})
  end

  # Server Callbacks

  @impl GenServer
  def init(_opts) do
    table = :ets.new(:cache, [:set, :private])
    {:ok, %{table: table}}
  end

  @impl GenServer
  def handle_call({:put, cache_id, entry}, _from, %{table: table} = state) do
    :ets.insert(table, {cache_id, entry})
    {:reply, :ok, state}
  end

  def handle_call({:get, cache_id}, _from, %{table: table} = state) do
    result =
      case :ets.lookup(table, cache_id) do
        [{^cache_id, entry}] ->
          if CacheEntry.expired?(entry) do
            :ets.delete(table, cache_id)
            {:error, :cache_miss}
          else
            {:ok, entry}
          end

        [] ->
          {:error, :cache_miss}
      end

    {:reply, result, state}
  end

  def handle_call({:delete, cache_id}, _from, %{table: table} = state) do
    :ets.delete(table, cache_id)
    {:reply, :ok, state}
  end

  def handle_call({:update_usage, cache_id, messages, bytes}, _from, %{table: table} = state) do
    result =
      case :ets.lookup(table, cache_id) do
        [{^cache_id, entry}] ->
          updated = %{
            entry
            | messages_used: entry.messages_used + messages,
              bytes_used: entry.bytes_used + bytes
          }

          :ets.insert(table, {cache_id, updated})
          :ok

        [] ->
          {:error, :cache_miss}
      end

    {:reply, result, state}
  end

  @impl GenServer
  def terminate(_reason, %{table: table}) do
    :ets.delete(table)
    :ok
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix quality --quick` passes
- [x] Unit tests for LocalCache pass

#### Manual Verification:
- [x] Cache operations work in IEx:
  ```elixir
  alias AwsEncryptionSdk.Cache.{LocalCache, CacheEntry}
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.AlgorithmSuite

  {:ok, cache} = LocalCache.start_link([])
  suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
  materials = EncryptionMaterials.new_for_encrypt(suite, %{})
  entry = CacheEntry.new(materials, 300)
  cache_id = :crypto.hash(:sha384, "test")

  LocalCache.put_cache_entry(cache, cache_id, entry)
  {:ok, _} = LocalCache.get_cache_entry(cache, cache_id)
  LocalCache.update_usage(cache, cache_id, 1, 100)
  {:ok, updated} = LocalCache.get_cache_entry(cache, cache_id)
  updated.messages_used  # 1
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Caching CMM Core

### Overview
Implement the Caching CMM with cache ID computation and cache lookup/store for encryption and decryption materials.

### Spec Requirements Addressed
- "the caching CMM MUST attempt to find the encryption materials from the underlying CMC"
- "the caching CMM MUST add the encryption materials obtained from the underlying CMM into the underlying CMC"
- "The caching CMM MUST use the formulas specified in Appendix A"
- Partition ID generation and immutability
- CMM or Keyring initialization (mutually exclusive)

### Changes Required

#### 1. Caching CMM Module
**File**: `lib/aws_encryption_sdk/cmm/caching.ex`
**Changes**: New file

```elixir
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

      cmm = Caching.new(default_cmm, cache, max_age: 300)
      cmm = Caching.new(default_cmm, cache, max_age: 300, partition_id: "my-partition")
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

      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
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
      cache_id = compute_encryption_cache_id(cmm.partition_id, algorithm_suite, encryption_context)
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
      cache_id = compute_decryption_cache_id(cmm.partition_id, algorithm_suite, edks, encryption_context)
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
          # Suite specified: 0x01 || 0x00 || 0x01 || 0x00 || partition_id || 0x00 || 0x01 || 0x00 || suite_id || 0x00 || context
          <<0x01, 0x00, 0x01, 0x00>> <>
            partition_id <> <<0x00, 0x01, 0x00, suite.id::16-big, 0x00>> <> serialized_context
      end

    :crypto.hash(:sha384, data)
  end

  @doc false
  @spec compute_decryption_cache_id(binary(), AlgorithmSuite.t(), [EncryptedDataKey.t()], map()) :: binary()
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
    <<a::48, _::4, b::12, _::2, c::62>> = :crypto.strong_rand_bytes(16)
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
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix quality --quick` passes
- [x] Unit tests for Caching CMM pass

#### Manual Verification:
- [x] Basic caching works in IEx:
  ```elixir
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Cmm.Caching
  alias AwsEncryptionSdk.Keyring.RawAes

  key = :crypto.strong_rand_bytes(32)
  {:ok, keyring} = RawAes.new("ns", "key", key, :aes_256_gcm)
  {:ok, cache} = LocalCache.start_link([])
  cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

  request = %{
    encryption_context: %{"tenant" => "acme"},
    commitment_policy: :require_encrypt_require_decrypt
  }

  # First call - cache miss, calls underlying CMM
  {:ok, materials1} = Caching.get_encryption_materials(cmm, request)

  # Second call - cache hit, returns same materials
  {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

  # Same plaintext data key means cache hit worked
  materials1.plaintext_data_key == materials2.plaintext_data_key
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: Tests & Integration

### Overview
Add comprehensive tests for all cache components and verify integration with the rest of the SDK.

### Changes Required

#### 1. CacheEntry Tests
**File**: `test/aws_encryption_sdk/cache/cache_entry_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Cache.CacheEntryTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.CacheEntry
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  defp create_test_materials do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    EncryptionMaterials.new_for_encrypt(suite, %{})
  end

  describe "new/2" do
    test "creates entry with correct fields" do
      materials = create_test_materials()
      entry = CacheEntry.new(materials, 300)

      assert entry.materials == materials
      assert entry.messages_used == 0
      assert entry.bytes_used == 0
      assert entry.expiry_time > entry.creation_time
    end
  end

  describe "expired?/1" do
    test "returns false for fresh entry" do
      materials = create_test_materials()
      entry = CacheEntry.new(materials, 300)

      refute CacheEntry.expired?(entry)
    end

    test "returns true for expired entry" do
      materials = create_test_materials()
      # Create entry that's already expired
      entry = %CacheEntry{
        materials: materials,
        creation_time: System.monotonic_time(:second) - 400,
        expiry_time: System.monotonic_time(:second) - 100,
        messages_used: 0,
        bytes_used: 0
      }

      assert CacheEntry.expired?(entry)
    end
  end

  describe "exceeded_limits?/3" do
    test "returns false when under limits" do
      materials = create_test_materials()
      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 10,
        bytes_used: 1000
      }

      refute CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end

    test "returns true when messages exceeded" do
      materials = create_test_materials()
      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 100,
        bytes_used: 0
      }

      assert CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end

    test "returns true when bytes exceeded" do
      materials = create_test_materials()
      entry = %CacheEntry{
        materials: materials,
        creation_time: 0,
        expiry_time: 1000,
        messages_used: 0,
        bytes_used: 10_000
      }

      assert CacheEntry.exceeded_limits?(entry, 100, 10_000)
    end
  end
end
```

#### 2. LocalCache Tests
**File**: `test/aws_encryption_sdk/cache/local_cache_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Cache.LocalCacheTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.{CacheEntry, LocalCache}
  alias AwsEncryptionSdk.Materials.EncryptionMaterials

  defp create_test_entry(max_age \\ 300) do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    materials = EncryptionMaterials.new_for_encrypt(suite, %{})
    CacheEntry.new(materials, max_age)
  end

  defp create_cache_id(data \\ "test") do
    :crypto.hash(:sha384, data)
  end

  describe "start_link/1" do
    test "starts cache process" do
      {:ok, cache} = LocalCache.start_link([])
      assert is_pid(cache)
    end

    test "starts with name" do
      {:ok, _cache} = LocalCache.start_link(name: :test_cache)
      assert Process.whereis(:test_cache) != nil
    after
      Process.whereis(:test_cache) && GenServer.stop(:test_cache)
    end
  end

  describe "put_cache_entry/3" do
    test "stores entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      assert :ok = LocalCache.put_cache_entry(cache, cache_id, entry)
    end

    test "replaces existing entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry1 = create_test_entry()
      entry2 = %{entry1 | messages_used: 99}

      LocalCache.put_cache_entry(cache, cache_id, entry1)
      LocalCache.put_cache_entry(cache, cache_id, entry2)

      {:ok, retrieved} = LocalCache.get_cache_entry(cache, cache_id)
      assert retrieved.messages_used == 99
    end
  end

  describe "get_cache_entry/2" do
    test "returns entry when found" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      {:ok, retrieved} = LocalCache.get_cache_entry(cache, cache_id)

      assert retrieved.materials == entry.materials
    end

    test "returns error when not found" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end

    test "returns error for expired entry and deletes it" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      # Create already expired entry
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      materials = EncryptionMaterials.new_for_encrypt(suite, %{})
      expired_entry = %CacheEntry{
        materials: materials,
        creation_time: System.monotonic_time(:second) - 400,
        expiry_time: System.monotonic_time(:second) - 100,
        messages_used: 0,
        bytes_used: 0
      }

      # Manually insert (bypassing normal put which would use current time)
      GenServer.call(cache, {:put, cache_id, expired_entry})

      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end
  end

  describe "delete_cache_entry/2" do
    test "deletes existing entry" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      assert :ok = LocalCache.delete_cache_entry(cache, cache_id)
      assert {:error, :cache_miss} = LocalCache.get_cache_entry(cache, cache_id)
    end

    test "succeeds when entry doesn't exist" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert :ok = LocalCache.delete_cache_entry(cache, cache_id)
    end
  end

  describe "update_usage/4" do
    test "increments counters" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()
      entry = create_test_entry()

      LocalCache.put_cache_entry(cache, cache_id, entry)
      LocalCache.update_usage(cache, cache_id, 1, 100)
      LocalCache.update_usage(cache, cache_id, 2, 200)

      {:ok, updated} = LocalCache.get_cache_entry(cache, cache_id)
      assert updated.messages_used == 3
      assert updated.bytes_used == 300
    end

    test "returns error when entry doesn't exist" do
      {:ok, cache} = LocalCache.start_link([])
      cache_id = create_cache_id()

      assert {:error, :cache_miss} = LocalCache.update_usage(cache, cache_id, 1, 100)
    end
  end
end
```

#### 3. Caching CMM Tests
**File**: `test/aws_encryption_sdk/cmm/caching_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Cmm.CachingTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Cmm.{Caching, Default}
  alias AwsEncryptionSdk.Keyring.RawAes

  defp create_test_keyring do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test-namespace", "test-key", key, :aes_256_gcm)
    keyring
  end

  describe "new/3" do
    test "creates CMM with required options" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300)

      assert caching_cmm.underlying_cmm == cmm
      assert caching_cmm.cache == cache
      assert caching_cmm.max_age == 300
      assert byte_size(caching_cmm.partition_id) == 16
    end

    test "uses custom partition_id" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300, partition_id: "custom-partition")

      assert caching_cmm.partition_id == "custom-partition"
    end

    test "sets default limits" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300)

      assert caching_cmm.max_bytes == 9_223_372_036_854_775_807
      assert caching_cmm.max_messages == 4_294_967_296
    end

    test "accepts custom limits" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      caching_cmm = Caching.new(cmm, cache, max_age: 300, max_bytes: 1000, max_messages: 10)

      assert caching_cmm.max_bytes == 1000
      assert caching_cmm.max_messages == 10
    end

    test "raises on invalid max_age" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Default.new(keyring)

      assert_raise ArgumentError, fn ->
        Caching.new(cmm, cache, max_age: 0)
      end
    end
  end

  describe "new_with_keyring/3" do
    test "wraps keyring in Default CMM" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()

      caching_cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      assert %Default{keyring: ^keyring} = caching_cmm.underlying_cmm
    end
  end

  describe "get_encryption_materials/2 - cache behavior" do
    test "cache miss calls underlying CMM and stores result" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      {:ok, materials} = Caching.get_encryption_materials(cmm, request)

      assert materials.plaintext_data_key != nil
      assert materials.encrypted_data_keys != []
    end

    test "cache hit returns same materials" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Same plaintext key = cache hit
      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end

    test "different context results in cache miss" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request1 = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      request2 = %{
        encryption_context: %{"tenant" => "other"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request1)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request2)

      # Different plaintext keys = cache miss
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end

    test "exceeding message limit triggers refresh" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300, max_messages: 2)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)
      # Third call should exceed limit (2 messages used)
      {:ok, materials3} = Caching.get_encryption_materials(cmm, request)

      assert materials1.plaintext_data_key == materials2.plaintext_data_key
      assert materials2.plaintext_data_key != materials3.plaintext_data_key
    end
  end

  describe "get_encryption_materials/2 - Identity KDF bypass" do
    test "bypasses cache for Identity KDF suite" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      # Deprecated NO_KDF suite
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf()

      request = %{
        encryption_context: %{},
        commitment_policy: :forbid_encrypt_allow_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm, request)

      # Different keys each time = cache bypass
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end
  end

  describe "get_encryption_materials/2 - partition isolation" do
    test "different partition IDs don't share cache entries" do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm1 = Caching.new_with_keyring(keyring, cache, max_age: 300, partition_id: "partition-1")
      cmm2 = Caching.new_with_keyring(keyring, cache, max_age: 300, partition_id: "partition-2")
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, materials1} = Caching.get_encryption_materials(cmm1, request)
      {:ok, materials2} = Caching.get_encryption_materials(cmm2, request)

      # Different partitions = different keys
      assert materials1.plaintext_data_key != materials2.plaintext_data_key
    end
  end

  describe "get_decryption_materials/2" do
    setup do
      {:ok, cache} = LocalCache.start_link([])
      keyring = create_test_keyring()
      cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      # Get encryption materials to create valid EDKs
      enc_request = %{
        encryption_context: %{"tenant" => "acme"},
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      }

      {:ok, enc_materials} = Caching.get_encryption_materials(cmm, enc_request)

      {:ok, cmm: cmm, suite: suite, enc_materials: enc_materials}
    end

    test "cache miss calls underlying CMM", ctx do
      dec_request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.enc_materials.encrypted_data_keys,
        encryption_context: ctx.enc_materials.encryption_context
      }

      {:ok, materials} = Caching.get_decryption_materials(ctx.cmm, dec_request)

      assert materials.plaintext_data_key == ctx.enc_materials.plaintext_data_key
    end

    test "cache hit returns same materials", ctx do
      dec_request = %{
        algorithm_suite: ctx.suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: ctx.enc_materials.encrypted_data_keys,
        encryption_context: ctx.enc_materials.encryption_context
      }

      {:ok, materials1} = Caching.get_decryption_materials(ctx.cmm, dec_request)
      {:ok, materials2} = Caching.get_decryption_materials(ctx.cmm, dec_request)

      assert materials1.plaintext_data_key == materials2.plaintext_data_key
    end
  end

  describe "cache ID computation" do
    test "encryption cache ID is deterministic" do
      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{"key" => "value"}

      id1 = Caching.compute_encryption_cache_id(partition_id, suite, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, suite, context)

      assert id1 == id2
      assert byte_size(id1) == 48  # SHA-384 output
    end

    test "encryption cache ID differs for different suite" do
      partition_id = "test-partition-id!"
      suite1 = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      suite2 = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
      context = %{}

      id1 = Caching.compute_encryption_cache_id(partition_id, suite1, context)
      id2 = Caching.compute_encryption_cache_id(partition_id, suite2, context)

      assert id1 != id2
    end

    test "decryption cache ID is deterministic" do
      partition_id = "test-partition-id!"
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      context = %{}

      keyring = create_test_keyring()
      cmm = Default.new(keyring)
      {:ok, enc_materials} = Default.get_encryption_materials(cmm, %{
        encryption_context: context,
        commitment_policy: :require_encrypt_require_decrypt,
        algorithm_suite: suite
      })
      edks = enc_materials.encrypted_data_keys

      id1 = Caching.compute_decryption_cache_id(partition_id, suite, edks, context)
      id2 = Caching.compute_decryption_cache_id(partition_id, suite, edks, context)

      assert id1 == id2
      assert byte_size(id1) == 48  # SHA-384 output
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix quality` passes (full quality check)
- [x] All new tests pass: `mix test test/aws_encryption_sdk/cache/ test/aws_encryption_sdk/cmm/caching_test.exs`

#### Manual Verification:
- [x] Full round-trip encrypt/decrypt works with Caching CMM in IEx
- [x] Cache hits return same materials (verify via plaintext_data_key comparison)
- [x] TTL expiration works (create entry with 1s TTL, wait 2s, verify miss)

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All cache tests pass: `mix test test/aws_encryption_sdk/cache/`
- [x] All CMM tests pass: `mix test test/aws_encryption_sdk/cmm/`

### Manual:
- [x] End-to-end: Encrypt with Caching CMM, decrypt, verify plaintext matches
- [x] Cache efficiency: Same request twice returns identical materials
- [x] Partition isolation: Different partition IDs don't share entries
- [x] Identity KDF bypass: NO_KDF suites bypass cache

## Testing Strategy

### Unit Tests
- CacheEntry: creation, expiration check, limit check
- LocalCache: CRUD operations, TTL enforcement, usage updates
- Caching CMM: cache hit/miss, limits, bypass, partition isolation

### Integration Tests
- Round-trip encrypt/decrypt with Caching CMM
- Caching CMM wrapping RequiredEncryptionContext CMM
- Multiple Caching CMMs sharing same cache

### Manual Testing Steps
1. Create cache and Caching CMM in IEx
2. Encrypt same request twice, verify same plaintext_data_key
3. Encrypt different context, verify different plaintext_data_key
4. Set low max_messages, verify refresh after limit
5. Use Identity KDF suite, verify no caching

## References

- Issue: #61
- Research: `thoughts/shared/research/2026-01-28-GH61-caching-cmm.md`
- Spec: [caching-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md)
- Spec: [cryptographic-materials-cache.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md)
