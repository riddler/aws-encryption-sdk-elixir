# Research: Implement Caching CMM

**Issue**: #61 - Implement Caching CMM
**Date**: 2026-01-28
**Status**: Research complete

## Issue Summary

Implement the Caching Cryptographic Materials Manager (CMM) that wraps another CMM and caches cryptographic materials to reduce expensive calls to key providers like AWS KMS. The Caching CMM is a performance optimization layer that:

- **Reduces KMS API calls** - Caches generated data keys and EDKs
- **Improves performance** - No key generation/encryption on cache hit
- **Maintains security** - Enforces key rotation via TTL and usage limits
- **Supports sharing** - Multiple Caching CMMs can share cache via Partition IDs

## Current Implementation State

### Existing Code

| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk/cmm/behaviour.ex` | CMM behaviour definition with `get_encryption_materials/2` and `get_decryption_materials/2` callbacks |
| `lib/aws_encryption_sdk/cmm/default.ex` | Default CMM implementation that wraps keyrings |
| `lib/aws_encryption_sdk/cmm/required_encryption_context.ex` | CMM that wraps another CMM to enforce required context keys |
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials struct |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | DecryptionMaterials struct |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EncryptedDataKey (EDK) struct with serialization |
| `lib/aws_encryption_sdk/format/encryption_context.ex` | Encryption context serialization (sorted key-value pairs) |
| `lib/aws_encryption_sdk/algorithm_suite.ex` | Algorithm suite definitions with `kdf_type` field for Identity KDF detection |

### Relevant Patterns

#### CMM Behaviour Callbacks

```elixir
@callback get_encryption_materials(cmm :: t(), request :: encryption_materials_request()) ::
  {:ok, EncryptionMaterials.t()} | {:error, term()}

@callback get_decryption_materials(cmm :: t(), request :: decrypt_materials_request()) ::
  {:ok, DecryptionMaterials.t()} | {:error, term()}
```

#### CMM Wrapping Pattern (from RequiredEncryptionContext CMM)

```elixir
defstruct [
  :required_encryption_context_keys,
  :underlying_cmm  # The wrapped CMM
]

def new(required_keys, underlying_cmm) do
  %__MODULE__{
    required_encryption_context_keys: required_keys,
    underlying_cmm: underlying_cmm
  }
end

def new_with_keyring(required_keys, keyring) do
  underlying_cmm = Default.new(keyring)
  new(required_keys, underlying_cmm)
end
```

#### CMM Dispatch Pattern

```elixir
defp call_underlying_cmm(cmm, %Default{} = default_cmm, request) do
  Default.get_encryption_materials(default_cmm, request)
end

defp call_underlying_cmm(cmm, %RequiredEncryptionContext{} = rec_cmm, request) do
  RequiredEncryptionContext.get_encryption_materials(rec_cmm, request)
end
```

#### Identity KDF Detection

```elixir
# In algorithm_suite.ex - Identity KDF suites have kdf_type: :identity
def deprecated?(%__MODULE__{kdf_type: :identity}), do: true

# Check if suite uses Identity KDF (NO_KDF variants: 0x0078, 0x0046, 0x0014)
algorithm_suite.kdf_type == :identity
```

#### Encryption Context Serialization

```elixir
# Empty context returns empty binary
def serialize(%{}), do: <<>>

# Non-empty context: sorted by key, count-prefixed
def serialize(context) do
  sorted = Enum.sort_by(context, fn {k, _v} -> k end)
  count = length(sorted)
  entries = Enum.map(sorted, &serialize_entry/1) |> IO.iodata_to_binary()
  <<count::16-big, entries::binary>>
end

# Entry format: <<key_len::16-big, key, value_len::16-big, value>>
```

#### EDK Serialization

```elixir
def serialize(%EncryptedDataKey{} = edk) do
  <<
    byte_size(edk.key_provider_id)::16-big,
    edk.key_provider_id::binary,
    byte_size(edk.key_provider_info)::16-big,
    edk.key_provider_info::binary,
    byte_size(edk.ciphertext)::16-big,
    edk.ciphertext::binary
  >>
end
```

### Dependencies

**Existing modules to use:**
- `AwsEncryptionSdk.Cmm.Behaviour` - CMM interface and validation helpers
- `AwsEncryptionSdk.Cmm.Default` - Can be underlying CMM or wrap keyrings
- `AwsEncryptionSdk.Format.EncryptionContext` - For serializing context in cache IDs
- `AwsEncryptionSdk.Materials.EncryptedDataKey` - For serializing EDKs in cache IDs
- `AwsEncryptionSdk.AlgorithmSuite` - For Identity KDF detection

**New modules to create:**
- `AwsEncryptionSdk.Cmm.Caching` - Caching CMM implementation
- `AwsEncryptionSdk.Cache.CryptographicMaterialsCache` - CMC behaviour
- `AwsEncryptionSdk.Cache.LocalCache` - ETS-based CMC implementation
- `AwsEncryptionSdk.Cache.CacheEntry` - Cache entry struct

## Specification Requirements

### Source Documents

- [caching-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md) - Caching CMM specification
- [cryptographic-materials-cache.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md) - CMC interface specification

### MUST Requirements

#### Initialization (caching-cmm.md#initialization)

1. **Mandatory parameters**
   > "the caller MUST provide the following values: [Underlying Cryptographic Materials Cache (CMC)], [Cache Limit TTL]"

   Implementation: Accept `cache` and `max_age` (TTL in seconds, must be > 0)

2. **CMM or Keyring**
   > "the caller MUST provide one of the following values: [Underlying Cryptographic Materials Manager (CMM)], [Keyring]"

   Implementation: Accept either `cmm` or `keyring` (mutually exclusive)

3. **Keyring wrapping**
   > "the caching CMM MUST set its underlying CMM to a default CMM initialized with the keyring"

   Implementation: If `keyring` provided, wrap in `Default.new(keyring)`

4. **Partition ID default**
   > "If this parameter is not set, the caching CMM MUST set a partition ID that uniquely identifies the respective caching CMM"

   Implementation: Generate UUID if not provided

5. **Partition ID immutability**
   > "The Partition ID MUST NOT be changed after initialization"

   Implementation: Store as immutable field

6. **Limit Bytes default**
   > "If this parameter is not set, the caching CMM MUST set it to a value no more than 2^63-1"

   Implementation: Default to `9_223_372_036_854_775_807`

7. **Limit Messages default**
   > "If this parameter is not set, the caching CMM MUST set it to 2^32"

   Implementation: Default to `4_294_967_296`

#### Get Encryption Materials (caching-cmm.md#get-encryption-materials)

8. **Identity KDF bypass**
   > "If the algorithm suite requested contains an Identity KDF, the caching CMM MUST obtain the encryption materials by making a call to the underlying CMM's Get Encryption Materials function"

   > "the caching CMM MUST NOT store the encryption materials in the underlying CMC"

   Implementation: Check `algorithm_suite.kdf_type == :identity`, bypass cache if true

9. **Cache lookup**
   > "the caching CMM MUST attempt to find the encryption materials from the underlying CMC"

   > "The caching CMM MUST use the formulas specified in Appendix A"

   Implementation: Compute cache ID, call `CMC.get_cache_entry/2`

10. **Cache miss handling**
    > "the caching CMM MUST add the encryption materials obtained from the underlying CMM into the underlying CMC"

    Implementation: On miss, get from underlying CMM, then cache

11. **Usage stats tracking**
    > "the caching CMM MUST provide a structure as defined below, to track usage statistics"

    > "the caching CMM MUST set the initial usage stats for the cache entry"

    > "the caching CMM MUST update the usage stats for the cache entry retrieved"

    Implementation: Track `messages_encrypted` and `bytes_encrypted`, increment on cache hit

#### Get Decryption Materials (caching-cmm.md#decrypt-materials)

12. **Identity KDF bypass**
    > "If the algorithm suite requested contains an Identity KDF, the caching CMM MUST obtain the decryption materials by making a call to the underlying CMM's Decrypt Materials function"

    > "the caching CMM MUST NOT store the decryption materials in the underlying CMC"

    Implementation: Check `algorithm_suite.kdf_type == :identity`, bypass cache if true

13. **Cache lookup with EDKs**
    > "the caching CMM MUST attempt to find the decryption materials from the underlying CMC"

    > "The caching CMM MUST use the formulas specified in Appendix A"

    Implementation: Compute cache ID including sorted EDKs

#### Cache ID Formulas (caching-cmm.md#appendix-a)

14. **Encryption cache ID (no suite)**
    ```
    SHA-384(0x01 || 0x00 || 0x01 || 0x00 || partition_id || 0x00 || 0x00 || 0x00 || serialized_context)
    ```

    - Resource ID: `0x01` (Caching CMM)
    - Scope ID: `0x01` (Encrypt)
    - Suite flag: `0x00` (no suite)
    - Fields separated by NULL byte `0x00`

15. **Encryption cache ID (with suite)**
    ```
    SHA-384(0x01 || 0x00 || 0x01 || 0x00 || partition_id || 0x00 || 0x01 || 0x00 || suite_id || 0x00 || serialized_context)
    ```

    - Suite flag: `0x01` (suite present)
    - Suite ID: 2-byte big-endian

16. **Decryption cache ID**
    ```
    SHA-384(0x01 || 0x00 || 0x02 || 0x00 || partition_id || 0x00 || suite_id || 0x00 || sorted_edks || 0x00 || serialized_context)
    ```

    - Scope ID: `0x02` (Decrypt)
    - EDKs: lexicographically sorted, serialized, concatenated (no separator)

#### CMC Interface (cryptographic-materials-cache.md)

17. **TTL enforcement**
    > "After a cache entry's TTL has elapsed, we say that the entry is _TTL-expired_, and a CMC MUST NOT return the entry to any caller."

    Implementation: Check expiry time, return miss if expired

18. **Put removes existing**
    > "If a cache entry for the given cache ID exists in the cache, it must be removed."

    Implementation: Overwrite existing entry

19. **Put no return**
    > "This operation MUST NOT return the inserted cache entry."

    Implementation: Return `:ok`

20. **Delete idempotent**
    > "If no cache entry exists for the specified cache ID, Delete Cache Entry must return successfully."

    Implementation: Return `:ok` even if entry doesn't exist

### SHOULD Requirements

1. **Atomic usage metadata updates** (cryptographic-materials-cache.md#usage-metadata)
   > "Updating usage metadata SHOULD be atomic."

   Implementation: Use ETS atomic operations or GenServer serialization

2. **Background cleanup** (cryptographic-materials-cache.md#background-processing)
   > "An implementation SHOULD provide a way to avoid this, for example, by spawning a background thread to occasionally remove expired entries."

   Implementation: Consider optional background cleanup task

### MAY Requirements

1. **Cache sharing**
   > "Multiple caching CMMs MAY share the same cryptographic materials cache"

   Implementation: Support passing same CMC instance to multiple caching CMMs

## Test Vectors

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets

**Note**: No dedicated test vectors exist for Caching CMM in official repositories. This is because caching is an implementation-specific optimization layer that cannot be validated through static ciphertext test vectors.

Testing approach:
1. **Unit tests** - Primary method for testing cache behavior (hit/miss, TTL, limits)
2. **Integration tests** - Verify Caching CMM produces identical results to Default CMM when processing existing decrypt test vectors

### Implementation Order

#### Phase 1: CMC Infrastructure
| Component | Description | Priority |
|-----------|-------------|----------|
| `CryptographicMaterialsCache` behaviour | Define CMC interface | Start here |
| `CacheEntry` struct | Entry with materials, times, usage | Second |
| `LocalCache` implementation | ETS-based cache | Third |

#### Phase 2: Caching CMM Core
| Component | Description | Priority |
|-----------|-------------|----------|
| Cache ID computation | SHA-384 formulas per spec | Fourth |
| `get_encryption_materials/2` | Cache lookup/store for encryption | Fifth |
| `get_decryption_materials/2` | Cache lookup/store with EDKs | Sixth |

#### Phase 3: Limits & Bypass
| Component | Description | Priority |
|-----------|-------------|----------|
| TTL enforcement | Expiration checking | Seventh |
| Usage limits | messages/bytes tracking | Eighth |
| Identity KDF bypass | Skip cache for deprecated suites | Ninth |

### Test Setup

Caching CMM tests should follow patterns from existing CMM tests:

```elixir
# test/aws_encryption_sdk/cmm/caching_test.exs
defmodule AwsEncryptionSdk.Cmm.CachingTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cmm.{Caching, Default, Behaviour}
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Keyring.RawAes

  setup do
    # Create test keyring
    key = :crypto.strong_rand_bytes(32)
    keyring = RawAes.new("test", "test-key", key, :aes_256_gcm_iv12_tag16)

    # Create cache
    {:ok, cache} = LocalCache.start_link([])

    # Create caching CMM
    cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)

    {:ok, cmm: cmm, cache: cache, keyring: keyring}
  end
end
```

### Key Test Cases

| Test Category | Description |
|---------------|-------------|
| Initialization | Valid params, defaults, keyring wrapping |
| Cache miss | Calls underlying CMM, stores result |
| Cache hit | Returns cached, no underlying call |
| TTL expiration | Expired entry triggers refresh |
| Usage limits | Exceeds limits triggers refresh |
| Identity KDF bypass | No caching for deprecated suites |
| Partition isolation | Different partitions don't share entries |
| Cache ID computation | SHA-384 formula correctness |

## Implementation Considerations

### Technical Approach

1. **Cache Storage**: Use ETS for local cache with atomic counter operations
2. **TTL Tracking**: Store creation_time and expiry_time in cache entry
3. **Usage Tracking**: Atomic counter updates for messages/bytes
4. **Partition ID**: Use UUID v4 for auto-generated partition IDs
5. **Cache ID**: Use `:crypto.hash(:sha384, data)` for SHA-384

### Data Structures

```elixir
# Caching CMM struct
defmodule AwsEncryptionSdk.Cmm.Caching do
  defstruct [
    :underlying_cmm,    # Default or RequiredEncryptionContext CMM
    :cache,             # CMC implementation
    :partition_id,      # 16-byte UUID string
    :max_age,           # TTL in seconds
    :max_bytes,         # Default 2^63-1
    :max_messages       # Default 2^32
  ]
end

# Cache entry struct
defmodule AwsEncryptionSdk.Cache.CacheEntry do
  defstruct [
    :materials,         # EncryptionMaterials or DecryptionMaterials
    :creation_time,     # System.monotonic_time(:second)
    :expiry_time,       # creation_time + max_age
    :messages_used,     # Counter (encryption only)
    :bytes_used         # Counter (encryption only)
  ]
end

# CMC behaviour
defmodule AwsEncryptionSdk.Cache.CryptographicMaterialsCache do
  @callback put_cache_entry(cache, binary(), CacheEntry.t()) :: :ok
  @callback get_cache_entry(cache, binary()) :: {:ok, CacheEntry.t()} | {:error, :cache_miss}
  @callback delete_cache_entry(cache, binary()) :: :ok
  @callback update_usage(cache, binary(), pos_integer(), pos_integer()) :: :ok | {:error, :cache_miss}
end
```

### Cache ID Computation

```elixir
def compute_encryption_cache_id(partition_id, algorithm_suite, encryption_context) do
  serialized_context = EncryptionContext.serialize(encryption_context)

  data = case algorithm_suite do
    nil ->
      # No suite specified
      <<0x01, 0x00, 0x01, 0x00>> <> partition_id <> <<0x00, 0x00, 0x00>> <> serialized_context

    suite ->
      # Suite specified
      <<0x01, 0x00, 0x01, 0x00>> <> partition_id <> <<0x00, 0x01, 0x00, suite.id::16-big, 0x00>> <> serialized_context
  end

  :crypto.hash(:sha384, data)
end

def compute_decryption_cache_id(partition_id, algorithm_suite, edks, encryption_context) do
  sorted_edks = edks
    |> Enum.sort_by(&(&1.ciphertext))  # Lexicographic sort
    |> Enum.map(&EncryptedDataKey.serialize/1)
    |> IO.iodata_to_binary()

  serialized_context = EncryptionContext.serialize(encryption_context)

  data = <<0x01, 0x00, 0x02, 0x00>> <> partition_id <> <<0x00, algorithm_suite.id::16-big, 0x00>> <>
         sorted_edks <> <<0x00>> <> serialized_context

  :crypto.hash(:sha384, data)
end
```

### Potential Challenges

1. **Concurrent access**: ETS handles concurrent reads well, but atomic counter updates need care
2. **Memory management**: Cache can grow unbounded without cleanup; consider max entries or background cleanup
3. **Clock skew**: TTL based on monotonic time to avoid wall-clock issues
4. **EDK sorting**: Need consistent lexicographic comparison across all EDK fields

### Open Questions

1. **Usage limit enforcement**: When exactly to reject cache hits based on approaching limits?
   - Option A: Reject when limit reached
   - Option B: Reject when limit would be exceeded by this operation

2. **Background cleanup**: Implement SHOULD requirement for cleanup or leave for future?

3. **Cache size limits**: Should we add max_entries option beyond TTL/usage limits?

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-28-GH61-caching-cmm.md`
2. Implement in phases:
   - Phase 1: CMC behaviour and LocalCache
   - Phase 2: Caching CMM core (cache lookup/store)
   - Phase 3: Limits enforcement and bypass logic
   - Phase 4: Comprehensive tests

## References

- Issue: https://github.com/owner/repo/issues/61
- Caching CMM Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md
- CMC Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cryptographic-materials-cache.md
- Python SDK Caching CMM: https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/materials_managers/caching.py
- AWS Data Key Caching Docs: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-caching-details.html
