# Research: Caching CMM Conformance Audit

**Date**: 2026-08-06
**Status**: Audit complete
**Scope**: Workstream B of `thoughts/shared/plans/2026-08-06-kms-vectors-cmm-gcp.md`

Audits the existing implementation against:

- `framework/caching-cmm.md` (spec version 0.4.0)
- `framework/cryptographic-materials-cache.md` (spec version 0.5.2)

Code audited:

| File | Role |
|------|------|
| `lib/aws_encryption_sdk/cmm/caching.ex` | Caching CMM |
| `lib/aws_encryption_sdk/cache/local_cache.ex` | CMC implementation (GenServer + ETS) |
| `lib/aws_encryption_sdk/cache/cache_entry.ex` | Cache entry struct |
| `lib/aws_encryption_sdk/cache/cryptographic_materials_cache.ex` | CMC behaviour |

## Verdict

The core is sound. **Cache entry identifier formulas are byte-for-byte correct
for all three cases**, which was the highest-risk item, and the Identity KDF
bypass is correct on both encrypt and decrypt paths.

Five gaps found. One is a real security/conformance defect (`max_bytes` is
unenforceable in practice), one is a plaintext-key disclosure risk, the rest
are bounded correctness or robustness issues.

## MUST-by-MUST mapping

### caching-cmm.md - Initialization

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Caller MUST provide CMC and Cache Limit TTL | Met | `caching.ex:88-107`, `max_age` via `Keyword.fetch!` |
| Caller MUST provide underlying CMM or keyring | Met | `new/3` and `new_with_keyring/3` |
| Keyring MUST be wrapped in a default CMM | Met | `caching.ex:132` |
| TTL MUST be greater than zero | Met | `caching.ex:91-93` raises `ArgumentError` |
| MUST optionally accept Partition ID / Limit Bytes / Limit Messages | Met | `caching.ex:95-97` |
| Unset Partition ID MUST be uniquely generated | Met (see F4) | `caching.ex:220-224` |
| Partition ID MUST NOT change after initialization | Met | Immutable struct field |
| Unset Limit Bytes MUST be no more than 2^63-1 | Met | `caching.ex:39` |
| Unset Limit Messages MUST be 2^32 | Met | `caching.ex:40` |
| MUST set initial usage stats on store | Met | `caching.ex:251-253` |
| MUST update usage stats on retrieval | Partially met (see F1) | `caching.ex:238-239` |

### caching-cmm.md - Get Encryption Materials

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Identity KDF MUST bypass to underlying CMM | Met | `caching.ex:144-145`; `identity_kdf?/1` at `caching.ex:226-228` matches `kdf_type: :identity` (suites `0x0014`/`0x0046`/`0x0078` per `algorithm_suite.ex:357,383,409`) |
| Identity KDF MUST NOT store in CMC | Met | Bypass branch never calls `put_cache_entry` |
| MUST use Appendix A formulas | Met | See formula verification below |
| Cache hit MUST return retrieved materials | Met | `caching.ex:240` |
| Miss or expired MUST call underlying CMM | Met | `caching.ex:243-244`; expiry handled in CMC (`local_cache.ex:91-96`) |
| Non-Identity-KDF results MUST be added to CMC | Met | `caching.ex:254` |

### caching-cmm.md - Decrypt Materials

All six equivalents met (`caching.ex:161-168`, `259-277`). Decryption entries
correctly carry no usage-limit enforcement; limits are encrypt-only in the spec.

### caching-cmm.md - Appendix A (cache entry identifiers)

Verified by hand against the spec's byte tables. All three use SHA-384.

**Encryption, without algorithm suite** (`caching.ex:181-183`):

```
spec: 0x01 | 0x00 | 0x01 | 0x00 | partition | 0x00 | 0x00 | 0x00 | ctx
code: 0x01 | 0x00 | 0x01 | 0x00 | partition | 0x00 | 0x00 | 0x00 | ctx   MATCH
```

**Encryption, with algorithm suite** (`caching.ex:187-189`):

```
spec: 0x01 |0x00| 0x01 |0x00| partition |0x00| 0x01 |0x00| suite_id(2) |0x00| ctx
code: 0x01 |0x00| 0x01 |0x00| partition |0x00| 0x01 |0x00| suite_id(2) |0x00| ctx   MATCH
```

**Decryption** (`caching.ex:210-213`):

```
spec: 0x01 |0x00| 0x02 |0x00| partition |0x00| suite_id(2) |0x00| sorted_edks |0x00| ctx
code: 0x01 |0x00| 0x02 |0x00| partition |0x00| suite_id(2) |0x00| sorted_edks |0x00| ctx   MATCH
```

Supporting pieces also check out: EDKs are sorted lexicographically on their
serialized form and concatenated with no length prefix or count
(`caching.ex:200-204`), and `EncryptedDataKey.serialize/1`
(`encrypted_data_key.ex:73-87`) emits the message-header EDK entry layout the
spec cites. Note that `serialize_list/2` prepends a 2-byte count; the cache ID
correctly does not use it.

### cryptographic-materials-cache.md

| Requirement | Status | Evidence |
|-------------|--------|----------|
| Entry MUST have materials, creation time, expiry time, usage metadata | Met | `cache_entry.ex:26-33` |
| CMC MUST NOT return a TTL-expired entry | Met | `local_cache.ex:91-96` deletes and reports a miss |
| Put MUST replace any existing entry for the ID | Met | `:ets.insert/2` on a `:set` table |
| Put MUST NOT return the inserted entry | Met | Replies `:ok` |
| Delete MUST succeed when no entry exists | Met | `:ets.delete/2` is idempotent |
| Updating usage metadata SHOULD be atomic | Met | Serialized through the GenServer |
| SHOULD provide background removal of expired entries | Not met (see F5) | No sweeper; pruning is lookup-driven only |
| Local CMC SHOULD be a bounded LRU | Not met (see F5) | Table is unbounded |

## Findings

### F1. `max_bytes` is never enforced in any real code path (high)

`caching.ex:238` and `caching.ex:252` read `request[:max_plaintext_length]`, but
**nothing in `lib/` ever puts that key into a request**. The only producers are
`client.ex:339-343` (one-shot encrypt) and `stream.ex:87-90` (streaming), and
neither sets it. It appears solely in `caching.ex` and in the test file
(`caching_test.exs:182`), so the limit is exercised only by tests that construct
the request by hand.

Consequence: in production `bytes_used` is always 0, the `max_bytes` threshold
never trips, and a data key rotates on TTL or message count alone. The spec sets
Limit Bytes as "an additional security threshold to ensure that the data keys
expire and are refreshed periodically" - so the security control silently does
nothing.

Fix: thread the plaintext length from `client.ex` into the encryption materials
request. For the streaming path the length is not known up front; follow the
Python ESDK convention and **bypass the cache entirely when the length is
unknown**, since limits cannot be enforced without it. Document the streaming
behavior in the caching guide.

### F2. Limit check happens before the current request is counted (medium)

`CacheEntry.exceeded_limits?/3` (`cache_entry.ex:113-115`) tests
`bytes_used >= max_bytes` against usage *already recorded*, then
`caching.ex:238-239` adds the current request on top. A cached entry can
therefore exceed `max_bytes` by up to one full message. The spec calls Limit
Bytes "the maximum number of bytes that MAY be encrypted by a single data key",
which the overshoot violates.

The message counter is fine by construction: entries are created with
`messages_used: 1` (`caching.ex:253`), so an entry serves exactly `max_messages`
messages before refresh.

Fix: check the prospective total, `bytes_used + request_bytes > max_bytes`,
before reusing an entry. Depends on F1 to be meaningful.

### F3. Plaintext data keys are printable via `inspect/1` (medium, security)

There is no `defimpl Inspect` anywhere in `lib/`. `CacheEntry`,
`EncryptionMaterials`, and `DecryptionMaterials` all inspect in full, so a
`Logger.debug(inspect(entry))`, an exception with the struct in its message, or a
crashed GenServer's state dump writes the plaintext data key to logs. Caching
widens the exposure because keys now live in long-lived process state that
appears in supervisor crash reports.

Fix: add a redacted `Inspect` implementation for `CacheEntry` and both materials
structs. This is worth doing beyond the caching layer.

### F4. Auto-generated partition ID is raw bytes, not a UTF-8 string (low)

The spec's formulas take "the UTF-8 encoding of the caching CMM's Partition ID",
treating it as a string. `generate_partition_id/0` (`caching.ex:220-224`)
returns 16 raw random bytes. Uniqueness holds and cache IDs are still
well-defined, so nothing breaks, but it diverges from the other implementations
(which use a UUID string) and a raw-byte partition ID is awkward to log or
configure. `new/3` also does not validate a caller-supplied `:partition_id`, nor
that `max_bytes`/`max_messages` fall in the UInt64 range the spec specifies.

Fix: format the generated UUID as its canonical string, and validate the
caller-supplied values.

### F5. LocalCache is unbounded with no background pruning (low)

The spec describes the built-in local CMC as "a configurable, in-memory, least
recently used (LRU) cache" and says an implementation SHOULD remove expired
entries in the background. `LocalCache` has neither an entry cap nor a sweeper:
expired entries are dropped only when their exact cache ID is looked up again
(`local_cache.ex:91-96`). A long-lived process encrypting under many distinct
encryption contexts grows the ETS table without bound, and each dead entry holds
a plaintext data key in memory past its TTL.

Both are SHOULDs, so this is not a conformance failure, but for the multi-tenant
GKE use case in the parent plan (per-tenant partition IDs, so per-tenant cache
IDs) unbounded growth is a live concern.

Fix: add a `:max_entries` option with LRU eviction, plus a periodic sweep.

### Non-finding: hardcoded CMM dispatch

`call_underlying_cmm_encrypt/2` (`caching.ex:281-295`) pattern-matches on the
three known CMM structs and rejects everything else, so a user-defined CMM
implementing `Cmm.Behaviour` cannot be wrapped. The same pattern is repeated in
`client.ex:350-363` and `stream.ex:202-215`. Not a spec violation and not caused
by the caching CMM, but it will block any third-party or future in-tree CMM.
Worth a separate issue.

## Test coverage gaps

`test/aws_encryption_sdk/cmm/caching_test.exs` covers cache hit/miss, partition
isolation, limit refresh, Identity KDF bypass, and CMM nesting. Two gaps:

1. **No known-answer test for cache identifiers.** The four tests under
   `describe "cache ID computation"` only assert determinism and that IDs
   differ across inputs. Every one would still pass with a wrong byte layout.
   Since the formulas exist to make caches interoperable across
   implementations, they need fixed expected digests. Generate them from the
   spec by hand (or cross-check against the Python ESDK) and commit them.
2. **No TTL expiry test through the CMM.** `local_cache_test.exs` covers
   `CacheEntry.expired?/1`, but nothing asserts that an expired entry causes
   the caching CMM to re-call the underlying CMM.

Property tests for the limit and TTL behavior, as the parent plan suggests, are
worth adding once F1 and F2 land.

## Guide gap

`guides/security-best-practices.md` should state the caching tradeoff: reusing a
data key widens the blast radius of a compromise, TTL and the usage limits are
the controls that bound it, and multi-tenant deployments should use per-tenant
partition IDs so one tenant's cached keys can be isolated and evicted. The
streaming caveat from F1 belongs here too.

## Recommended sequencing

1. F1 + F2 together (they are one change to the limit logic, plus threading the
   plaintext length) with tests.
2. F3 (small, independent, security-relevant).
3. Cache identifier known-answer tests and the TTL-through-CMM test.
4. F4, F5, and the guide update.
5. File the CMM dispatch issue separately.

## Open question

The `max_plaintext_length` key is documented in `cmm/behaviour.ex:67,74` as a
"maximum plaintext length hint" and is optional in the request type. Confirm
whether the intent was for callers to supply it (making F1 a wiring bug) or for
the caching CMM to derive it (making F1 a design gap). Either way the fix is the
same; it only changes whether `client.ex` or the CMM computes the value.
