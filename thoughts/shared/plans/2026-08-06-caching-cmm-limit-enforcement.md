# Caching CMM Limit Enforcement Plan (F1 + F2)

## Overview

Make the Caching CMM's `max_bytes` security threshold actually enforceable, and
stop cache entries from overshooting it.

Today `max_bytes` is dead: `Cmm.Caching` reads `request[:max_plaintext_length]`,
but no caller in `lib/` ever sets that key, so `bytes_used` stays 0 forever and
the limit never trips. Separately, the limit check tests usage already recorded
rather than the prospective total, so an entry can exceed `max_bytes` by up to
one full message.

**Research**: `thoughts/shared/research/2026-08-06-caching-cmm-conformance-audit.md`
(findings F1 and F2)
**Parent plan**: `thoughts/shared/plans/2026-08-06-kms-vectors-cmm-gcp.md`
(workstream B)

## Specification Requirements

### Source Documents
- [caching-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md) - spec version 0.4.0

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Limit Bytes is the max bytes that MAY be encrypted by a single data key | caching-cmm.md#limit-bytes | MUST |
| Limit Bytes exists as an additional security threshold forcing data key refresh | caching-cmm.md#limit-bytes | Rationale |
| MUST set initial usage stats when storing encryption materials | caching-cmm.md#usage-stats | MUST |
| MUST update usage stats when obtaining materials from the CMC | caching-cmm.md#usage-stats | MUST |

The spec does not prescribe *how* the plaintext length reaches the CMM; the CMM
interface's encryption materials request carries it as an optional field. This
plan wires it through and defines the behavior when it is absent.

## Test Vectors

No official test vectors cover the Caching CMM - caching is an implementation
layer that static ciphertext vectors cannot exercise. Validation is by unit and
integration tests, consistent with the original caching CMM plan
(`thoughts/shared/plans/2026-01-28-GH61-caching-cmm.md`).

## Current State Analysis

| Location | Current behavior |
|----------|------------------|
| `lib/aws_encryption_sdk/cmm/behaviour.ex:67,74` | Documents `:max_plaintext_length` as an optional "maximum plaintext length hint" on the request |
| `lib/aws_encryption_sdk/client.ex:338-347` | Builds the encrypt request with only `encryption_context`, `commitment_policy`, `algorithm_suite` - never the length |
| `lib/aws_encryption_sdk/stream.ex:82-95` | Builds the request with only `encryption_context`, `commitment_policy` |
| `lib/aws_encryption_sdk/cmm/caching.ex:238,252` | Reads `Map.get(request, :max_plaintext_length, 0)` - always the 0 default in practice |
| `lib/aws_encryption_sdk/cache/cache_entry.ex:113-115` | `exceeded_limits?/3` compares recorded usage only: `messages_used >= max_messages or bytes_used >= max_bytes` |

`Client.encrypt/3` (`client.ex:166`) already has the full plaintext in hand
before it calls `get_encryption_materials/3`, so the one-shot path can supply an
exact length with no API change. The streaming path cannot.

**Resolved decision**: streaming bypasses the cache when the length is unknown
(matching the Python ESDK), and `Stream.encrypt/3` gains an optional
`:plaintext_length` opt so callers who do know the size keep caching.

Note the message counter is already correct and needs no change: entries are
created with `messages_used: 1` (`caching.ex:253`), so an entry serves exactly
`max_messages` messages before refresh.

## Desired End State

- `max_bytes` refreshes data keys in real encrypt paths.
- No cache entry is reused when doing so would push `bytes_used` past
  `max_bytes`.
- Streaming callers either supply a length (and get caching) or do not (and
  bypass the cache), with no silent limit hole either way.
- Behavior is documented in the caching guide.

## What We're NOT Doing

- F3 (redacted `Inspect`), F4 (partition ID format), F5 (bounded/pruned
  LocalCache) - separate PRs per the audit's sequencing.
- Cache identifier known-answer tests - separate PR.
- The hardcoded CMM dispatch issue - separate issue.
- Any change to decryption caching; usage limits are encrypt-only per spec.

## Implementation Approach

Three small changes: thread the length in, make the limit check prospective, add
an explicit unknown-length bypass. The bypass is what keeps the prospective
check honest - without it, an absent length silently reads as 0 bytes and the
check passes vacuously.

### Phase 1: Prospective limit check (F2)

**Changes**: `lib/aws_encryption_sdk/cache/cache_entry.ex`

Replace `exceeded_limits?/3` with a function that takes the pending request's
byte count and answers whether the entry may serve it:

```elixir
@spec can_serve?(t(), non_neg_integer(), non_neg_integer(), non_neg_integer()) :: boolean()
def can_serve?(%__MODULE__{} = entry, request_bytes, max_messages, max_bytes) do
  entry.messages_used < max_messages and
    entry.bytes_used + request_bytes <= max_bytes
end
```

Keep `exceeded_limits?/3` as a deprecated delegate, or remove it - it is
`@doc`'d and has doctests, so if removed, drop the doctest with it. Prefer
removal; it has no callers outside `caching.ex` and the tests.

Update `caching.ex:233` to call `can_serve?/4`, computing `request_bytes` once
and reusing it for both the check and the subsequent `update_usage` call.

**Edge case that must be handled**: a single message larger than `max_bytes`.
A freshly fetched entry must always serve the request that caused the fetch,
otherwise the CMM re-fetches forever. This falls out naturally as long as
`fetch_and_cache_encryption_materials/3` does not re-check the limit - it
stores the entry with the usage recorded and returns the materials. The next
request then finds the entry over limit and refreshes. Add a test pinning this.

#### Success Criteria

**Automated**:
- [x] `mix test test/aws_encryption_sdk/cache/`
- [x] `mix test test/aws_encryption_sdk/cmm/caching_test.exs`
- [x] New test: entry at `bytes_used = max_bytes - 10` refuses an 11-byte
      request and refreshes instead
- [x] New test: a request larger than `max_bytes` succeeds once and refreshes
      on the next call (no infinite refetch)
- [x] New test: `max_messages` boundary still serves exactly `max_messages`
      messages (guards against regressing the currently-correct behavior)

**Manual**:
- [x] No entry observed with `bytes_used > max_bytes` in a scripted loop
      (verified via a 20-message scripted loop checking the cache entry after
      every encrypt)

**Implementation note**: `exceeded_limits?/3` was removed outright rather than
deprecated (the plan left this open). It had no callers outside `caching.ex` and
its own tests.

### Phase 2: Thread plaintext length through one-shot encrypt (F1)

**Changes**: `lib/aws_encryption_sdk/client.ex`

Pass `byte_size(plaintext)` from `encrypt/3` (`client.ex:166`) into
`get_encryption_materials/3` and set it as `:max_plaintext_length` on the
request map (`client.ex:339-343`). This is an internal private function
signature change - no public API impact.

Check the other producers of encryption materials requests for the same gap:
`encrypt_with_keyring/3` and anything else that reaches
`call_cmm_get_encryption_materials/2`. Every path with the plaintext in hand
should supply the length.

#### Success Criteria

**Automated**:
- [x] `mix test test/aws_encryption_sdk/`
- [x] New test: `Client.encrypt/3` through a Caching CMM with a small
      `max_bytes` produces a *different* plaintext data key once cumulative
      bytes cross the limit (this is the test that would have caught F1)
- [x] New test: the same, under the limit, reuses the data key

**Manual**:
- [x] `mix docs` renders without new warnings (also fixed two pre-existing
      README `examples/` link warnings, so the build is now warning-free)

### Phase 3: Streaming bypass plus opt-in hint (F1, streaming half)

**Changes**: `lib/aws_encryption_sdk/stream.ex`, `lib/aws_encryption_sdk/cmm/caching.ex`

1. `Stream.encrypt/3` (`stream.ex:43`) accepts an optional `:plaintext_length`.
   When given, `init_encryptor_for_stream/2` (`stream.ex:82`) sets
   `:max_plaintext_length` on the request; when absent, it omits the key
   entirely (do not default it to 0).
2. In `Caching.get_encryption_materials/2`, add a bypass branch alongside the
   existing Identity KDF bypass: if the request has no `:max_plaintext_length`
   key, call the underlying CMM directly and do not store the result. Use
   `Map.has_key?/2`, not `Map.get/3` with a default - the whole point is
   distinguishing "unknown" from "zero".
3. Update `behaviour.ex:67,74` docs: the field is no longer a soft "hint"; its
   absence disables caching for that request.

Also decide and document what `AwsEncryptionSdk.encrypt_stream/3`
(`aws_encryption_sdk.ex:299`) forwards - it should pass the opt through.

**Caution**: a Caching CMM wrapped in another Caching CMM
(`caching.ex:289-291`) forwards the request unchanged, so the bypass propagates
correctly through nesting. Add a test for the nested case rather than assuming.

#### Success Criteria

**Automated**:
- [x] `mix test test/aws_encryption_sdk/stream/`
- [x] New test: streaming encrypt with no `:plaintext_length` calls the
      underlying CMM every time and leaves the cache empty
- [x] New test: streaming encrypt with `:plaintext_length` reuses a cached
      entry and increments `bytes_used` by the declared amount
- [x] New test: nested Caching CMMs both bypass on unknown length
- [x] Existing streaming tests unchanged and passing (several caching CMM
      unit tests gained `max_plaintext_length: 0` since absence now means
      bypass, and the old "handles request without max_plaintext_length"
      test flipped to assert the bypass)

**Manual**:
- [x] Stream a file larger than `max_bytes` with a hint set; confirm the key
      refreshes on the following stream (verified by script: a 500-byte
      stream against `max_bytes: 100` was served once, and the next stream
      carried different EDKs)

### Phase 4: Documentation

**Changes**: `guides/` (caching guide), `lib/aws_encryption_sdk/cmm/caching.ex`
moduledoc

- Document that `max_bytes` is enforced against the declared plaintext length,
  and that streaming without `:plaintext_length` bypasses the cache. Explain
  why (limits are unenforceable without a length) so the behavior does not read
  as a bug.
- Note the one-message overshoot is now closed, and that a single message
  larger than `max_bytes` is served once by design.

The broader caching security tradeoff text called for in the audit
(`guides/security-best-practices.md`) is deliberately left to the F4/F5 PR so
this one stays reviewable.

#### Success Criteria

**Automated**:
- [x] `mix test` (guide code extraction runs via
      `test/support/guide_code_extractor.ex`, so guide snippets must compile)
- [x] `mix quality`

**Manual**:
- [ ] Guide reads correctly for a user deciding whether to cache with streams

**Implementation note**: there is no dedicated caching guide; the caching
behavior docs went into `guides/choosing-components.md` (the existing Caching
CMM sections) and the `Cmm.Caching` moduledoc. The stale "Caching CMM
currently works with the streaming API" note was removed.

## Final Verification

**Automated**:
- [x] `mix quality` clean (all 844 tests, 4,240 error vectors + 2,861 success
      vectors, Credo, Dialyzer, deps audit, 93.5% coverage)
- [x] Full suite green, including the test-vector suites if vectors are present

**Implementation note**: unrelated pre-existing gate failures were also fixed
in this branch: AWS KMS integration tests now auto-exclude without
`KMS_KEY_ARN`; hackney/ex_aws/ex_aws_kms and doctor/decimal were updated to
clear `mix deps.audit` advisories; `kms_client/ex_aws.ex` is skipped in
coverage (only reachable via credential-gated integration tests); README
`examples/` links were fixed for the docs build.

**Manual**:
- [x] Round-trip: encrypt with Caching CMM under a low `max_bytes`, decrypt all
      messages successfully across the key rotation boundary (scripted: 20
      messages, 7 distinct data keys, every message decrypted)
- [x] Confirm no cache entry ever reports `bytes_used > max_bytes` (same
      script asserts this after every encrypt)

## Testing Strategy

### Unit Tests
- `CacheEntry.can_serve?/4`: boundary conditions at exactly `max_bytes`, one
  over, one under; zero-byte requests; requests larger than `max_bytes`
- `Cmm.Caching`: bypass on missing `:max_plaintext_length`; usage accumulation
  across successive requests; refresh on crossing the byte limit

### Integration Tests
- `Client.encrypt/3` through a Caching CMM crossing `max_bytes` mid-run
- `Stream.encrypt/3` with and without `:plaintext_length`
- Nested Caching CMMs

### Property Tests (optional, if cheap)
Per the parent plan: for any sequence of request sizes, the sum of bytes served
by any single cache entry never exceeds `max_bytes`, except where a single
request alone exceeds it.

## Performance Considerations

The prospective check is a single extra addition and comparison per cache
lookup - negligible. The streaming bypass removes caching for streaming callers
who do not pass a length, which is a real throughput change for anyone relying
on it today. Call this out in the CHANGELOG as a behavior change, not a bug fix.

## Migration Notes

Behavior changes visible to users:

1. Streaming encrypt no longer uses the cache unless `:plaintext_length` is
   given. Callers wanting the old behavior pass the opt.
2. `max_bytes` now actually triggers data key refresh, so deployments that set a
   low `max_bytes` will see more calls to their key provider (KMS). This is the
   intended security behavior, but it can be a cost surprise - flag it
   prominently in the CHANGELOG.
3. `CacheEntry.exceeded_limits?/3` is removed (or deprecated). It is a public
   function on a public module, so this is technically breaking for anyone
   using the cache layer directly. Given pre-1.0 status, removal is acceptable;
   note it in the CHANGELOG.

## References

- Research: `thoughts/shared/research/2026-08-06-caching-cmm-conformance-audit.md`
- Parent plan: `thoughts/shared/plans/2026-08-06-kms-vectors-cmm-gcp.md`
- Original implementation plan: `thoughts/shared/plans/2026-01-28-GH61-caching-cmm.md`
- Spec: [caching-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/caching-cmm.md)
