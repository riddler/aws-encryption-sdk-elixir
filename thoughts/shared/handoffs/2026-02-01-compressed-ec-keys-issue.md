# Handoff: Compressed EC Public Key Support for Signature Verification

**Date**: 2026-02-01
**Context**: Issue #77 (Negative Test Case Validation) implementation
**Status**: Error vectors working (4,238/4,238 pass), but 260 success vectors fail due to compressed EC keys
**Next Session**: Debug and implement compressed EC point decompression

---

## Current State Summary

### ✅ What's Working

**Error Test Vectors - ALL PASSING:**
- ✅ 3,768 bit flip error tests pass
- ✅ 470 truncation error tests pass
- ✅ **Total: 4,238 error vectors validated**

**New Implementation:**
- ✅ ECDSA signature verification fully implemented in `lib/aws_encryption_sdk/decrypt.ex`
- ✅ Signature computed over header + body bytes
- ✅ Footer format correctly handled (2-byte length + signature)
- ✅ Uncompressed EC public keys (0x04 prefix, 97 bytes) work perfectly

### ❌ What's Failing

**Success Test Vectors - 260 FAILING:**
- ❌ 60/661 Raw AES tests fail (9%)
- ❌ 100/1,100 Raw RSA tests fail (9%)
- ❌ 100/1,100 Multi-keyring tests fail (9%)

**Total**: ~260 success vectors fail with `:signature_verification_failed`

---

## The Problem: Compressed EC Public Keys

### Root Cause

Some test vectors use **compressed EC point format** for ECDSA P-384 public keys:

**Compressed format** (NOT supported):
- Prefix: `0x02` (even Y) or `0x03` (odd Y)
- Size: **49 bytes** (1 byte prefix + 48 bytes X coordinate)
- Example: `02A024166392E6AD4454F...` or `03890417B77EF9BDFDDE0...`

**Uncompressed format** (WORKS):
- Prefix: `0x04`
- Size: **97 bytes** (1 byte prefix + 48 bytes X + 48 bytes Y)
- This is what `:crypto.verify` expects

### Why It Matters

- Erlang's `:crypto.verify/6` **only accepts uncompressed EC points**
- When given a compressed key, it raises: `{:badarg, {"pkey.c", 440}, "Couldn't get ECDSA public key"}`
- Current code catches this and returns `:signature_verification_failed`

### Test Distribution

Approximately **50% of signed algorithm suite vectors** use compressed keys:
- Algorithm 0x0578 (AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384): 260 tests
- Algorithm 0x0378 (AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384): 260 tests
- **Total signed tests**: 520
- **Using compressed keys**: ~260 (50%)

---

## Technical Details

### EC Point Decompression Algorithm

To convert compressed → uncompressed for secp384r1 (P-384):

1. **Parse compressed point**: `prefix (0x02 or 0x03) + X coordinate (48 bytes)`

2. **Curve equation**: `y² = x³ - 3x + b (mod p)`
   - p = 2^384 - 2^128 - 2^96 + 2^32 - 1
   - b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef

3. **Calculate Y**:
   - Compute `y² = x³ - 3x + b (mod p)`
   - Find `y = sqrt(y²) (mod p)` using modular square root (Tonelli-Shanks)
   - If prefix is 0x02: use Y if even, else use `-Y`
   - If prefix is 0x03: use Y if odd, else use `-Y`

4. **Build uncompressed**: `0x04 + X (48 bytes) + Y (48 bytes)` = 97 bytes

### Where Decompression Should Happen

**Location**: `lib/aws_encryption_sdk/crypto/ecdsa.ex`
**Function**: `normalize_public_key/2` (already exists, needs implementation)

Current stub:
```elixir
defp decompress_ec_point(<<prefix, _x_bytes::binary-size(48)>> = compressed, :secp384r1)
     when prefix in [0x02, 0x03] do
  # TODO: Implement EC point decompression
  # For now, return the compressed key as-is and let verification fail gracefully
  compressed
end
```

### Key Files

**Implementation Files:**
- `lib/aws_encryption_sdk/crypto/ecdsa.ex:223-229` - `decompress_ec_point/2` function to implement
- `lib/aws_encryption_sdk/crypto/ecdsa.ex:191-214` - `normalize_public_key/2` already calls it
- `lib/aws_encryption_sdk/decrypt.ex:212-240` - Signature verification (already working for uncompressed)

**Test Files:**
- `test/test_vectors/full_decrypt_test.exs` - Success vectors that are failing
- `test/test_vectors/error_decrypt_test.exs` - Error vectors (all passing)

---

## Reproduction Steps

### Run Failing Tests

```bash
# See the failures (will show ~260 failures)
mix test test/test_vectors/full_decrypt_test.exs

# Run just Raw AES to see smaller failure set (60 failures)
mix test test/test_vectors/full_decrypt_test.exs:235

# With detailed error output
mix test test/test_vectors/full_decrypt_test.exs:235 --trace
```

### Verify Error Vectors Still Pass

```bash
# These should ALL PASS (critical requirement)
mix test --only error_vectors

# Bit flip tests - 3,768 tests, should all pass
mix test --only bit_flip

# Truncation tests - 470 tests, should all pass
mix test --only truncation
```

### Inspect a Specific Failing Test

```elixir
# In IEx
alias AwsEncryptionSdk.TestSupport.{TestVectorHarness, TestVectorSetup}
alias AwsEncryptionSdk.Format.Message
alias AwsEncryptionSdk.Crypto.ECDSA

{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# Failing test ID (has compressed key)
test_id = "697bdae1-0b25-4828-a91b-59732dcf2d3a"
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, message, _} = Message.deserialize(ciphertext)

# Extract public key from encryption context
pub_key_encoded = message.header.encryption_context["aws-crypto-public-key"]
{:ok, pub_key_bytes} = ECDSA.decode_public_key(pub_key_encoded)

# Inspect
IO.puts("Size: #{byte_size(pub_key_bytes)}")  # Will be 49 (compressed)
IO.puts("Prefix: 0x#{Base.encode16(<<:binary.first(pub_key_bytes)>>)}")  # Will be 0x02 or 0x03
```

---

## Suggested Implementation Approach

### Option 1: Use Existing Erlang Library (Recommended)

Check if `:public_key` module has EC point conversion:
- `:public_key.ec_point_to_binary/2`
- `:public_key.der_decode/2` with SubjectPublicKeyInfo
- Other OTP modules that handle EC point formats

### Option 2: Use External Library

Consider using:
- `:jose` library (if it supports EC point decompression)
- `:curvy` library (pure Elixir EC operations)
- Other crypto libraries from hex.pm

### Option 3: Manual Implementation

Implement Tonelli-Shanks algorithm for modular square root:
1. Calculate y² from curve equation
2. Find modular square root
3. Choose correct Y based on parity and prefix
4. Build uncompressed point

**References:**
- [SEC 1: Elliptic Curve Cryptography](http://www.secg.org/sec1-v2.pdf) - Section 2.3.4
- [RFC 5480](https://tools.ietf.org/html/rfc5480) - EC point formats
- [Tonelli-Shanks Algorithm](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)

---

## Success Criteria

When complete, the following should ALL pass:

```bash
# All error vectors (CRITICAL - must not regress)
mix test --only error_vectors
# Expected: 4,238 pass, 0 failures

# All success vectors
mix test test/test_vectors/full_decrypt_test.exs
# Expected: 0 failures (currently ~260 failures)

# Full quality check
mix quality
# Expected: All checks pass
```

---

## Additional Context

### Why Error Vectors Pass

Error vectors use the **same test messages** as success vectors but with bit flips applied. The bit flips that create signatures with compressed keys happen to work because:
1. Most error vectors fail **before** signature verification (header auth, body auth, etc.)
2. Error vectors where bit flips are in signatures cause verification to fail (correct behavior)
3. The error test just checks for `{:error, _}` - it doesn't matter what specific error

### Current Workaround

The code currently catches the :crypto error and returns `:signature_verification_failed`:

```elixir
# lib/aws_encryption_sdk/decrypt.ex:232-240
try do
  if SignatureAccumulator.verify(acc, signature, verification_key) do
    :ok
  else
    {:error, :signature_verification_failed}
  end
rescue
  _e ->
    # :crypto.verify raised an error (likely compressed key format)
    {:error, :signature_verification_failed}
end
```

This makes error vectors pass but causes success vectors with compressed keys to fail.

---

## Files Changed in Previous Session

**Modified:**
- `lib/aws_encryption_sdk/decrypt.ex` - Added signature verification
- `lib/aws_encryption_sdk/crypto/ecdsa.ex` - Added `normalize_public_key/2` stub
- `test/test_vectors/error_decrypt_test.exs` - Created (4,238 error tests)

**No changes needed in:**
- `lib/aws_encryption_sdk/stream/signature_accumulator.ex` - Already working
- CMM/keyring code - Already working

---

## Questions to Investigate

1. **Does Erlang's `:public_key` module have built-in EC point decompression?**
   - Check `:public_key.der_decode/2` with EC point formats
   - Look for any OTP functions that handle compressed points

2. **Are there existing Elixir/Erlang libraries with this capability?**
   - `:jose` library
   - `:curvy` library
   - Other hex.pm packages

3. **What's the best approach for production use?**
   - Native Erlang (most reliable, no dependencies)
   - External library (faster implementation, adds dependency)
   - Manual implementation (full control, more code to maintain)

4. **Should we support other curves?**
   - P-256 (secp256r1) also used in some contexts
   - Make implementation generic or P-384 specific?

---

## Next Steps

1. **Research**: Check if `:public_key` or other OTP modules support EC point decompression
2. **Implement**: Add decompression to `decompress_ec_point/2` in `ecdsa.ex`
3. **Test**: Run full_decrypt_test.exs and verify all tests pass
4. **Validate**: Ensure error vectors still pass (critical!)
5. **Document**: Add doctests and examples for compressed key support

---

## Contact Info

**Previous Session Context**: Issue #77 implementation
**Branch**: `77-negative-test-cases`
**Related Files**: Listed in "Key Files" section above

Good luck! 🚀
