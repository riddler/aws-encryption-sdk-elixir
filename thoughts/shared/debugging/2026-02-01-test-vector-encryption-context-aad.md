# Test Vector Failures: Encryption Context in Header AAD

**Date**: 2026-02-01
**Issue**: 481/661 Raw AES test vectors fail with header authentication or commitment errors
**Context**: Phase 3 of Full Test Vector Runner implementation (GH#76)
**Status**: BLOCKED - Requires spec compliance investigation
**Handoff to**: Next debugging session (Opus recommended)

## Executive Summary

We successfully fixed the initial header authentication bug (version/type bytes), improving test pass rate from 0% → 27% (45/661). However, 481 test vectors still fail, primarily with `:header_authentication_failed`, suggesting a remaining issue with how encryption context is included in the header authentication AAD.

## What Was Fixed ✅

### 1. Header Version/Type Bytes in AAD (RESOLVED)
**Files Changed**:
- `lib/aws_encryption_sdk/format/header.ex:224-252` - v1 body includes `<<0x01, 0x80>>`
- `lib/aws_encryption_sdk/format/header.ex:150-173` - v2 body includes `<<0x02>>`

**Result**: Basic v1 messages with empty EC now decrypt successfully.

### 2. Required Encryption Context Keys in AAD (PARTIALLY FIXED)
**Files Changed**:
- `lib/aws_encryption_sdk/crypto/header_auth.ex:53-136` - Filter EC by required keys
- `lib/aws_encryption_sdk/cmm/required_encryption_context.ex:108-145` - Set required_encryption_context_keys in materials
- All encrypt/decrypt call sites updated to pass full EC + required keys

**Result**: Required EC CMM tests pass for non-streaming. Streaming still fails (2 tests).

### 3. RSA PEM Loading in Test Harness (RESOLVED)
**File**: `test/test_vectors/full_decrypt_test.exs:117`
**Change**: Added `RawRsa.load_private_key_pem(pem)` before passing to keyring

**Result**: RSA smoke test now passes.

## What's Still Broken ❌

### Test Results Summary
```
Raw AES Test Vectors: 180 passed, 481 failed (27% pass rate)
- Empty EC vectors: PASS ✅
- Non-empty EC vectors: MOSTLY FAIL ❌
- Committed suites: FAIL ❌

Required EC CMM:
- Non-streaming: PASS ✅
- Streaming: FAIL ❌ (2 tests)
```

### Failure Modes

1. **`:header_authentication_failed`** (most common)
   - 400+ test vectors
   - Pattern: Tests with non-empty encryption context
   - Example IDs:
     - `5caff5ef-0851-45f5-846a-6fbdb55765e4`
     - `697bdae1-0b25-4828-a91b-59732dcf2d3a`
     - `742b4558-ac3d-48dd-bea1-af5f048c6728`

2. **`:commitment_mismatch`** (committed suites)
   - ~80 test vectors
   - Pattern: Algorithm suites 0x0478, 0x0578 (committed)
   - Example IDs:
     - `49ce0159-d401-4635-be8d-c0080e864065`
     - `4acf6434-6e95-4c2e-9d61-40d4c255c4ee`

## Current Understanding

### AAD Computation Per Spec

From [aws-encryption-sdk-specification](https://github.com/awslabs/aws-encryption-sdk-specification):

> **Header Authentication AAD**:
> The AAD MUST be the concatenation of:
> 1. Serialized message header body
> 2. Serialization of "encryption context to only authenticate"
>
> **"Encryption context to only authenticate"**:
> The encryption context from materials filtered to only contain keys listed in `required_encryption_context_keys`.

### Our Implementation

```elixir
# lib/aws_encryption_sdk/crypto/header_auth.ex:120-130
def verify_header_auth_tag(header, derived_key, full_encryption_context, required_ec_keys) do
  {:ok, header_body} = Header.serialize_body(header)

  # Filter full EC by required keys
  required_ec = Map.take(full_encryption_context, required_ec_keys)
  ec_bytes = EncryptionContext.serialize(required_ec)

  aad = header_body <> ec_bytes
  # ... verify with aad
end
```

### Key Questions

1. **For test vectors WITHOUT Required EC CMM** (basic vectors):
   - `required_encryption_context_keys = []`
   - "EC to only authenticate" = `{}` (empty)
   - Serialization = `<<>>` (empty binary)
   - **This should work, but 481 tests fail!**

2. **Why do some non-empty EC tests pass?**
   - 180 tests pass with our current implementation
   - What's different about these vs. the 481 that fail?

3. **Is Python SDK implementing the spec differently?**
   - Did Python SDK append full EC instead of filtered EC?
   - Did spec change between when vectors were created and now?

## Debugging Strategy

### Immediate Next Steps

1. **Analyze a single failing test in detail**
   ```elixir
   # Pick one failing test
   test_id = "5caff5ef-0851-45f5-846a-6fbdb55765e4"

   # Extract all details:
   # - Algorithm suite ID
   # - Encryption context (stored in header)
   # - Message format version (v1 or v2)
   # - Expected vs actual AAD bytes
   ```

2. **Compare passing vs failing tests**
   - What's common among the 180 passing tests?
   - What's common among the 481 failing tests?
   - Look for patterns by:
     - Algorithm suite
     - Encryption context presence/content
     - Message format version
     - Frame length / content type

3. **Byte-level AAD debugging**
   Add detailed logging in `header_auth.ex`:
   ```elixir
   def verify_header_auth_tag(header, derived_key, full_ec, required_keys) do
     {:ok, header_body} = Header.serialize_body(header)
     IO.puts("Header body length: #{byte_size(header_body)}")
     IO.inspect(header_body, label: "Header body bytes", limit: :infinity)

     required_ec = Map.take(full_ec, required_keys)
     IO.inspect(full_ec, label: "Full EC")
     IO.inspect(required_keys, label: "Required keys")
     IO.inspect(required_ec, label: "Filtered EC")

     ec_bytes = EncryptionContext.serialize(required_ec)
     IO.inspect(ec_bytes, label: "EC bytes", limit: :infinity)

     aad = header_body <> ec_bytes
     IO.puts("Total AAD length: #{byte_size(aad)}")
     # ...
   end
   ```

4. **Check Python SDK source code**
   - How does Python SDK compute header auth AAD?
   - File: `aws_encryption_sdk/internal/crypto/authentication.py`
   - Look for: `_serialize_encryption_context` or similar
   - URL: https://github.com/aws/aws-encryption-sdk-python

### Alternative Hypotheses

#### Hypothesis 1: Spec Interpretation Difference
**Theory**: The spec says to append "encryption context to only authenticate", but Python SDK might interpret this differently for backward compatibility.

**Test**: Compare our serialization with Python SDK for same EC:
```python
# Python SDK
from aws_encryption_sdk.structures import EncryptionContext
ec = {"key1": "value1", "key2": "value2"}
serialized = EncryptionContext.serialize(ec)
```

```elixir
# Our SDK
ec = %{"key1" => "value1", "key2" => "value2"}
serialized = EncryptionContext.serialize(ec)
```

#### Hypothesis 2: Legacy Behavior
**Theory**: Test vectors were created with old behavior that appended full EC, not filtered EC.

**Evidence**:
- Spec might have been clarified after vectors were created
- Required EC CMM is a newer feature
- Test vectors might pre-date the spec clarification

**Test**: Try appending full EC instead of filtered EC and see if more tests pass.

#### Hypothesis 3: Encryption Context Serialization Bug
**Theory**: Our `EncryptionContext.serialize/1` produces different bytes than Python SDK.

**Test**:
1. Create test vector with known EC using Python SDK
2. Parse with our SDK and compare serialized bytes
3. Check:
   - Key/value length encoding (big-endian?)
   - UTF-8 encoding
   - Sorting order
   - Empty context handling

#### Hypothesis 4: Header Body Serialization Difference
**Theory**: Even though we fixed version/type bytes, there might be other subtle differences in header body serialization.

**Test**:
1. Parse a failing test vector
2. Serialize header body with our code
3. Compare byte-by-byte with original

Check:
- Algorithm suite ID encoding
- Message ID length/encoding
- EDK serialization
- Content type encoding
- Frame length encoding

## Code Locations

### Key Files

**Header Authentication**:
- `lib/aws_encryption_sdk/crypto/header_auth.ex:48-136` - Compute and verify header auth tag
- `lib/aws_encryption_sdk/format/header.ex:109-246` - Header serialization (v1 and v2)
- `lib/aws_encryption_sdk/format/encryption_context.ex:59-86` - EC serialization

**Decrypt Flow**:
- `lib/aws_encryption_sdk/decrypt.ex:54-69` - Main decrypt function
- `lib/aws_encryption_sdk/decrypt.ex:123-125` - Header auth verification call

**Test Infrastructure**:
- `test/test_vectors/full_decrypt_test.exs:217-267` - Raw AES test suite
- `test/support/test_vector_harness.ex` - Test vector loading utilities

**Required EC CMM**:
- `lib/aws_encryption_sdk/cmm/required_encryption_context.ex:108-145` - Materials handling

### Relevant Spec Sections

- [data-format/message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md) - Header format and authentication
- [client-apis/encrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - Header auth AAD computation
- [framework/structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Encryption context serialization

## Reproduction

### Run Failing Tests
```bash
# All Raw AES tests
mix test test/test_vectors/full_decrypt_test.exs --only raw_aes --seed 0

# Single failing test (add this to test file first)
mix test test/test_vectors/full_decrypt_test.exs:XXX --trace
```

### Debug Single Test Vector
```elixir
# In IEx
alias AwsEncryptionSdk.TestSupport.TestVectorHarness
alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Keyring.RawAes

{:ok, harness} = TestVectorHarness.load_manifest(
  "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
)

test_id = "5caff5ef-0851-45f5-846a-6fbdb55765e4"

{:ok, test} = TestVectorHarness.get_test(harness, test_id)
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, message, _} = TestVectorHarness.parse_ciphertext(ciphertext)

# Inspect message details
IO.inspect(message.header.algorithm_suite.id, label: "Algorithm Suite")
IO.inspect(message.header.encryption_context, label: "Stored EC")
IO.inspect(message.header.encrypted_data_keys, label: "EDKs")

# Build keyring and try decrypt
# ...
```

### Compare With Python SDK

Create test vector with Python SDK:
```python
import aws_encryption_sdk
from aws_encryption_sdk.keyrings.raw import RawAESKeyring

# Use same key as test vector
wrapping_key = bytes([...])  # From test vector keys.json

keyring = RawAESKeyring(
    key_namespace="test-namespace",
    key_name=b"test-key",
    wrapping_key=wrapping_key
)

client = aws_encryption_sdk.EncryptionSDKClient()
ciphertext, header = client.encrypt(
    source=b"test plaintext",
    keyring=keyring,
    encryption_context={"key1": "value1"}
)

# Inspect header bytes
print(f"Header: {header.hex()}")
```

## Success Criteria

Once resolved:
1. ✅ Raw AES tests: >95% pass rate (>630/661 passing)
2. ✅ Committed suite tests: All passing
3. ✅ Required EC CMM streaming tests: All passing (2 tests)
4. ✅ No regression in existing tests (822 total should pass)

## References

- **Previous Debug Doc**: `thoughts/shared/debugging/2026-02-01-header-auth-failure-test-vectors.md` (RESOLVED)
- **Implementation Plan**: `thoughts/shared/plans/2026-02-01-GH76-full-test-vector-runner.md`
- **Issue**: #76 - Implement Full Test Vector Runner for Success Cases
- **AWS Spec**: https://github.com/awslabs/aws-encryption-sdk-specification
- **Python SDK**: https://github.com/aws/aws-encryption-sdk-python
- **Test Vectors**: https://github.com/awslabs/aws-encryption-sdk-test-vectors

## Files Modified in This Session

### Core Implementation
- `lib/aws_encryption_sdk/format/header.ex` - Added version/type bytes to v1 and v2 body
- `lib/aws_encryption_sdk/crypto/header_auth.ex` - Filter EC by required keys for AAD
- `lib/aws_encryption_sdk/encrypt.ex` - Pass full EC to header auth
- `lib/aws_encryption_sdk/decrypt.ex` - Pass full EC to header auth
- `lib/aws_encryption_sdk/stream/encryptor.ex` - Pass full EC to header auth
- `lib/aws_encryption_sdk/cmm/required_encryption_context.ex` - Set required_encryption_context_keys

### Test Infrastructure
- `test/test_vectors/full_decrypt_test.exs` - Added Raw AES test suite, fixed RSA PEM loading
- `test/aws_encryption_sdk/format/header_test.exs` - Updated test expectations

### Plans
- `thoughts/shared/plans/2026-02-01-GH76-full-test-vector-runner.md` - Updated Phase 2 status

## Quick Start for Next Session

1. **Run failing test with debug output**:
   ```bash
   # Add IO.inspect calls to header_auth.ex first
   mix test test/test_vectors/full_decrypt_test.exs --only raw_aes --seed 0 | head -200
   ```

2. **Pick one failing test to analyze**:
   - Start with: `5caff5ef-0851-45f5-846a-6fbdb55765e4`
   - Understand its EC, algorithm suite, and why header auth fails
   - Compare AAD bytes with what Python SDK would produce

3. **Form hypothesis**:
   - Based on byte-level analysis
   - Test with minimal code change
   - Verify with subset of test vectors

4. **Iterate**:
   - Fix one category of failures at a time
   - Ensure no regression in passing tests
   - Document findings

Good luck! The core architecture is sound, this is a spec interpretation/compatibility issue. 🔍
