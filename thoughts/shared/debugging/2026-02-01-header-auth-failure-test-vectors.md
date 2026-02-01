# Header Authentication Failure with Test Vectors

**Date**: 2026-02-01
**Issue**: Full decrypt of AWS test vectors fails with `:header_authentication_failed`
**Context**: Implementing full test vector runner (#76)
**Status**: RESOLVED

## Resolution

**Root Cause**: The `serialize_v1_body` and `serialize_v2_body` functions in `lib/aws_encryption_sdk/format/header.ex` were not including the version byte (0x01 for v1, 0x02 for v2) and type byte (0x80 for v1) in the header body used for AAD computation during header authentication.

Per the AWS Encryption SDK specification, the header body for authentication **MUST** include:
- For v1: Version byte (0x01) + Type byte (0x80) + rest of header fields
- For v2: Version byte (0x02) + rest of header fields

**Fix Applied**:
1. Modified `serialize_v1_body` to include `<<0x01::8, 0x80::8>>` at the start of the body
2. Modified `serialize_v2_body` to include `<<0x02::8>>` at the start of the body
3. Updated `serialize/1` for both versions to not prepend the version/type bytes (since they're now in the body)
4. Fixed test in `header_test.exs` that incorrectly expected version byte to NOT be in body

**Files Changed**:
- `lib/aws_encryption_sdk/format/header.ex`
- `test/aws_encryption_sdk/format/header_test.exs`

**Verification**:
- All 821 existing tests pass
- The original failing test vector (`83928d8e-9f97-4861-8f70-ab1eaa6930ea`) now passes full decrypt

---

## Original Problem Statement (Historical)

## Problem Statement

When attempting full end-to-end decryption of AWS Encryption SDK test vectors using `Client.decrypt_with_keyring/3`, all tests fail with `:header_authentication_failed`. However, keyring-only unwrap operations succeed.

**Critical Discovery**: All existing test vector tests (16 total) only test `keyring.unwrap_key/3`, NOT full `Client.decrypt`. This is the first attempt at full end-to-end decryption with test vectors.

## What Works ✓

1. **Test Vector Loading**: Harness correctly loads manifests and test data
2. **Keyring Building**: Successfully creates keyrings from test vector master keys and EDKs
3. **Key Extraction**: Correctly extracts key names from EDK provider_info
4. **EDK Unwrapping**: `RawAes.unwrap_key/3` successfully decrypts the data key
5. **Data Key Validation**: Unwrapped key has correct size (16 bytes for AES-128 suite)

## What Fails ✗

**Full Decrypt**: `Client.decrypt_with_keyring/3` → `:header_authentication_failed`

The failure occurs during header authentication tag verification in the decrypt flow, after successful EDK unwrapping.

## Reproduction

### Minimal Test Case

```elixir
# File: /tmp/test_header_auth.exs
ExUnit.start()

defmodule TestHeaderAuth do
  use ExUnit.Case

  alias AwsEncryptionSdk.TestSupport.TestVectorHarness
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Client

  test "test vector header authentication" do
    {:ok, harness} = TestVectorHarness.load_manifest(
      "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
    )

    test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"

    # Load test data
    {:ok, test} = TestVectorHarness.get_test(harness, test_id)
    {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
    {:ok, message, _} = TestVectorHarness.parse_ciphertext(ciphertext)

    # Build keyring
    [mk] = test.master_keys
    {:ok, key_data} = TestVectorHarness.get_key(harness, mk["key"])
    {:ok, key_bytes} = TestVectorHarness.decode_key_material(key_data)

    [edk] = message.header.encrypted_data_keys
    key_name_len = byte_size(edk.key_provider_info) - 20
    <<key_name::binary-size(key_name_len), _::binary>> = edk.key_provider_info

    {:ok, keyring} = RawAes.new(
      mk["provider-id"],
      key_name,
      key_bytes,
      :aes_256_gcm
    )

    # This succeeds:
    result = Client.decrypt_with_keyring(
      keyring,
      ciphertext,
      commitment_policy: :require_encrypt_allow_decrypt
    )

    # Expected: {:ok, %{plaintext: _}}
    # Actual: {:error, :header_authentication_failed}
    IO.inspect(result)
  end
end
```

Run: `mix test /tmp/test_header_auth.exs`

### Successful Unwrap Test

```elixir
# This works - proves keyring and unwrap are correct
alias AwsEncryptionSdk.Materials.DecryptionMaterials

materials = DecryptionMaterials.new_for_decrypt(
  message.header.algorithm_suite,
  message.header.encryption_context
)

{:ok, result_materials} = RawAes.unwrap_key(
  keyring,
  materials,
  message.header.encrypted_data_keys
)

# Succeeds! Data key is unwrapped correctly
assert byte_size(result_materials.plaintext_data_key) == 16
```

## Test Vector Details

### Test ID: `83928d8e-9f97-4861-8f70-ab1eaa6930ea`

**Algorithm Suite**: `0x14` (AES_128_GCM_IV12_TAG16_NO_KDF)
- ID: 20 (decimal)
- Name: "AES_128_GCM_IV12_TAG16_NO_KDF"
- Message format version: 1
- Encryption algorithm: :aes_128_gcm
- Data key length: 128 bits
- KDF type: :identity (NO_KDF)
- This is a deprecated, non-committed algorithm suite

**Master Key**:
- Type: raw
- Encryption algorithm: aes
- Key ID: "aes-256"
- Provider ID: "aws-raw-vectors-persistant"
- Key size: 256 bits (wrapping key)

**EDK Details**:
- Provider ID: "aws-raw-vectors-persistant"
- Provider info: 27 bytes
  - Format: key_name (7 bytes: "aes-256") + tag_len (4 bytes) + iv_len (4 bytes) + iv (12 bytes)
- Ciphertext: 32 bytes (16-byte key + 16-byte auth tag)

**Message**:
- Ciphertext size: 10,429 bytes
- Encryption context: empty (`%{}`)
- EDK count: 1

## Code Locations

### Key Files

1. **Test Infrastructure** (new):
   - `test/test_vectors/full_decrypt_test.exs` - Full decrypt test file with helpers
   - `test/support/test_vector_harness.ex` - Filtering helpers added

2. **Decrypt Flow**:
   - `lib/aws_encryption_sdk/client.ex:307` - `decrypt_with_keyring/3` entry point
   - `lib/aws_encryption_sdk/decrypt.ex:54` - `decrypt/2` main function
   - `lib/aws_encryption_sdk/decrypt.ex:59` - Header auth verification call
   - `lib/aws_encryption_sdk/crypto/header_auth.ex:81` - `verify_header_auth_tag/2`

3. **Header Auth Logic**:
   ```elixir
   # lib/aws_encryption_sdk/crypto/header_auth.ex:82-103
   def verify_header_auth_tag(header, derived_key) do
     # Compute AAD: header body + serialized encryption context
     {:ok, header_body} = Header.serialize_body(header)
     ec_bytes = EncryptionContext.serialize(header.encryption_context)
     aad = header_body <> ec_bytes

     # IV is all zeros for header
     iv = AesGcm.zero_iv()

     # Decrypt empty ciphertext to verify tag
     case AesGcm.decrypt(
            header.algorithm_suite.encryption_algorithm,
            derived_key,
            iv,
            <<>>,
            aad,
            header.header_auth_tag
          ) do
       {:ok, <<>>} -> :ok
       {:error, :authentication_failed} -> {:error, :header_authentication_failed}
     end
   end
   ```

4. **Keyring Implementation**:
   - `lib/aws_encryption_sdk/keyring/raw_aes.ex:246` - `unwrap_key/3` (works)
   - `lib/aws_encryption_sdk/keyring/raw_aes.ex:274` - `try_decrypt_edk/3`
   - `lib/aws_encryption_sdk/keyring/raw_aes.ex:134` - `deserialize_provider_info/2`

### Existing Working Tests

- `test/aws_encryption_sdk/keyring/raw_aes_test_vectors_test.exs:24` - AES unwrap only
- `test/aws_encryption_sdk/keyring/raw_rsa_test_vectors_test.exs:24` - RSA unwrap only
- `test/aws_encryption_sdk/cmm/default_test_vectors_test.exs:25` - CMM materials only

**None test full decrypt!**

## Decrypt Flow Analysis

### What Happens During Decrypt

1. **Parse Message** ✓
   - Deserializes ciphertext into header + body + footer

2. **Get Decryption Materials** ✓
   - CMM calls keyring.unwrap_key
   - Data key successfully unwrapped (verified)

3. **Derive Data Key** ✓
   - For NO_KDF suites: returns plaintext_data_key as-is
   - No HKDF derivation needed

4. **Verify Commitment** ✓
   - Skipped for non-committed suites (0x14)

5. **Verify Header Auth Tag** ✗ FAILS HERE
   - Computes AAD from header body + encryption context
   - Uses zero IV
   - Uses derived_key (which is the unwrapped data key for NO_KDF)
   - Attempts AES-GCM decrypt of empty plaintext with stored auth tag
   - **FAILS** with `:authentication_failed`

6. **Decrypt Body** (never reached)

7. **Verify Signature** (never reached)

## Investigation Questions

### Critical Questions

1. **Is the header being serialized identically to how Python SDK did it?**
   - The AAD for header auth is `header_body + encryption_context_bytes`
   - Any difference in serialization would cause auth failure

2. **Is the data key being derived correctly for NO_KDF suites?**
   - For NO_KDF: derived_key should equal plaintext_data_key directly
   - Verified: unwrapped key is 16 bytes (correct for AES-128)
   - Is this the exact same key Python used?

3. **Are we using the correct header IV?**
   - Spec says header auth uses zero IV (12 bytes of 0x00)
   - Code: `AesGcm.zero_iv()`
   - Is this implemented correctly?

4. **Is the algorithm suite being applied correctly?**
   - Header uses: `header.algorithm_suite.encryption_algorithm` → `:aes_128_gcm`
   - Should match the algorithm suite in the message (0x14)

5. **Is encryption context being serialized correctly?**
   - Test vector has empty EC: `%{}`
   - Should serialize to: `<<0, 0>>` (2-byte count of 0)
   - Check: `EncryptionContext.serialize(%{})` output

### Potential Root Causes

**Theory 1: Header Serialization Mismatch**
- Python SDK may serialize header differently than our implementation
- Small difference in byte ordering, field order, or encoding would break auth

**Theory 2: Encryption Context Serialization**
- Even empty EC might serialize differently
- UTF-8 ordering, encoding differences

**Theory 3: Key Derivation Issue**
- Even for NO_KDF, maybe there's a step we're missing
- Or unwrapped key is correct but being used incorrectly

**Theory 4: IV Handling**
- Header auth requires specific IV handling for v1 vs v2 messages
- Message is v1 (format_version=1 for suite 0x14)
- Check: is `header_iv` field being handled correctly?

**Theory 5: Algorithm Suite Mismatch**
- Using wrong encryption algorithm for header auth
- Should use suite's encryption_algorithm, not wrapping algorithm

## Debugging Steps

### Step 1: Verify Zero IV

```elixir
# In header_auth.ex or via IEx
iv = AwsEncryptionSdk.Crypto.AesGcm.zero_iv()
IO.inspect(iv, label: "Zero IV", limit: :infinity)
# Expected: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>> (12 bytes)
```

### Step 2: Inspect AAD Composition

```elixir
# In decrypt.ex or add logging
{:ok, header_body} = Header.serialize_body(header)
ec_bytes = EncryptionContext.serialize(header.encryption_context)
aad = header_body <> ec_bytes

IO.puts("Header body size: #{byte_size(header_body)}")
IO.puts("EC bytes: #{inspect(ec_bytes)}")
IO.puts("Total AAD size: #{byte_size(aad)}")
```

### Step 3: Compare With Python SDK

Encrypt the same plaintext with Python SDK using same key:
```python
import aws_encryption_sdk
from aws_encryption_sdk.keyrings.raw import RawAESKeyring

# Use same key as test vector
wrapping_key = bytes([0,1,2,3,4,5,6,7,8,9,16,17,18,19,20,21,22,23,24,25,32,33,34,35,36,37,38,39,40,41,48,49])

keyring = RawAESKeyring(
    key_namespace="aws-raw-vectors-persistant",
    key_name=b"aes-256",
    wrapping_key=wrapping_key
)

# Encrypt small plaintext
client = aws_encryption_sdk.EncryptionSDKClient()
ciphertext, header = client.encrypt(
    source=b"test",
    keyring=keyring,
    algorithm=aws_encryption_sdk.Algorithm.AES_128_GCM_IV12_TAG16_NO_KDF
)

# Compare header bytes with our serialization
```

### Step 4: Inspect Stored Auth Tag

```elixir
# Parse test vector
{:ok, message, _} = TestVectorHarness.parse_ciphertext(ciphertext)
IO.inspect(message.header.header_auth_tag, label: "Stored auth tag", limit: :infinity)
# Should be 16 bytes
```

### Step 5: Check Header IV Field

```elixir
# For v1 messages (suite 0x14)
IO.inspect(message.header.header_iv, label: "Header IV")
# Expected for v1: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
# Expected for v2: nil
```

### Step 6: Test Round-Trip

```elixir
# Encrypt with our SDK, decrypt with our SDK
{:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
cmm = Default.new(keyring)
client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

{:ok, encrypted} = Client.encrypt(client, "test plaintext", algorithm_suite: :aes_128_gcm_iv12_tag16_no_kdf)
{:ok, decrypted} = Client.decrypt(client, encrypted.ciphertext)

# If this works, problem is with test vector compatibility
# If this fails, problem is in our implementation
```

## Relevant Spec References

### Header Authentication

From `data-format/message-header.md`:

> The header authentication tag authenticates the entire header body and the serialized encryption context using AES-GCM.
>
> For message format version 1:
> - AAD: header body || serialized encryption context
> - IV: 12 bytes of zeros
> - Key: derived data key (or plaintext data key for NO_KDF suites)
> - Plaintext: empty
> - Tag length: 16 bytes

### Algorithm Suite 0x14

From `framework/algorithm-suites.md`:

> Suite ID: 0x0014
> Name: AES_128_GCM_IV12_TAG16_NO_KDF
> Message Format: v1
> Encryption: AES-128-GCM
> Data Key Length: 128 bits
> Key Derivation: Identity (no KDF)
> Commitment: None
> Signature: None
> **Status: DEPRECATED** - use committed suites for new encryptions

## Next Steps

### Immediate Actions

1. **Verify Header Serialization**
   - Add logging to `Header.serialize_body/1`
   - Compare byte-for-byte with expected format from spec
   - Check field ordering, lengths, encodings

2. **Verify Encryption Context Serialization**
   - Test `EncryptionContext.serialize(%{})` output
   - Should be exactly `<<0, 0>>` for empty context

3. **Compare With Working Unwrap**
   - Unwrap works, which means we can decrypt the EDK correctly
   - The same key is used for header auth
   - What's different between unwrap success and header auth failure?

4. **Test Round-Trip**
   - Encrypt+decrypt with our SDK using same algorithm suite
   - If this works, issue is test vector compatibility
   - If this fails, issue is in our core implementation

5. **Python Comparison**
   - Create identical message with Python SDK
   - Compare headers byte-for-byte
   - Identify first byte of difference

### Long-Term Solutions

**If Issue is Our Bug**:
- Fix header serialization/authentication
- Add regression tests
- Update implementation to match spec exactly

**If Issue is Test Vector Incompatibility**:
- Document the incompatibility
- Create our own test vectors using round-trip encrypt/decrypt
- File issue with AWS SDK team about test vector format

**If Issue is Spec Ambiguity**:
- Clarify with AWS SDK team
- Document our interpretation
- Add compatibility mode if needed

## Files Modified

### New Files
- `test/test_vectors/full_decrypt_test.exs` - Full decrypt test infrastructure

### Modified Files
- `test/support/test_vector_harness.ex` - Added filtering helpers

### Plan Files
- `thoughts/shared/plans/2026-02-01-GH76-full-test-vector-runner.md` - Updated with actual counts

## References

- **Issue**: #76 - Implement Full Test Vector Runner for Success Cases
- **Plan**: `thoughts/shared/plans/2026-02-01-GH76-full-test-vector-runner.md`
- **Research**: `thoughts/shared/research/2026-02-01-GH76-full-test-vector-runner.md`
- **Spec - Message Header**: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md
- **Spec - Algorithm Suites**: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- **Test Vectors**: https://github.com/awslabs/aws-encryption-sdk-test-vectors

## Success Criteria

Once resolved, this test should pass:

```elixir
test "decrypts test vector with header authentication", %{harness: harness} do
  test_id = "83928d8e-9f97-4861-8f70-ab1eaa6930ea"

  {:ok, test} = TestVectorHarness.get_test(harness, test_id)
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  {:ok, expected} = TestVectorHarness.load_expected_plaintext(harness, test_id)
  {:ok, message, _} = TestVectorHarness.parse_ciphertext(ciphertext)

  # Build keyring from test vector
  {:ok, keyring} = build_keyring_from_test_vector(harness, test, message)

  # Full decrypt should succeed
  {:ok, result} = Client.decrypt_with_keyring(
    keyring,
    ciphertext,
    commitment_policy: :require_encrypt_allow_decrypt
  )

  # Verify plaintext matches
  assert result.plaintext == expected
end
```

Good luck debugging! 🐛🔍
