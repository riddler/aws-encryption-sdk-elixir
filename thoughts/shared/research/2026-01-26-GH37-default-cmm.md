# Research: Implement Default CMM with keyring orchestration

**Issue**: #37 - Implement Default CMM with keyring orchestration
**Date**: 2026-01-26
**Status**: Research complete

## Issue Summary

Implement the Default CMM that wraps a keyring and provides the standard CMM behavior for encryption and decryption operations. The Default CMM is the primary CMM implementation that most users will use. It wraps a single keyring (or multi-keyring) and handles:
- Algorithm suite validation and selection
- Calling keyring's `on_encrypt` to get encryption materials
- Calling keyring's `on_decrypt` to get decryption materials
- Managing required encryption context keys
- No caching (caching CMM is a separate advanced feature)

## Current Implementation State

### Existing Code

**CMM Behaviour Interface:**
- `lib/aws_encryption_sdk/cmm/behaviour.ex` - CMM behaviour with callbacks and validation helpers (COMPLETE)

**Materials Structs:**
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - EncryptionMaterials struct with `new_for_encrypt/3` and mutators
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - DecryptionMaterials struct with `new_for_decrypt/3` and mutators
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EncryptedDataKey struct

**Keyring Implementations (to be wrapped by CMM):**
- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour with `on_encrypt/1` and `on_decrypt/2`
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring (uses `wrap_key/2` and `unwrap_key/3`)
- `lib/aws_encryption_sdk/keyring/raw_rsa.ex` - Raw RSA keyring
- `lib/aws_encryption_sdk/keyring/multi.ex` - Multi-keyring composition

### Relevant Patterns

**CMM Behaviour provides helper functions:**
- `default_algorithm_suite/1` - Returns default suite based on commitment policy
- `validate_commitment_policy_for_encrypt/2` - Validates suite against policy for encryption
- `validate_commitment_policy_for_decrypt/2` - Validates suite against policy for decryption
- `validate_encryption_materials/1` - Validates final encryption materials
- `validate_decryption_materials/1` - Validates final decryption materials
- `validate_encryption_context_for_encrypt/1` - Checks reserved key not in context
- `validate_signing_context_consistency/2` - Validates signing context matches suite
- `validate_reproduced_context/2` - Compares reproduced with message context
- `merge_reproduced_context/2` - Merges reproduced context into message context
- `reserved_encryption_context_key/0` - Returns `"aws-crypto-public-key"`

**Materials Builder Pattern:**
- Materials start without plaintext data key (nil) when created for keyring use
- Keyrings populate materials incrementally using mutator functions
- `set_plaintext_data_key/2` sets the data key once
- `add_encrypted_data_key/2` appends EDKs to list

**Keyring Dispatch Pattern:**
- Keyrings use struct-specific functions (`wrap_key/2`, `unwrap_key/3`) instead of behaviour callbacks
- Multi-keyring dispatches based on struct type using pattern matching

### Dependencies

**Required Modules:**
- `AwsEncryptionSdk.Cmm.Behaviour` - Validation helpers already implemented
- `AwsEncryptionSdk.Materials.EncryptionMaterials` - Output structure
- `AwsEncryptionSdk.Materials.DecryptionMaterials` - Output structure
- `AwsEncryptionSdk.Keyring.Behaviour` - For `generate_data_key/1`
- `AwsEncryptionSdk.AlgorithmSuite` - For suite definitions
- `AwsEncryptionSdk.Crypto.ECDSA` - For signing key generation (P-384)

**Dependent Modules (will use CMM):**
- `AwsEncryptionSdk.Encrypt` - High-level encrypt API
- `AwsEncryptionSdk.Decrypt` - High-level decrypt API
- `AwsEncryptionSdk.Client` - Client configuration with default CMM

## Specification Requirements

### Source Documents
- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - CMM behaviour interface
- [default-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md) - Default CMM implementation

### MUST Requirements

#### Initialization

1. **Keyring Initialization** (default-cmm.md#keyring)
   > the [keyring](keyring-interface.md) this CMM uses to [get encryption materials](#get-encryption-materials)

   Implementation: Accept `keyring` parameter in `new/1` constructor

#### Get Encryption Materials

2. **Return Appropriate Materials** (cmm-interface.md#get-encryption-materials)
   > The CMM MUST return encryption materials appropriate for the request.

3. **Algorithm Suite - Default Selection** (default-cmm.md#get-encryption-materials)
   > the operation MUST add the default algorithm suite for the [commitment policy](./commitment-policy.md) as the algorithm suite in the encryption materials returned

   Implementation: If `request.algorithm_suite == nil`, use `Behaviour.default_algorithm_suite/1`

4. **Algorithm Suite - Commitment Policy Validation** (default-cmm.md#get-encryption-materials)
   > the request MUST fail if the algorithm suite is not supported by the [commitment policy](./commitment-policy.md)

   Implementation: Call `Behaviour.validate_commitment_policy_for_encrypt/2`

5. **Algorithm Suite - Preservation** (default-cmm.md#get-encryption-materials)
   > the encryption materials returned MUST contain the same algorithm suite

6. **Encryption Context Conflict Check** (default-cmm.md#get-encryption-materials)
   > If the encryption context included in the [encryption materials request] already contains the `aws-crypto-public-key` key, this operation MUST fail

   Implementation: Call `Behaviour.validate_encryption_context_for_encrypt/1`

7. **Signing Key Generation** (default-cmm.md#get-encryption-materials)
   > When the suite includes signing algorithms, the default CMM MUST Generate a [signing key]

   Implementation: For signing suites, generate ECDSA P-384 key pair

8. **Public Key Addition to Context** (default-cmm.md#get-encryption-materials)
   > [CMM MUST] add the base64-encoded public key to the encryption context

   Implementation: Add `"aws-crypto-public-key"` → Base64-encoded verification key

9. **Keyring On Encrypt Invocation** (default-cmm.md#get-encryption-materials)
   > On each call to Get Encryption Materials, the default CMM MUST make a call to its [keyring's] [On Encrypt] operation

10. **Plaintext Data Key Validation - Non-NULL** (cmm-interface.md#get-encryption-materials)
    > Plaintext data key MUST be non-NULL

11. **Plaintext Data Key Validation - Length** (cmm-interface.md#get-encryption-materials)
    > Key length MUST be equal to the key derivation input length

    Implementation: `byte_size(key) == suite.kdf_input_length`

12. **Encrypted Data Keys Validation** (cmm-interface.md#get-encryption-materials)
    > Encrypted data keys list MUST contain at least one encrypted data key

13. **Required Context Keys Validation** (cmm-interface.md#get-encryption-materials)
    > Required context keys MUST have matching keys in encryption context

14. **Signing Key Inclusion** (cmm-interface.md#get-encryption-materials)
    > When algorithm suite includes signing: The CMM MUST include a signing key

#### Decrypt Materials

15. **Return Appropriate Materials** (cmm-interface.md#decrypt-materials)
    > The CMM MUST return decryption materials appropriate for the request.

16. **Algorithm Suite - Commitment Policy Validation** (default-cmm.md#decrypt-materials)
    > The request MUST fail if the algorithm suite on the request is not supported by the [commitment policy]

    Implementation: Call `Behaviour.validate_commitment_policy_for_decrypt/2`

17. **Verification Key Extraction** (default-cmm.md#decrypt-materials)
    > If the algorithm suite contains a [signing algorithm], the default CMM MUST extract the verification key from the encryption context under the reserved `aws-crypto-public-key` key

18. **Missing Verification Key Failure** (default-cmm.md#decrypt-materials)
    > If this key is not present in the encryption context, the operation MUST fail without returning any decryption materials

19. **Verification Key Mismatch** (default-cmm.md#decrypt-materials)
    > If the algorithm suite does not contain a [signing algorithm], but the encryption context includes the reserved `aws-crypto-public-key` key, the operation MUST fail

20. **Keyring On Decrypt Invocation** (default-cmm.md#decrypt-materials)
    > On each call to Decrypt Materials, the default CMM MUST make a call to its [keyring's] [On Decrypt] operation

21. **Encryption Context Validation** (cmm-interface.md#decrypt-materials)
    > The CMM MUST validate the Encryption Context by comparing it to the customer supplied Reproduced Encryption Context. For matching keys, the values MUST be equal or the operation MUST fail.

    Implementation: Call `Behaviour.validate_reproduced_context/2`

22. **Plaintext Data Key Validation - Non-NULL** (cmm-interface.md#decrypt-materials)
    > Plaintext data key MUST be non-NULL

23. **Verification Key Inclusion** (cmm-interface.md#decrypt-materials)
    > When signing algorithm present: decryption materials MUST include the signature verification key

### SHOULD Requirements

24. **Encryption Context Copy** (default-cmm.md#get-encryption-materials)
    > Adding the key `aws-crypto-public-key` SHOULD be done to a copy of the encryption context so that the caller's encryption context is not mutated

25. **Append Reproduced Context** (cmm-interface.md#decrypt-materials)
    > [SHOULD] Append key-value pairs from reproduced context not in request context

    Implementation: Call `Behaviour.merge_reproduced_context/2`

### MAY Requirements

26. **Encryption Context Modification** (cmm-interface.md)
    > CMM MAY modify the encryption context

### SHOULD NOT Requirements

27. **Legacy Master Key Provider** (default-cmm.md#initialization)
    > [Master Key Provider support] SHOULD NOT [be included] in new implementations

## Commitment Policy Validation Matrix

| Policy | Encrypt - Committed | Encrypt - Non-Committed | Decrypt - Committed | Decrypt - Non-Committed |
|--------|---------------------|-------------------------|---------------------|-------------------------|
| `FORBID_ENCRYPT_ALLOW_DECRYPT` | MUST FAIL | ALLOWED | ALLOWED | ALLOWED |
| `REQUIRE_ENCRYPT_ALLOW_DECRYPT` | ALLOWED | MUST FAIL | ALLOWED | ALLOWED |
| `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` | ALLOWED | MUST FAIL | ALLOWED | MUST FAIL |

## Test Vectors

### Harness Setup

Test vectors are accessed via the existing test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, harness} = TestVectorHarness.load_manifest("test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json")

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets

**Primary Location**: `test/fixtures/test_vectors/vectors/awses-decrypt/`

- **Type**: `awses-decrypt` (version 2)
- **Client**: Generated by aws-encryption-sdk-python 2.2.0
- **Keys**: Includes AES-128, AES-192, AES-256, RSA-4096 keys
- **Total Tests**: 100+ decrypt test cases

### Implementation Order

#### Phase 1: Basic CMM Decrypt (Committed Suites)

Test vectors using **algorithm suite 0x0478** (AES_256_GCM_HKDF_SHA512_COMMIT_KEY):

| Test ID | Key Type | Priority | Notes |
|---------|----------|----------|-------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Raw AES-256 | Start here | Basic committed suite |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | Raw AES-192 | Second | Different AES key size |
| `4be2393c-2916-4668-ae7a-d26ddb8de593` | Raw AES-128 | Third | Minimum AES key size |

**CMM Validation Points:**
- CMM calls keyring's `unwrap_key` callback
- CMM validates commitment policy (allow decrypt for committed suites)
- CMM assembles materials with correct algorithm suite from header
- CMM preserves encryption context from header

#### Phase 2: RSA Keyring Integration

| Test ID | Padding | Priority | Notes |
|---------|---------|----------|-------|
| `d20b31a6-200d-4fdb-819d-7ded46c99d10` | PKCS1 | First RSA | Legacy suite |
| `24088ba0-bf47-4d06-bb12-f6ba40956bd6` | OAEP-SHA256 | Second RSA | Different padding |
| `7c640f28-9fa1-4ff9-9179-196149f8c346` | OAEP-SHA1 | Third RSA | Older hash |

**CMM Validation Points:**
- CMM works with different keyring types
- CMM handles legacy algorithm suites without commitment

#### Phase 3: ECDSA Signing Suites

Test vectors with **algorithm suite 0x0578** (with ECDSA P-384) or **0x0378** (legacy with ECDSA):

**CMM Validation Points:**
- CMM extracts verification key from `aws-crypto-public-key` encryption context entry
- CMM includes verification_key in DecryptionMaterials
- CMM validates signing context consistency
- CMM handles base64-encoded public keys

#### Phase 4: Commitment Policy Errors

Manual test cases for policy validation:

| Scenario | Policy | Suite | Expected |
|----------|--------|-------|----------|
| Decrypt committed | `:require_encrypt_require_decrypt` | 0x0478 | Success |
| Decrypt non-committed | `:require_encrypt_require_decrypt` | 0x0178 | Error |
| Decrypt non-committed | `:require_encrypt_allow_decrypt` | 0x0178 | Success |
| Encrypt non-committed | `:require_encrypt_allow_decrypt` | 0x0178 | Error |
| Encrypt committed | `:forbid_encrypt_allow_decrypt` | 0x0478 | Error |

### Test Vector Access Pattern

```elixir
# Load harness
{:ok, harness} = TestVectorHarness.load_manifest("test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json")

# Get test data
{:ok, test} = TestVectorHarness.get_test(harness, test_id)
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, message, _} = Message.deserialize(ciphertext)

# Get key material
[master_key | _] = test.master_keys
key_id = master_key["key"]
{:ok, key_data} = TestVectorHarness.get_key(harness, key_id)
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)

# Create keyring
keyring = RawAes.new!(provider_id, key_name, raw_key, wrapping_algorithm)

# Create CMM
cmm = Default.new(keyring)

# Get decryption materials via CMM
request = %{
  algorithm_suite: message.header.algorithm_suite,
  commitment_policy: :require_encrypt_allow_decrypt,
  encrypted_data_keys: message.header.encrypted_data_keys,
  encryption_context: message.header.encryption_context
}

{:ok, materials} = Default.get_decryption_materials(cmm, request)
```

## Implementation Considerations

### Technical Approach

1. **Struct Definition:**
   ```elixir
   defstruct [:keyring]
   ```

2. **Constructor:**
   ```elixir
   def new(keyring) do
     %__MODULE__{keyring: keyring}
   end
   ```

3. **Keyring Dispatch:**
   The Default CMM needs to dispatch to different keyring implementations. Follow the pattern from Multi-keyring:
   ```elixir
   defp call_wrap_key(%RawAes{} = keyring, materials), do: RawAes.wrap_key(keyring, materials)
   defp call_wrap_key(%RawRsa{} = keyring, materials), do: RawRsa.wrap_key(keyring, materials)
   defp call_wrap_key(%Multi{} = keyring, materials), do: Multi.wrap_key(keyring, materials)
   ```

4. **Get Encryption Materials Flow:**
   1. Validate encryption context (no reserved key)
   2. Select algorithm suite (from request or default for policy)
   3. Validate suite against commitment policy
   4. Generate signing key if needed (ECDSA P-384)
   5. Add public key to encryption context if signed
   6. Create initial EncryptionMaterials with `new_for_encrypt/3`
   7. Call keyring's wrap_key to generate/wrap data key
   8. Validate final materials with `validate_encryption_materials/1`
   9. Return materials

5. **Get Decryption Materials Flow:**
   1. Validate suite against commitment policy
   2. Validate reproduced context if provided
   3. Merge reproduced context
   4. Validate signing context consistency
   5. Extract verification key if signed suite
   6. Create initial DecryptionMaterials with `new_for_decrypt/3`
   7. Call keyring's unwrap_key to decrypt data key
   8. Validate final materials with `validate_decryption_materials/1`
   9. Return materials

### Potential Challenges

1. **Keyring Type Dispatch**: Need to handle multiple keyring types. Consider either:
   - Protocol-based dispatch (create `AwsEncryptionSdk.Keyring` protocol)
   - Pattern matching on struct types (current Multi-keyring approach)

2. **ECDSA Key Generation**: Need to implement or use existing ECDSA P-384 key generation for signing suites. Check if `AwsEncryptionSdk.Crypto.ECDSA` module exists.

3. **Verification Key Encoding**: Need to properly base64-encode/decode the ECDSA public key for the `aws-crypto-public-key` context entry.

### Open Questions

1. **Keyring Protocol vs Pattern Matching**: Should we create a protocol for keyrings to standardize the interface, or continue with pattern matching on struct types?

2. **ECDSA Module Status**: Does `AwsEncryptionSdk.Crypto.ECDSA` exist? If not, need to implement ECDSA key generation.

3. **Error Message Consistency**: What error atoms/messages should be used for various failure conditions?

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-26-GH37-default-cmm.md`
2. Check ECDSA module implementation status
3. Implement Default CMM struct and constructor
4. Implement `get_decryption_materials/2` first (simpler, test vectors available)
5. Implement `get_encryption_materials/2`
6. Add comprehensive tests including test vector validation

## References

- Issue: https://github.com/awslabs/aws-encryption-sdk/issues/37
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Default CMM Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
