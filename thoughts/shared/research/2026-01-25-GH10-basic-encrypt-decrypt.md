# Research: Implement Basic Encryption/Decryption Operations

**Issue**: #10 - Implement basic encryption/decryption operations
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Implement core encrypt and decrypt operations for the AWS Encryption SDK, using AES-GCM via Erlang `:crypto`. Initial implementation is non-streaming (full plaintext in memory). This is the foundational API that ties together algorithm suites, HKDF key derivation, and message format serialization.

## Current Implementation State

### Existing Code

The codebase has strong foundational components already implemented:

| Component | File | Status |
|-----------|------|--------|
| Algorithm Suite | `lib/aws_encryption_sdk/algorithm_suite.ex` | ✅ Complete (all 11 suites) |
| HKDF | `lib/aws_encryption_sdk/crypto/hkdf.ex` | ✅ Complete (RFC 5869) |
| Header | `lib/aws_encryption_sdk/format/header.ex` | ✅ Complete (v1 + v2) |
| Body | `lib/aws_encryption_sdk/format/body.ex` | ✅ Complete (framed + non-framed) |
| Footer | `lib/aws_encryption_sdk/format/footer.ex` | ✅ Complete |
| Message | `lib/aws_encryption_sdk/format/message.ex` | ✅ Complete (deserialization) |
| Body AAD | `lib/aws_encryption_sdk/format/body_aad.ex` | ✅ Complete |
| Encryption Context | `lib/aws_encryption_sdk/format/encryption_context.ex` | ✅ Complete |
| Encrypted Data Key | `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | ✅ Complete |
| Test Vector Harness | `test/support/test_vector_harness.ex` | ✅ Complete |

### Files to Create

| Component | File | Purpose |
|-----------|------|---------|
| Encrypt Module | `lib/aws_encryption_sdk/encrypt.ex` | High-level encryption orchestration |
| Decrypt Module | `lib/aws_encryption_sdk/decrypt.ex` | High-level decryption orchestration |
| AES-GCM Wrapper | `lib/aws_encryption_sdk/crypto/aes_gcm.ex` | Optional AES-GCM wrapper |
| Encryption Materials | `lib/aws_encryption_sdk/materials/encryption_materials.ex` | Encryption materials struct |
| Decryption Materials | `lib/aws_encryption_sdk/materials/decryption_materials.ex` | Decryption materials struct |

### Relevant Patterns

From existing code analysis:

1. **Result Tuple Pattern**: Functions return `{:ok, result}` or `{:error, reason}`
2. **Struct-Based Data Modeling**: All complex types use structs with `@enforce_keys`
3. **Binary Pattern Matching**: Extensive use for serialization/deserialization
4. **Factory Functions**: Algorithm suites use named constructor functions
5. **Erlang Interop**: Direct use of `:crypto` module for primitives

### Dependencies

**Depends On** (already implemented):
- Algorithm suite definitions (#7) ✅
- HKDF implementation (#8) ✅
- Message format serialization (#9) ✅

**Blocked By** (not yet implemented):
- Keyring implementations - need at least one keyring to test encrypt/decrypt
- CMM implementations - or can work with raw materials directly

**Note**: For initial testing, we can bypass keyring/CMM by providing encryption/decryption materials directly.

## Specification Requirements

### Source Documents

- [encrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - Encryption operation
- [decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Decryption operation
- [client.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md) - Commitment policy

### MUST Requirements

#### Encrypt Operation

1. **Input Requirements** (encrypt.md)
   > The encryption operation MUST require either a CMM or keyring as input.
   > The encryption operation MUST require plaintext as input.

   Implementation: Accept encryption_materials or CMM/keyring. For initial implementation, work directly with materials.

2. **Reserved Prefix Validation** (encrypt.md)
   > If the input encryption context contains any entries with a key beginning with `aws-crypto-` prefix, the encryption operation MUST fail.

   Implementation: Validate encryption context before proceeding.

3. **Output Requirements** (encrypt.md)
   > The encryption operation MUST output an encrypted message that conforms to the message format.
   > The encryption operation MUST also output the encryption context that was used as additional authenticated data.
   > The encryption operation MUST output the algorithm suite used to encrypt the message.

   Implementation: Return `{:ok, %{ciphertext: binary, encryption_context: map, algorithm_suite: suite}}`.

4. **Algorithm Suite Validation** (encrypt.md)
   > If the algorithm suite is not supported by the commitment policy, encrypt MUST yield an error.

   Implementation: Validate commitment policy compliance.

5. **Message Header Construction - V2** (encrypt.md)
   > The value of this field MUST be 2. (version)
   > The value of this field MUST be the algorithm suite ID. (algorithm)
   > The value of this field MUST use a good source of randomness. (message ID)
   > The value of this field MUST be the derived commit key. (algorithm suite data)

   Implementation: Use `:crypto.strong_rand_bytes/1` for message ID, derive commit key via HKDF.

6. **Header Authentication Tag** (encrypt.md)
   > The AAD MUST be the concatenation of the serialized message header body and the serialization of encryption context to only authenticate.
   > The cipherkey MUST be the derived data key.
   > The plaintext MUST be an empty byte array.
   > The IV value used MUST be 0.

   Implementation: AES-GCM encrypt empty plaintext with header body as AAD.

7. **Frame Construction** (encrypt.md)
   > The first frame encrypted within a message MUST use a sequence number of 1.
   > Each subsequent frame MUST use a sequentially increasing sequence number.
   > The AAD MUST be the serialized Message Body AAD.
   > The IV MUST have a value equal to the sequence number padded to the IV length.

   Implementation: Use Body.serialize_regular_frame/4 and Body.serialize_final_frame/4.

8. **Footer Signature** (encrypt.md)
   > If the algorithm suite contains a signature algorithm, the encryption operation MUST construct a message footer.
   > The input to the signature algorithm MUST be the concatenation of the serialization of the message header and message body.

   Implementation: For signed suites, ECDSA sign over header + body.

9. **No Extraneous Data** (encrypt.md)
   > Any data that is not specified within the message format MUST NOT be added to the output message.

10. **Non-Framed Prohibition** (encrypt.md)
    > Implementations of the AWS Encryption SDK MUST NOT encrypt using the Non-Framed content type.

    Implementation: Always use framed content type (0x02).

#### Decrypt Operation

1. **Sequential Processing** (decrypt.md)
   > This operation MUST perform all the above steps unless otherwise specified, and it MUST perform them in the above order.

   Order: Parse header → Get decryption materials → Verify header → Decrypt body → Verify signature

2. **No Unauthenticated Data Release** (decrypt.md - CRITICAL)
   > This operation MUST NOT release any unauthenticated plaintext or unauthenticated associated data.

   Implementation: Only return plaintext after ALL verification passes.

3. **Commitment Policy Enforcement** (decrypt.md)
   > If the algorithm suite is not supported by the commitment policy, decrypt MUST yield an error.

4. **Key Commitment Verification** (decrypt.md)
   > If the algorithm suite supports key commitment, the commit key MUST equal the commit key stored in the message header.

   Implementation: Derive commit key from plaintext data key, compare with header's algorithm_suite_data.

5. **Header Authentication** (decrypt.md)
   > If this tag verification fails, this operation MUST immediately halt and fail.

   Implementation: Verify header auth tag before proceeding.

6. **Body Decryption** (decrypt.md)
   > If this decryption fails, this operation MUST immediately halt and fail.
   > This operation MUST NOT release any unauthenticated plaintext.

   Implementation: AES-GCM decrypt verifies tag automatically; only accumulate plaintext after verification.

7. **Signature Verification** (decrypt.md)
   > For non-framed data: plaintext MUST NOT be released until signature verification successfully completes.
   > For final frame: plaintext MUST NOT be released until signature verification successfully completes.

   Implementation: Verify ECDSA signature before returning any plaintext.

### SHOULD Requirements

1. **Streaming API Design** (encrypt.md, decrypt.md)
   > If an implementation of this operation requires holding the entire plaintext in memory in order to perform this operation, that implementation SHOULD NOT provide an API that allows this input to be streamed.

   Implementation: For now, this is a non-streaming implementation. Document this clearly.

2. **Base64 Detection** (decrypt.md)
   > Implementations SHOULD detect the first two bytes of the Base64 encoding of the message format version and fail with a specific error message.

   Implementation: Check for "AQ" or "Ag" at start (Base64 of 0x01 or 0x02).

3. **Parsed Header Output** (encrypt.md)
   > The encryption operation SHOULD output a parsed header.

   Implementation: Return the header struct along with ciphertext.

### MAY Requirements

1. **AES-GCM Wrapper Module**
   - Encapsulate `:crypto.crypto_one_time_aead/6` and `:crypto.crypto_one_time_aead/7`
   - Not strictly required but improves code organization

## Test Vectors

### Applicable Test Vector Sets

- **awses-decrypt**: Decrypt test vectors from Python SDK 2.3.0
- **awses-encrypt**: Encrypt test vectors (round-trip verification)

The test vector harness is already implemented in `test/support/test_vector_harness.ex`.

### Implementation Order

#### Phase 1: Basic Decryption (Committed, Unsigned)

| Test Pattern | Algorithm | Description | Priority |
|--------------|-----------|-------------|----------|
| Raw AES keyring, non-framed | 0x0478 | Simplest committed case | **Start here** |
| Raw AES keyring, small frames | 0x0478 | Multi-frame handling | Second |
| Raw AES keyring, varying sizes | 0x0478 | Different plaintext sizes | Third |

**Why start with 0x0478**:
- Committed (v2 header) - modern format
- No signature - simpler verification
- HKDF-SHA512 - use existing HKDF module

#### Phase 2: Signed Algorithm Suites

| Test Pattern | Algorithm | Description | Priority |
|--------------|-----------|-------------|----------|
| Raw AES keyring | 0x0578 | Committed + ECDSA P384 | After Phase 1 |
| Raw AES keyring | 0x0378 | Legacy HKDF + ECDSA P384 | Later |

**Requires**: ECDSA verification implementation

#### Phase 3: Legacy Algorithm Suites

| Test Pattern | Algorithm | Description | Priority |
|--------------|-----------|-------------|----------|
| Raw AES keyring | 0x0178 | Legacy HKDF, no signature | Lower |
| Raw AES keyring | 0x0078 | No KDF (deprecated) | Lowest |

#### Phase 4: Edge Cases

| Test Case | Description | Expected |
|-----------|-------------|----------|
| Empty plaintext | 0-byte plaintext | Success, empty output |
| Single byte | 1-byte plaintext | Success |
| Large plaintext | Multi-frame, large data | Success |

#### Phase 5: Negative Tests

| Test Case | Description | Expected |
|-----------|-------------|----------|
| Wrong key | Incorrect decryption key | Decryption failure |
| Tampered header | Modified header bytes | Auth tag verification failure |
| Tampered body | Modified ciphertext | Auth tag verification failure |
| Commitment mismatch | Wrong commitment key | Commitment verification failure |

### Test Vector Details

**Fetching test vectors**:
```bash
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip \
  -o test/fixtures/test_vectors/python-2.3.0.zip
unzip test/fixtures/test_vectors/python-2.3.0.zip -d test/fixtures/test_vectors/
```

**Key material needed**:
- `aes-256`: 256-bit AES key for Raw AES keyring tests
- `aes-128`: 128-bit AES key for legacy suite tests
- `rsa-4096-private`: RSA private key for Raw RSA keyring tests (Phase 2+)

## Implementation Considerations

### Technical Approach

#### Data Key Derivation

For committed algorithm suites (0x0478, 0x0578):

```elixir
# Derive data key
{:ok, derived_data_key} = HKDF.derive(
  :sha512,                          # hash algorithm
  message_id,                       # salt
  plaintext_data_key,               # IKM
  "DERIVEKEY" <> <<0x00, 0x01>>,    # info (label + suite ID big-endian)
  32                                # output length (256 bits)
)

# Derive commitment key
{:ok, commitment_key} = HKDF.derive(
  :sha512,
  message_id,
  plaintext_data_key,
  "COMMITKEY" <> <<0x00, 0x01>>,
  32
)
```

For non-committed suites, derivation varies by suite. For identity KDF (0x0078, etc.), the derived key equals the plaintext data key.

#### AES-GCM Operations

```elixir
# Encrypt
{ciphertext, auth_tag} = :crypto.crypto_one_time_aead(
  :aes_256_gcm,
  derived_data_key,
  iv,
  plaintext,
  aad,
  true  # encrypt mode
)

# Decrypt (returns plaintext or raises on auth failure)
plaintext = :crypto.crypto_one_time_aead(
  :aes_256_gcm,
  derived_data_key,
  iv,
  ciphertext,
  aad,
  auth_tag,
  false  # decrypt mode
)
```

**Important**: Decryption returns `:error` if auth tag verification fails - this is how we ensure no unauthenticated data is released.

#### Header Authentication

For v2 headers:
```elixir
# AAD = header body + encryption context for authentication only
header_body = Header.serialize_v2_body(header)
ec_to_auth = EncryptionContext.serialize(header.encryption_context)
aad = header_body <> ec_to_auth

# IV is all zeros
iv = :binary.copy(<<0>>, 12)

# Encrypt empty plaintext
{<<>>, auth_tag} = :crypto.crypto_one_time_aead(
  :aes_256_gcm,
  derived_data_key,
  iv,
  <<>>,
  aad,
  true
)
```

### Security Considerations

1. **Never release unauthenticated plaintext** - This is the most critical security requirement
2. **Zero plaintext data key after use** - Consider using `:crypto.hash/2` to overwrite sensitive data
3. **Validate all inputs** - Check encryption context for reserved prefixes
4. **Enforce commitment policy** - Default to REQUIRE_ENCRYPT_REQUIRE_DECRYPT

### Potential Challenges

1. **Keyring dependency** - Need at least one keyring implementation to fully test
   - **Mitigation**: Can test with raw materials directly, add keyring integration later

2. **ECDSA signature verification** - Required for signed suites (0x0578, 0x0378)
   - **Mitigation**: Start with unsigned suite (0x0478), add ECDSA support separately

3. **Large message handling** - Memory usage for non-streaming implementation
   - **Mitigation**: Document memory requirements, add streaming in later phase

### Open Questions

1. **Should we require keyring/CMM for initial implementation?**
   - Recommendation: No, allow direct materials for testing, add keyring support later

2. **Should encrypt.ex support non-framed messages?**
   - Spec says MUST NOT encrypt non-framed, but decrypt MUST support reading them
   - Recommendation: Encrypt always uses framed; Decrypt supports both

3. **Default frame size?**
   - Common values: 4096, 65536 bytes
   - Recommendation: Default to 4096, allow configuration

## Recommended Next Steps

1. **Create materials structs** - `EncryptionMaterials` and `DecryptionMaterials`
2. **Implement decrypt module** - Start with decryption (can validate against test vectors)
3. **Add commitment validation** - For 0x0478/0x0578 suites
4. **Implement encrypt module** - After decrypt works, implement encrypt
5. **Add round-trip tests** - Encrypt then decrypt should return original plaintext
6. **Integrate with test vectors** - Validate against Python SDK test vectors

**Next command**: `/create_plan thoughts/shared/research/2026-01-25-GH10-basic-encrypt-decrypt.md`

## References

- Issue: https://github.com/[owner]/[repo]/issues/10
- Encrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md
- Decrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Client Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md
- Algorithm Suites: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
