# Research: Implement Algorithm Suite Definitions

**Issue**: #7 - Implement algorithm suite definitions
**Date**: 2026-01-24
**Status**: Research complete

## Issue Summary

Define all 17 algorithm suites per the AWS Encryption SDK specification, with priority focus on committed suites. Each suite defines cryptographic algorithms and parameters for encryption/decryption operations.

## Current Implementation State

### Existing Code

**None.** This is a greenfield project with only:
- `lib/aws_encryption_sdk.ex` - Placeholder module with `hello/0` function
- `test/aws_encryption_sdk_test.exs` - Placeholder test

The planned file `lib/aws_encryption_sdk/algorithm_suite.ex` does not exist yet.

### Relevant Patterns

No established patterns in the codebase yet. Code quality tools are configured:
- Credo strict mode enabled
- Max line length: 120 characters
- Specs and strict module layout checks enabled via Credo

### Dependencies

- **Depends on**: Nothing (this is foundational)
- **Depended on by**:
  - #8 - HKDF implementation (needs hash algorithm info from suites)
  - #9 - Message format serialization (needs version, suite data length)
  - #10 - Encryption/decryption (needs all suite parameters)

## Specification Requirements

### Source Documents

- [framework/algorithm-suites.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md) - Complete algorithm suite definitions (v0.4.0)

### Algorithm Suite Overview

The specification defines 16 algorithm suites across three formats:
- **ESDK** (AWS Encryption SDK): 11 suites - **Focus of this implementation**
- **S3EC** (S3 Encryption Client): 3 suites
- **DBE** (Database Encryption): 2 suites

### Complete ESDK Algorithm Suite Table

| ID | Name | Msg Ver | Key Bits | IV | Tag | KDF | Hash | Commitment | Signature |
|----|------|---------|----------|----|----|-----|------|------------|-----------|
| `0x0578` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 | 2 | 256 | 12 | 16 | HKDF | SHA-512 | Yes (32B) | ECDSA-P384 |
| `0x0478` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY | 2 | 256 | 12 | 16 | HKDF | SHA-512 | Yes (32B) | None |
| `0x0378` | AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | 1 | 256 | 12 | 16 | HKDF | SHA-384 | No | ECDSA-P384 |
| `0x0346` | AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | 1 | 192 | 12 | 16 | HKDF | SHA-384 | No | ECDSA-P384 |
| `0x0214` | AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 | 1 | 128 | 12 | 16 | HKDF | SHA-256 | No | ECDSA-P256 |
| `0x0178` | AES_256_GCM_IV12_TAG16_HKDF_SHA256 | 1 | 256 | 12 | 16 | HKDF | SHA-256 | No | None |
| `0x0146` | AES_192_GCM_IV12_TAG16_HKDF_SHA256 | 1 | 192 | 12 | 16 | HKDF | SHA-256 | No | None |
| `0x0114` | AES_128_GCM_IV12_TAG16_HKDF_SHA256 | 1 | 128 | 12 | 16 | HKDF | SHA-256 | No | None |
| `0x0078` | AES_256_GCM_IV12_TAG16_NO_KDF | 1 | 256 | 12 | 16 | Identity | N/A | No | None |
| `0x0046` | AES_192_GCM_IV12_TAG16_NO_KDF | 1 | 192 | 12 | 16 | Identity | N/A | No | None |
| `0x0014` | AES_128_GCM_IV12_TAG16_NO_KDF | 1 | 128 | 12 | 16 | Identity | N/A | No | None |

### MUST Requirements

1. **Reserved ID** (algorithm-suites.md)
   > "The value 00 00 is reserved and MUST NOT be used as an Algorithm Suite ID in the future."

   Implementation: Validate that `0x0000` is never accepted as a valid suite ID.

2. **Encryption Key Length** (algorithm-suites.md)
   > "The length of the input encryption key MUST equal the encryption key length specified by the algorithm suite."

   Implementation: Validate key length matches suite's `data_key_length`.

3. **IV Length** (algorithm-suites.md)
   > "The length of the input IV MUST equal the IV length specified by the algorithm suite."

   Implementation: Validate IV is 12 bytes for all ESDK suites.

4. **Authentication Tag Length** (algorithm-suites.md)
   > "The length of the authentication tag MUST equal the authentication tag length specified by the algorithm suite."

   Implementation: Validate auth tag is 16 bytes for all ESDK suites.

5. **Identity KDF Behavior** (algorithm-suites.md)
   > "MUST take a byte sequence as input, and MUST return the input, unchanged, as output"
   > "Algorithm suite's encryption key length MUST equal the algorithm suite's key derivation input length"

   Implementation: For NO_KDF suites (0x0014, 0x0046, 0x0078), return input key unchanged.

6. **Asymmetric Signature Generation** (algorithm-suites.md)
   > "Asymmetric signatures MUST be generated using the specified asymmetric signature algorithm"
   > When NOT specified: "Asymmetric signatures MUST NOT be generated"

   Implementation: Only generate signatures for suites with signature algorithm specified.

7. **Asymmetric Signature Verification** (algorithm-suites.md)
   > "MUST be verified using the specified asymmetric signature algorithm"
   > When NOT specified: "MUST NOT be verified"

   Implementation: Only verify signatures for suites with signature algorithm specified.

### SHOULD Requirements

None explicitly stated in the algorithm suites specification.

### MAY Requirements

None explicitly stated. Algorithm suite selection is deterministic.

## Test Vectors

### Applicable Test Vector Sets

- **awses-decrypt**: Pre-generated ciphertexts organized by algorithm ID
- **awses-legacy**: Older format with algorithm-specific directories
- **Framework-generated**: Comprehensive scenarios using `0x0014` only

### Test Vector Location

```bash
# Primary source
https://github.com/awslabs/aws-encryption-sdk-test-vectors

# Python SDK generated vectors (comprehensive)
vectors/awses-decrypt/python-2.3.0.zip
```

### Implementation Order

#### Phase 1: Core Committed Suites (Start Here)

| Test ID Pattern | Algorithm | Description | Priority |
|-----------------|-----------|-------------|----------|
| `0478/*` | 0x0478 | Default committed suite | **Start here** |
| `0578/*` | 0x0578 | Recommended with ECDSA | Second |

#### Phase 2: Legacy HKDF Suites

| Test ID Pattern | Algorithm | Description | Priority |
|-----------------|-----------|-------------|----------|
| `0178/*` | 0x0178 | Common legacy, no signing | Third |
| `0378/*` | 0x0378 | Legacy with ECDSA | Fourth |

#### Phase 3: Additional Key Sizes

| Test ID Pattern | Algorithm | Description | Priority |
|-----------------|-----------|-------------|----------|
| `0114/*` | 0x0114 | 128-bit, HKDF-SHA256 | Lower |
| `0146/*` | 0x0146 | 192-bit, HKDF-SHA256 | Lower |
| `0214/*` | 0x0214 | 128-bit, ECDSA-P256 | Lower |
| `0346/*` | 0x0346 | 192-bit, ECDSA-P384 | Lower |

#### Phase 4: Deprecated Suites (Decrypt Only)

| Test ID Pattern | Algorithm | Description | Priority |
|-----------------|-----------|-------------|----------|
| `0078/*` | 0x0078 | 256-bit, no KDF | Decrypt only |
| `0046/*` | 0x0046 | 192-bit, no KDF | Decrypt only |
| `0014/*` | 0x0014 | 128-bit, no KDF | Decrypt only |

### How to Fetch Test Vectors

```bash
mkdir -p test/fixtures/test_vectors
cd test/fixtures/test_vectors
curl -L -O https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip
unzip python-2.3.0.zip -d python-2.3.0
```

## Implementation Considerations

### Technical Approach

Create `lib/aws_encryption_sdk/algorithm_suite.ex` with:

1. **Struct definition** with all suite parameters
2. **Module attributes** for suite ID constants
3. **Lookup functions** (`by_id/1`, `default/0`, `recommended/0`)
4. **Predicate functions** (`committed?/1`, `signed?/1`, `allows_encryption?/1`)
5. **Individual suite functions** returning populated structs

### Proposed Struct

```elixir
defmodule AwsEncryptionSdk.AlgorithmSuite do
  @type t :: %__MODULE__{
    id: non_neg_integer(),
    name: String.t(),
    message_format_version: 1 | 2,
    encryption_algorithm: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm,
    data_key_length: 128 | 192 | 256,           # bits
    iv_length: 12,                               # bytes
    auth_tag_length: 16,                         # bytes
    kdf_type: :hkdf | :identity,
    kdf_hash: :sha256 | :sha384 | :sha512 | nil,
    kdf_input_length: non_neg_integer(),         # bytes
    signature_algorithm: :ecdsa_p256 | :ecdsa_p384 | nil,
    signature_hash: :sha256 | :sha384 | nil,
    suite_data_length: 0 | 32,                   # bytes (32 for committed)
    commit_key_length: 0 | 32                    # bytes (32 for committed)
  }

  defstruct [
    :id,
    :name,
    :message_format_version,
    :encryption_algorithm,
    :data_key_length,
    :iv_length,
    :auth_tag_length,
    :kdf_type,
    :kdf_hash,
    :kdf_input_length,
    :signature_algorithm,
    :signature_hash,
    :suite_data_length,
    :commit_key_length
  ]
end
```

### Erlang :crypto Mapping

| Suite Parameter | Erlang :crypto Value |
|-----------------|---------------------|
| AES-128-GCM | `:aes_128_gcm` |
| AES-192-GCM | `:aes_192_gcm` |
| AES-256-GCM | `:aes_256_gcm` |
| ECDSA P-256 | `{key, :secp256r1}` with `:sha256` |
| ECDSA P-384 | `{key, :secp384r1}` with `:sha384` |
| HMAC-SHA256 | `:crypto.mac(:hmac, :sha256, ...)` |
| HMAC-SHA384 | `:crypto.mac(:hmac, :sha384, ...)` |
| HMAC-SHA512 | `:crypto.mac(:hmac, :sha512, ...)` |

### Potential Challenges

1. **192-bit AES**: Erlang `:crypto` supports it, but less commonly used. Ensure tests cover this.

2. **Deprecated suite restrictions**: Need to implement `allows_encryption?/1` that returns `false` for NO_KDF suites to enforce decrypt-only policy.

3. **Commitment key derivation**: Committed suites require specific HKDF labels ("DERIVEKEY", "COMMITKEY"). This crosses into HKDF implementation but suite must expose the required parameters.

### Open Questions

1. **S3EC and DBE suites**: Should we implement these for compatibility, or focus only on ESDK suites?
   - **Recommendation**: Start with ESDK only, add S3EC/DBE later if needed.

2. **Suite deprecation warnings**: Should `by_id/1` return warnings for deprecated suites (NO_KDF)?
   - **Recommendation**: Add `deprecated?/1` predicate, let callers decide on warnings.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-24-GH7-algorithm-suite-definitions.md`

2. Implement in order:
   - Define struct and typespec
   - Add the 4 high-priority suites (0x0478, 0x0578, 0x0178, 0x0378)
   - Add lookup functions
   - Add predicate functions
   - Add remaining 7 ESDK suites
   - Add comprehensive tests

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/7
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- AWS Docs: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
- RFC 5869 (HKDF): https://tools.ietf.org/html/rfc5869
