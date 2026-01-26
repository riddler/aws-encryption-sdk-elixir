# Research: Implement Cryptographic Materials Manager (CMM) Behaviour

**Issue**: #36 - Implement Cryptographic Materials Manager (CMM) behaviour
**Date**: 2026-01-26
**Status**: Research complete

## Issue Summary

Define the CMM (Cryptographic Materials Manager) behaviour interface that all CMM implementations must follow per the AWS Encryption SDK specification. The CMM sits between the encrypt/decrypt APIs and keyrings, managing algorithm suite selection, encryption context handling, and orchestrating keyring operations.

## Current Implementation State

### Existing Code

- `lib/aws_encryption_sdk/keyring/behaviour.ex` - **Pattern to follow** - Keyring behaviour with `on_encrypt/1` and `on_decrypt/2` callbacks
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - EncryptionMaterials struct with `new/5`, `new_for_encrypt/3`, setters
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - DecryptionMaterials struct with `new/4`, `new_for_decrypt/3`, setters
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EncryptedDataKey struct with serialization
- `lib/aws_encryption_sdk/encrypt.ex` - Encryption logic (currently takes materials directly)
- `lib/aws_encryption_sdk/decrypt.ex` - Decryption logic (currently takes materials directly)
- `lib/aws_encryption_sdk/algorithm_suite.ex` - Algorithm suite definitions

### CMM Directory (Does Not Exist Yet)

```
lib/aws_encryption_sdk/cmm/
├── behaviour.ex           # CMM behaviour definition (to be created)
└── default.ex             # Default CMM implementation (future issue #37)
```

### Relevant Patterns from Keyring Behaviour

The keyring behaviour at `lib/aws_encryption_sdk/keyring/behaviour.ex` provides the pattern:

```elixir
# Callback definitions (lines 66-93)
@callback on_encrypt(materials :: EncryptionMaterials.t()) ::
            {:ok, EncryptionMaterials.t()} | {:error, term()}

@callback on_decrypt(
            materials :: DecryptionMaterials.t(),
            encrypted_data_keys :: [EncryptedDataKey.t()]
          ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}

# Helper functions (lines 96-164)
def validate_provider_id(provider_id)
def generate_data_key(algorithm_suite)
def has_plaintext_data_key?(materials)
```

### Materials Struct Fields

**EncryptionMaterials:**
- `:algorithm_suite` - Required
- `:encryption_context` - Required
- `:encrypted_data_keys` - List, defaults to `[]`
- `:plaintext_data_key` - Binary or nil
- `:signing_key` - Binary or nil
- `:required_encryption_context_keys` - List, defaults to `[]`

**DecryptionMaterials:**
- `:algorithm_suite` - Required
- `:encryption_context` - Required
- `:plaintext_data_key` - Binary or nil
- `:verification_key` - Binary or nil
- `:required_encryption_context_keys` - List, defaults to `[]`

## Specification Requirements

### Source Documents

- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - Core CMM behaviour definition
- [default-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md) - Default CMM implementation
- [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Material structure definitions

### Get Encryption Materials Operation

#### MUST Requirements

1. **Input Requirements** (cmm-interface.md)
   > Encryption materials request MUST include:
   > - Encryption context (may be empty)
   > - Commitment policy

   Implementation: Define request struct/map with required fields

2. **Plaintext Data Key** (cmm-interface.md)
   > Include a plaintext data key with value that is non-NULL.
   > Plaintext data key length MUST equal the key derivation input length.

   Implementation: Validate returned materials have plaintext_data_key

3. **Encrypted Data Keys** (cmm-interface.md)
   > Include encrypted data keys list with at least one entry.
   > Every encrypted data key MUST correspond to the plaintext data key.

   Implementation: Validate at least one EDK in returned materials

4. **Required Encryption Context Keys** (cmm-interface.md)
   > Include required encryption context keys.
   > Returned required keys MUST be superset of requested required keys.

   Implementation: Validate required keys preserved

5. **Signing Key** (cmm-interface.md)
   > If algorithm suite has signing algorithm: include signing key.

   Implementation: Validate signing_key present for signed suites

6. **Return Valid Materials** (cmm-interface.md)
   > Return valid encryption materials per specification.

   Implementation: Full validation before returning

#### SHOULD Requirements

1. **Signing Key Context** (cmm-interface.md)
   > If algorithm suite contains signing algorithm, add `aws-crypto-public-key` key to encryption context with signature verification key as value.

   Implementation: Helper to add verification key to context

2. **Algorithm Suite** (cmm-interface.md)
   > Include an algorithm suite (SHOULD match requested suite if provided).

   Implementation: Return same suite if specified

#### MAY Requirements

1. **Optional Inputs** (cmm-interface.md)
   > Encryption materials request MAY include:
   > - Algorithm suite ID
   > - Required encryption context keys
   > - Max plaintext length

   Implementation: Make these fields optional in request type

### Decrypt Materials Operation

#### MUST Requirements

1. **Input Requirements** (cmm-interface.md)
   > Decrypt materials request MUST include:
   > - Algorithm suite ID
   > - Commitment policy
   > - Encrypted data keys
   > - Encryption context (may be empty)

   Implementation: Define request struct/map with required fields

2. **Encryption Context Validation** (cmm-interface.md)
   > Validate encryption context against reproduced encryption context.
   > For matching keys between contexts, values MUST be equal or operation fails.

   Implementation: Helper function for context comparison

3. **Plaintext Data Key** (cmm-interface.md)
   > Include plaintext data key (non-NULL value).
   > Plaintext data key MUST correspond with at least one encrypted data key.

   Implementation: Validate returned materials have plaintext_data_key

4. **Required Encryption Context Keys** (cmm-interface.md)
   > Include required encryption context keys.
   > All keys in required encryption context keys MUST exist in decryption materials context.

   Implementation: Validate required keys present

5. **Verification Key** (cmm-interface.md)
   > If algorithm suite has signing algorithm: include signature verification key.

   Implementation: Validate verification_key present for signed suites

#### SHOULD Requirements

1. **Encryption Context Handling** (cmm-interface.md)
   > Invert encryption context modifications from Get Encryption Materials call.
   > Append key-value pairs from reproduced context missing in decrypt request context.

   Implementation: Helper for context modification

2. **Signing Key Validation** (cmm-interface.md)
   > Operation SHOULD fail if signing algorithm present but `aws-crypto-public-key` missing.
   > Operation SHOULD fail if no signing algorithm but `aws-crypto-public-key` present.

   Implementation: Validation helpers for verification key consistency

#### MAY Requirements

1. **Optional Inputs** (cmm-interface.md)
   > Decrypt materials request MAY include:
   > - Reproduced encryption context

   Implementation: Optional field in request type

## CMM Callback Signatures

Based on the specification, define these callbacks:

```elixir
@type encryption_materials_request :: %{
  required(:encryption_context) => %{String.t() => String.t()},
  required(:commitment_policy) => commitment_policy(),
  optional(:algorithm_suite) => AlgorithmSuite.t() | nil,
  optional(:required_encryption_context_keys) => [String.t()],
  optional(:max_plaintext_length) => non_neg_integer()
}

@type decrypt_materials_request :: %{
  required(:algorithm_suite) => AlgorithmSuite.t(),
  required(:commitment_policy) => commitment_policy(),
  required(:encrypted_data_keys) => [EncryptedDataKey.t()],
  required(:encryption_context) => %{String.t() => String.t()},
  optional(:reproduced_encryption_context) => %{String.t() => String.t()}
}

@type commitment_policy ::
  :forbid_encrypt_allow_decrypt |
  :require_encrypt_allow_decrypt |
  :require_encrypt_require_decrypt

@callback get_encryption_materials(cmm :: t(), request :: encryption_materials_request()) ::
  {:ok, EncryptionMaterials.t()} | {:error, term()}

@callback decrypt_materials(cmm :: t(), request :: decrypt_materials_request()) ::
  {:ok, DecryptionMaterials.t()} | {:error, term()}
```

## Reserved Encryption Context Key

The key `"aws-crypto-public-key"` is reserved:
- CMM MUST add it when algorithm suite includes signing
- CMM MUST fail if caller already provided this key
- Value is base64-encoded DER format public key
- Decrypt MUST extract verification key from this key

## Test Vectors

### Note on CMM Testing

The CMM behaviour is an interface definition. Test vectors do not directly test CMM implementations - instead, they test the complete encrypt/decrypt flow which implicitly validates CMM behavior through keyring interactions.

### Test Infrastructure

```elixir
# Test harness available at test/support/test_vector_harness.ex
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
{:ok, test} = TestVectorHarness.get_test(harness, test_id)
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
```

### Applicable Test Vectors

Test vectors at `test/fixtures/test_vectors/vectors/awses-decrypt/`:
- 9,089+ test cases covering all algorithm suites
- Raw AES, Raw RSA, and AWS KMS keyrings
- Signed and unsigned suites
- Committed and non-committed suites

### Implementation Order for CMM Testing

| Phase | Focus | Test Pattern |
|-------|-------|--------------|
| 1 | Basic CMM flow | Raw AES single keyring decrypt vectors |
| 2 | Signing key handling | Signed algorithm suite vectors (0x0578, 0x0378) |
| 3 | Multi-keyring coordination | Multiple master key vectors |
| 4 | Algorithm suite coverage | All 17 suite types |

## Implementation Considerations

### Technical Approach

1. **Create `lib/aws_encryption_sdk/cmm/behaviour.ex`**
   - Define module with comprehensive moduledoc
   - Define types for requests and commitment policy
   - Define `@callback` for both operations
   - Add helper functions for common validations

2. **Helper Functions to Include**
   - `validate_commitment_policy/2` - Check suite vs policy compatibility
   - `validate_encryption_materials/1` - Validate materials completeness
   - `validate_decryption_materials/1` - Validate materials completeness
   - `extract_verification_key/1` - Extract from `aws-crypto-public-key`
   - `add_verification_key_to_context/2` - Add base64 public key

3. **Type Definitions**
   - `@type t :: term()` - CMM implementation struct
   - `@type encryption_materials_request :: map()`
   - `@type decrypt_materials_request :: map()`
   - `@type commitment_policy :: atom()`

### Commitment Policy and Algorithm Suite Mapping

| Commitment Policy | Default Suite | Allowed Suites |
|-------------------|---------------|----------------|
| `:require_encrypt_require_decrypt` | 0x0578 | Committed only (0x04xx, 0x05xx) |
| `:require_encrypt_allow_decrypt` | 0x0578 | All suites |
| `:forbid_encrypt_allow_decrypt` | 0x0378 | Non-committed only for encrypt |

### Potential Challenges

1. **Verification Key Format** - Must handle base64-encoded DER format public keys
2. **Context Validation** - Comparing reproduced context with message context
3. **Generic CMM Type** - Defining `t()` type that works for all implementations

### Open Questions

1. Should the CMM behaviour define a `__using__` macro for common functionality?
2. Should commitment policy validation be in the behaviour or implementations?
3. How to handle the CMM struct type generically in the behaviour?

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-26-GH36-cmm-behaviour.md`
2. Implement CMM behaviour module
3. Add unit tests for helper functions
4. Proceed to Default CMM implementation (issue #37)

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/36
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Default CMM Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
- Structures Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md
- Existing Keyring Behaviour: `lib/aws_encryption_sdk/keyring/behaviour.ex`
