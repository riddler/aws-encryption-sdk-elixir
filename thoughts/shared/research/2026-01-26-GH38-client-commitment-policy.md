# Research: Add Client module with commitment policy enforcement for encryption

**Issue**: #38 - Add Client module with commitment policy enforcement for encryption
**Date**: 2026-01-26
**Status**: Research complete

## Issue Summary

Implement the Client configuration module and update the Encrypt API to support CMM-based encryption with commitment policy enforcement. Currently, `AwsEncryptionSdk.Encrypt.encrypt/3` works directly with encryption materials. We need to:

1. Add a Client module that holds configuration (CMM, commitment policy)
2. Update Encrypt to accept a Client and use its CMM to get materials
3. Enforce commitment policy during encryption (only allow committed algorithm suites by default)

## Current Implementation State

### Existing Code

| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk.ex` | Main public API - delegates encrypt/decrypt to implementation modules |
| `lib/aws_encryption_sdk/encrypt.ex` | Current encrypt implementation - accepts EncryptionMaterials directly |
| `lib/aws_encryption_sdk/decrypt.ex` | Current decrypt implementation |
| `lib/aws_encryption_sdk/cmm/behaviour.ex` | CMM behaviour with commitment_policy type definitions |
| `lib/aws_encryption_sdk/cmm/default.ex` | Default CMM - handles keyring orchestration |
| `lib/aws_encryption_sdk/algorithm_suite.ex` | Algorithm suite definitions with commitment flags |
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials struct |

### Current API

The current encrypt function signature (`lib/aws_encryption_sdk/encrypt.ex:52-54`):

```elixir
@spec encrypt(EncryptionMaterials.t(), binary(), encrypt_opts()) ::
        {:ok, encrypt_result()} | {:error, term()}
def encrypt(%EncryptionMaterials{} = materials, plaintext, opts \\ [])
```

Users must manually:
1. Select an algorithm suite
2. Generate a plaintext data key
3. Create encrypted data keys
4. Assemble the materials struct

### CMM Layer (Exists but Not Integrated)

The Default CMM (`lib/aws_encryption_sdk/cmm/default.ex`) already:
- Validates commitment policy against algorithm suite
- Selects default algorithm suite based on policy
- Generates signing keys for signed suites
- Calls keyring to wrap/unwrap data keys

The CMM Behaviour (`lib/aws_encryption_sdk/cmm/behaviour.ex`) defines:
- `commitment_policy` type: `:forbid_encrypt_allow_decrypt`, `:require_encrypt_allow_decrypt`, `:require_encrypt_require_decrypt`
- `get_encryption_materials/2` callback
- `validate_commitment_policy_for_encrypt/2` helper
- `default_algorithm_suite/1` helper

### Gap Analysis

The encryption layer and CMM layer are disconnected. Need to:
1. Create Client struct to hold CMM and commitment_policy
2. Add Client-based encrypt function that calls CMM first
3. Integrate commitment policy enforcement into the encryption flow

## Specification Requirements

### Source Documents
- [client-apis/client.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md) - Client configuration
- [client-apis/encrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - Encrypt operation
- [framework/algorithm-suites.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md) - Algorithm suite definitions

### MUST Requirements

#### Client Configuration

1. **Configuration Options** (client.md)
   > "On client initialization, the caller MUST have the option to provide a: [commitment policy] [and] maximum number of encrypted data keys"

   Implementation: Client struct accepts `:commitment_policy` and `:max_encrypted_data_keys` options

2. **Default Commitment Policy** (client.md)
   > "If no commitment policy is provided the default MUST be REQUIRE_ENCRYPT_REQUIRE_DECRYPT"

   Implementation: Default to `:require_encrypt_require_decrypt` in `Client.new/1`

3. **Default EDK Limit** (client.md)
   > "If no maximum number of encrypted data keys is provided the default MUST result in no limit on the number of encrypted data keys"

   Implementation: Default `:max_encrypted_data_keys` to `nil` (unlimited)

4. **Policy Support** (client.md)
   > "The SDK implementation is required to support FORBID_ENCRYPT_ALLOW_DECRYPT, REQUIRE_ENCRYPT_ALLOW_DECRYPT, and REQUIRE_ENCRYPT_REQUIRE_DECRYPT."

   Implementation: Support all three policies

#### Commitment Policy Behavior

5. **FORBID_ENCRYPT_ALLOW_DECRYPT - Default Suite** (client.md)
   > "03 78 MUST be the default algorithm suite"

   Implementation: Use `0x0378` (AES_256_GCM_HKDF_SHA384_ECDSA_P384)

6. **FORBID_ENCRYPT_ALLOW_DECRYPT - Encrypt Constraint** (client.md)
   > "encrypt MUST only support algorithm suites that have a Key Commitment value of False"

   Implementation: Reject `0x0578` and `0x0478` for encryption

7. **REQUIRE_ENCRYPT_ALLOW_DECRYPT - Default Suite** (client.md)
   > "05 78 MUST be the default algorithm suite"

   Implementation: Use `0x0578` (AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)

8. **REQUIRE_ENCRYPT_* - Encrypt Constraint** (client.md)
   > "encrypt MUST only support algorithm suites that have a Key Commitment value of True"

   Implementation: Only allow `0x0578` and `0x0478` for encryption

9. **REQUIRE_ENCRYPT_REQUIRE_DECRYPT - Decrypt Constraint** (client.md)
   > "decrypt MUST only support algorithm suites that have a Key Commitment value of True"

   Implementation: Reject non-committed suites during decryption

#### Encryption Operation

10. **Input Validation** (encrypt.md)
    > "The following inputs to this behavior are REQUIRED: Plaintext, Either a CMM or a Keyring"

    Implementation: `encrypt/3` requires plaintext and CMM (or keyring wrapped in CMM)

11. **Algorithm Suite Policy Validation** (encrypt.md)
    > "If the algorithm suite is not supported by the commitment policy configured in the client encrypt MUST yield an error."

    Implementation: Validate suite against policy before and after getting materials

12. **EDK Limit** (encrypt.md)
    > "If the number of encrypted data keys on the encryption materials is greater than the maximum number of encrypted data keys configured in the client encrypt MUST yield an error."

    Implementation: Check `length(encrypted_data_keys) <= max_encrypted_data_keys`

### SHOULD Requirements

13. **Immutability** (client.md)
    > "Once a commitment policy has been set it SHOULD be immutable"

    Implementation: Use struct pattern to prevent modification

14. **Parsed Header Output** (encrypt.md)
    > "Client should return Parsed Header as output alongside encrypted message"

    Implementation: Return header in result map

### MAY Requirements

15. **Algorithm Suite Override** (encrypt.md)
    > "Algorithm Suite input is optional"

    Implementation: Accept optional `:algorithm_suite` option

16. **Encryption Context** (encrypt.md)
    > "Encryption Context input is optional"

    Implementation: Accept optional `:encryption_context` option

## Algorithm Suite Reference

### Committed Suites (Key Commitment = True, Message Format v2)

| ID | Name | Default For |
|----|------|-------------|
| `0x0578` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 | `:require_encrypt_*` |
| `0x0478` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY | - |

### Non-Committed Suites (Key Commitment = False, Message Format v1)

| ID | Name | Default For |
|----|------|-------------|
| `0x0378` | AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | `:forbid_encrypt_allow_decrypt` |
| `0x0178` | AES_256_GCM_IV12_TAG16_HKDF_SHA256 | - |
| `0x0078` | AES_256_GCM_IV12_TAG16_NO_KDF | (deprecated for encrypt) |

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

- **awses-decrypt**: Decrypt test vectors from Python SDK v2.2.0
- **Location**: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- **Total tests**: ~115 tests (subset with raw keyrings)

### Available Raw Keyring Test Vectors

| Test ID | Keyring | Key ID |
|---------|---------|--------|
| `4be2393c-2916-4668-ae7a-d26ddb8de593` | Raw AES | aes-128 |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | Raw AES | aes-192 |
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Raw AES | aes-256 |
| `d20b31a6-200d-4fdb-819d-7ded46c99d10` | Raw RSA | rsa-4096-private |
| `7c640f28-9fa1-4ff9-9179-196149f8c346` | Raw RSA | rsa-4096-private (OAEP SHA1) |
| `24088ba0-bf47-4d06-bb12-f6ba40956bd6` | Raw RSA | rsa-4096-private (OAEP SHA256) |

### Implementation Order

#### Phase 1: Basic Client with Committed Suites
| Test ID | Algorithm | Key Type | Notes |
|---------|-----------|----------|-------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Analyze | Raw AES-256 | Start here |

#### Phase 2: Non-Committed Suite Validation
Identify test vectors using non-committed suites (0x0178, 0x0378) to test `:forbid_encrypt_allow_decrypt` policy.

#### Phase 3: Full Policy Matrix
Test all three policies with both committed and non-committed suite vectors:

| Policy | Encrypt Committed | Encrypt Non-Committed | Decrypt Committed | Decrypt Non-Committed |
|--------|-------------------|----------------------|-------------------|----------------------|
| `forbid_encrypt_allow_decrypt` | Fail | Pass | Pass | Pass |
| `require_encrypt_allow_decrypt` | Pass | Fail | Pass | Pass |
| `require_encrypt_require_decrypt` | Pass | Fail | Pass | Fail |

### Test Vector Setup

If test vectors are not present:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Available keys
"aes-128" - 128-bit AES key
"aes-192" - 192-bit AES key
"aes-256" - 256-bit AES key
"rsa-4096-private" - RSA private key (PEM)
"rsa-4096-public" - RSA public key (PEM)
```

## Implementation Considerations

### Technical Approach

1. **Create Client struct** with `:cmm` and `:commitment_policy` fields
2. **Add Client.new/2** constructor accepting CMM and options
3. **Add Client.encrypt/3** that:
   - Validates commitment policy against requested algorithm suite
   - Calls CMM.get_encryption_materials/2 with policy
   - Validates returned materials against policy
   - Validates EDK count
   - Delegates to existing Encrypt.encrypt/3
4. **Update public API** in `aws_encryption_sdk.ex`
5. **Keep existing Encrypt.encrypt/3** as internal implementation

### Proposed Client Structure

```elixir
defmodule AwsEncryptionSdk.Client do
  @type commitment_policy ::
    :forbid_encrypt_allow_decrypt |
    :require_encrypt_allow_decrypt |
    :require_encrypt_require_decrypt

  @type t :: %__MODULE__{
    cmm: Cmm.Behaviour.t(),
    commitment_policy: commitment_policy(),
    max_encrypted_data_keys: non_neg_integer() | nil
  }

  defstruct [
    :cmm,
    commitment_policy: :require_encrypt_require_decrypt,
    max_encrypted_data_keys: nil
  ]
end
```

### Encryption Flow

```
Client.encrypt(client, plaintext, opts)
  │
  ├─► Validate encryption_context (no reserved keys)
  │
  ├─► Build CMM request with:
  │   - encryption_context
  │   - commitment_policy (from client)
  │   - algorithm_suite (from opts, optional)
  │
  ├─► Call client.cmm.get_encryption_materials(request)
  │
  ├─► Validate returned algorithm suite against commitment policy
  │
  ├─► Validate EDK count <= max_encrypted_data_keys
  │
  └─► Call Encrypt.encrypt(materials, plaintext, opts)
```

### Potential Challenges

1. **Keyring type dispatching** - Default CMM uses pattern matching, may need to support additional keyring types
2. **Error message clarity** - Need specific errors for commitment policy violations
3. **Backwards compatibility** - Current direct-materials API should remain available

### Open Questions

1. Should `Client.encrypt/3` also accept a keyring directly and wrap it in Default CMM?
2. Should the direct `Encrypt.encrypt/3` be deprecated or kept for advanced use cases?
3. What specific error tuple format for commitment policy violations?

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-26-GH38-client-commitment-policy.md`
2. Implement Client struct and new/2 constructor
3. Add Client.encrypt/3 with policy enforcement
4. Update public API
5. Add comprehensive tests for each policy
6. Create integration tests with test vectors

## References

- Issue: https://github.com/owner/repo/issues/38
- Spec - Client: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md
- Spec - Encrypt: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md
- Spec - Algorithm Suites: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
