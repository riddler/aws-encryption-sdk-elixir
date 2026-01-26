# Research: Define Keyring behaviour interface

**Issue**: #25 - Define Keyring behaviour interface
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Define the Keyring behaviour interface per the AWS Encryption SDK specification. This establishes the contract that all keyring implementations (Raw AES, Raw RSA, AWS KMS, Multi-Keyring) must follow for encryption and decryption operations.

## Current Implementation State

### Existing Code

| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials struct with algorithm_suite, encryption_context, encrypted_data_keys, plaintext_data_key, signing_key |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | DecryptionMaterials struct with algorithm_suite, encryption_context, plaintext_data_key, verification_key |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EncryptedDataKey struct with key_provider_id, key_provider_info, ciphertext; includes serialization/deserialization |
| `lib/aws_encryption_sdk/encrypt.ex` | Encrypt operation accepting pre-built EncryptionMaterials |
| `lib/aws_encryption_sdk/decrypt.ex` | Decrypt operation accepting pre-built DecryptionMaterials |

### Relevant Patterns

The codebase currently operates with **manually constructed materials**:
- Tests directly create `EncryptionMaterials` structs via `EncryptionMaterials.new/5`
- Tests manually specify `plaintext_data_key` and `encrypted_data_keys` lists
- No keyring abstraction exists to generate or unwrap data keys
- No CMM (Cryptographic Materials Manager) exists to coordinate keyrings

**Current test pattern** (`integration_test.exs`):
```elixir
# 1. Generate plaintext data key manually
plaintext_data_key = :crypto.strong_rand_bytes(div(suite.data_key_length, 8))

# 2. Create EDK (test uses plaintext key as ciphertext - placeholder)
edk = EncryptedDataKey.new("test-provider", "test-key", plaintext_data_key)

# 3. Build encryption materials manually
enc_materials = EncryptionMaterials.new(suite, %{}, [edk], plaintext_data_key)

# 4. Encrypt
{:ok, enc_result} = AwsEncryptionSdk.encrypt(enc_materials, plaintext)
```

### Dependencies

**What this feature depends on:**
- `AwsEncryptionSdk.Materials.EncryptionMaterials` (exists)
- `AwsEncryptionSdk.Materials.DecryptionMaterials` (exists)
- `AwsEncryptionSdk.Materials.EncryptedDataKey` (exists)
- `AwsEncryptionSdk.AlgorithmSuite` (exists)

**What depends on this feature:**
- Raw AES Keyring (#26)
- Raw RSA Keyring (#27)
- Multi-Keyring (#28)
- CMM behaviour (Milestone 3)
- Default CMM (Milestone 3)

## Specification Requirements

### Source Documents
- [framework/keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Version 0.2.4
- [framework/structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Data structures

### MUST Requirements

#### OnEncrypt Operation

1. **OnEncrypt Input** (keyring-interface.md#onencrypt)
   > This interface MUST take [encryption materials](structures.md#encryption-materials) as input.

   Implementation: Accept `%EncryptionMaterials{}` struct

2. **OnEncrypt Behaviors** (keyring-interface.md#onencrypt)
   > It MUST modify it with at least one of the following behaviors:
   > - Generate data key
   > - Encrypt data key

   Implementation: Keyring must perform at least one of these operations

3. **OnEncrypt Success Output** (keyring-interface.md#onencrypt)
   > If this keyring attempted any of the above behaviors, and successfully completed those behaviors, it MUST output the modified [encryption materials](structures.md#encryption-materials).

   Implementation: Return `{:ok, modified_encryption_materials}`

4. **OnEncrypt No Action Failure** (keyring-interface.md#onencrypt)
   > If the keyring did not attempt any of the above behaviors, it MUST fail and it MUST NOT modify the [encryption materials](structures.md#encryption-materials).

   Implementation: Return `{:error, reason}` without modifying materials

#### OnDecrypt Operation

5. **OnDecrypt Input** (keyring-interface.md#ondecrypt)
   > This interface MUST take [decryption materials](structures.md#decryption-materials) and a list of [encrypted data keys](structures.md#encrypted-data-key) as input.

   Implementation: Accept `(%DecryptionMaterials{}, [%EncryptedDataKey{}])`

6. **OnDecrypt Existing Key Check** (keyring-interface.md#ondecrypt)
   > If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

   Implementation: Check `materials.plaintext_data_key`, return error if non-nil

7. **OnDecrypt Success Output** (keyring-interface.md#ondecrypt)
   > If this keyring attempted the above behavior, and succeeded, it MUST output the modified [decryption materials](structures.md#decryption-materials).

   Implementation: Return `{:ok, modified_decryption_materials}`

8. **OnDecrypt No Action Failure** (keyring-interface.md#ondecrypt)
   > If the keyring did not attempt the above behavior, the keyring MUST fail and MUST NOT modify the [decryption materials](structures.md#decryption-materials).

   Implementation: Return `{:error, reason}` if no decryption attempted

#### Generate Data Key Behavior

9. **Generate When Missing** (keyring-interface.md#generate-data-key)
   > If the [encryption materials](structures.md#encryption-materials) do not contain a plaintext data key, OnEncrypt MUST generate a data key.

   Implementation: Check `materials.plaintext_data_key == nil`, then generate

10. **Don't Generate When Present** (keyring-interface.md#generate-data-key)
    > If the encryption materials contain a plaintext data key, OnEncrypt MUST NOT generate a data key.

    Implementation: Skip generation if `materials.plaintext_data_key != nil`

11. **Key Length Requirement** (keyring-interface.md#generate-data-key)
    > The length of the output plaintext data key MUST be equal to the KDF input length of the [algorithm suite](algorithm-suites.md) specified in the [encryption materials](structures.md#encryption-materials).

    Implementation: Use `div(materials.algorithm_suite.data_key_length, 8)` bytes

12. **Cryptographic Randomness** (keyring-interface.md#generate-data-key)
    > The value of the plaintext data key MUST consist of cryptographically secure (pseudo-)random bits.

    Implementation: Use `:crypto.strong_rand_bytes/1`

#### Encrypt Data Key Behavior

13. **Encrypt When Present** (keyring-interface.md#encrypt-data-key)
    > If the [encryption materials](structures.md#encryption-materials) contain a plaintext data key, OnEncrypt MUST encrypt a data key.

    Implementation: Check `materials.plaintext_data_key != nil`, then encrypt

14. **Decryptable Ciphertext** (keyring-interface.md#encrypt-data-key)
    > The [encrypted data keys](structures.md#encrypted-data-key) produced by this keyring MUST have [ciphertexts](structures.md#ciphertext) that can be decrypted to the plaintext data key in the [encryption materials](structures.md#encryption-materials).

    Implementation: Ensure encrypt/decrypt operations are inverse operations

#### Decrypt Data Key Behavior

15. **Don't Decrypt When Present** (keyring-interface.md#decrypt-data-key)
    > If the encryption materials do contain a plaintext data key, OnDecrypt MUST NOT decrypt a data key.

    Implementation: Skip if `materials.plaintext_data_key != nil`

16. **No Update on Failure** (keyring-interface.md#decrypt-data-key)
    > If the keyring is unable to get any plaintext data key using the input [encrypted data keys](structures.md#encrypted-data-key), the keyring MUST NOT not update the [decryption materials](structures.md#decryption-materials) and MUST return failure.

    Implementation: Return `{:error, :unable_to_decrypt}` with unmodified materials

#### Key Provider Identifiers

17. **Key Provider ID Type** (keyring-interface.md#key-provider-id)
    > The key provider ID MUST be a binary value

    Implementation: Use `binary()` type in `%EncryptedDataKey{}`

18. **AWS KMS Restriction** (keyring-interface.md#key-provider-id)
    > This value MUST NOT be or start with "aws-kms" unless this encrypted data key was produced by one of the [AWS KMS Keyrings](./aws-kms/).

    Implementation: Validate provider ID doesn't start with "aws-kms" for non-KMS keyrings

19. **Key Provider Info Type** (keyring-interface.md#key-provider-info)
    > The key provider info MUST be a binary value

    Implementation: Use `binary()` type in `%EncryptedDataKey{}`

### SHOULD Requirements

1. **Key Provider ID Encoding** (keyring-interface.md#key-provider-id)
   > The key provider ID SHOULD be equal to a UTF-8 encoding of the key namespace.

   Implementation: `key_provider_id = key_namespace` (UTF-8 encoded)

2. **Key Provider Info Encoding** (keyring-interface.md#key-provider-info)
   > The key provider info SHOULD be equal to a UTF-8 encoding of the key name.

   Implementation: `key_provider_info = key_name` (UTF-8 encoded)

3. **Don't Store Encryption Context in EDK** (keyring-interface.md#onencrypt)
   > The keyring SHOULD NOT attempt to store the encryption context in the [encrypted data key's](structures.md#encrypted-data-key) properties.

   Implementation: Don't include encryption context in `key_provider_info`

4. **Integrity Guarantees** (keyring-interface.md#security-considerations)
   > Keyring implementations SHOULD provide integrity guarantees for the [encrypted data keys](structures.md#encrypted-data-key) they return on [OnEncrypt](#onencrypt) such that tampered versions of those encrypted data keys, if input into [OnDecrypt](#ondecrypt), are overwhelmingly likely to cause a decryption failure

   Implementation: Use authenticated encryption (e.g., AES-GCM) for key wrapping

5. **Encryption Context Integrity** (keyring-interface.md#security-considerations)
   > Such integrity guarantees SHOULD include the integrity of the [encryption context](structures.md#encryption-context)

   Implementation: Include encryption context as AAD in authenticated encryption

### MAY Requirements

1. **Generate Then Encrypt** (keyring-interface.md#generate-data-key)
   > Note: If the keyring successfully performs this behavior, this means that the keyring MAY then perform the [Encrypt Data Key](#encrypt-data-key) behavior.

   Implementation: After generating, optionally encrypt the data key with same keyring

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

The Keyring behaviour itself is an interface definition and doesn't have direct test vectors. However, test vectors exist for keyring implementations that will use this behaviour:

- **awses-decrypt**: Decrypt test vectors for various keyring types
- Manifest path: `test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json`
- Total raw keyring tests: ~8,201 test cases

### Test Vector Categories by Keyring Type

| Keyring Type | Test Cases | Key Sizes | Example Test ID |
|--------------|------------|-----------|-----------------|
| Raw AES | 3+ identified | 128, 192, 256-bit | `4be2393c-2916-4668-ae7a-d26ddb8de593` |
| Raw RSA | 2+ identified | 4096-bit | `d20b31a6-200d-4fdb-819d-7ded46c99d10` |
| Multi-keyring | 1+ identified | Mixed | `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` |

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Get key metadata
{:ok, key_data} = TestVectorHarness.get_key(harness, "aes-256")

# Decode key material
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)
```

## Implementation Considerations

### Technical Approach

Create `lib/aws_encryption_sdk/keyring/behaviour.ex` with Elixir behaviour callbacks:

```elixir
defmodule AwsEncryptionSdk.Keyring.Behaviour do
  @moduledoc """
  Behaviour for keyring implementations.

  Keyrings are responsible for generating, encrypting, and decrypting data keys.
  All keyring implementations must implement this behaviour.

  ## Callbacks

  - `on_encrypt/1` - Generate and/or encrypt data keys during encryption
  - `on_decrypt/2` - Decrypt data keys during decryption

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
  """

  alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials, EncryptedDataKey}

  @doc """
  OnEncrypt operation.

  Takes encryption materials and returns modified encryption materials.
  MUST perform at least one of: Generate Data Key or Encrypt Data Key.

  ## Behaviors

  1. If `materials.plaintext_data_key` is nil, MUST generate a data key
  2. If `materials.plaintext_data_key` is set, MUST encrypt it and add EDK
  3. After generating, MAY also encrypt the generated key

  ## Returns

  - `{:ok, %EncryptionMaterials{}}` - Successfully modified materials
  - `{:error, term()}` - Failed to perform any behavior
  """
  @callback on_encrypt(materials :: EncryptionMaterials.t()) ::
              {:ok, EncryptionMaterials.t()} | {:error, term()}

  @doc """
  OnDecrypt operation.

  Takes decryption materials and list of encrypted data keys.
  Returns modified decryption materials with plaintext data key set.

  ## Preconditions

  - MUST fail if `materials.plaintext_data_key` is already set

  ## Behaviors

  1. Attempt to decrypt one of the provided EDKs
  2. On success, set the plaintext_data_key on materials
  3. On failure, return error without modifying materials

  ## Returns

  - `{:ok, %DecryptionMaterials{}}` - Successfully decrypted a data key
  - `{:error, term()}` - Unable to decrypt any data key
  """
  @callback on_decrypt(
              materials :: DecryptionMaterials.t(),
              encrypted_data_keys :: [EncryptedDataKey.t()]
            ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}
end
```

### Potential Challenges

1. **Key Zeroing**: The spec says plaintext data keys "SHOULD support zeroing functionality". BEAM's immutable binaries make this difficult. Consider:
   - Documenting BEAM memory model limitations
   - Using NIFs for sensitive key storage in future versions

2. **aws-kms Provider ID Validation**: Non-KMS keyrings must validate that provider IDs don't start with "aws-kms". Need helper function for this.

3. **Error Handling Consistency**: Need to define consistent error tuple formats across all keyring implementations.

### Open Questions

1. **Multiple EDK Decryption**: If a keyring can decrypt multiple EDKs, should we:
   - Use the first successfully decrypted key? (recommended)
   - Validate all decrypted keys match before setting?

2. **Error Details**: Should error tuples include detailed reasons for debugging, or keep them opaque for security?
   - Recommendation: Include details for debugging; callers can sanitize for end users

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-25-GH25-keyring-behaviour.md`
2. Implement the behaviour module
3. Add comprehensive documentation with examples
4. Create unit tests for behaviour contract validation

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/25
- Keyring Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Data Structures Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md
- Algorithm Suites Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
