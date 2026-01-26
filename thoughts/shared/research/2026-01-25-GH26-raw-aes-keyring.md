# Research: Implement Raw AES Keyring

**Issue**: #26 - Implement Raw AES Keyring
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Implement the Raw AES Keyring per the AWS Encryption SDK specification. This keyring uses locally-provided AES keys to wrap and unwrap data keys using AES-GCM. It enables encryption scenarios where keys are managed locally rather than through AWS KMS.

### Acceptance Criteria (from issue)
- Create `AwsEncryptionSdk.Keyring.RawAes` module implementing the Keyring behaviour
- Implement `on_encrypt/1` callback (generate/wrap data key)
- Implement `on_decrypt/2` callback (find matching EDK, unwrap data key)
- Support configurable key namespace and key name
- Validate wrapping key length (128, 192, or 256 bits)
- Unit tests for encrypt/decrypt round-trip
- Pass Raw AES keyring test vectors

## Current Implementation State

### Existing Code

| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk/keyring/behaviour.ex` | Keyring behaviour with `on_encrypt/1` and `on_decrypt/2` callbacks |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EDK struct with serialization/deserialization |
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials struct for encryption |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | DecryptionMaterials struct for decryption |
| `lib/aws_encryption_sdk/crypto/aes_gcm.ex` | AES-GCM encrypt/decrypt operations |
| `lib/aws_encryption_sdk/format/encryption_context.ex` | Encryption context serialization |

### Relevant Patterns

**Keyring Behaviour Interface** (`behaviour.ex:66-93`):
```elixir
@callback on_encrypt(materials :: EncryptionMaterials.t()) ::
            {:ok, EncryptionMaterials.t()} | {:error, term()}

@callback on_decrypt(
            materials :: DecryptionMaterials.t(),
            encrypted_data_keys :: [EncryptedDataKey.t()]
          ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}
```

**Helper Functions Available**:
- `Keyring.Behaviour.generate_data_key/1` - Generates random data key from algorithm suite
- `Keyring.Behaviour.has_plaintext_data_key?/1` - Checks if materials have a data key
- `Keyring.Behaviour.validate_provider_id/1` - Validates provider ID isn't reserved

**AES-GCM Operations** (`crypto/aes_gcm.ex`):
- `encrypt/5` - Returns `{ciphertext, auth_tag}` tuple
- `decrypt/6` - Returns `{:ok, plaintext}` or `{:error, :authentication_failed}`
- Constants: IV = 12 bytes, Tag = 16 bytes

**Encryption Context Serialization** (`format/encryption_context.ex`):
- `serialize/1` - Returns binary (empty for empty map, count-prefixed for non-empty)
- Already sorted by key, handles empty context correctly

### Dependencies

- **Depends on**: Keyring behaviour (#25, merged)
- **Depended by**: Multi-keyring (future), CMM (future)

## Specification Requirements

### Source Documents
- [framework/raw-aes-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md) - Raw AES keyring specification
- [framework/keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - General keyring interface

### MUST Requirements

#### Initialization

1. **Initialization Parameters** (raw-aes-keyring.md#initialization)
   > "On keyring initialization, the caller MUST provide the following: Key Namespace, Key Name, Wrapping Key, Wrapping Algorithm"

   Implementation: Accept four required parameters - key_namespace (String), key_name (String), wrapping_key (binary), wrapping_algorithm (atom).

2. **Wrapping Key Length Validation** (raw-aes-keyring.md#wrapping-key)
   > "length of the wrapping key MUST be 128, 192, or 256"

   Implementation: Validate `bit_size(wrapping_key) in [128, 192, 256]` on initialization.

3. **Key-Algorithm Match** (raw-aes-keyring.md#wrapping-algorithm)
   > "Initialization MUST fail if the length of the wrapping key does not match the length specified by the wrapping algorithm"

   Implementation: Ensure wrapping key size matches algorithm's expected key size.

4. **Wrapping Algorithm Support** (raw-aes-keyring.md#wrapping-algorithm)
   > "keyring MUST support the following algorithm configurations: AES_GCM with key size 128/192/256 bits, IV length 12 bytes, and tag length 16 bytes"

   Implementation: Support `:aes_128_gcm`, `:aes_192_gcm`, `:aes_256_gcm` configurations.

#### OnEncrypt

5. **Data Key Generation** (raw-aes-keyring.md#onencrypt)
   > "If the encryption materials do not contain a plaintext data key, OnEncrypt MUST generate a random plaintext data key"

   Implementation: Use `Keyring.Behaviour.generate_data_key/1` when `plaintext_data_key` is nil.

6. **Encryption Context Serialization** (raw-aes-keyring.md#onencrypt)
   > "keyring MUST attempt to serialize the encryption context; if it cannot, OnEncrypt MUST fail"

   Implementation: Call `EncryptionContext.serialize/1` and handle any errors.

7. **AES-GCM Wrapping** (raw-aes-keyring.md#onencrypt)
   > "keyring MUST encrypt the plaintext data key using AES-GCM"
   > "MUST use the serialized encryption context as the additional authenticated data (AAD)"
   > "MUST use this keyring's wrapping key as the AES-GCM cipher key"
   > "MUST use a cryptographically random generated IV of length specified"
   > "MUST use an authentication tag bit of length specified"

   Implementation:
   ```elixir
   iv = :crypto.strong_rand_bytes(12)
   {encrypted_key, tag} = AesGcm.encrypt(cipher, wrapping_key, iv, plaintext_key, serialized_ec)
   ```

8. **EDK Construction** (raw-aes-keyring.md#onencrypt)
   > "keyring MUST construct an encrypted data key with key provider ID as this keyring's key namespace"

   Implementation:
   ```elixir
   %EncryptedDataKey{
     key_provider_id: keyring.key_namespace,
     key_provider_info: serialize_provider_info(key_name, tag_length_bits, iv),
     ciphertext: encrypted_key <> tag
   }
   ```

9. **EDK Append** (raw-aes-keyring.md#onencrypt)
   > "keyring MUST append the constructed encrypted data key to the encrypted data key list"

   Implementation: Use `EncryptionMaterials.add_encrypted_data_key/2`.

#### OnDecrypt

10. **Existing Key Check** (raw-aes-keyring.md#ondecrypt)
    > "If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the decryption materials"

    Implementation: Check `has_plaintext_data_key?/1` first, return error if true.

11. **Serial Processing** (raw-aes-keyring.md#ondecrypt)
    > "keyring MUST perform actions on each encrypted data key serially, until it successfully decrypts one"

    Implementation: Use `Enum.reduce_while/3` to iterate EDKs.

12. **Key Provider Matching** (raw-aes-keyring.md#ondecrypt)
    > "key provider ID MUST have a value equal to this keyring's key namespace"
    > "key name from encrypted data key's key provider information MUST have a value equal to this keyring's key name"

    Implementation: Skip EDKs where `edk.key_provider_id != keyring.key_namespace` or `provider_info.key_name != keyring.key_name`.

13. **Parameter Validation** (raw-aes-keyring.md#ondecrypt)
    > "IV length obtained from key provider information MUST have a value equal to length specified by wrapping algorithm"
    > "authentication tag length obtained from key provider information MUST have a value equal to length specified by wrapping algorithm"

    Implementation: Validate IV length = 12 bytes, auth tag length = 128 bits before decryption.

14. **AES-GCM Unwrapping** (raw-aes-keyring.md#ondecrypt)
    > "MUST use the encrypt key obtained from deserialization as the AES-GCM input ciphertext"
    > "MUST use the authentication tag obtained from deserialization as the AES-GCM input authentication tag"
    > "MUST use this keyring's wrapping key as the AES-GCM cipher key"
    > "MUST use the IV obtained from deserialization as the AES-GCM IV"
    > "MUST use the serialized encryption context as the AES-GCM AAD"

    Implementation:
    ```elixir
    AesGcm.decrypt(cipher, wrapping_key, iv, encrypted_key, serialized_ec, tag)
    ```

15. **Successful Decryption** (raw-aes-keyring.md#ondecrypt)
    > "If decryption succeeds, keyring MUST add the resulting plaintext data key to decryption materials"

    Implementation: Use `DecryptionMaterials.set_plaintext_data_key/2`.

16. **All Failures** (raw-aes-keyring.md#ondecrypt)
    > "If no decryption succeeds, keyring MUST fail and MUST NOT modify the decryption materials"

    Implementation: Return `{:error, :unable_to_decrypt_data_key}` without modifying materials.

### SHOULD Requirements

1. **Encryption Context Storage** (keyring-interface.md#onencrypt)
   > "SHOULD NOT attempt to store the encryption context" in encrypted data key properties

   Implementation: EC is used as AAD only, not stored in provider info.

2. **Single Key Set** (keyring-interface.md#ondecrypt)
   > "SHOULD set one resulting plaintext data key" after successful retrieval

   Implementation: Stop iteration after first successful decryption.

### MAY Requirements

No explicit MAY requirements. All requirements are MUST or SHOULD.

## Data Structures

### Key Provider Information Format

Per raw-aes-keyring.md#key-provider-information, the provider info is serialized as:

```
<<key_name_length::16-big, key_name::binary,
  auth_tag_length_bits::32-big,
  iv_length::32-big,
  iv::binary>>
```

| Field | Size | Value |
|-------|------|-------|
| Key Name Length | 2 bytes | Variable |
| Key Name | Variable | UTF-8 string |
| Auth Tag Length | 4 bytes | 128 (bits) |
| IV Length | 4 bytes | 12 (bytes) |
| IV | 12 bytes | Random |

### Ciphertext Field Format

The EDK's `ciphertext` field contains:
```
ciphertext = encrypted_data_key || authentication_tag
```

Where:
- `encrypted_data_key` = same length as plaintext data key
- `authentication_tag` = 16 bytes (128 bits)

## Test Vectors

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Load manifest
{:ok, harness} = TestVectorHarness.load_manifest(
  "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
)

# Get key material
{:ok, key_data} = TestVectorHarness.get_key(harness, "aes-256")
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)
```

### Key Material Available

From `keys.json`:
- `aes-128`: 128-bit key (`AAECAwQFBgcICRAREhMUFQ==`)
- `aes-192`: 192-bit key (`AAECAwQFBgcICRAREhMUFRYXGBkgISIj`)
- `aes-256`: 256-bit key (`AAECAwQFBgcICRAREhMUFRYXGBkgISIjJCUmJygpMDE=`)

Provider ID used in test vectors: `aws-raw-vectors-persistant`

### Implementation Order

#### Phase 1: Basic AES-256 (Start Here)

| Test ID | Algorithm | Key Type | Plaintext | Priority |
|---------|-----------|----------|-----------|----------|
| `83928d8e-9f97-4861-8f70-ab1eaa6930ea` | Various | aes-256 | small | First test |
| `917a3a40-3b92-48f7-9cbe-231c9bde6222` | Various | aes-256 | small | Verify consistency |
| `0d159b30-e85d-4d76-8fe5-2fb98936d772` | Various | aes-256 | small | Additional coverage |

#### Phase 2: Different Key Sizes

| Test ID | Key Type | Notes |
|---------|----------|-------|
| `4be2393c-2916-4668-ae7a-d26ddb8de593` | aes-128 | 128-bit key support |
| `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` | aes-192 | 192-bit key support |

#### Phase 3: Algorithm Suite Coverage

- Suite 0x0478: AES-256-GCM-HKDF-SHA512-COMMIT-KEY (committed, no signing)
- Suite 0x0578: AES-256-GCM-HKDF-SHA512-COMMIT-KEY-ECDSA-P384 (committed + ECDSA)
- Suite 0x0178: AES-256-GCM-IV12-TAG16-HKDF-SHA256 (legacy, no commitment)

#### Phase 4: Edge Cases

- Empty encryption context
- Large plaintexts (multi-frame)
- Tiny plaintexts (~11 bytes)

### Test Vector Setup

If test vectors are not present, run:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

## Implementation Considerations

### Technical Approach

1. **Module Structure**:
   ```elixir
   defmodule AwsEncryptionSdk.Keyring.RawAes do
     @behaviour AwsEncryptionSdk.Keyring.Behaviour

     defstruct [:key_namespace, :key_name, :wrapping_key, :wrapping_algorithm]

     def new(key_namespace, key_name, wrapping_key, opts \\ [])
     def on_encrypt(materials)
     def on_decrypt(materials, encrypted_data_keys)
   end
   ```

2. **Wrapping Algorithm Configuration**:
   ```elixir
   @wrapping_algorithms %{
     aes_128_gcm: %{cipher: :aes_128_gcm, key_bits: 128, iv_length: 12, tag_length: 16},
     aes_192_gcm: %{cipher: :aes_192_gcm, key_bits: 192, iv_length: 12, tag_length: 16},
     aes_256_gcm: %{cipher: :aes_256_gcm, key_bits: 256, iv_length: 12, tag_length: 16}
   }
   ```

3. **Cipher Selection Helper**:
   ```elixir
   defp cipher_for_key_bits(128), do: :aes_128_gcm
   defp cipher_for_key_bits(192), do: :aes_192_gcm
   defp cipher_for_key_bits(256), do: :aes_256_gcm
   ```

### Potential Challenges

1. **Provider Info Parsing**: The key provider info format is specific to Raw AES keyrings. Must parse length-prefixed fields correctly with big-endian integers.

2. **Ciphertext Splitting**: The ciphertext field contains both encrypted data and auth tag concatenated. Must split correctly (tag is always last 16 bytes).

3. **Error Handling**: Must distinguish between "wrong keyring" (skip EDK) vs "decryption failed" (authentication error) scenarios.

4. **Test Vector Provider ID**: Test vectors use `aws-raw-vectors-persistant` (note: "persistant" spelling) as provider ID.

### Open Questions

None identified. The specification is comprehensive and clear.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-25-GH26-raw-aes-keyring.md`
2. Implement `RawAes` struct with `new/4` constructor and validation
3. Implement provider info serialization/deserialization helpers
4. Implement `on_encrypt/1` callback
5. Implement `on_decrypt/2` callback
6. Add unit tests for encrypt/decrypt round-trip
7. Add test vector tests starting with basic AES-256

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/26
- Raw AES Keyring Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-aes-keyring.md
- Keyring Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
