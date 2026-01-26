# Research: Implement Multi-Keyring

**Issue**: #28 - Implement Multi-Keyring
**Date**: 2026-01-26
**Status**: Research complete

## Issue Summary

Implement the Multi-Keyring per the AWS Encryption SDK specification. The Multi-Keyring composes multiple keyrings together, enabling encryption with multiple keys and flexible decryption with any available key.

**Use Cases**:
- **Redundancy**: Encrypt with multiple keys so any one can decrypt
- **Key rotation**: Include both old and new keys during transitions
- **Multi-party access**: Different parties can decrypt with their respective keys

## Current Implementation State

### Existing Code

| File | Description |
|------|-------------|
| `lib/aws_encryption_sdk/keyring/behaviour.ex` | Keyring behaviour with `on_encrypt/1` and `on_decrypt/2` callbacks |
| `lib/aws_encryption_sdk/keyring/raw_aes.ex` | Raw AES keyring implementation (pattern to follow) |
| `lib/aws_encryption_sdk/keyring/raw_rsa.ex` | Raw RSA keyring implementation (pattern to follow) |
| `lib/aws_encryption_sdk/materials/encryption_materials.ex` | EncryptionMaterials struct with EDK list |
| `lib/aws_encryption_sdk/materials/decryption_materials.ex` | DecryptionMaterials struct |
| `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` | EncryptedDataKey (EDK) struct |

### Keyring Behaviour Callbacks

From `lib/aws_encryption_sdk/keyring/behaviour.ex:66-93`:

```elixir
@callback on_encrypt(materials :: EncryptionMaterials.t()) ::
            {:ok, EncryptionMaterials.t()} | {:error, term()}

@callback on_decrypt(
            materials :: DecryptionMaterials.t(),
            encrypted_data_keys :: [EncryptedDataKey.t()]
          ) :: {:ok, DecryptionMaterials.t()} | {:error, term()}
```

### Relevant Patterns from Existing Keyrings

**Data Key Generation** (`behaviour.ex:135-139`):
```elixir
def generate_data_key(algorithm_suite) do
  :crypto.strong_rand_bytes(div(algorithm_suite.data_key_length, 8))
end
```

**Encryption Materials Modification**:
- `EncryptionMaterials.set_plaintext_data_key/2` - Sets the plaintext data key
- `EncryptionMaterials.add_encrypted_data_key/2` - Appends EDK to list

**Decryption Materials Modification**:
- `DecryptionMaterials.set_plaintext_data_key/2` - Sets key, returns `{:error, :plaintext_data_key_already_set}` if already present

**Decryption Pattern** (from `raw_aes.ex` and `raw_rsa.ex`):
- Use `Enum.reduce_while/3` to iterate through EDKs
- Halt on first successful decrypt
- Continue with `:no_match` accumulator on failure

### File to Create

- `lib/aws_encryption_sdk/keyring/multi.ex` - **Does not exist yet**
- `test/aws_encryption_sdk/keyring/multi_test.exs` - Unit tests
- `test/aws_encryption_sdk/keyring/multi_test_vectors_test.exs` - Test vector integration tests

## Specification Requirements

### Source Documents
- [multi-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md) - Multi-keyring behavior
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Base keyring contract

### MUST Requirements

#### Initialization

1. **At least one keyring source** (multi-keyring.md#inputs)
   > "A keyring MUST define at least one of the following: Generator Keyring or Child Keyrings"

   Implementation: Constructor must accept either `generator` keyring, `children` list, or both.

2. **Generator required if no children** (multi-keyring.md#inputs)
   > "If the list of child keyrings is empty, a generator keyring MUST be defined for the keyring."

   Implementation: When `children` is empty, `generator` cannot be nil.

#### OnEncrypt Behavior

3. **Fail on pre-existing plaintext data key (with generator)** (multi-keyring.md#onencrypt)
   > "This keyring MUST fail if the input encryption materials already contain a plaintext data key."

   Implementation: Before calling generator's `on_encrypt`, check if materials already have `plaintext_data_key` set.

4. **Call generator first** (multi-keyring.md#onencrypt)
   > "This keyring MUST first call the generator keyring's OnEncrypt using the input encryption materials as input."

5. **Fail if generator fails** (multi-keyring.md#onencrypt)
   > "If the generator keyring's OnEncrypt fails, this OnEncrypt MUST also fail."

6. **Fail if generator returns no plaintext data key** (multi-keyring.md#onencrypt)
   > "This keyring MUST fail if the generator keyring's OnEncrypt returns encryption materials that do not contain a plaintext data key."

7. **Fail if no generator and no plaintext data key** (multi-keyring.md#onencrypt)
   > "If a generator keyring is not provided and the input encryption materials do not contain a plaintext data key, OnEncrypt MUST fail."

8. **Call OnEncrypt on each child** (multi-keyring.md#onencrypt)
   > "For each keyring in this keyring's list of child keyrings, the keyring MUST call OnEncrypt."

9. **Chain child keyring outputs** (multi-keyring.md#onencrypt)
   > "For each keyring in the child keyrings list, OnEncrypt MUST be called with the encryption materials returned by the previous OnEncrypt call."

10. **Fail if any child fails** (multi-keyring.md#onencrypt)
    > "If the child keyring's OnEncrypt fails, this OnEncrypt MUST also fail."

11. **Return final materials** (multi-keyring.md#onencrypt)
    > "The encryption materials returned by the final OnEncrypt call in the multi-keyring MUST be returned."

#### OnDecrypt Behavior

12. **Fail if plaintext data key already exists** (multi-keyring.md#ondecrypt)
    > "If the decryption materials already contain a plaintext data key, the keyring MUST fail and MUST NOT modify the decryption materials."

13. **Try generator first, then children** (multi-keyring.md#ondecrypt)
    > "If the generator keyring is defined, this keyring MUST first attempt to decrypt using the generator keyring. If the generator keyring fails to decrypt, the multi-keyring MUST attempt to decrypt using its child keyrings."

14. **Call OnDecrypt with unmodified materials** (multi-keyring.md#ondecrypt)
    > "For each keyring to be used for decryption, the multi-keyring MUST call that keyring's OnDecrypt using the unmodified decryption materials."

    Note: Unlike encrypt, don't chain outputs. Each keyring gets the original materials.

15. **Return immediately on success** (multi-keyring.md#ondecrypt)
    > "If the child keyring's OnDecrypt call succeeds, the multi-keyring MUST immediately return the decryption materials."

16. **Collect errors and continue** (multi-keyring.md#ondecrypt)
    > "If the child keyring's OnDecrypt call fails, the multi-keyring MUST collect the error and continue to the next keyring."

17. **Fail with collected errors if all fail** (multi-keyring.md#ondecrypt)
    > "If, after calling OnDecrypt on every child keyring (and possibly the generator keyring), the decryption materials still do not contain a plaintext data key, OnDecrypt MUST return a failure message containing the collected failure messages."

### SHOULD Requirements

1. **Users should understand decryption capabilities** (multi-keyring.md#security-considerations)
   > "Users SHOULD examine the keyrings they include in a multi-keyring to ensure that they understand what set of keyrings will be capable of obtaining the plaintext data key from the returned set of encrypted data keys."

   Implementation: Document in module documentation.

### MAY Requirements

No explicit MAY requirements in the multi-keyring specification.

## Test Vectors

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
manifest_path = "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets

**awses-decrypt**: Decrypt test vectors containing multi-keyring scenarios (messages encrypted with multiple keyrings)
- Manifest version: 3
- Multi-keyring tests: Identified by having multiple `master-keys` entries

### Implementation Order

#### Phase 1: Basic Multi-RSA Decryption (Start Here)

These test vectors use Raw RSA keyrings with different padding schemes. The existing Raw RSA keyring implementation can be used directly.

| Test ID | Keys | Padding Schemes | Priority |
|---------|------|-----------------|----------|
| `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` | 2 RSA keys | PKCS1 + OAEP-SHA256 | **1st - Start Here** |
| `6b8d3386-9824-46db-8764-8d58d8086f77` | 2 RSA keys | OAEP-SHA256 (2x) | 2nd |
| `afb2ba6d-e8b7-4c74-99ff-f7925485a868` | 2 RSA keys | PKCS1 + OAEP-SHA256 | 3rd |
| `bca8fe01-878d-4705-9ee4-8ea9faf6328b` | 2 RSA keys | OAEP-SHA1 + OAEP-SHA256 | 4th |
| `1aa68ab1-3752-48e8-af6b-cea6650df263` | 2 RSA keys | OAEP-SHA384 + OAEP-SHA256 | 5th |
| `aba06ffc-a839-4639-967c-a739d8626adc` | 2 RSA keys | OAEP-SHA512 + OAEP-SHA256 | 6th |
| `e05108d7-cde8-42ae-8901-ee7d39af0eae` | 2 RSA keys | OAEP-SHA256 (2x) | 7th |

**Key Material**:
- `rsa-4096-private` - RSA private key for decryption
- `rsa-4096-public` - RSA public key (encrypt-only)

#### Phase 2: AWS KMS Multi-Keyring (Future - Requires AWS Credentials)

| Test ID | Keys | Description |
|---------|------|-------------|
| `008a5704-9930-4340-809d-1c27ff7b4868` | 2 KMS keys | Decryptable + encrypt-only |
| `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | 2 KMS keys | KMS multi-region |
| `4de0e71e-08ef-4a80-af61-8268f10021ab` | 2 KMS keys | KMS multi-region |
| `36c24e3e-c670-4eed-b83c-891c2480236a` | 2 KMS keys | KMS multi-region |

### Test Vector Structure

Example for test `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e`:

```json
{
  "ciphertext": "file://ciphertexts/8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e",
  "master-keys": [
    {
      "type": "raw",
      "key": "rsa-4096-private",
      "provider-id": "aws-raw-vectors-persistant",
      "encryption-algorithm": "rsa",
      "padding-algorithm": "pkcs1"
    },
    {
      "type": "raw",
      "key": "rsa-4096-public",
      "provider-id": "aws-raw-vectors-persistant",
      "encryption-algorithm": "rsa",
      "padding-algorithm": "oaep-mgf1",
      "padding-hash": "sha256"
    }
  ],
  "result": {
    "output": {
      "plaintext": "file://plaintexts/small"
    }
  }
}
```

### Test Vector Setup

If test vectors are not present, run:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Get key metadata
{:ok, key_data} = TestVectorHarness.get_key(harness, "rsa-4096-private")

# Decode key material
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)
```

### Important Finding: No Pure AES Multi-Keyring Vectors

The manifest does **not** contain test vectors with multiple Raw AES keyrings. All multi-key vectors use either:
- Multiple AWS KMS keys
- Multiple Raw RSA keys with different padding schemes

This means unit tests will be needed for AES multi-keyring scenarios.

## Implementation Considerations

### Technical Approach

#### Module Structure

```elixir
defmodule AwsEncryptionSdk.Keyring.Multi do
  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  defstruct [:generator, :children]

  @type t :: %__MODULE__{
    generator: keyring() | nil,
    children: [keyring()]
  }
end
```

#### Constructor

```elixir
@spec new(keyword()) :: {:ok, t()} | {:error, String.t()}
def new(opts) do
  generator = Keyword.get(opts, :generator)
  children = Keyword.get(opts, :children, [])

  cond do
    is_nil(generator) and children == [] ->
      {:error, :no_keyrings_provided}

    true ->
      {:ok, %__MODULE__{generator: generator, children: children}}
  end
end
```

#### OnEncrypt Implementation

```elixir
@impl true
def on_encrypt(%__MODULE__{generator: gen, children: children}, materials) do
  with {:ok, materials} <- maybe_generate(gen, materials),
       {:ok, materials} <- validate_has_plaintext_key(gen, materials),
       {:ok, materials} <- encrypt_with_children(children, materials) do
    {:ok, materials}
  end
end
```

**Key Behaviors**:
- Generator is called first (if present) to generate and wrap the data key
- Each child receives the output of the previous keyring (chained)
- All keyrings must succeed (fail-fast on any error)
- EDKs accumulate through the pipeline

#### OnDecrypt Implementation

```elixir
@impl true
def on_decrypt(%__MODULE__{generator: gen, children: children}, materials, edks) do
  if materials.plaintext_data_key != nil do
    {:error, :plaintext_data_key_already_set}
  else
    keyrings = if gen, do: [gen | children], else: children
    attempt_decryption(keyrings, materials, edks, [])
  end
end
```

**Key Behaviors**:
- Each keyring receives the **unmodified** original materials (not chained)
- First successful decryption returns immediately
- Errors are collected and iteration continues
- Final error includes all collected failure messages

### Potential Challenges

1. **Callback Signature Mismatch**: The Keyring behaviour uses `on_encrypt/1` and `on_decrypt/2`, but Raw AES/RSA use `wrap_key/2` and `unwrap_key/3` with keyring instance. Multi-keyring needs to call child keyrings via their `wrap_key`/`unwrap_key` functions since the behaviour callbacks don't receive the keyring instance.

2. **Error Accumulation**: Need to preserve meaningful error messages from all failed keyrings without losing context.

3. **Type Safety**: Ensuring all keyrings in the multi-keyring implement the correct interface.

### Open Questions

1. **Keyring Invocation Pattern**: Should Multi-Keyring call `wrap_key/unwrap_key` directly on child keyrings (like the existing tests do), or use the behaviour callbacks? The existing Raw AES and Raw RSA implementations return errors from their behaviour callbacks directing users to call `wrap_key/unwrap_key` directly.

   **Recommendation**: Use `wrap_key/unwrap_key` pattern to match existing implementation style.

2. **Error Message Format**: What structure should collected errors have? String with joined messages or structured data?

   **Recommendation**: Use `{:error, {:all_keyrings_failed, [reason1, reason2, ...]}}` for structured errors.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-26-GH28-multi-keyring.md`
2. Implement `Multi.new/1` constructor with validation
3. Implement `wrap_key/2` for encryption flow
4. Implement `unwrap_key/3` for decryption flow
5. Unit tests for edge cases (generator-only, children-only, all fail, etc.)
6. Test vector tests starting with `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e`

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/28
- Multi-Keyring Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md
- Keyring Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
