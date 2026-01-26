# Research: Implement Raw RSA Keyring

**Issue**: #27 - Implement Raw RSA Keyring
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Implement the Raw RSA Keyring per the AWS Encryption SDK specification. This keyring uses locally-provided RSA key pairs to wrap and unwrap data keys using asymmetric encryption with configurable padding schemes (OAEP-SHA1/256/384/512 and PKCS1 v1.5).

## Current Implementation State

### Existing Code

- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour interface with `on_encrypt/2` and `on_decrypt/2` callbacks
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring implementation (primary reference pattern)
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EDK struct definition
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - Encryption materials struct
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - Decryption materials struct

### Relevant Patterns from Raw AES Keyring

1. **Struct Definition** (raw_aes.ex:34-42):
   - All fields are enforced at struct creation
   - `key_namespace` serves as `key_provider_id` in EDKs
   - Algorithm configuration stored in module attribute map

2. **Constructor Pattern** (raw_aes.ex:83-98):
   - Uses `with` chain for validation
   - Validates provider ID, algorithm, key parameters
   - Returns `{:ok, struct}` or `{:error, reason}`

3. **Provider Info Format** (raw_aes.ex:118-127):
   - Key name has NO length prefix in serialization
   - Deserialization requires knowing expected key name length from keyring

4. **Wrap/Unwrap Pattern**:
   - `wrap_key/2` - Ensures data key exists, encrypts, creates EDK
   - `unwrap_key/3` - Iterates EDKs with `reduce_while`, decrypts first match

5. **Behaviour Callbacks** (raw_aes.ex:328-338):
   - Implemented but return helpful error directing to explicit functions
   - Keyring needs its struct instance to access keys

### Dependencies

- Requires: Keyring behaviour (#25) - ✅ Complete
- Blocks: Multi-Keyring (#28) - needs this for composition

## Specification Requirements

### Source Documents
- [raw-rsa-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md)
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md)
- [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md)

### MUST Requirements

#### Initialization

1. **Required Configuration Parameters** (raw-rsa-keyring.md#initialization)
   > The raw RSA keyring MUST provide a key namespace, key name, padding scheme, and at least one of public key or private key.

   Implementation: Constructor accepts `key_namespace`, `key_name`, `padding_scheme`, and optionally `public_key` and/or `private_key`. At least one key required.

2. **Padding Scheme Restriction** (raw-rsa-keyring.md#initialization)
   > This keyring MUST NOT use a padding scheme outside those defined above.

   Supported schemes only:
   - PKCS1 v1.5 Padding
   - OAEP with SHA-1 and MGF1 with SHA-1 Padding
   - OAEP with SHA-256 and MGF1 with SHA-256 Padding
   - OAEP with SHA-384 and MGF1 with SHA-384 Padding
   - OAEP with SHA-512 and MGF1 with SHA-512 Padding

3. **MGF1 Hash Function Matching** (raw-rsa-keyring.md#initialization)
   > If the padding scheme uses MGF1 Padding, the hash function used as part of MGF1 MUST be the same hash function used to hash the plaintext data key.

   Implementation: For OAEP modes, MGF1 hash matches the OAEP hash (e.g., OAEP-SHA256 uses MGF1-SHA256).

4. **Public Key Format** (raw-rsa-keyring.md#initialization)
   > The public key MUST follow the RSA specification for public keys.

5. **Private Key Format** (raw-rsa-keyring.md#initialization)
   > The private key MUST follow the RSA specification for private keys.

6. **AWS KMS Namespace Prohibition** (raw-rsa-keyring.md#security-considerations)
   > The raw RSA keyring MUST NOT accept a key namespace of 'aws-kms'.

   Implementation: Reject `key_namespace` starting with "aws-kms" during initialization (use `KeyringBehaviour.validate_provider_id/1`).

#### OnEncrypt Operation

7. **Public Key Requirement** (raw-rsa-keyring.md#on-encrypt)
   > OnEncrypt MUST fail if this keyring does not have a specified public key.

8. **No Public Key Derivation** (raw-rsa-keyring.md#on-encrypt)
   > The keyring MUST NOT derive a public key from a specified private key.

9. **Data Key Generation** (raw-rsa-keyring.md#on-encrypt)
   > If the encryption materials do not contain a plaintext data key, OnEncrypt MUST generate a random plaintext data key.

   Implementation: Use `KeyringBehaviour.generate_data_key/1` if `materials.plaintext_data_key` is nil.

10. **Encrypted Data Key Creation** (raw-rsa-keyring.md#on-encrypt)
    > The keyring MUST encrypt the plaintext data key using RSA with the configured padding scheme, then add the resulting encrypted data key to the encryption materials.

    EDK fields:
    - `key_provider_id` = keyring's `key_namespace`
    - `key_provider_info` = keyring's `key_name`
    - `ciphertext` = RSA-encrypted data key

11. **Output Modified Materials** (keyring-interface.md#on-encrypt)
    > If this keyring attempted any of the above behaviors, and successfully completed those behaviors, it MUST output the modified encryption materials.

#### OnDecrypt Operation

12. **Private Key Requirement** (raw-rsa-keyring.md#on-decrypt)
    > OnDecrypt MUST fail if this keyring does not have a specified private key.

13. **Reject Pre-existing Data Key** (raw-rsa-keyring.md#on-decrypt)
    > If the decryption materials already contain a plaintext data key, the keyring MUST fail.

14. **Sequential Decryption Attempts** (raw-rsa-keyring.md#on-decrypt)
    > The keyring MUST attempt to decrypt the input encrypted data keys, in list order, until it successfully decrypts one.

15. **Key Namespace/Name Matching** (raw-rsa-keyring.md#on-decrypt)
    > The keyring MUST only attempt to decrypt an encrypted data key if:
    > - The encrypted data key's key provider information has a value equal to this keyring's key name
    > - The encrypted data key's key provider ID has a value equal to this keyring's key namespace

16. **Immediate Success Return** (raw-rsa-keyring.md#on-decrypt)
    > If any decryption succeeds, this keyring MUST immediately return the input decryption materials with the plaintext data key set.

17. **Failure Without Modification** (raw-rsa-keyring.md#on-decrypt)
    > If no decryption succeeds, the keyring MUST fail and MUST NOT modify the decryption materials.

### SHOULD Requirements

1. **PEM Public Key Support** (raw-rsa-keyring.md#initialization)
   > The raw RSA keyring SHOULD support loading PEM encoded X.509 SubjectPublicKeyInfo structures.

2. **PEM Private Key Support** (raw-rsa-keyring.md#initialization)
   > The raw RSA keyring SHOULD support loading PEM encoded PKCS #8 PrivateKeyInfo structures.

3. **CRT Components** (raw-rsa-keyring.md#initialization)
   > The private key SHOULD contain all Chinese Remainder Theorem (CRT) components.

   Note: Erlang's `:public_key` handles this when parsing.

### MAY Requirements

1. **Reversible Transformation** (structures.md#encrypted-data-key)
   > The ciphertext MAY be any reversible operation, not necessarily encryption/decryption.

   For RSA keyring, this is always RSA encryption/decryption.

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

- **awses-decrypt**: Decrypt test vectors for RSA keyring decryption
- **Location**: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- **Manifest version**: 2 (generated by aws-encryption-sdk-python 2.2.0)
- **Keys version**: 3
- **Total RSA test vectors**: ~550 test cases

### RSA Key Material

From `keys.json`:
- `rsa-4096-private`: PEM-encoded private key (4096-bit), can encrypt and decrypt
- `rsa-4096-public`: PEM-encoded public key (4096-bit), can encrypt only
- Provider ID: `aws-raw-vectors-persistant`

### Implementation Order

#### Phase 1: Basic Single-Keyring Decryption (Start Here)

| Test ID | Padding Scheme | Notes | Priority |
|---------|----------------|-------|----------|
| `d20b31a6-200d-4fdb-819d-7ded46c99d10` | PKCS1 v1.5 | Simplest legacy padding | Start here |
| `7c640f28-9fa1-4ff9-9179-196149f8c346` | OAEP-SHA1 | OAEP with SHA-1 | Second |
| `24088ba0-bf47-4d06-bb12-f6ba40956bd6` | OAEP-SHA256 | Recommended modern padding | High priority |
| `0ad7c010-79ad-4710-876b-21c677c97b19` | OAEP-SHA384 | OAEP with SHA-384 | After basics |
| `a2adc73f-6885-4a1c-a2bb-3294d48766b4` | OAEP-SHA512 | OAEP with SHA-512 | After basics |

**Implementation notes**:
- Single RSA private key for decryption
- Single EDK in message
- Tests all 5 supported padding schemes
- Start with PKCS1 (simplest) or OAEP-SHA256 (recommended)

#### Phase 2: Multi-Keyring Tests (After Phase 1)

| Test ID | Private Padding | Notes |
|---------|----------------|-------|
| `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` | PKCS1 | Mixed padding schemes |
| `6b8d3386-9824-46db-8764-8d58d8086f77` | OAEP-SHA256 | Same padding both keys |
| `3f5aad89-f184-4547-ac26-432b97e98bf5` | OAEP-SHA1 | Different OAEP hashes |
| `1aa68ab1-3752-48e8-af6b-cea6650df263` | OAEP-SHA384 | SHA-384 decrypt test |
| `aba06ffc-a839-4639-967c-a739d8626adc` | OAEP-SHA512 | SHA-512 decrypt test |

**Implementation notes**:
- Messages encrypted with multi-keyring (private + public)
- Contains 2 EDKs
- Tests keyring's ability to skip EDKs it can't decrypt

#### Phase 3: Encryption Test Coverage

After decryption works, test encryption:
- Generate data key
- Encrypt with RSA public key
- Verify EDK format matches test vectors
- Round-trip: encrypt then decrypt

### Test Vector Setup

If test vectors are not present, run:

```elixir
TestVectorSetup.ensure_test_vectors()
```

Or manually:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Key Material Access

```elixir
# Get key metadata
{:ok, key_data} = TestVectorHarness.get_key(harness, "rsa-4096-private")

# key_data contains:
# %{
#   "encrypt" => true,
#   "decrypt" => true,
#   "algorithm" => "rsa",
#   "type" => "private",
#   "bits" => 4096,
#   "encoding" => "pem",
#   "material" => "-----BEGIN PRIVATE KEY-----\n..."
# }

# Decode PEM to Erlang key format
{:ok, pem_material} = TestVectorHarness.decode_key_material(key_data)
[{:PrivateKeyInfo, der, _}] = :public_key.pem_decode(pem_material)
private_key = :public_key.der_decode(:PrivateKeyInfo, der)
```

## Implementation Considerations

### Technical Approach

#### Struct Definition

```elixir
defmodule AwsEncryptionSdk.Keyring.RawRsa do
  @type padding_scheme ::
    :pkcs1_v1_5
    | {:oaep, :sha1}
    | {:oaep, :sha256}
    | {:oaep, :sha384}
    | {:oaep, :sha512}

  @type t :: %__MODULE__{
    key_namespace: String.t(),
    key_name: String.t(),
    padding_scheme: padding_scheme(),
    public_key: :public_key.rsa_public_key() | nil,
    private_key: :public_key.rsa_private_key() | nil
  }

  @enforce_keys [:key_namespace, :key_name, :padding_scheme]
  defstruct [:key_namespace, :key_name, :padding_scheme, :public_key, :private_key]
end
```

#### Padding Scheme Mapping to Erlang

```elixir
@padding_schemes %{
  pkcs1_v1_5: [:rsa_pkcs1_padding],
  {:oaep, :sha1}: [
    {:rsa_padding, :rsa_pkcs1_oaep_padding},
    {:rsa_oaep_md, :sha},
    {:rsa_mgf1_md, :sha}
  ],
  {:oaep, :sha256}: [
    {:rsa_padding, :rsa_pkcs1_oaep_padding},
    {:rsa_oaep_md, :sha256},
    {:rsa_mgf1_md, :sha256}
  ],
  {:oaep, :sha384}: [
    {:rsa_padding, :rsa_pkcs1_oaep_padding},
    {:rsa_oaep_md, :sha384},
    {:rsa_mgf1_md, :sha384}
  ],
  {:oaep, :sha512}: [
    {:rsa_padding, :rsa_pkcs1_oaep_padding},
    {:rsa_oaep_md, :sha512},
    {:rsa_mgf1_md, :sha512}
  ]
}
```

#### RSA Encryption/Decryption

```elixir
# Encrypt with public key
ciphertext = :public_key.encrypt_public(plaintext, public_key, padding_opts)

# Decrypt with private key
case :public_key.decrypt_private(ciphertext, private_key, padding_opts) do
  {:error, _} -> {:error, :decryption_failed}
  plaintext when is_binary(plaintext) -> {:ok, plaintext}
end
```

#### PEM Key Loading

```elixir
# Load public key from PEM
def load_public_key_pem(pem_string) do
  case :public_key.pem_decode(pem_string) do
    [{:SubjectPublicKeyInfo, der, _}] ->
      {:ok, :public_key.der_decode(:SubjectPublicKeyInfo, der)}
    [{:RSAPublicKey, der, _}] ->
      {:ok, :public_key.der_decode(:RSAPublicKey, der)}
    _ ->
      {:error, :invalid_pem_format}
  end
end

# Load private key from PEM
def load_private_key_pem(pem_string) do
  case :public_key.pem_decode(pem_string) do
    [{:PrivateKeyInfo, der, _}] ->
      {:ok, :public_key.der_decode(:PrivateKeyInfo, der)}
    [{:RSAPrivateKey, der, _}] ->
      {:ok, :public_key.der_decode(:RSAPrivateKey, der)}
    _ ->
      {:error, :invalid_pem_format}
  end
end
```

### Provider Info Format

Unlike Raw AES (which has structured provider info with IV, tag length), RSA provider info is simply the key name:

```elixir
# EDK fields for RSA:
# key_provider_id = keyring.key_namespace
# key_provider_info = keyring.key_name  (raw bytes, no additional structure)
# ciphertext = RSA-encrypted data key
```

### Potential Challenges

1. **PEM Format Variations**: Different PEM types (SubjectPublicKeyInfo vs RSAPublicKey, PrivateKeyInfo vs RSAPrivateKey)
2. **Padding Options**: Erlang `:public_key` uses `:sha` instead of `:sha1` for SHA-1
3. **Key Validation**: RSA keys don't have built-in length validation like AES
4. **Error Handling**: RSA decryption errors are not as specific as AES-GCM

### Open Questions

1. **Key Size Validation**: Should we enforce minimum 2048-bit RSA keys? (Spec doesn't mandate, but industry standard)
2. **Error Granularity**: What level of detail for error messages? (e.g., "decryption failed" vs specific padding error)

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-25-GH27-raw-rsa-keyring.md`
2. Implement basic struct and constructor with validation
3. Implement `wrap_key/2` with RSA encryption
4. Implement `unwrap_key/3` with RSA decryption
5. Add unit tests for all padding schemes
6. Add test vector tests starting with Phase 1 vectors

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/27
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/raw-rsa-keyring.md
- Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- Erlang :public_key docs: https://www.erlang.org/doc/apps/public_key/public_key.html
