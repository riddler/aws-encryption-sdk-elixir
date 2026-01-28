# Research: Implement AWS KMS Keyring

**Issue**: #48 - Implement AWS KMS Keyring
**Date**: 2026-01-27
**Status**: Research complete

## Issue Summary

Implement the basic AWS KMS Keyring that encrypts and decrypts data keys using a single configured AWS KMS key. This keyring uses AWS KMS to generate and encrypt data keys during encryption, and to decrypt data keys during decryption. It is the core keyring for production use cases.

## Current Implementation State

### Existing Code

**Keyring Infrastructure:**
- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour with `on_encrypt/1` and `on_decrypt/2` callbacks
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring implementation (reference pattern)
- `lib/aws_encryption_sdk/keyring/raw_rsa.ex` - Raw RSA keyring implementation (reference pattern)
- `lib/aws_encryption_sdk/keyring/multi.ex` - Multi-keyring composition with dispatch

**KMS Client Abstraction (Issue #46 - COMPLETED):**
- `lib/aws_encryption_sdk/keyring/kms_client.ex` - KMS client behaviour definition
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` - Production ExAws implementation
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Mock implementation for testing

**KMS Key ARN Utilities (Issue #47 - IN PROGRESS, staged):**
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` - ARN parsing, MRK detection, MRK matching

**Materials Structs:**
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - Encryption materials struct
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - Decryption materials struct
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EDK struct

**CMM Integration:**
- `lib/aws_encryption_sdk/cmm/default.ex` - Default CMM (needs dispatch clauses for AwsKms)

**Algorithm Suites:**
- `lib/aws_encryption_sdk/algorithm_suite.ex` - All 17 algorithm suites with `kdf_input_length`

### Relevant Patterns

**1. Keyring Implementation Pattern (from Raw AES/RSA):**
```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKms do
  @moduledoc """..."""

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  @type t :: %__MODULE__{...}
  defstruct [:kms_key_id, :kms_client, :grant_tokens]

  @spec new(String.t(), module(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_key_id, kms_client, opts \\ [])

  @spec wrap_key(t(), EncryptionMaterials.t()) :: {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(keyring, materials)

  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) :: {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(keyring, materials, encrypted_data_keys)
end
```

**2. EDK Creation Pattern (from Raw AES at line 213):**
```elixir
edk = EncryptedDataKey.new(
  "aws-kms",                    # key_provider_id (always "aws-kms")
  response.key_id,              # key_provider_info (ARN from KMS response)
  response.ciphertext_blob      # ciphertext
)
```

**3. EDK Filtering Pattern (from Raw AES lines 274-290):**
```elixir
defp try_decrypt_edk(edk, keyring, materials) do
  with :ok <- match_provider_id(edk, keyring),
       :ok <- validate_provider_info(edk),
       :ok <- match_key_identifier(edk, keyring),
       {:ok, plaintext} <- decrypt_with_kms(edk, keyring, materials) do
    {:ok, plaintext}
  end
end
```

**4. Decryption Loop Pattern (from Raw AES lines 258-272):**
```elixir
def unwrap_key(keyring, materials, edks) do
  if has_plaintext_data_key?(materials) do
    {:error, :plaintext_data_key_already_set}
  else
    try_decrypt_edks(edks, keyring, materials, [])
  end
end

defp try_decrypt_edks([], _keyring, _materials, errors) do
  {:error, {:unable_to_decrypt_any_data_key, Enum.reverse(errors)}}
end

defp try_decrypt_edks([edk | rest], keyring, materials, errors) do
  case try_decrypt_edk(edk, keyring, materials) do
    {:ok, plaintext} ->
      {:ok, DecryptionMaterials.set_plaintext_data_key(materials, plaintext)}
    {:error, reason} ->
      try_decrypt_edks(rest, keyring, materials, [reason | errors])
  end
end
```

**5. KMS Client Usage (from kms_client.ex):**
```elixir
# GenerateDataKey
KmsClient.generate_data_key(
  client,
  key_id,
  algorithm_suite.kdf_input_length,  # NumberOfBytes
  materials.encryption_context,
  keyring.grant_tokens || []
)

# Encrypt
KmsClient.encrypt(
  client,
  key_id,
  materials.plaintext_data_key,
  materials.encryption_context,
  keyring.grant_tokens || []
)

# Decrypt
KmsClient.decrypt(
  client,
  key_id,
  edk.ciphertext,
  materials.encryption_context,
  keyring.grant_tokens || []
)
```

**6. Default CMM Dispatch (from default.ex lines 72-88):**
```elixir
defp call_wrap_key(%RawAes{} = keyring, materials), do: RawAes.wrap_key(keyring, materials)
defp call_wrap_key(%RawRsa{} = keyring, materials), do: RawRsa.wrap_key(keyring, materials)
defp call_wrap_key(%Multi{} = keyring, materials), do: Multi.wrap_key(keyring, materials)
# Need to add:
defp call_wrap_key(%AwsKms{} = keyring, materials), do: AwsKms.wrap_key(keyring, materials)
```

### Dependencies

**Required (COMPLETED):**
- Issue #46: KMS Client Abstraction Layer - ✅ Merged (fc70176)

**Required (IN PROGRESS):**
- Issue #47: KMS Key ARN Utilities - Staged on current branch, not committed

**Blocked by This:**
- AWS KMS Discovery Keyring
- AWS KMS MRK-aware Keyrings
- Full test vector support for KMS

## Specification Requirements

### Source Documents

- [aws-kms-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md) - Main KMS keyring specification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - General keyring interface
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN validation requirements

### MUST Requirements

#### Initialization

1. **Key Identifier Required** (aws-kms-keyring.md#initialization)
   > The AWS KMS key identifier MUST NOT be null or empty

   Implementation: Validate `kms_key_id != nil && kms_key_id != ""`

2. **Valid Key Identifier** (aws-kms-keyring.md#initialization)
   > The AWS KMS key identifier MUST be a valid identifier

   Implementation: Accept ARN, alias ARN, alias name, or key ID

3. **Client Required** (aws-kms-keyring.md#initialization)
   > The AWS KMS SDK client MUST NOT be null

   Implementation: Validate `kms_client != nil`

#### OnEncrypt - GenerateDataKey Path

4. **Generate When No Plaintext Key** (aws-kms-keyring.md#onencrypt)
   > If the input encryption materials do not contain a plaintext data key, OnEncrypt MUST attempt to generate a new plaintext data key

   Implementation: Check `materials.plaintext_data_key == nil`, call `KmsClient.generate_data_key/5`

5. **KeyId Parameter** (aws-kms-keyring.md#onencrypt)
   > The keyring MUST call AWS KMS GenerateDataKey with a request constructed as follows: KeyId MUST be the configured AWS KMS key identifier

   Implementation: `key_id: keyring.kms_key_id`

6. **NumberOfBytes Parameter** (aws-kms-keyring.md#onencrypt)
   > NumberOfBytes MUST be the key derivation input length specified by the algorithm suite included in the input encryption materials

   Implementation: `number_of_bytes: materials.algorithm_suite.kdf_input_length`

7. **EncryptionContext Parameter** (aws-kms-keyring.md#onencrypt)
   > EncryptionContext MUST be the encryption context included in the input encryption materials

   Implementation: `encryption_context: materials.encryption_context`

8. **GrantTokens Parameter** (aws-kms-keyring.md#onencrypt)
   > GrantTokens MUST be this keyring's grant tokens

   Implementation: `grant_tokens: keyring.grant_tokens || []`

9. **GenerateDataKey Failure** (aws-kms-keyring.md#onencrypt)
   > If the call to AWS KMS GenerateDataKey does not succeed, OnEncrypt MUST NOT modify the encryption materials and MUST fail

   Implementation: Return `{:error, reason}` without modifying materials on KMS error

10. **Response Plaintext Length Validation** (aws-kms-keyring.md#onencrypt)
    > The response's "Plaintext" MUST have a length equal to the key derivation input length specified by the algorithm suite included in the input encryption materials

    Implementation: `byte_size(response.plaintext) == algorithm_suite.kdf_input_length`

11. **Response KeyId Validation** (aws-kms-keyring.md#onencrypt)
    > The response's "KeyId" MUST be a valid AWS KMS ARN

    Implementation: Use `KmsKeyArn.parse/1` to validate ARN format

12. **Set Plaintext Data Key** (aws-kms-keyring.md#onencrypt)
    > OnEncrypt MUST set the plaintext data key on the encryption materials as the response "Plaintext"

    Implementation: `EncryptionMaterials.set_plaintext_data_key(materials, response.plaintext)`

13. **Create and Append EDK** (aws-kms-keyring.md#onencrypt)
    > OnEncrypt MUST append a new encrypted data key to the encrypted data key list in the encryption materials. The encrypted data key MUST be constructed with: key provider id of "aws-kms", key provider info of the response "KeyId", ciphertext of the response "CiphertextBlob"

    Implementation:
    ```elixir
    edk = EncryptedDataKey.new("aws-kms", response.key_id, response.ciphertext_blob)
    EncryptionMaterials.add_encrypted_data_key(materials, edk)
    ```

#### OnEncrypt - Encrypt Path (Existing Plaintext Key)

14. **Encrypt When Plaintext Key Exists** (aws-kms-keyring.md#onencrypt)
    > If the input encryption materials contain a plaintext data key, OnEncrypt MUST attempt to encrypt the plaintext data key using the configured AWS KMS key identifier

    Implementation: Check `materials.plaintext_data_key != nil`, call `KmsClient.encrypt/5`

15. **Encrypt KeyId Parameter** (aws-kms-keyring.md#onencrypt)
    > KeyId MUST be the configured AWS KMS key identifier

    Implementation: `key_id: keyring.kms_key_id`

16. **Encrypt Plaintext Parameter** (aws-kms-keyring.md#onencrypt)
    > Plaintext MUST be the plaintext data key in the encryption materials

    Implementation: `plaintext: materials.plaintext_data_key`

17. **Encrypt Failure** (aws-kms-keyring.md#onencrypt)
    > If the call to AWS KMS Encrypt does not succeed, OnEncrypt MUST fail

    Implementation: Return `{:error, reason}` on KMS error

18. **Encrypt Response KeyId Validation** (aws-kms-keyring.md#onencrypt)
    > The response's "KeyId" MUST be a valid AWS KMS ARN

    Implementation: Use `KmsKeyArn.parse/1` to validate ARN format

19. **Append EDK After Encrypt** (aws-kms-keyring.md#onencrypt)
    > OnEncrypt MUST append a new encrypted data key to the encrypted data key list

    Implementation: Same EDK creation pattern as GenerateDataKey path

#### OnDecrypt

20. **Pre-condition Check** (aws-kms-keyring.md#ondecrypt)
    > If the decryption materials already contain a valid plaintext data key, OnDecrypt MUST return an error

    Implementation: Check `materials.plaintext_data_key != nil`

21. **Filter by Provider ID** (aws-kms-keyring.md#ondecrypt)
    > The set of encrypted data keys MUST first be filtered to match this keyring's configuration. For each encrypted data key: the key provider ID of the encrypted data key MUST be "aws-kms"

    Implementation: `edk.key_provider_id == "aws-kms"`

22. **Provider Info ARN Validation** (aws-kms-keyring.md#ondecrypt)
    > The key provider info MUST be a valid AWS KMS ARN. The AWS KMS ARN resource type MUST be "key"

    Implementation: Parse ARN, validate `arn.resource_type == "key"`

23. **Provider Info Key Matching** (aws-kms-keyring.md#ondecrypt)
    > The key provider info MUST match the configured AWS KMS key identifier

    Implementation: Use `KmsKeyArn.mrk_match?/2` for MRK-aware matching

24. **Decrypt Call** (aws-kms-keyring.md#ondecrypt)
    > For each encrypted data key that passes the filter, one at a time, the OnDecrypt MUST attempt to decrypt the data key

    Implementation: Sequential iteration with early return on success

25. **Decrypt KeyId Parameter** (aws-kms-keyring.md#ondecrypt)
    > KeyId MUST be the configured AWS KMS key identifier

    Implementation: `key_id: keyring.kms_key_id`

26. **Decrypt CiphertextBlob Parameter** (aws-kms-keyring.md#ondecrypt)
    > CiphertextBlob MUST be the encrypted data key ciphertext

    Implementation: `ciphertext_blob: edk.ciphertext`

27. **Decrypt EncryptionContext Parameter** (aws-kms-keyring.md#ondecrypt)
    > EncryptionContext MUST be the encryption context included in the input decryption materials

    Implementation: `encryption_context: materials.encryption_context`

28. **Response KeyId Verification** (aws-kms-keyring.md#ondecrypt)
    > If the call succeeds, OnDecrypt MUST verify that the response "KeyId" corresponds to the configured AWS KMS key identifier

    Implementation: Use `KmsKeyArn.mrk_match?/2` for comparison

29. **Response Plaintext Length Verification** (aws-kms-keyring.md#ondecrypt)
    > The response's "Plaintext" length MUST equal the key derivation input length specified by the algorithm suite included in the input decryption materials

    Implementation: `byte_size(response.plaintext) == algorithm_suite.kdf_input_length`

30. **Set Plaintext Data Key on Success** (aws-kms-keyring.md#ondecrypt)
    > If the above response verification is successful, OnDecrypt MUST set the plaintext data key on the decryption materials

    Implementation: `DecryptionMaterials.set_plaintext_data_key(materials, response.plaintext)`

31. **Return Immediately on Success** (aws-kms-keyring.md#ondecrypt)
    > OnDecrypt MUST immediately return the modified decryption materials

    Implementation: Early return with `{:ok, materials}`

32. **Error Collection** (aws-kms-keyring.md#ondecrypt)
    > If the AWS KMS Decrypt call does not succeed, OnDecrypt MUST NOT fail but MUST continue attempting to decrypt any remaining encrypted data keys

    Implementation: Accumulate errors, continue to next EDK

33. **Final Failure with All Errors** (aws-kms-keyring.md#ondecrypt)
    > If OnDecrypt fails to successfully decrypt any encrypted data key, then it MUST yield an error that includes all the collected errors

    Implementation: `{:error, {:unable_to_decrypt_any_data_key, collected_errors}}`

### MAY Requirements

1. **Grant Tokens** (aws-kms-keyring.md#initialization)
   > MAY provide a list of Grant Tokens

   Implementation: Accept optional `grant_tokens` list

2. **ARN Construction** (aws-kms-key-arn.md)
   > Implementations MAY provide a function to construct ARNs from components

   Implementation: `KmsKeyArn.to_string/1` already implemented

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

- **awses-decrypt**: Decrypt test vectors for validating KMS keyring decryption
- **Location**: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- **Manifest version**: 2
- **Generated by**: aws/aws-encryption-sdk-python v2.2.0

### KMS Keys in Test Vectors

| Key Name | ARN | Is MRK | Can Decrypt |
|----------|-----|--------|-------------|
| `us-west-2-decryptable` | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | No | Yes |
| `us-west-2-encrypt-only` | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | No | No |
| `us-west-2-mrk` | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes | Yes |
| `us-east-1-mrk` | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes | Yes |

### Implementation Order

#### Phase 1: Basic Single-Key Implementation

Start with unit tests using mock KMS client:

| Test Case | Description | Priority |
|-----------|-------------|----------|
| `wrap_key_generates_new_key` | GenerateDataKey path when no plaintext key | Start here |
| `wrap_key_encrypts_existing_key` | Encrypt path when plaintext key exists | Second |
| `unwrap_key_decrypts_matching_edk` | Decrypt with matching EDK | Third |
| `unwrap_key_filters_non_matching` | Filter EDKs by provider ID and key ID | Fourth |

#### Phase 2: Test Vector Validation (with Mock)

Since test vectors require actual KMS keys, use mock responses extracted from message headers:

| Test ID | KMS Key | Purpose |
|---------|---------|---------|
| `686aae13-ec9b-4eab-9dc0-0a1794a2ba34` | `us-west-2-decryptable` | Single KMS key decrypt |
| `7bb5cace-2274-4134-957d-0426c9f96637` | `us-west-2-mrk` | MRK key decrypt |

#### Phase 3: Multi-Key Tests

| Test ID | KMS Keys | Purpose |
|---------|----------|---------|
| `008a5704-9930-4340-809d-1c27ff7b4868` | `us-west-2-decryptable` + `us-west-2-encrypt-only` | Multiple KMS keys |

#### Phase 4: Error Cases

| Test Case | Description |
|-----------|-------------|
| `unwrap_key_fails_with_plaintext_key_already_set` | Pre-condition check |
| `unwrap_key_collects_all_errors` | Error collection |
| `wrap_key_fails_on_kms_error` | KMS error propagation |
| `new_validates_key_id_not_empty` | Initialization validation |
| `new_validates_client_not_nil` | Initialization validation |

### Test Vector Setup

If test vectors are not present:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Testing Strategy

Since real KMS calls require AWS credentials, use the Mock KMS client for unit tests:

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsTest do
  use ExUnit.Case

  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Keyring.KmsClient.Mock
  alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials, EncryptedDataKey}
  alias AwsEncryptionSdk.AlgorithmSuite

  @kms_key_arn "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012"

  setup do
    suite = AlgorithmSuite.by_id!(0x0478)  # AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    plaintext_key = :crypto.strong_rand_bytes(32)
    ciphertext_blob = :crypto.strong_rand_bytes(128)

    # Mock KMS responses
    {:ok, mock_client} = Mock.new(%{
      {:generate_data_key, @kms_key_arn} => %{
        plaintext: plaintext_key,
        ciphertext: ciphertext_blob,
        key_id: @kms_key_arn
      },
      {:encrypt, @kms_key_arn} => %{
        ciphertext: ciphertext_blob,
        key_id: @kms_key_arn
      },
      {:decrypt, @kms_key_arn} => %{
        plaintext: plaintext_key,
        key_id: @kms_key_arn
      }
    })

    {:ok, keyring} = AwsKms.new(@kms_key_arn, mock_client)
    materials = EncryptionMaterials.new_for_encrypt(suite, %{}, [])

    {:ok,
     keyring: keyring,
     mock_client: mock_client,
     materials: materials,
     suite: suite,
     plaintext_key: plaintext_key,
     ciphertext_blob: ciphertext_blob}
  end

  test "wrap_key generates new data key when none exists", ctx do
    {:ok, result} = AwsKms.wrap_key(ctx.keyring, ctx.materials)

    assert result.plaintext_data_key == ctx.plaintext_key
    assert [edk] = result.encrypted_data_keys
    assert edk.key_provider_id == "aws-kms"
    assert edk.key_provider_info == @kms_key_arn
    assert edk.ciphertext == ctx.ciphertext_blob
  end
end
```

## Implementation Considerations

### Technical Approach

#### Module Structure

```
lib/aws_encryption_sdk/keyring/
├── aws_kms.ex           # AWS KMS keyring implementation
├── kms_client.ex        # KMS client behaviour (existing)
├── kms_client/
│   ├── ex_aws.ex        # ExAws implementation (existing)
│   └── mock.ex          # Mock for testing (existing)
└── kms_key_arn.ex       # ARN utilities (staged, issue #47)
```

#### Struct Definition

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKms do
  @moduledoc """
  AWS KMS Keyring implementation.

  Encrypts and decrypts data keys using AWS KMS. This keyring can:
  - Generate new data keys using KMS GenerateDataKey
  - Encrypt existing data keys using KMS Encrypt (for multi-keyring)
  - Decrypt data keys using KMS Decrypt

  ## Specification

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  @type t :: %__MODULE__{
    kms_key_id: String.t(),
    kms_client: struct(),
    grant_tokens: [String.t()]
  }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]
end
```

#### Constructor

```elixir
@spec new(String.t(), struct(), keyword()) :: {:ok, t()} | {:error, term()}
def new(kms_key_id, kms_client, opts \\ []) do
  with :ok <- validate_key_id(kms_key_id),
       :ok <- validate_client(kms_client) do
    {:ok, %__MODULE__{
      kms_key_id: kms_key_id,
      kms_client: kms_client,
      grant_tokens: Keyword.get(opts, :grant_tokens, [])
    }}
  end
end

defp validate_key_id(nil), do: {:error, :key_id_required}
defp validate_key_id(""), do: {:error, :key_id_empty}
defp validate_key_id(key_id) when is_binary(key_id), do: :ok
defp validate_key_id(_), do: {:error, :invalid_key_id_type}

defp validate_client(nil), do: {:error, :client_required}
defp validate_client(%{__struct__: _}), do: :ok
defp validate_client(_), do: {:error, :invalid_client_type}
```

### Potential Challenges

1. **Key Identifier Matching**
   - Configured key ID may be alias, key ID, or ARN
   - Response KeyId is always full ARN
   - Need to compare correctly (exact match or MRK match)

2. **MRK Cross-Region Matching**
   - When configured with MRK, should match EDKs from any region
   - Use `KmsKeyArn.mrk_match?/2` for comparison
   - Handle both full ARNs and raw identifiers

3. **Error Aggregation**
   - Must collect all errors during decrypt attempts
   - Return comprehensive error with all failure reasons
   - Don't short-circuit on first error (continue trying other EDKs)

4. **Multi-Keyring Integration**
   - When used as child in multi-keyring, may receive existing plaintext key
   - Must use Encrypt path instead of GenerateDataKey
   - Materials are chained through children

### Open Questions

1. **Key Identifier Validation Strictness**
   - Should we validate ARN format during initialization?
   - Recommendation: No, let KMS validate - accept any non-empty string

2. **Response KeyId Comparison**
   - Spec says "corresponds to" configured identifier
   - Recommendation: Use MRK-aware matching for flexibility

3. **Grant Token Validation**
   - Should we validate grant token format?
   - Recommendation: No, pass through to KMS

## Recommended Next Steps

1. Complete and commit issue #47 (KMS ARN Utilities) first - it's staged but not committed

2. Create implementation plan:
   ```
   /create_plan thoughts/shared/research/2026-01-27-GH48-aws-kms-keyring.md
   ```

3. Implementation order:
   - Define struct and constructor with validation
   - Implement `wrap_key/2` with both GenerateDataKey and Encrypt paths
   - Implement `unwrap_key/3` with EDK filtering and decryption
   - Add dispatch clauses to Default CMM and Multi-keyring
   - Unit tests with mock KMS client
   - Integration tests (optional, requires AWS credentials)

## References

- Issue: https://github.com/owner/repo/issues/48
- Spec - AWS KMS Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
- Spec - Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- KMS Client (Issue #46): Completed (fc70176)
- KMS ARN Utilities (Issue #47): Staged, in progress
