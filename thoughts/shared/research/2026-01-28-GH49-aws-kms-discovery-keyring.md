# Research: Implement AWS KMS Discovery Keyring

**Issue**: #49 - Implement AWS KMS Discovery Keyring
**Date**: 2026-01-28
**Status**: Research complete

## Issue Summary

Implement the AWS KMS Discovery Keyring that can decrypt data keys encrypted by any KMS key the caller has access to. Discovery keyrings are **decrypt-only** - they cannot encrypt. They examine encrypted data keys (EDKs) and attempt decryption using the key ARN stored in the EDK's provider info, optionally filtered by partition and account.

## Current Implementation State

### Existing Code

The AWS KMS Keyring infrastructure is already in place:

- `lib/aws_encryption_sdk/keyring/aws_kms.ex` - Standard AWS KMS keyring (encrypt + decrypt)
- `lib/aws_encryption_sdk/keyring/kms_client.ex` - KMS client behaviour definition
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` - ExAws implementation
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Mock implementation for testing
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` - KMS key ARN parsing and validation

### Relevant Patterns

#### Keyring Struct Pattern
```elixir
@type t :: %__MODULE__{
  kms_key_id: String.t(),      # Not used for discovery
  kms_client: struct(),        # Required
  grant_tokens: [String.t()]   # Optional, defaults to []
}

@enforce_keys [:kms_key_id, :kms_client]
defstruct [:kms_key_id, :kms_client, grant_tokens: []]
```

#### Constructor Pattern
```elixir
def new(kms_key_id, kms_client, opts \\ []) do
  with :ok <- validate_key_id(kms_key_id),
       :ok <- validate_client(kms_client) do
    {:ok, %__MODULE__{...}}
  end
end
```

#### Decryption Pattern (from AwsKms.unwrap_key/3)
```elixir
def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
  if KeyringBehaviour.has_plaintext_data_key?(materials) do
    {:error, :plaintext_data_key_already_set}
  else
    try_decrypt_edks(keyring, materials, edks, [])
  end
end

defp try_decrypt_edks(_keyring, _materials, [], errors) do
  {:error, {:unable_to_decrypt_any_data_key, Enum.reverse(errors)}}
end

defp try_decrypt_edks(keyring, materials, [edk | rest], errors) do
  case try_decrypt_edk(keyring, materials, edk) do
    {:ok, plaintext} ->
      DecryptionMaterials.set_plaintext_data_key(materials, plaintext)
    {:error, reason} ->
      try_decrypt_edks(keyring, materials, rest, [reason | errors])
  end
end
```

### Dependencies

**Required** (Already Implemented):
- `AwsEncryptionSdk.Keyring.Behaviour` - Keyring interface
- `AwsEncryptionSdk.Keyring.KmsClient` - KMS client abstraction (#46 ✓)
- `AwsEncryptionSdk.Keyring.KmsKeyArn` - ARN parsing utilities (#47 ✓)
- `AwsEncryptionSdk.Materials.DecryptionMaterials` - Decryption materials struct
- `AwsEncryptionSdk.Materials.EncryptedDataKey` - EDK struct

**Depends On**:
- `AwsEncryptionSdk.Keyring.AwsKms` (#48 - in progress) - Can reuse helper functions

**Blocks**:
- AWS KMS MRK Discovery Keyring (future issue)
- Multi-Keyring Integration (dispatch clauses needed)

## Specification Requirements

### Source Documents
- [aws-kms-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md) - Primary specification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface requirements
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN validation

### MUST Requirements

1. **Keyring Interface Implementation** (keyring-interface.md)
   > The keyring MUST implement the AWS Encryption SDK Keyring interface.

   Implementation: `@behaviour AwsEncryptionSdk.Keyring.Behaviour`

2. **Client Not Null** (aws-kms-discovery-keyring.md#initialization)
   > The AWS KMS SDK client MUST NOT be null.

   Implementation: Validate in constructor, return `{:error, :client_required}`

3. **Discovery Filter Validation** (aws-kms-discovery-keyring.md#initialization)
   > If a discovery filter is configured, both partition and accounts MUST be present.

   Implementation: Validate filter structure if provided

4. **OnEncrypt Must Fail** (aws-kms-discovery-keyring.md#onencrypt)
   > This function MUST fail.

   Implementation: Return `{:error, :discovery_keyring_cannot_encrypt}`

5. **Reject Materials with Existing Key** (aws-kms-discovery-keyring.md#ondecrypt)
   > If the decryption materials already contain a valid plaintext data key, the keyring MUST fail and MUST NOT modify the decryption materials.

   Implementation: Check `has_plaintext_data_key?(materials)` first

6. **Provider ID Matching** (aws-kms-discovery-keyring.md#ondecrypt)
   > For an encrypted data key to match with the keyring, the provider ID MUST exactly match "aws-kms".

   Implementation: Filter EDKs where `edk.key_provider_id == "aws-kms"`

7. **Provider Info ARN Validation** (aws-kms-discovery-keyring.md#ondecrypt)
   > The provider info MUST be a valid AWS KMS ARN with a resource type of `key`.

   Implementation: Use `KmsKeyArn.parse/1`, validate `resource_type == "key"`

8. **Discovery Filter - Partition Matching** (aws-kms-discovery-keyring.md#ondecrypt)
   > If a discovery filter is configured, the partition MUST match the discovery filter partition.

   Implementation: Compare `arn.partition` with `filter.partition`

9. **Discovery Filter - Account Matching** (aws-kms-discovery-keyring.md#ondecrypt)
   > If a discovery filter is configured, its set of accounts MUST contain the provider info account.

   Implementation: Check `arn.account in filter.accounts`

10. **Use ARN from Provider Info** (aws-kms-discovery-keyring.md#ondecrypt)
    > The keyring MUST call AWS KMS Decrypt with KeyId set to the AWS KMS ARN from the provider info.

    Implementation: Pass `edk.key_provider_info` as the key_id to KMS (NOT a configured key)

11. **Decrypt Parameters** (aws-kms-discovery-keyring.md#ondecrypt)
    > The keyring MUST call AWS KMS Decrypt with:
    > - KeyId: The AWS KMS ARN from the provider info
    > - CiphertextBlob: The encrypted data key ciphertext
    > - EncryptionContext: From the input decryption materials
    > - GrantTokens: The keyring's configured grant tokens

    Implementation: Call `client_module.decrypt(client, edk.key_provider_info, edk.ciphertext, materials.encryption_context, grant_tokens)`

12. **Response KeyId Validation** (aws-kms-discovery-keyring.md#ondecrypt)
    > The response KeyId MUST equal the provider info ARN.

    Implementation: Verify `response.key_id == edk.key_provider_info`

13. **Plaintext Length Validation** (aws-kms-discovery-keyring.md#ondecrypt)
    > The response Plaintext length MUST equal the key derivation input length specified by the algorithm suite.

    Implementation: Verify `byte_size(response.plaintext) == materials.algorithm_suite.kdf_input_length`

14. **Error Collection** (aws-kms-discovery-keyring.md#ondecrypt)
    > If the AWS KMS Decrypt call succeeds but the response does not meet the requirements, the keyring MUST collect the error and attempt to decrypt the next encrypted data key.

    Implementation: Accumulate errors in list, try next EDK

15. **Aggregate Error Return** (aws-kms-discovery-keyring.md#ondecrypt)
    > If all decryption attempts fail, the keyring MUST return an error that includes information from all collected errors.

    Implementation: Return `{:error, {:unable_to_decrypt_any_data_key, errors}}`

### SHOULD Requirements

1. **Use Discovery Filters** (aws-kms-discovery-keyring.md#security)
   > It is RECOMMENDED to use discovery filters to limit which AWS accounts and partitions can be used for decryption, reducing the attack surface.

### MAY Requirements

None explicitly stated.

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
- **awses-decrypt**: Decrypt test vectors for validating decryption operations
- Location: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- Manifest version: 2
- Generated by: aws-encryption-sdk-python v2.2.0
- Total KMS occurrences: ~1,981 test cases

### Available KMS Keys (from keys.json)

| Key ID | Type | ARN | Notes |
|--------|------|-----|-------|
| `us-west-2-decryptable` | aws-kms | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | Standard key |
| `us-west-2-encrypt-only` | aws-kms | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | Cannot decrypt |
| `us-west-2-mrk` | aws-kms | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Multi-region key |
| `us-east-1-mrk` | aws-kms | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Same MRK, different region |

### Implementation Order

#### Phase 1: Basic Discovery Decryption (No Filter)
| Test ID | KMS Keys | EDKs | Priority |
|---------|----------|------|----------|
| `686aae13-ec9b-4eab-9dc0-0a1794a2ba34` | us-west-2-decryptable | 1 | Start here |
| `7bb5cace-2274-4134-957d-0426c9f96637` | us-west-2-mrk | 1 | MRK support |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | us-east-1-mrk | 1 | Cross-region MRK |

#### Phase 2: Multiple EDKs
| Test ID | KMS Keys | EDKs | Priority |
|---------|----------|------|----------|
| `008a5704-9930-4340-809d-1c27ff7b4868` | us-west-2-decryptable + encrypt-only | 2 | EDK iteration |
| `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | us-west-2-mrk + encrypt-only | 2 | MRK + iteration |

#### Phase 3: Discovery Filter Scenarios (Mock-based)
| Scenario | Filter Config | Expected |
|----------|---------------|----------|
| Matching partition | partition: "aws" | Success |
| Mismatched partition | partition: "aws-cn" | Filter out EDK |
| Account in list | accounts: ["658956600833"] | Success |
| Account not in list | accounts: ["123456789012"] | Filter out EDK |

#### Phase 4: Edge Cases (Mock-based)
| Scenario | Expected |
|----------|----------|
| OnEncrypt called | Error: discovery_keyring_cannot_encrypt |
| Plaintext already set | Error: plaintext_data_key_already_set |
| Invalid ARN in provider info | Filter out EDK |
| Non-key resource type (alias) | Filter out EDK |
| All EDKs fail | Aggregate error |

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

## Implementation Considerations

### Struct Definition

```elixir
@type discovery_filter :: %{
  partition: String.t(),
  accounts: [String.t()]
}

@type t :: %__MODULE__{
  kms_client: struct(),
  discovery_filter: discovery_filter() | nil,
  grant_tokens: [String.t()]
}

@enforce_keys [:kms_client]
defstruct [:kms_client, :discovery_filter, grant_tokens: []]
```

### Key Difference from Standard KMS Keyring

| Aspect | AwsKms Keyring | AwsKmsDiscovery Keyring |
|--------|----------------|-------------------------|
| Key configuration | Required `kms_key_id` | No key configured |
| Encryption | Supported | MUST fail |
| Key for decrypt | Uses configured key ID | Uses ARN from EDK provider info |
| Key matching | MRK-aware matching against configured key | No matching (any key accepted) |
| Filtering | None | Optional partition/account filter |

### EDK Filtering Logic

```elixir
defp filter_and_process_edks(keyring, materials, edks) do
  edks
  |> Enum.filter(&matches_provider_id?/1)           # Must be "aws-kms"
  |> Enum.filter(&valid_arn_with_key_type?/1)       # Valid ARN, resource_type = "key"
  |> Enum.filter(&passes_discovery_filter?(keyring, &1))  # Partition/account filter
  |> try_decrypt_each(keyring, materials)
end
```

### Discovery Filter Validation

```elixir
defp validate_discovery_filter(nil), do: :ok

defp validate_discovery_filter(%{partition: partition, accounts: accounts})
    when is_binary(partition) and is_list(accounts) and accounts != [] do
  if Enum.all?(accounts, &is_binary/1) do
    :ok
  else
    {:error, :invalid_account_ids}
  end
end

defp validate_discovery_filter(_), do: {:error, :invalid_discovery_filter}
```

### Technical Approach

1. **Create new module** `AwsEncryptionSdk.Keyring.AwsKmsDiscovery`
2. **Reuse utilities** from `AwsKms` module where appropriate:
   - `validate_client/1`
   - `validate_decrypted_length/2`
   - Provider ID constant `"aws-kms"`
3. **Implement custom logic** for:
   - Discovery filter validation
   - EDK filtering (no key matching, just filter criteria)
   - Using provider info ARN as decrypt key ID
   - `wrap_key/2` that always fails

### Potential Challenges

1. **Discovery Filter Structure**: Issue specifies `%{partition: String.t(), accounts: [String.t()]}` but spec may expect a specific type - verify against other SDKs
2. **Response Key ID Validation**: Discovery keyring should verify response key_id equals provider_info exactly (no MRK matching)
3. **Error Aggregation**: Need clear error messages distinguishing filter failures from KMS failures

### Open Questions

1. **MRK Discovery Keyring Separation**: Should this keyring support MRK semantics, or leave that to a separate MRK Discovery Keyring? Based on spec, base discovery keyring does not do MRK-aware matching.

2. **Region Validation**: The base AWS KMS Discovery Keyring spec doesn't mention region matching. Should we:
   - Ignore region (rely on KMS API to reject cross-region calls)?
   - Add optional region matching?

   **Recommendation**: Leave region handling to KMS API per spec.

## Files to Create

- `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex` - Discovery keyring implementation
- `test/aws_encryption_sdk/keyring/aws_kms_discovery_test.exs` - Unit tests

## Files to Modify

- `lib/aws_encryption_sdk/cmm/default.ex` - Add dispatch clause for `%AwsKmsDiscovery{}`
- `lib/aws_encryption_sdk/keyring/multi.ex` - Add dispatch clause for `%AwsKmsDiscovery{}`

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-28-GH49-aws-kms-discovery-keyring.md`
2. Ensure AWS KMS Keyring (#48) is complete first (shares utilities)
3. Implement discovery keyring with mock-based tests
4. Add test vector integration tests

## References

- Issue: https://github.com/[owner]/[repo]/issues/49
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
- Keyring Interface: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
