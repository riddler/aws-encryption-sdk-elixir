# Research: Implement AWS KMS MRK Discovery Keyring

**Issue**: #51 - Implement AWS KMS MRK Discovery Keyring
**Date**: 2026-01-28
**Status**: Research complete

## Issue Summary

Implement the AWS KMS Multi-Region Key (MRK) Discovery Keyring - a decrypt-only keyring that combines discovery keyring behavior with MRK awareness. Unlike the basic discovery keyring that uses exact ARN matching, the MRK Discovery Keyring:

1. **For MRK keys**: Reconstructs the ARN with the configured region before calling KMS Decrypt, enabling cross-region decryption
2. **For non-MRK keys**: Filters out EDKs where the region doesn't match the keyring's configured region

This enables applications to decrypt data encrypted with MRKs in any region using a single keyring configured for their local region.

## Current Implementation State

### Existing Code

The KMS keyring infrastructure is complete and ready for extension:

| File | Description | Status |
|------|-------------|--------|
| `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex` | Base discovery keyring pattern | Complete |
| `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex` | MRK-aware keyring (GH50) | In progress |
| `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` | ARN parsing + MRK utilities | Complete |
| `lib/aws_encryption_sdk/keyring/kms_client.ex` | KMS client behaviour | Complete |
| `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` | ExAws implementation | Complete |
| `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` | Mock for testing | Complete |
| `lib/aws_encryption_sdk/cmm/default.ex` | Default CMM with keyring dispatch | Complete |
| `lib/aws_encryption_sdk/keyring/multi.ex` | Multi-keyring composition | Complete |

### Key Discovery Keyring Pattern (from `aws_kms_discovery.ex`)

The existing discovery keyring provides the base pattern:

```elixir
# Struct - MRK Discovery will add :region field
defstruct [:kms_client, :discovery_filter, grant_tokens: []]

# Key behavior: cannot encrypt
def wrap_key(%__MODULE__{}, %EncryptionMaterials{}) do
  {:error, :discovery_keyring_cannot_encrypt}
end

# Decryption flow:
# 1. Check for existing plaintext key
# 2. Filter EDKs by provider ID, ARN validity, discovery filter
# 3. For each matching EDK, call KMS Decrypt using ARN from provider info
# 4. Verify response KeyId matches expected (exact match at line 228)
# 5. Validate decrypted length
```

**Critical Difference**: At line 228, the discovery keyring uses **exact comparison**:
```elixir
defp verify_response_key_id(expected, actual) when expected == actual, do: :ok
```

The MRK Discovery keyring must use **MRK matching** instead:
```elixir
defp verify_response_key_id(expected, actual) do
  if KmsKeyArn.mrk_match?(expected, actual), do: :ok, else: {:error, ...}
end
```

### Available MRK Utilities (from `kms_key_arn.ex`)

```elixir
# Parse ARN into struct
@spec parse(String.t()) :: {:ok, t()} | {:error, term()}
def parse(arn_string)

# Check if identifier is MRK (mrk- prefix)
@spec mrk?(t() | String.t()) :: boolean()
def mrk?(identifier)

# MRK match for decrypt - compares all components except region
@spec mrk_match?(String.t(), String.t()) :: boolean()
def mrk_match?(identifier_a, identifier_b)

# Reconstruct ARN string from struct
@spec to_string(t()) :: String.t()
def to_string(%__MODULE__{} = arn)
```

### Relevant Patterns

#### Struct Definition Pattern
```elixir
# From AwsKmsDiscovery
@type discovery_filter :: %{
  partition: String.t(),
  accounts: [String.t(), ...]
}

@type t :: %__MODULE__{
  kms_client: struct(),
  discovery_filter: discovery_filter() | nil,
  grant_tokens: [String.t()]
}
```

#### Dispatch Pattern (for integration)
```elixir
# From cmm/default.ex and keyring/multi.ex
def call_wrap_key(%AwsKmsDiscovery{} = keyring, materials) do
  AwsKmsDiscovery.wrap_key(keyring, materials)
end

# Will need to add:
def call_wrap_key(%AwsKmsMrkDiscovery{} = keyring, materials) do
  AwsKmsMrkDiscovery.wrap_key(keyring, materials)
end
```

### Dependencies

**Required (Already Implemented):**
- `AwsEncryptionSdk.Keyring.Behaviour` - Keyring interface
- `AwsEncryptionSdk.Keyring.KmsClient` - KMS client abstraction
- `AwsEncryptionSdk.Keyring.KmsKeyArn` - ARN parsing with MRK utilities

**Depends On (Assumed Complete):**
- `AwsEncryptionSdk.Keyring.AwsKmsDiscovery` (#49 - discovery keyring pattern)
- `AwsEncryptionSdk.Keyring.AwsKmsMrk` (#50 - MRK matching patterns)

**Blocks:**
- Multi-Keyring Integration (dispatch clauses needed)
- AWS KMS MRK Discovery Multi-Keyring (convenience constructor)

## Specification Requirements

### Source Documents

- [aws-kms-mrk-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md) - Primary specification
- [aws-kms-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md) - Base discovery behavior
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN validation and MRK identification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface

### MUST Requirements

#### Constructor (Initialization)

1. **Required Parameters** (aws-kms-mrk-discovery-keyring.md)
   > The keyring MUST accept the following parameters:
   > - A required AWS KMS client
   > - A required string indicating the region of the KMS client
   > - An optional discovery filter that is an AWS partition and a set of AWS accounts
   > - An optional list of AWS KMS grant tokens

   Implementation: `new(kms_client, region, opts \\ [])` with `:discovery_filter` and `:grant_tokens` options

2. **Non-null Client** (aws-kms-mrk-discovery-keyring.md)
   > The AWS KMS SDK client MUST NOT be null

   Implementation: Validate client is non-nil struct

3. **Non-null Region** (aws-kms-mrk-discovery-keyring.md)
   > The region MUST NOT be null or empty

   Implementation: Validate region is non-nil, non-empty string

4. **Discovery Filter Validation** (aws-kms-mrk-discovery-keyring.md)
   > If discovery filter is provided, both partition and accounts MUST be present

   Implementation: Reuse validation from `AwsKmsDiscovery.validate_discovery_filter/1`

#### OnEncrypt

5. **Encryption Prohibited** (aws-kms-mrk-discovery-keyring.md)
   > This function MUST fail

   Implementation: Return `{:error, :discovery_keyring_cannot_encrypt}` (same as base discovery)

#### OnDecrypt

6. **Early Return** (aws-kms-mrk-discovery-keyring.md)
   > If decryption materials already contain valid plaintext data key, return immediately without modification

   Implementation: Check `has_plaintext_data_key?(materials)` first

7. **Filter EDKs - Provider ID** (aws-kms-mrk-discovery-keyring.md)
   > Provider ID MUST be exactly "aws-kms"

   Implementation: Match `edk.key_provider_id == "aws-kms"`

8. **Filter EDKs - Valid ARN** (aws-kms-mrk-discovery-keyring.md)
   > Provider info MUST be a valid AWS KMS ARN with resource type "key"

   Implementation: Use `KmsKeyArn.parse/1` and check `arn.resource_type == "key"`

9. **Filter EDKs - Discovery Filter** (aws-kms-mrk-discovery-keyring.md)
   > If discovery filter set: partition must match, account must be in allowed list

   Implementation: Reuse `passes_discovery_filter/2` from base discovery

10. **MRK Region Handling** (aws-kms-mrk-discovery-keyring.md - **KEY DIFFERENTIATOR**)
    > For each matching EDK, determine the key to use for decryption:
    > - If the EDK's provider info ARN is identified as a multi-Region key:
    >   **Construct a new ARN with the same partition, service, account, resource type,
    >   and resource, but with the configured region**
    > - If the EDK's provider info ARN is NOT a multi-Region key:
    >   **The ARN's region MUST match the configured region, otherwise skip this EDK**

    Implementation:
    ```elixir
    defp determine_decrypt_key_id(arn, region) do
      if KmsKeyArn.mrk?(arn) do
        # Reconstruct ARN with configured region
        reconstructed = %{arn | region: region}
        {:ok, KmsKeyArn.to_string(reconstructed)}
      else
        # Non-MRK: must be in same region
        if arn.region == region do
          {:ok, KmsKeyArn.to_string(arn)}
        else
          {:error, {:region_mismatch, expected: region, actual: arn.region}}
        end
      end
    end
    ```

11. **KMS Decrypt Call** (aws-kms-mrk-discovery-keyring.md)
    > Call AWS KMS Decrypt with:
    > - KeyId: The determined key ARN (reconstructed for MRK, original for same-region non-MRK)
    > - CiphertextBlob: The EDK ciphertext
    > - EncryptionContext: From decryption materials
    > - GrantTokens: Configured grant tokens

12. **Validate Response KeyId** (aws-kms-mrk-discovery-keyring.md)
    > The response KeyId MUST equal the request KeyId

    Implementation: Exact string comparison (since we use the determined ARN)

13. **Validate Plaintext Length** (aws-kms-mrk-discovery-keyring.md)
    > Plaintext length MUST match algorithm suite's key derivation input length

14. **Error Collection** (aws-kms-mrk-discovery-keyring.md)
    > Collect all errors and continue to next EDK on failure

15. **Final Error** (aws-kms-mrk-discovery-keyring.md)
    > If no key decrypts successfully, yield error including all collected errors

### SHOULD Requirements

1. **Region Validation** (aws-kms-mrk-discovery-keyring.md)
   > The keyring SHOULD fail initialization if the provided region does not match the region of the KMS client

   Implementation: If client has a `region` field/function, compare and warn/error

### MAY Requirements

None explicitly stated.

## Key Differences from Base Discovery Keyring

| Aspect | AwsKmsDiscovery | AwsKmsMrkDiscovery |
|--------|-----------------|---------------------|
| **Struct Fields** | `kms_client, discovery_filter, grant_tokens` | + **`region`** (required) |
| **OnEncrypt** | Error | Error (same) |
| **MRK in Same Region** | Uses ARN from EDK | Uses ARN from EDK (same) |
| **MRK in Different Region** | Skips (exact match fails) | **Reconstructs ARN with configured region** |
| **Non-MRK in Same Region** | Uses ARN from EDK | Uses ARN from EDK (same) |
| **Non-MRK in Different Region** | Attempts (may work if access) | **Filtered out explicitly** |
| **Response KeyId Validation** | Exact string match | Exact string match (uses reconstructed ARN) |

## Test Vectors

### Harness Setup

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

- **awses-decrypt**: Decrypt test vectors with `type: "aws-kms-mrk-aware-discovery"`
- Location: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- Manifest version: 2
- Total MRK Discovery test cases: ~117 vectors

### Available MRK Keys (from keys.json)

| Key ID | ARN | Region | Resource ID |
|--------|-----|--------|-------------|
| `us-west-2-mrk` | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | us-west-2 | mrk-80bd8ecdcd4342aebd84b7dc9da498a7 |
| `us-east-1-mrk` | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | us-east-1 | mrk-80bd8ecdcd4342aebd84b7dc9da498a7 |

Both share the same MRK resource ID but different regions - this is the core MRK concept.

### Implementation Order

#### Phase 1: ARN Validation (Error Cases)

Test that malformed ARNs are properly rejected/filtered:

| Test ID | Error Description | Priority |
|---------|-------------------|----------|
| `495bfc25-24a6-4b65-9e20-47c58c6f1a01` | Colon-delimited ARN (should use slashes) | High |
| `3aef648d-e636-4328-90d1-2e8f107c719c` | Missing `arn` prefix | High |
| `267ef05f-d28b-49e2-a897-c1f1a7f69ffc` | Invalid `arn-not` prefix | High |
| `317955eb-185a-4c92-b4b4-3fa195535b4c` | Malformed ARN structure | High |

These validate that `KmsKeyArn.parse/1` correctly rejects malformed provider info ARNs.

#### Phase 2: MRK Same Region (Basic Success)

| Scenario | Setup | Expected |
|----------|-------|----------|
| MRK decrypt same region | keyring.region = "us-west-2", EDK from us-west-2-mrk | Success, no ARN reconstruction needed |
| Non-MRK same region | keyring.region = "us-west-2", EDK from us-west-2 regular key | Success, exact ARN used |

#### Phase 3: MRK Cross-Region (Core Value Proposition)

| Scenario | Setup | Expected |
|----------|-------|----------|
| West keyring → East ciphertext | keyring.region = "us-west-2", EDK from us-east-1-mrk | **Success** - ARN reconstructed to us-west-2 |
| East keyring → West ciphertext | keyring.region = "us-east-1", EDK from us-west-2-mrk | **Success** - ARN reconstructed to us-east-1 |

This is the critical test - decrypt data encrypted in one region using MRK Discovery configured for another region.

#### Phase 4: Non-MRK Region Filtering

| Scenario | Setup | Expected |
|----------|-------|----------|
| Non-MRK different region | keyring.region = "us-west-2", EDK from us-east-1 regular key | **Filtered out** - EDK skipped |

#### Phase 5: Discovery Filter + MRK

| Scenario | Setup | Expected |
|----------|-------|----------|
| MRK matches filter | Filter: partition=aws, accounts=[123], MRK in different region | Success |
| MRK fails partition filter | Filter: partition=aws-cn, MRK in partition=aws | Filtered out |
| MRK fails account filter | Filter: accounts=[999], MRK in account 123 | Filtered out |

### Test Vector Setup

If test vectors are not present:

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
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery do
  @type discovery_filter :: %{
    partition: String.t(),
    accounts: [String.t(), ...]
  }

  @type t :: %__MODULE__{
    kms_client: struct(),
    region: String.t(),           # NEW - required
    discovery_filter: discovery_filter() | nil,
    grant_tokens: [String.t()]
  }

  @enforce_keys [:kms_client, :region]
  defstruct [:kms_client, :region, :discovery_filter, grant_tokens: []]
end
```

### Technical Approach

**Recommended**: Copy `AwsKmsDiscovery` and modify for MRK awareness.

The key changes from base discovery:

1. **Add `region` field** to struct (required)
2. **Add region validation** in constructor
3. **Add `determine_decrypt_key_id/2`** that handles MRK ARN reconstruction
4. **Modify EDK filtering** to call `determine_decrypt_key_id/2` before attempting decrypt
5. **Keep response validation** as exact match (using reconstructed ARN)

```elixir
# Core MRK handling logic
defp try_decrypt_edk(keyring, materials, edk) do
  with :ok <- match_provider_id(edk),
       {:ok, arn} <- parse_provider_info_arn(edk),
       :ok <- validate_resource_type_is_key(arn),
       :ok <- passes_discovery_filter(keyring.discovery_filter, arn),
       # NEW: Determine key ID with MRK handling
       {:ok, decrypt_key_id} <- determine_decrypt_key_id(arn, keyring.region),
       {:ok, plaintext} <- call_kms_decrypt(keyring, materials, edk, decrypt_key_id),
       :ok <- validate_decrypted_length(plaintext, materials.algorithm_suite.kdf_input_length) do
    {:ok, plaintext}
  end
end

defp determine_decrypt_key_id(arn, region) do
  if KmsKeyArn.mrk?(arn) do
    # MRK: Reconstruct with configured region
    reconstructed = %{arn | region: region}
    {:ok, KmsKeyArn.to_string(reconstructed)}
  else
    # Non-MRK: Must be in same region
    if arn.region == region do
      {:ok, KmsKeyArn.to_string(arn)}
    else
      {:error, {:region_mismatch, expected: region, actual: arn.region}}
    end
  end
end
```

### Potential Challenges

1. **ARN Reconstruction**: Need to ensure `%{arn | region: region}` works correctly with the struct
2. **Region Validation**: Getting region from different KMS client implementations may vary
3. **Test Mocking**: Need to mock KMS to return different KeyIds for cross-region scenarios
4. **Discovery Filter + MRK**: Ensure filter is applied before MRK reconstruction

### Open Questions

1. **Should we validate region matches client region?**
   - The spec says SHOULD validate
   - ExAws client stores region in struct - can compare
   - Mock client may not have region - skip validation?
   - Recommendation: Validate if client has `.region` field, otherwise skip with warning

2. **What error code for region mismatch?**
   - For non-MRK in different region, should we use `{:region_mismatch, ...}` or just skip?
   - Recommendation: Use descriptive error `{:non_mrk_region_mismatch, ...}` to distinguish from other errors

## Files to Create

- `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex` - MRK Discovery keyring implementation
- `test/aws_encryption_sdk/keyring/aws_kms_mrk_discovery_test.exs` - Unit tests

## Files to Modify

- `lib/aws_encryption_sdk/cmm/default.ex` - Add dispatch clauses for `%AwsKmsMrkDiscovery{}`
- `lib/aws_encryption_sdk/keyring/multi.ex` - Add dispatch clauses for `%AwsKmsMrkDiscovery{}`

### CMM Dispatch Additions

```elixir
# lib/aws_encryption_sdk/cmm/default.ex

# Add to @type keyring union at line 40-46
| AwsKmsMrkDiscovery.t()

# Add alias at line 37
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, AwsKmsMrkDiscovery, Multi, RawAes, RawRsa}

# Add dispatch clause after line 98
def call_wrap_key(%AwsKmsMrkDiscovery{} = keyring, materials) do
  AwsKmsMrkDiscovery.wrap_key(keyring, materials)
end

# Add dispatch clause after line 129
def call_unwrap_key(%AwsKmsMrkDiscovery{} = keyring, materials, edks) do
  AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)
end
```

### Multi-Keyring Dispatch Additions

```elixir
# lib/aws_encryption_sdk/keyring/multi.ex

# Add alias at line 55
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, AwsKmsMrk, AwsKmsMrkDiscovery, RawAes, RawRsa}

# Add dispatch clause after line 229
defp call_wrap_key(%AwsKmsMrkDiscovery{} = keyring, materials) do
  AwsKmsMrkDiscovery.wrap_key(keyring, materials)
end

# Add dispatch clause after line 309
defp call_unwrap_key(%AwsKmsMrkDiscovery{} = keyring, materials, edks) do
  AwsKmsMrkDiscovery.unwrap_key(keyring, materials, edks)
end
```

## Example Usage

```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Create KMS client in us-west-2
{:ok, kms_client} = ExAws.new(region: "us-west-2")

# Create MRK Discovery keyring for us-west-2
{:ok, keyring} = AwsKmsMrkDiscovery.new(kms_client, "us-west-2")

# With discovery filter (restrict to specific partition/accounts)
{:ok, keyring} = AwsKmsMrkDiscovery.new(kms_client, "us-west-2",
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012", "987654321098"]
  }
)

# With grant tokens
{:ok, keyring} = AwsKmsMrkDiscovery.new(kms_client, "us-west-2",
  grant_tokens: ["token1", "token2"]
)

# Cannot encrypt - discovery keyrings are decrypt-only
{:error, :discovery_keyring_cannot_encrypt} = AwsKmsMrkDiscovery.wrap_key(keyring, enc_materials)

# Can decrypt MRK-encrypted data from ANY region
# EDK was encrypted with us-east-1 MRK replica
{:ok, materials} = AwsKmsMrkDiscovery.unwrap_key(keyring, dec_materials, edks)
# Success! ARN was reconstructed to us-west-2 for the Decrypt call
```

## ARN Reconstruction Examples

```elixir
# Scenario 1: MRK Discovery keyring in us-west-2
keyring_region = "us-west-2"

# EDK encrypted with MRK in us-east-1:
edk_provider_info = "arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd"

# Since it's an MRK, reconstruct with keyring's region:
decrypt_key_id = "arn:aws:kms:us-west-2:123456789012:key/mrk-1234abcd"
# => Decrypt call uses us-west-2 replica

# Scenario 2: Non-MRK in different region
edk_provider_info = "arn:aws:kms:us-east-1:123456789012:key/regular-key-id"

# Not an MRK and region doesn't match => EDK FILTERED OUT
# (Won't even attempt decrypt)

# Scenario 3: Non-MRK in same region
edk_provider_info = "arn:aws:kms:us-west-2:123456789012:key/regular-key-id"

# Not an MRK but region matches => Use original ARN
decrypt_key_id = "arn:aws:kms:us-west-2:123456789012:key/regular-key-id"
# => Decrypt call uses original ARN
```

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-28-GH51-aws-kms-mrk-discovery-keyring.md`
2. Ensure GH50 (AWS KMS MRK Keyring) is complete first
3. Implement MRK Discovery keyring based on AwsKmsDiscovery pattern
4. Add region field and MRK ARN reconstruction logic
5. Add dispatch clauses to CMM and Multi-keyring
6. Add unit tests with mock KMS client
7. Add test vector tests for MRK discovery scenarios

## References

- Issue: https://github.com/[owner]/[repo]/issues/51
- Spec - MRK Discovery Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md
- Spec - Discovery Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
