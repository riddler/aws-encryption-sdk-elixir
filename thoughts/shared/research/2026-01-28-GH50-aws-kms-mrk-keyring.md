# Research: Implement AWS KMS MRK Keyring

**Issue**: #50 - Implement AWS KMS MRK Keyring
**Date**: 2026-01-28
**Status**: Research complete

## Issue Summary

Implement the AWS KMS Multi-Region Key (MRK) aware Keyring that can decrypt data using related MRK keys across regions. MRKs are KMS keys replicated across AWS regions - the MRK Keyring allows decryption with any replica of the MRK used for encryption, enabling cross-region disaster recovery and data access scenarios.

The key difference from the basic KMS keyring is that this keyring uses **MRK matching** instead of exact matching for decrypt operations, and uses the **configured key identifier** for the Decrypt call rather than the ARN from the EDK.

## Current Implementation State

### Existing Code

The AWS KMS infrastructure is complete:

- `lib/aws_encryption_sdk/keyring/aws_kms.ex` - Standard AWS KMS keyring (to be extended)
- `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex` - Discovery keyring (will be complete per GH49)
- `lib/aws_encryption_sdk/keyring/kms_client.ex` - KMS client behaviour definition
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` - ExAws implementation
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Mock implementation for testing
- `lib/aws_encryption_sdk/keyring/kms_key_arn.ex` - KMS key ARN parsing with **MRK utilities already implemented**

### Critical Existing Utility: MRK Matching

The `KmsKeyArn` module already has the MRK matching algorithm implemented:

```elixir
# lib/aws_encryption_sdk/keyring/kms_key_arn.ex

# Check if identifier is an MRK
@spec mrk?(t() | String.t()) :: boolean()
def mrk?(identifier)  # Returns true if resource_id starts with "mrk-"

# MRK match for decrypt - THE KEY FUNCTION
@spec mrk_match?(String.t(), String.t()) :: boolean()
def mrk_match?(identifier_a, identifier_b)
  # 1. Identical identifiers always match
  # 2. Both must be MRKs with same partition/service/account/resource_type/resource_id
  #    Region may differ!
```

The existing `AwsKms` keyring already uses `mrk_match?/2` for:
- EDK filtering at `aws_kms.ex:252` - `KmsKeyArn.mrk_match?(kms_key_id, edk.key_provider_info)`
- Response validation at `aws_kms.ex:278` - `KmsKeyArn.mrk_match?(keyring.kms_key_id, response.key_id)`

**Important Realization**: The basic `AwsKms` keyring already implements MRK-aware matching! Looking at the code in `aws_kms.ex:251-257`:

```elixir
defp match_key_identifier(%__MODULE__{kms_key_id: kms_key_id}, edk) do
  if KmsKeyArn.mrk_match?(kms_key_id, edk.key_provider_info) do
    :ok
  else
    {:error, {:key_identifier_mismatch, kms_key_id, edk.key_provider_info}}
  end
end
```

This means the existing `AwsKms` keyring may already function as an MRK-aware keyring. Need to verify against spec.

### Relevant Patterns

#### Keyring Struct Pattern
```elixir
# From AwsKms
@type t :: %__MODULE__{
  kms_key_id: String.t(),
  kms_client: struct(),
  grant_tokens: [String.t()]
}

@enforce_keys [:kms_key_id, :kms_client]
defstruct [:kms_key_id, :kms_client, grant_tokens: []]
```

#### Dispatch Pattern (from CMM and Multi-keyring)
```elixir
# lib/aws_encryption_sdk/cmm/default.ex:86-88
defp call_wrap_key(%AwsKms{} = keyring, materials) do
  AwsKms.wrap_key(keyring, materials)
end

# Similar dispatch needed for AwsKmsMrk
```

### Dependencies

**Required** (Already Implemented):
- `AwsEncryptionSdk.Keyring.Behaviour` - Keyring interface
- `AwsEncryptionSdk.Keyring.KmsClient` - KMS client abstraction (#46 ✓)
- `AwsEncryptionSdk.Keyring.KmsKeyArn` - ARN parsing with MRK utilities (#47 ✓)
- `AwsEncryptionSdk.Keyring.AwsKms` - Basic KMS keyring (#48 ✓)

**Depends On**:
- `AwsEncryptionSdk.Keyring.AwsKmsDiscovery` (#49 - will be complete before this)

**Blocks**:
- AWS KMS MRK Discovery Keyring (future issue)
- Multi-Keyring Integration (dispatch clauses needed)

## Specification Requirements

### Source Documents
- [aws-kms-mrk-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md) - Primary specification (v0.2.2)
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN structure and MRK identification
- [keyring-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/keyring-interface.md) - Keyring interface requirements

### MUST Requirements

#### Constructor

1. **Valid Key Identifier** (aws-kms-mrk-keyring.md#initialization)
   > The AWS KMS key identifier MUST be a valid identifier

   Implementation: Validate non-null, non-empty string

2. **Non-null Client** (aws-kms-mrk-keyring.md#initialization)
   > The AWS KMS SDK client MUST NOT be null

   Implementation: Validate client is non-nil struct

#### OnEncrypt - Generate Path (no existing plaintext key)

3. **Generate New Data Key** (aws-kms-mrk-keyring.md#onencrypt)
   > OnEncrypt MUST attempt to generate a new plaintext data key

   Implementation: Call AWS KMS GenerateDataKey

4. **GenerateDataKey Request Parameters** (aws-kms-mrk-keyring.md#onencrypt)
   > MUST call AWS KMS GenerateDataKey with:
   > - KeyId: The configured AWS KMS key identifier
   > - NumberOfBytes: Algorithm suite's key derivation input length
   > - EncryptionContext: From encryption materials
   > - GrantTokens: Configured grant tokens

5. **Validate Response Plaintext Length** (aws-kms-mrk-keyring.md#onencrypt)
   > The Generate Data Key response's Plaintext MUST be validated

   Length must match key derivation input length.

6. **Validate Response KeyId** (aws-kms-mrk-keyring.md#onencrypt)
   > The Generate Data Key response's KeyId MUST be a valid AWS KMS key ARN

7. **Set Plaintext Data Key** (aws-kms-mrk-keyring.md#onencrypt)
   > Set the plaintext data key on the encryption materials

8. **Append EDK** (aws-kms-mrk-keyring.md#onencrypt)
   > Append encrypted data key with:
   > - ciphertext: Response CiphertextBlob
   > - key provider ID: "aws-kms"
   > - key provider info: Response KeyId (ARN)

9. **Error Handling** (aws-kms-mrk-keyring.md#onencrypt)
   > On failure, OnEncrypt MUST NOT modify the encryption materials and MUST fail

#### OnEncrypt - Encrypt Path (existing plaintext key)

10. **Encrypt Existing Key** (aws-kms-mrk-keyring.md#onencrypt)
    > Call AWS KMS Encrypt with:
    > - KeyId: Configured AWS KMS key identifier
    > - Plaintext: Existing plaintext data key
    > - EncryptionContext: From encryption materials
    > - GrantTokens: Configured grant tokens

11. **Validate Encrypt Response** (aws-kms-mrk-keyring.md#onencrypt)
    > The response's KeyId MUST be a valid AWS KMS key ARN

12. **Append EDK** (same structure as GenerateDataKey path)

#### OnDecrypt

13. **Early Return** (aws-kms-mrk-keyring.md#ondecrypt)
    > If decryption materials already contain valid plaintext data key, return immediately

14. **Filter EDKs - Provider ID** (aws-kms-mrk-keyring.md#ondecrypt)
    > Provider ID MUST be "aws-kms" exactly

15. **Filter EDKs - Valid ARN** (aws-kms-mrk-keyring.md#ondecrypt)
    > Provider info MUST be a valid AWS KMS ARN with resource type "key"

16. **Filter EDKs - MRK Match** (aws-kms-mrk-keyring.md#ondecrypt)
    > Matching configured key via AWS KMS MRK Match for Decrypt function

    This is the key difference from basic keyring - uses MRK matching, not exact match.

17. **Decrypt Request** (aws-kms-mrk-keyring.md#ondecrypt)
    > Call AWS KMS Decrypt with:
    > - **KeyId: The configured AWS KMS key identifier** (NOT the ARN from EDK!)
    > - CiphertextBlob: The EDK ciphertext
    > - EncryptionContext: From decryption materials
    > - GrantTokens: Configured grant tokens

    **Critical**: The MRK keyring uses the configured key for Decrypt, not the EDK's ARN. This enables cross-region decryption.

18. **Validate Response KeyId** (aws-kms-mrk-keyring.md#ondecrypt)
    > Verify response KeyId equals configured identifier

19. **Validate Plaintext Length** (aws-kms-mrk-keyring.md#ondecrypt)
    > Plaintext length MUST match algorithm suite's key derivation input length

20. **Success Path** (aws-kms-mrk-keyring.md#ondecrypt)
    > On success, set plaintext and return immediately

21. **Error Collection** (aws-kms-mrk-keyring.md#ondecrypt)
    > Collect all errors and continue to next EDK on failure

22. **Final Error** (aws-kms-mrk-keyring.md#ondecrypt)
    > If no key succeeds, yield combined error

### MRK Match Algorithm Requirements (aws-kms-mrk-match-for-decrypt.md)

23. **Identity Check**
    > If both identifiers are identical, return true

24. **Non-MRK Check**
    > If either identifier is not identified as a multi-Region key, return false

25. **Component Comparison**
    > When both inputs qualify as MRKs, compare:
    > - partition (MUST match)
    > - service (MUST match - always "kms")
    > - accountId (MUST match)
    > - resourceType (MUST match - always "key")
    > - resource (MUST match - the key ID)
    > - **region is NOT compared**

### SHOULD Requirements

1. **Non-MRK Warning** (aws-kms-mrk-keyring.md)
   > MAY warn if configured key is not an MRK (still functional, but no cross-region benefit)

### MAY Requirements

None explicitly stated.

## Implementation Analysis: New Module vs Extension

### Option A: Create Separate Module (Recommended)

Create `AwsEncryptionSdk.Keyring.AwsKmsMrk` as a distinct keyring type:

**Pros:**
- Clear separation of concerns
- Explicit opt-in to MRK behavior
- Matches spec naming (aws-kms-mrk-keyring)
- Can add MRK-specific validation/warnings
- Users explicitly choose MRK-aware behavior

**Cons:**
- Some code duplication with AwsKms
- Additional dispatch clauses needed

### Option B: Extend Existing AwsKms

The existing `AwsKms` keyring already uses `mrk_match?/2`. Could be "good enough".

**Pros:**
- No new module needed
- Less code to maintain

**Cons:**
- Basic keyring spec says exact match, we do MRK match
- Users may not expect MRK behavior from basic keyring
- Can't distinguish intent in logs/debugging

### Recommendation: Option A

Create a separate `AwsKmsMrk` module for clarity and spec compliance. The modules can share utility functions.

## Test Vectors

### Harness Setup

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
```

### Applicable Test Vector Sets
- **awses-decrypt**: Decrypt test vectors
- Location: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- Manifest version: 2
- Generated by: aws-encryption-sdk-python v2.2.0

### Available MRK Keys (from keys.json)

| Key ID | Type | ARN | Notes |
|--------|------|-----|-------|
| `us-west-2-mrk` | aws-kms | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | West replica |
| `us-east-1-mrk` | aws-kms | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | East replica |

Both keys share the same MRK resource ID (`mrk-80bd8ecdcd4342aebd84b7dc9da498a7`) but different regions.

### Implementation Order

#### Phase 1: Basic MRK Decryption (Same Region)
| Test ID | Region | Master Keys | Priority | Notes |
|---------|--------|-------------|----------|-------|
| `7bb5cace-2274-4134-957d-0426c9f96637` | us-west-2 | `us-west-2-mrk` | Start here | Single MRK, same region |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | us-east-1 | `us-east-1-mrk` | Second | Single MRK, different region |

#### Phase 2: Cross-Region MRK Decryption (Core Value Proposition)
| Scenario | Ciphertext From | Keyring Config | Expected |
|----------|-----------------|----------------|----------|
| West→East | `7bb5cace` (us-west-2-mrk) | us-east-1-mrk keyring | **SUCCESS** |
| East→West | `af7b820f` (us-east-1-mrk) | us-west-2-mrk keyring | **SUCCESS** |

This is the critical test - decrypt data encrypted in one region using a different regional replica of the same MRK.

#### Phase 3: Multi-Keyring Scenarios
| Test ID | Master Keys | Notes |
|---------|-------------|-------|
| `dd7a49cf-e9d6-425a-ba14-df40002a82ff` | us-west-2-mrk + us-west-2-encrypt-only | MRK + regular KMS |
| `4de0e71e-08ef-4a80-af61-8268f10021ab` | us-east-1-mrk + us-west-2-encrypt-only | Cross-region MRK + regular |

#### Phase 4: Negative Cases (Mock-based)
| Scenario | Expected |
|----------|----------|
| Different MRK (mrk-abc vs mrk-xyz) | Fail - no matching EDK |
| Non-MRK cross-region | Fail - exact match required |
| Invalid ARN in provider info | Filter out EDK |
| Response KeyId mismatch | Error, try next EDK |

### Test Vector File Structure

```
test/fixtures/test_vectors/vectors/awses-decrypt/
├── manifest.json
├── keys.json
├── plaintexts/
│   ├── small (~3KB)
│   └── tiny
└── ciphertexts/
    ├── 7bb5cace-2274-4134-957d-0426c9f96637  # us-west-2-mrk
    ├── af7b820f-b4a9-48a2-8afc-40b747220f69  # us-east-1-mrk
    ├── dd7a49cf-e9d6-425a-ba14-df40002a82ff  # us-west-2-mrk + encrypt-only
    └── 4de0e71e-08ef-4a80-af61-8268f10021ab  # us-east-1-mrk + encrypt-only
```

## Implementation Considerations

### Struct Definition

```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrk do
  @type t :: %__MODULE__{
    kms_key_id: String.t(),
    kms_client: struct(),
    grant_tokens: [String.t()]
  }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]
end
```

**Note**: Identical struct to `AwsKms` - the difference is in behavior.

### Key Differences from Basic KMS Keyring

| Aspect | AwsKms Keyring | AwsKmsMrk Keyring |
|--------|----------------|-------------------|
| **OnEncrypt** | Same | **Same** (no difference) |
| **OnDecrypt - Key Matching** | Uses `mrk_match?/2` | Uses `mrk_match?/2` (same!) |
| **OnDecrypt - Decrypt KeyId** | Uses configured key | Uses configured key (same!) |
| **Response Validation** | Uses `mrk_match?/2` | Uses `mrk_match?/2` (same!) |

Wait - looking at this table, the behaviors are identical! Let me re-check the spec...

After reviewing the specification again:
- **Basic KMS Keyring spec** (aws-kms-keyring.md): Uses exact matching
- **MRK Keyring spec** (aws-kms-mrk-keyring.md): Uses MRK matching

**However**, our current `AwsKms` implementation already uses `mrk_match?/2`, which makes it MRK-aware. This was likely intentional to simplify the implementation.

### Implementation Decision

Given that `AwsKms` already has MRK-aware behavior, creating `AwsKmsMrk` would be:
1. **For spec compliance** - explicit MRK keyring type
2. **For user clarity** - users know they're using MRK features
3. **For future differentiation** - could add MRK-specific features like warnings

The simplest approach: `AwsKmsMrk` can **delegate** to or **alias** `AwsKms` since the behavior is the same, just with a different module name for semantic clarity.

### Technical Approach

#### Option A: Thin Wrapper (Recommended)
```elixir
defmodule AwsEncryptionSdk.Keyring.AwsKmsMrk do
  alias AwsEncryptionSdk.Keyring.AwsKms

  # Same struct as AwsKms
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]

  # Delegate to AwsKms, converting struct types
  def new(kms_key_id, kms_client, opts \\ []) do
    with {:ok, inner} <- AwsKms.new(kms_key_id, kms_client, opts) do
      {:ok, %__MODULE__{
        kms_key_id: inner.kms_key_id,
        kms_client: inner.kms_client,
        grant_tokens: inner.grant_tokens
      }}
    end
  end

  def wrap_key(%__MODULE__{} = keyring, materials) do
    AwsKms.wrap_key(to_aws_kms(keyring), materials)
  end

  def unwrap_key(%__MODULE__{} = keyring, materials, edks) do
    AwsKms.unwrap_key(to_aws_kms(keyring), materials, edks)
  end

  defp to_aws_kms(%__MODULE__{} = keyring) do
    %AwsKms{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end
end
```

#### Option B: Copy Implementation
Duplicate the `AwsKms` code into `AwsKmsMrk`. More code but clearer separation.

**Recommendation**: Option A - thin wrapper. The behavior is identical, so delegation avoids duplication.

### Potential Challenges

1. **CMM Dispatch**: Need to add dispatch clause for `%AwsKmsMrk{}`
2. **Multi-Keyring Dispatch**: Need to add dispatch clause for `%AwsKmsMrk{}`
3. **Testing Cross-Region**: Need mock setup that simulates different regional KMS responses
4. **Non-MRK Warning**: MAY add warning when configured key isn't an MRK

### Open Questions

1. **Should we warn for non-MRK keys?** The spec says MAY warn. Probably good practice to log at `:info` level when using MRK keyring with non-MRK key.

2. **Should we validate the key is an MRK?** No - per spec, non-MRK keys still work (with exact matching). The MRK keyring just enables cross-region MRK matching when applicable.

3. **Integration with Discovery?** The MRK Discovery keyring (future issue) will need different logic - it reconstructs ARNs with the client's region. That's separate from this issue.

## Files to Create

- `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex` - MRK keyring implementation
- `test/aws_encryption_sdk/keyring/aws_kms_mrk_test.exs` - Unit tests

## Files to Modify

- `lib/aws_encryption_sdk/cmm/default.ex` - Add dispatch clause for `%AwsKmsMrk{}`
- `lib/aws_encryption_sdk/keyring/multi.ex` - Add dispatch clause for `%AwsKmsMrk{}`

## Example Usage

```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsMrk
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Create KMS client in us-west-2
kms_client = ExAws.new(region: "us-west-2")

# Create MRK keyring with us-west-2 replica
# Can decrypt data encrypted with us-east-1 replica of same MRK
{:ok, keyring} = AwsKmsMrk.new(
  "arn:aws:kms:us-west-2:123456789012:key/mrk-1234abcd",
  kms_client
)

# Encryption works same as basic keyring
{:ok, materials} = AwsKmsMrk.wrap_key(keyring, encryption_materials)

# Decryption can handle EDKs from any region's replica of the MRK
{:ok, materials} = AwsKmsMrk.unwrap_key(keyring, decryption_materials, edks)
```

## MRK Matching Examples

```elixir
# These two ARNs "MRK match" - same MRK in different regions
"arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd"
"arn:aws:kms:us-west-2:123456789012:key/mrk-1234abcd"
# => KmsKeyArn.mrk_match?(...) returns true

# These do NOT match - different key IDs
"arn:aws:kms:us-east-1:123456789012:key/mrk-1234abcd"
"arn:aws:kms:us-east-1:123456789012:key/mrk-5678efgh"
# => KmsKeyArn.mrk_match?(...) returns false

# These do NOT match - non-MRK keys require exact match
"arn:aws:kms:us-east-1:123456789012:key/1234abcd"
"arn:aws:kms:us-west-2:123456789012:key/1234abcd"
# => KmsKeyArn.mrk_match?(...) returns false
```

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-28-GH50-aws-kms-mrk-keyring.md`
2. Ensure AWS KMS Discovery Keyring (#49) is complete first
3. Implement MRK keyring as thin wrapper over AwsKms
4. Add dispatch clauses to CMM and Multi-keyring
5. Add unit tests with mock KMS client
6. Add test vector integration tests for cross-region scenarios

## References

- Issue: https://github.com/[owner]/[repo]/issues/50
- Spec - MRK Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
