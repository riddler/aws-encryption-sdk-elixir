# Research: Implement KMS Key ARN Utilities

**Issue**: #47 - Implement KMS Key ARN Utilities
**Date**: 2026-01-27
**Status**: Research complete

## Issue Summary

Implement utility functions for parsing, validating, and comparing AWS KMS key ARNs, including support for Multi-Region Key (MRK) identification and matching. These utilities are foundational for all KMS keyring implementations (standard, discovery, MRK-aware).

## Current Implementation State

### Existing Code

The codebase has established patterns for keyrings and utility modules:

- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour with provider ID validation
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring (pattern reference)
- `lib/aws_encryption_sdk/keyring/raw_rsa.ex` - Raw RSA keyring (pattern reference)
- `lib/aws_encryption_sdk/keyring/multi.ex` - Multi-keyring with type-based dispatch
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EDK struct with `key_provider_id`, `key_provider_info`
- `lib/aws_encryption_sdk/format/encryption_context.ex` - Parsing/serialization utility (pattern reference)

### Relevant Patterns

**1. Module Structure for Utilities**
From `format/encryption_context.ex`:
- Pure functions with struct types
- Clear input/output types
- `@moduledoc` with specification references

**2. Struct Definition Pattern**
```elixir
defstruct [:field1, :field2, :field3]

@type t :: %__MODULE__{
  field1: String.t(),
  field2: String.t(),
  field3: String.t()
}
```

**3. Constructor Validation Pattern**
From `raw_aes.ex`:
```elixir
def new(arg1, arg2, arg3) do
  with :ok <- validate_step_1(arg1),
       :ok <- validate_step_2(arg2) do
    {:ok, %__MODULE__{...}}
  end
end
```

**4. Error Handling**
- `{:ok, result}` or `{:error, reason}` tuples
- Atomic error reasons: `:invalid_arn_format`, `:empty_partition`
- Tuple errors with context: `{:invalid_field, field_name, reason}`

### Dependencies

- None (pure utility module)
- Will be used by:
  - AWS KMS Keyring (#48)
  - AWS KMS Discovery Keyring
  - AWS KMS MRK-aware Keyrings

## Specification Requirements

### Source Documents

- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN format and MRK identification
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm
- [aws-kms-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md) - Key identifier validation in keyrings

### MUST Requirements

#### ARN Parsing (aws-kms-key-arn.md)

1. **Colon Count**
   > A valid AWS KMS ARN MUST contain exactly 5 colons creating 6 delimited sections

   Implementation: Split on `:` and validate `length(parts) == 6`

2. **Prefix Component**
   > MUST start with string `arn`

   Implementation: `hd(parts) == "arn"`

3. **Partition Component**
   > Partition component MUST be a non-empty string

   Implementation: `partition != ""`

4. **Service Component**
   > Service component MUST be the string `kms`

   Implementation: `service == "kms"`

5. **Region Component**
   > Region component MUST be a non-empty string

   Implementation: `region != ""`

6. **Account Component**
   > Account component MUST be a non-empty string

   Implementation: `account != ""`

7. **Resource Section**
   > Resource section MUST be non-empty and MUST be split by a single `/`

   Implementation: Split on first `/`, validate both parts non-empty

8. **Resource Type**
   > The resource type within the ARN MUST be either `alias` or `key`

   Implementation: `resource_type in ["alias", "key"]`

9. **Resource ID**
   > The resource id MUST be a non-empty string

   Implementation: `resource_id != ""`

#### MRK Identification (aws-kms-key-arn.md)

10. **Alias Not MRK**
    > If the resource type is "alias", the function MUST return false

    Implementation: Aliases are never MRKs

11. **MRK Key Detection**
    > When resource type is "key" and the ID begins with "mrk-", it MUST return true for multi-region status

    Implementation: `resource_type == "key" && String.starts_with?(resource_id, "mrk-")`

12. **Non-MRK Key Detection**
    > Otherwise, it MUST return false

    Implementation: Default to false for all other cases

13. **ARN-Prefixed Identifiers**
    > Inputs beginning with "arn:" MUST return the output of ARN-based identification logic

    Implementation: Parse as ARN first, then apply MRK rules

14. **Bare MRK Key IDs**
    > Identifiers beginning with "mrk-" represent multi-region keys and MUST return true

    Implementation: `String.starts_with?(identifier, "mrk-")` for non-ARN identifiers

15. **Alias Identifiers**
    > Identifiers starting with "alias/" MUST return false

    Implementation: Aliases are never MRKs

#### MRK Match for Decrypt (aws-kms-mrk-match-for-decrypt.md)

16. **Input Requirements**
    > The caller MUST provide: 2 AWS KMS key identifiers

    Implementation: Function signature `mrk_match?(identifier_a, identifier_b)`

17. **Identical Match**
    > If both identifiers are identical, this function MUST return `true`

    Implementation: `identifier_a == identifier_b` early return

18. **Non-MRK Handling**
    > If either identifier is not a multi-Region key, the function MUST return `false`

    Implementation: Check `mrk?/1` for both, return false if either is not MRK

19. **MRK Component Comparison**
    > When both inputs are multi-Region keys, the function MUST return the result of comparing the `partition`, `service`, `accountId`, `resourceType`, and `resource` parts

    Implementation: Compare all components EXCEPT region

### SHOULD Requirements

1. **Descriptive Error Messages**
   > Validation failures SHOULD include descriptive error information

   Implementation: Return specific error atoms/tuples for each validation failure

### MAY Requirements

1. **ARN Construction**
   > Implementations MAY provide a function to construct ARNs from components

   Implementation: `to_string/1` function for convenience

## Test Vectors

### Harness Setup

KMS ARN utilities don't have dedicated test vectors, but the test vector keys.json provides extensive test data:

```elixir
# Check for test vectors
TestVectorSetup.vectors_available?()

# Load keys manifest for ARN test data
{:ok, harness} = TestVectorHarness.load_manifest(
  "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
)

# Get key data with ARNs
{:ok, key_data} = TestVectorHarness.get_key(harness, "us-west-2-decryptable")
```

### Valid ARN Test Data (from keys.json)

| Key Name | ARN | Is MRK |
|----------|-----|--------|
| `us-west-2-decryptable` | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | No |
| `us-west-2-encrypt-only` | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | No |
| `us-west-2-mrk` | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |
| `us-east-1-mrk` | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |

### Invalid ARN Test Data (from keys.json)

The keys.json contains 21 malformed ARN entries (all marked `encrypt: false, decrypt: false`):

| Invalid ARN | Error Type |
|-------------|------------|
| `aws:kms:us-west-2:658956600833:key/mrk-...` | Missing "arn:" prefix |
| `:aws:kms:us-west-2:658956600833:key/mrk-...` | Empty prefix |
| `arn-not:aws:kms:us-west-2:658956600833:key/mrk-...` | Invalid prefix |
| `arn:kms:us-west-2:658956600833:key/mrk-...` | Missing partition |
| `arn::kms:us-west-2:658956600833:key/mrk-...` | Empty partition |
| `arn:aws:us-west-2:658956600833:key/mrk-...` | Missing service |
| `arn:aws::us-west-2:658956600833:key/mrk-...` | Empty service |
| `arn:aws:kms-not:us-west-2:658956600833:key/mrk-...` | Invalid service |
| `arn:aws:kms:658956600833:key/mrk-...` | Missing region |
| `arn:aws:kms::658956600833:key/mrk-...` | Empty region |
| `arn:aws:kms:us-west-2:key/mrk-...` | Missing account |
| `arn:aws:kms:us-west-2::key/mrk-...` | Empty account |
| `arn:aws:kms:us-west-2:658956600833:mrk-...` | Missing resource type |
| `arn:aws:kms:us-west-2:658956600833:/mrk-...` | Empty resource type |
| `arn:aws:kms:us-west-2:658956600833:key-not/mrk-...` | Invalid resource type |
| `arn:aws:kms:us-west-2:658956600833:key` | Missing resource ID |
| `arn:aws:kms:us-west-2:658956600833:key/` | Empty resource ID |
| `arn:aws:kms:us-west-2:658956600833:key:mrk-...` | Wrong separator (colon) |
| `arn:aws:kms:us-west-2:658956600833:key/mrk-...-not` | Invalid MRK ID format |
| `arn:aws:kms:us-west-2:658956600833:alias/mrk-...` | Alias with MRK prefix |
| `mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Raw MRK identifier (valid but not ARN) |

### MRK Match Test Cases

| Identifier A | Identifier B | Expected | Reason |
|--------------|--------------|----------|--------|
| `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd...` | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd...` | `true` | Same MRK, different regions |
| `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd...` | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd...` | `true` | Identical |
| `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd...` | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1...` | `false` | Second is not MRK |
| `arn:aws:kms:us-west-2:658956600833:key/b3537ef1...` | `arn:aws:kms:us-west-2:658956600833:key/590fd781...` | `false` | Neither is MRK |
| `mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | `mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | `true` | Raw identifiers match |
| `arn:aws:kms:us-west-2:658956600833:alias/mrk-lookalike` | `arn:aws:kms:us-east-1:658956600833:alias/mrk-lookalike` | `false` | Aliases are never MRKs |

### Implementation Order

#### Phase 1: ARN Parsing

| Test Category | Count | Priority |
|---------------|-------|----------|
| Valid standard ARN parsing | 2 | Start here |
| Valid MRK ARN parsing | 2 | Second |
| Invalid ARN format errors | 21 | Third |

#### Phase 2: MRK Identification

| Test Category | Count | Priority |
|---------------|-------|----------|
| ARN-based MRK detection | 4 | After parsing |
| Raw identifier MRK detection | 2 | After ARN tests |
| Alias edge cases | 2 | Last |

#### Phase 3: MRK Matching

| Test Category | Count | Priority |
|---------------|-------|----------|
| Identical match | 2 | Start here |
| Cross-region MRK match | 2 | Second |
| Non-MRK rejection | 4 | Third |
| Mixed format matching | 2 | Last |

## Implementation Considerations

### Technical Approach

#### Module Structure

```
lib/aws_encryption_sdk/keyring/
└── kms_key_arn.ex         # ARN parsing, MRK detection, MRK matching
```

Single module with clear function groupings:
1. Struct and type definitions
2. Parsing functions
3. MRK identification functions
4. MRK matching functions

#### Struct Definition

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsKeyArn do
  @moduledoc """
  AWS KMS Key ARN parsing, validation, and MRK matching utilities.

  Implements the AWS Encryption SDK specification for KMS key identifiers:
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
  """

  @type t :: %__MODULE__{
    partition: String.t(),
    service: String.t(),
    region: String.t(),
    account: String.t(),
    resource_type: String.t(),
    resource_id: String.t()
  }

  @enforce_keys [:partition, :service, :region, :account, :resource_type, :resource_id]
  defstruct [:partition, :service, :region, :account, :resource_type, :resource_id]
end
```

#### Key Functions

```elixir
# Parsing
@spec parse(String.t()) :: {:ok, t()} | {:error, term()}
def parse(arn_string)

# MRK identification
@spec mrk?(t() | String.t()) :: boolean()
def mrk?(arn_or_identifier)

# MRK matching
@spec mrk_match?(String.t(), String.t()) :: boolean()
def mrk_match?(identifier_a, identifier_b)

# Reconstruction
@spec to_string(t()) :: String.t()
def to_string(arn)

# ARN detection
@spec arn?(String.t()) :: boolean()
def arn?(identifier)
```

### Potential Challenges

1. **Resource Section Parsing**
   - Resource section format: `type/id` where id may contain `/`
   - Split on first `/` only, rest is resource ID
   - Example: `key/mrk-1234` → type: `key`, id: `mrk-1234`

2. **Mixed Identifier Formats**
   - MRK matching must handle: ARN vs ARN, ARN vs raw ID, raw ID vs raw ID
   - Raw IDs lack region/account for comparison
   - Spec says to parse both as ARNs if possible

3. **Edge Case: Alias with MRK Prefix**
   - `arn:aws:kms:us-west-2:123:alias/mrk-lookalike` is NOT an MRK
   - Only `key` resource type with `mrk-` prefix is MRK
   - Test data explicitly includes this case

4. **Partition Variations**
   - Standard: `aws`
   - China: `aws-cn`
   - GovCloud: `aws-us-gov`
   - Spec doesn't enumerate valid values; treat as non-empty string

### Open Questions

1. **Account ID Format Validation**
   - Should we validate 12-digit format?
   - Recommendation: No, treat as non-empty string per spec's pass-through approach

2. **Region Validation**
   - Should we validate against known regions?
   - Recommendation: No, just validate non-empty

3. **Raw ID Comparison in MRK Match**
   - When both inputs are raw IDs (`mrk-xxx`), they're identical strings
   - Spec says "compare all parts except region" but raw IDs have no region
   - Recommendation: If both are raw IDs and both start with `mrk-`, compare strings

## Recommended Next Steps

1. Create implementation plan:
   ```
   /create_plan thoughts/shared/research/2026-01-27-GH47-kms-key-arn-utilities.md
   ```

2. Implementation order:
   - Define struct and types
   - Implement `parse/1` with all validation
   - Implement `mrk?/1` for MRK identification
   - Implement `mrk_match?/2` for matching
   - Implement `to_string/1` for convenience
   - Comprehensive unit tests

3. After this issue:
   - Issue #46: KMS Client Abstraction (parallel work)
   - Issue #48: AWS KMS Keyring (depends on both #46 and #47)

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/47
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
- Spec - KMS Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
- Spec - MRK Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
