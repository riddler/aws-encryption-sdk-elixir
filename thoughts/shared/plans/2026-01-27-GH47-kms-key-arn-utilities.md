# KMS Key ARN Utilities Implementation Plan

## Overview

Implement utility functions for parsing, validating, and comparing AWS KMS key ARNs, including support for Multi-Region Key (MRK) identification and matching. These utilities are foundational for all KMS keyring implementations.

**Issue**: #47
**Research**: `thoughts/shared/research/2026-01-27-GH47-kms-key-arn-utilities.md`

## Specification Requirements

### Source Documents
- [aws-kms-key-arn.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md) - ARN format and MRK identification
- [aws-kms-mrk-match-for-decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md) - MRK matching algorithm

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| ARN must start with "arn" | aws-kms-key-arn.md | MUST |
| Partition must be non-empty | aws-kms-key-arn.md | MUST |
| Service must be "kms" | aws-kms-key-arn.md | MUST |
| Region must be non-empty | aws-kms-key-arn.md | MUST |
| Account must be non-empty | aws-kms-key-arn.md | MUST |
| Resource section must be non-empty with "/" separator | aws-kms-key-arn.md | MUST |
| Resource type must be "alias" or "key" | aws-kms-key-arn.md | MUST |
| Resource ID must be non-empty | aws-kms-key-arn.md | MUST |
| Invalid ARN must error | aws-kms-key-arn.md | MUST |
| Alias resource type returns false for MRK check | aws-kms-key-arn.md | MUST |
| Key with "mrk-" prefix returns true for MRK check | aws-kms-key-arn.md | MUST |
| Key without "mrk-" prefix returns false for MRK check | aws-kms-key-arn.md | MUST |
| Identifier starting with "alias/" returns false for MRK | aws-kms-key-arn.md | MUST |
| Identifier starting with "mrk-" returns true for MRK | aws-kms-key-arn.md | MUST |
| Identical identifiers must return true for match | aws-kms-mrk-match-for-decrypt.md | MUST |
| Non-MRK identifier must return false for match | aws-kms-mrk-match-for-decrypt.md | MUST |
| MRK match compares all parts except region | aws-kms-mrk-match-for-decrypt.md | MUST |

## Test Data

### Test Data Source
Test data is sourced from `test/fixtures/test_vectors/vectors/awses-decrypt/keys.json`.

### Valid ARNs (4 entries)

| Key Name | ARN | Is MRK |
|----------|-----|--------|
| `us-west-2-decryptable` | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | No |
| `us-west-2-encrypt-only` | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | No |
| `us-west-2-mrk` | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |
| `us-east-1-mrk` | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |

### Invalid ARNs (21 entries from keys.json)

| Invalid ARN | Error Type |
|-------------|------------|
| `aws:kms:us-west-2:658956600833:key:mrk-...` | Invalid prefix (not "arn") |
| `:aws:kms:us-west-2:658956600833:key/mrk-...` | Empty prefix |
| `arn-not:aws:kms:us-west-2:658956600833:key/mrk-...` | Invalid prefix |
| `arn:kms:us-west-2:658956600833:key:mrk-...` | Missing partition (5 parts instead of 6) |
| `arn::kms:us-west-2:658956600833:key/mrk-...` | Empty partition |
| `arn:aws-not:kms:us-west-2:658956600833:key/mrk-...` | Invalid partition (valid - non-empty string) |
| `arn:aws:us-west-2:658956600833:key:mrk-...` | Missing service (5 parts instead of 6) |
| `arn:aws::us-west-2:658956600833:key/mrk-...` | Empty service |
| `arn:aws:kms-not:us-west-2:658956600833:key/mrk-...` | Invalid service (not "kms") |
| `arn:aws:kms:658956600833:key:mrk-...` | Missing region (5 parts instead of 6) |
| `arn:aws:kms::658956600833:key/mrk-...` | Empty region |
| `arn:aws:kms:us-west-2:key:mrk-...` | Missing account (5 parts instead of 6) |
| `arn:aws:kms:us-west-2::key/mrk-...` | Empty account |
| `arn:aws:kms:us-west-2:658956600833-not:key/mrk-...` | Invalid account (valid - non-empty string) |
| `arn:aws:kms:us-west-2:658956600833:mrk-...` | Missing resource type separator |
| `arn:aws:kms:us-west-2:658956600833:/mrk-...` | Empty resource type |
| `arn:aws:kms:us-west-2:658956600833:key-not/mrk-...` | Invalid resource type |
| `arn:aws:kms:us-west-2:658956600833:key` | Missing resource ID |
| `arn:aws:kms:us-west-2:658956600833:key/` | Empty resource ID |
| `arn:aws:kms:us-west-2:658956600833:key/mrk-...-not` | Valid ARN, not MRK (doesn't start with "mrk-") |
| `arn:aws:kms:us-west-2:658956600833:alias/mrk-...` | Valid ARN, alias type (not MRK) |
| `mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Not an ARN (raw MRK identifier) |

**Note**: Several entries in keys.json are invalid because they use `:` instead of `/` as the resource separator (e.g., `key:mrk-...` instead of `key/mrk-...`). These fail the "exactly 5 colons" requirement. The entry `arn:aws-not:...` is actually valid per spec since partition only needs to be non-empty.

## Current State Analysis

### What Exists Now
- Keyring behaviour in `lib/aws_encryption_sdk/keyring/behaviour.ex` with validation patterns
- Raw AES/RSA keyrings following consistent patterns
- Encryption context serialization utilities showing parsing patterns

### What's Missing
- KMS key ARN parsing and validation
- MRK identification logic
- MRK matching for decrypt

### Key Patterns to Follow

**Struct Definition Pattern** (from `raw_aes.ex`):
```elixir
@type t :: %__MODULE__{
        field1: String.t(),
        field2: String.t()
      }

@enforce_keys [:field1, :field2]
defstruct @enforce_keys
```

**Validation Chain Pattern** (from `raw_aes.ex:85-98`):
```elixir
def new(arg1, arg2) do
  with :ok <- validate_step1(arg1),
       {:ok, result} <- validate_step2(arg2) do
    {:ok, %__MODULE__{...}}
  end
end
```

**Error Handling Pattern**:
- Simple errors: `{:error, :error_name}`
- Errors with context: `{:error, {:error_name, expected: x, actual: y}}`

## Desired End State

After this plan is complete:

1. **Module exists** at `lib/aws_encryption_sdk/keyring/kms_key_arn.ex`

2. **Public API**:
   - `parse/1` - Parse ARN string into struct, returns `{:ok, t()} | {:error, term()}`
   - `mrk?/1` - Check if ARN struct or identifier string is MRK, returns `boolean()`
   - `mrk_match?/2` - Check if two identifiers match per MRK rules, returns `boolean()`
   - `to_string/1` - Reconstruct ARN string from struct
   - `arn?/1` - Check if string is an ARN format

3. **Verification**:
   - All 4 valid ARNs from keys.json parse successfully
   - All 21 invalid ARNs return appropriate errors
   - MRK detection works for both ARN and raw identifier formats
   - MRK matching correctly handles cross-region MRK pairs

## What We're NOT Doing

- AWS KMS API integration (that's #48)
- KMS client abstraction (that's #46)
- Full keyring implementation
- Account ID format validation (12-digit check) - spec only requires non-empty
- Region name validation against known regions - spec only requires non-empty
- Caching or performance optimization

## Implementation Approach

The implementation follows a bottom-up approach:
1. Define the struct to hold parsed ARN components
2. Implement parsing with comprehensive validation
3. Add MRK identification (depends on parsing)
4. Add MRK matching (depends on MRK identification)
5. Add utility functions (to_string, arn?)

---

## Phase 1: Struct Definition and Basic Parsing

### Overview
Define the `KmsKeyArn` struct and implement basic ARN parsing with all validation rules from the spec.

### Spec Requirements Addressed
- ARN must start with "arn"
- Partition must be non-empty
- Service must be "kms"
- Region must be non-empty
- Account must be non-empty
- Resource section must be non-empty with "/" separator
- Resource type must be "alias" or "key"
- Resource ID must be non-empty
- Invalid ARN must error

### Test Cases for This Phase

**Valid ARN Parsing:**
| Input | Expected Result |
|-------|-----------------|
| `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | `{:ok, %KmsKeyArn{partition: "aws", service: "kms", region: "us-west-2", account: "658956600833", resource_type: "key", resource_id: "b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"}}` |
| `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Success with MRK resource_id |
| `arn:aws:kms:us-west-2:658956600833:alias/my-alias` | Success with resource_type: "alias" |

**Invalid ARN Errors:**
| Input | Expected Error |
|-------|----------------|
| `aws:kms:us-west-2:658956600833:key:mrk-...` | `{:error, :invalid_prefix}` |
| `:aws:kms:us-west-2:658956600833:key/mrk-...` | `{:error, :invalid_prefix}` |
| `arn-not:aws:kms:us-west-2:658956600833:key/mrk-...` | `{:error, :invalid_prefix}` |
| `arn::kms:us-west-2:658956600833:key/mrk-...` | `{:error, :empty_partition}` |
| `arn:aws::us-west-2:658956600833:key/mrk-...` | `{:error, :empty_service}` |
| `arn:aws:kms-not:us-west-2:658956600833:key/mrk-...` | `{:error, :invalid_service}` |
| `arn:aws:kms::658956600833:key/mrk-...` | `{:error, :empty_region}` |
| `arn:aws:kms:us-west-2::key/mrk-...` | `{:error, :empty_account}` |
| `arn:aws:kms:us-west-2:658956600833:mrk-...` | `{:error, :invalid_resource_section}` |
| `arn:aws:kms:us-west-2:658956600833:/mrk-...` | `{:error, :empty_resource_type}` |
| `arn:aws:kms:us-west-2:658956600833:key-not/mrk-...` | `{:error, :invalid_resource_type}` |
| `arn:aws:kms:us-west-2:658956600833:key` | `{:error, :invalid_resource_section}` |
| `arn:aws:kms:us-west-2:658956600833:key/` | `{:error, :empty_resource_id}` |

### Changes Required:

#### 1. Create KmsKeyArn Module
**File**: `lib/aws_encryption_sdk/keyring/kms_key_arn.ex`
**Changes**: New file with struct definition and parse function

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsKeyArn do
  @moduledoc """
  AWS KMS Key ARN parsing, validation, and MRK matching utilities.

  Implements the AWS Encryption SDK specification for KMS key identifiers:
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md

  ## ARN Format

  AWS KMS ARNs follow the format:
  `arn:partition:kms:region:account:resource-type/resource-id`

  Example: `arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab`

  ## Multi-Region Keys (MRK)

  Multi-Region keys have resource IDs that start with `mrk-`. They can be used
  interchangeably across regions for decrypt operations.
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
  defstruct @enforce_keys

  @valid_resource_types ["alias", "key"]

  @doc """
  Parses an AWS KMS ARN string into a structured format.

  ## Parameters

  - `arn_string` - A string containing an AWS KMS ARN

  ## Returns

  - `{:ok, t()}` on successful parsing
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :invalid_prefix}` - ARN does not start with "arn"
  - `{:error, :empty_partition}` - Partition component is empty
  - `{:error, :empty_service}` - Service component is empty
  - `{:error, :invalid_service}` - Service is not "kms"
  - `{:error, :empty_region}` - Region component is empty
  - `{:error, :empty_account}` - Account component is empty
  - `{:error, :invalid_resource_section}` - Resource section missing "/" separator
  - `{:error, :empty_resource_type}` - Resource type is empty
  - `{:error, :invalid_resource_type}` - Resource type not "alias" or "key"
  - `{:error, :empty_resource_id}` - Resource ID is empty

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123456789012:key/1234abcd")
      {:ok, %AwsEncryptionSdk.Keyring.KmsKeyArn{
        partition: "aws",
        service: "kms",
        region: "us-west-2",
        account: "123456789012",
        resource_type: "key",
        resource_id: "1234abcd"
      }}

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.parse("invalid")
      {:error, :invalid_prefix}

  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(arn_string) when is_binary(arn_string) do
    parts = String.split(arn_string, ":", parts: 6)

    with :ok <- validate_part_count(parts),
         [prefix, partition, service, region, account, resource] = parts,
         :ok <- validate_prefix(prefix),
         :ok <- validate_partition(partition),
         :ok <- validate_service(service),
         :ok <- validate_region(region),
         :ok <- validate_account(account),
         {:ok, {resource_type, resource_id}} <- parse_resource(resource) do
      {:ok,
       %__MODULE__{
         partition: partition,
         service: service,
         region: region,
         account: account,
         resource_type: resource_type,
         resource_id: resource_id
       }}
    end
  end

  # Private validation functions

  defp validate_part_count(parts) when length(parts) == 6, do: :ok
  defp validate_part_count(_parts), do: {:error, :invalid_arn_format}

  defp validate_prefix("arn"), do: :ok
  defp validate_prefix(_), do: {:error, :invalid_prefix}

  defp validate_partition(""), do: {:error, :empty_partition}
  defp validate_partition(_), do: :ok

  defp validate_service(""), do: {:error, :empty_service}
  defp validate_service("kms"), do: :ok
  defp validate_service(_), do: {:error, :invalid_service}

  defp validate_region(""), do: {:error, :empty_region}
  defp validate_region(_), do: :ok

  defp validate_account(""), do: {:error, :empty_account}
  defp validate_account(_), do: :ok

  defp parse_resource(resource) do
    case String.split(resource, "/", parts: 2) do
      [_type_only] ->
        {:error, :invalid_resource_section}

      [type, ""] ->
        if type == "", do: {:error, :invalid_resource_section}, else: {:error, :empty_resource_id}

      ["", _id] ->
        {:error, :empty_resource_type}

      [type, id] ->
        if type in @valid_resource_types do
          {:ok, {type, id}}
        else
          {:error, :invalid_resource_type}
        end
    end
  end
end
```

#### 2. Create Test File
**File**: `test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
**Changes**: New test file with comprehensive parsing tests

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsKeyArnTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.KmsKeyArn

  describe "parse/1" do
    test "parses valid standard key ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.partition == "aws"
      assert parsed.service == "kms"
      assert parsed.region == "us-west-2"
      assert parsed.account == "658956600833"
      assert parsed.resource_type == "key"
      assert parsed.resource_id == "b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    end

    test "parses valid MRK ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.resource_type == "key"
      assert parsed.resource_id == "mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    end

    test "parses valid alias ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:alias/my-alias"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.resource_type == "alias"
      assert parsed.resource_id == "my-alias"
    end

    test "parses ARN with non-standard partition" do
      arn = "arn:aws-cn:kms:cn-north-1:658956600833:key/1234abcd"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.partition == "aws-cn"
    end

    # Invalid prefix tests
    test "rejects ARN not starting with arn" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse("aws:kms:us-west-2:658956600833:key:mrk-123")
    end

    test "rejects ARN with empty prefix" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse(":aws:kms:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with wrong prefix" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse("arn-not:aws:kms:us-west-2:658956600833:key/mrk-123")
    end

    # Empty component tests
    test "rejects ARN with empty partition" do
      assert {:error, :empty_partition} =
               KmsKeyArn.parse("arn::kms:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with empty service" do
      assert {:error, :empty_service} =
               KmsKeyArn.parse("arn:aws::us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with invalid service" do
      assert {:error, :invalid_service} =
               KmsKeyArn.parse("arn:aws:kms-not:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with empty region" do
      assert {:error, :empty_region} =
               KmsKeyArn.parse("arn:aws:kms::658956600833:key/mrk-123")
    end

    test "rejects ARN with empty account" do
      assert {:error, :empty_account} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2::key/mrk-123")
    end

    # Resource section tests
    test "rejects ARN with missing resource separator" do
      assert {:error, :invalid_resource_section} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:mrk-123")
    end

    test "rejects ARN with empty resource type" do
      assert {:error, :empty_resource_type} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:/mrk-123")
    end

    test "rejects ARN with invalid resource type" do
      assert {:error, :invalid_resource_type} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key-not/mrk-123")
    end

    test "rejects ARN with missing resource id" do
      assert {:error, :invalid_resource_section} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key")
    end

    test "rejects ARN with empty resource id" do
      assert {:error, :empty_resource_id} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key/")
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
- [x] Code compiles: `mix compile --warnings-as-errors`
- [x] Quality checks: `mix quality --quick`

#### Manual Verification:
- [x] Verify struct fields are correct in IEx:
  ```elixir
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123456789012:key/test-key")
  arn.partition  # => "aws"
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: MRK Identification

### Overview
Implement the `mrk?/1` function that determines if a key identifier (ARN or raw identifier) represents a Multi-Region Key.

### Spec Requirements Addressed
- Alias resource type returns false for MRK check
- Key with "mrk-" prefix returns true for MRK check
- Key without "mrk-" prefix returns false for MRK check
- Identifier starting with "arn:" uses ARN-based logic
- Identifier starting with "alias/" returns false for MRK
- Identifier starting with "mrk-" returns true for MRK
- Other identifiers return false for MRK

### Test Cases for This Phase

**ARN-based MRK Detection:**
| Input | Expected |
|-------|----------|
| `%KmsKeyArn{resource_type: "key", resource_id: "mrk-..."}` | `true` |
| `%KmsKeyArn{resource_type: "key", resource_id: "b3537ef1-..."}` | `false` |
| `%KmsKeyArn{resource_type: "alias", resource_id: "mrk-..."}` | `false` |

**String Identifier MRK Detection:**
| Input | Expected |
|-------|----------|
| `"arn:aws:kms:us-west-2:123:key/mrk-abc"` | `true` |
| `"arn:aws:kms:us-west-2:123:key/normal-key"` | `false` |
| `"arn:aws:kms:us-west-2:123:alias/mrk-lookalike"` | `false` |
| `"mrk-80bd8ecdcd4342aebd84b7dc9da498a7"` | `true` |
| `"alias/my-alias"` | `false` |
| `"b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"` | `false` |

### Changes Required:

#### 1. Add MRK Detection Functions
**File**: `lib/aws_encryption_sdk/keyring/kms_key_arn.ex`
**Changes**: Add `mrk?/1`, `arn?/1` functions

```elixir
  @doc """
  Checks if a string looks like an ARN (starts with "arn:").

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.arn?("arn:aws:kms:us-west-2:123:key/abc")
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.arn?("mrk-123")
      false

  """
  @spec arn?(String.t()) :: boolean()
  def arn?(identifier) when is_binary(identifier) do
    String.starts_with?(identifier, "arn:")
  end

  @doc """
  Determines if a key identifier represents a Multi-Region Key (MRK).

  Accepts either a parsed `KmsKeyArn` struct or a string identifier.

  ## Parameters

  - `arn_or_identifier` - A `KmsKeyArn` struct or string key identifier

  ## Returns

  - `true` if the identifier represents an MRK
  - `false` otherwise

  ## Rules

  For ARN structs:
  - Resource type "alias" always returns false
  - Resource type "key" with ID starting with "mrk-" returns true
  - Otherwise returns false

  For string identifiers:
  - Strings starting with "arn:" are parsed and checked as ARNs
  - Strings starting with "alias/" return false
  - Strings starting with "mrk-" return true
  - All other strings return false

  ## Examples

      iex> {:ok, arn} = AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/mrk-abc")
      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?(arn)
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?("mrk-abc123")
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?("alias/my-key")
      false

  """
  @spec mrk?(t() | String.t()) :: boolean()
  def mrk?(%__MODULE__{resource_type: "alias"}), do: false

  def mrk?(%__MODULE__{resource_type: "key", resource_id: resource_id}) do
    String.starts_with?(resource_id, "mrk-")
  end

  def mrk?(%__MODULE__{}), do: false

  def mrk?(identifier) when is_binary(identifier) do
    cond do
      arn?(identifier) ->
        case parse(identifier) do
          {:ok, arn} -> mrk?(arn)
          {:error, _} -> false
        end

      String.starts_with?(identifier, "alias/") ->
        false

      String.starts_with?(identifier, "mrk-") ->
        true

      true ->
        false
    end
  end
```

#### 2. Add MRK Detection Tests
**File**: `test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
**Changes**: Add test cases for `mrk?/1`

```elixir
  describe "mrk?/1 with struct" do
    test "returns true for key with mrk- prefix" do
      {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/mrk-abc123")
      assert KmsKeyArn.mrk?(arn) == true
    end

    test "returns false for key without mrk- prefix" do
      {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")
      assert KmsKeyArn.mrk?(arn) == false
    end

    test "returns false for alias even with mrk- in name" do
      {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:alias/mrk-lookalike")
      assert KmsKeyArn.mrk?(arn) == false
    end
  end

  describe "mrk?/1 with string identifier" do
    test "returns true for MRK ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:key/mrk-abc") == true
    end

    test "returns false for non-MRK ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:key/normal-key") == false
    end

    test "returns false for alias ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:alias/mrk-lookalike") == false
    end

    test "returns true for raw mrk- identifier" do
      assert KmsKeyArn.mrk?("mrk-80bd8ecdcd4342aebd84b7dc9da498a7") == true
    end

    test "returns false for alias/ identifier" do
      assert KmsKeyArn.mrk?("alias/my-alias") == false
    end

    test "returns false for regular key id" do
      assert KmsKeyArn.mrk?("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") == false
    end

    test "returns false for invalid ARN" do
      assert KmsKeyArn.mrk?("arn:invalid:format") == false
    end
  end

  describe "arn?/1" do
    test "returns true for ARN strings" do
      assert KmsKeyArn.arn?("arn:aws:kms:us-west-2:123:key/abc") == true
    end

    test "returns false for non-ARN strings" do
      assert KmsKeyArn.arn?("mrk-123") == false
      assert KmsKeyArn.arn?("alias/my-key") == false
      assert KmsKeyArn.arn?("key-id") == false
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
- [x] Quality checks: `mix quality --quick`

#### Manual Verification:
- [x] Verify MRK detection in IEx:
  ```elixir
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:key/mrk-abc")  # => true
  KmsKeyArn.mrk?("mrk-abc")  # => true
  KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:alias/mrk-lookalike")  # => false
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 3: MRK Match for Decrypt

### Overview
Implement the `mrk_match?/2` function that determines if two key identifiers can be used interchangeably for decrypt operations.

### Spec Requirements Addressed
- Identical identifiers must return true for match
- Non-MRK identifier must return false for match
- MRK match compares all parts except region

### Test Cases for This Phase

| Identifier A | Identifier B | Expected | Reason |
|--------------|--------------|----------|--------|
| `arn:aws:kms:us-west-2:123:key/mrk-abc` | `arn:aws:kms:us-east-1:123:key/mrk-abc` | `true` | Same MRK, different regions |
| `arn:aws:kms:us-west-2:123:key/mrk-abc` | `arn:aws:kms:us-west-2:123:key/mrk-abc` | `true` | Identical |
| `arn:aws:kms:us-west-2:123:key/mrk-abc` | `arn:aws:kms:us-west-2:123:key/normal` | `false` | Second is not MRK |
| `arn:aws:kms:us-west-2:123:key/normal` | `arn:aws:kms:us-west-2:123:key/normal` | `true` | Identical (even non-MRK) |
| `arn:aws:kms:us-west-2:123:key/normal1` | `arn:aws:kms:us-west-2:123:key/normal2` | `false` | Neither is MRK, not identical |
| `mrk-abc` | `mrk-abc` | `true` | Identical raw identifiers |
| `mrk-abc` | `mrk-def` | `false` | Different MRK IDs |
| `arn:aws:kms:us-west-2:123:key/mrk-abc` | `arn:aws:kms:us-west-2:456:key/mrk-abc` | `false` | Different accounts |
| `arn:aws:kms:us-west-2:123:alias/mrk-a` | `arn:aws:kms:us-east-1:123:alias/mrk-a` | `false` | Aliases are never MRKs |

### Changes Required:

#### 1. Add MRK Match Function
**File**: `lib/aws_encryption_sdk/keyring/kms_key_arn.ex`
**Changes**: Add `mrk_match?/2` function

```elixir
  @doc """
  Determines if two key identifiers match for decrypt purposes.

  This implements the AWS KMS MRK Match for Decrypt algorithm. Two identifiers
  match if:
  1. They are identical strings, OR
  2. Both are Multi-Region keys with the same partition, service, account,
     resource type, and resource ID (region may differ)

  ## Parameters

  - `identifier_a` - First AWS KMS key identifier (ARN or raw ID)
  - `identifier_b` - Second AWS KMS key identifier (ARN or raw ID)

  ## Returns

  - `true` if the identifiers match for decrypt purposes
  - `false` otherwise

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk_match?(
      ...>   "arn:aws:kms:us-west-2:123:key/mrk-abc",
      ...>   "arn:aws:kms:us-east-1:123:key/mrk-abc"
      ...> )
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk_match?(
      ...>   "arn:aws:kms:us-west-2:123:key/mrk-abc",
      ...>   "arn:aws:kms:us-west-2:123:key/normal-key"
      ...> )
      false

  """
  @spec mrk_match?(String.t(), String.t()) :: boolean()
  def mrk_match?(identifier_a, identifier_b)
      when is_binary(identifier_a) and is_binary(identifier_b) do
    # Rule 1: Identical identifiers always match
    if identifier_a == identifier_b do
      true
    else
      # Rule 2: Both must be MRKs to match across regions
      mrk_match_different_identifiers(identifier_a, identifier_b)
    end
  end

  defp mrk_match_different_identifiers(identifier_a, identifier_b) do
    # If either is not MRK, they can't match (since they're already not identical)
    if not mrk?(identifier_a) or not mrk?(identifier_b) do
      false
    else
      # Both are MRKs - compare all parts except region
      compare_mrk_components(identifier_a, identifier_b)
    end
  end

  defp compare_mrk_components(identifier_a, identifier_b) do
    # For raw MRK identifiers (mrk-xxx), compare directly
    if not arn?(identifier_a) and not arn?(identifier_b) do
      identifier_a == identifier_b
    else
      # At least one is an ARN - need to parse and compare components
      with {:ok, arn_a} <- parse_if_arn(identifier_a),
           {:ok, arn_b} <- parse_if_arn(identifier_b) do
        compare_arn_components_except_region(arn_a, arn_b)
      else
        _ -> false
      end
    end
  end

  defp parse_if_arn(identifier) do
    if arn?(identifier) do
      parse(identifier)
    else
      # Raw identifier - can't compare components
      {:error, :not_an_arn}
    end
  end

  defp compare_arn_components_except_region(%__MODULE__{} = a, %__MODULE__{} = b) do
    a.partition == b.partition and
      a.service == b.service and
      a.account == b.account and
      a.resource_type == b.resource_type and
      a.resource_id == b.resource_id
  end
```

#### 2. Add MRK Match Tests
**File**: `test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
**Changes**: Add test cases for `mrk_match?/2`

```elixir
  describe "mrk_match?/2" do
    test "returns true for identical ARNs" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn, arn) == true
    end

    test "returns true for identical non-MRK ARNs" do
      arn = "arn:aws:kms:us-west-2:123:key/normal-key"
      assert KmsKeyArn.mrk_match?(arn, arn) == true
    end

    test "returns true for same MRK in different regions" do
      arn_west = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_east = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_west, arn_east) == true
    end

    test "returns false when first is MRK but second is not" do
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_normal = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn_mrk, arn_normal) == false
    end

    test "returns false when second is MRK but first is not" do
      arn_normal = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_normal, arn_mrk) == false
    end

    test "returns false for different non-MRK keys" do
      arn1 = "arn:aws:kms:us-west-2:658956600833:key/key-1"
      arn2 = "arn:aws:kms:us-west-2:658956600833:key/key-2"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns true for identical raw MRK identifiers" do
      mrk_id = "mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(mrk_id, mrk_id) == true
    end

    test "returns false for different raw MRK identifiers" do
      assert KmsKeyArn.mrk_match?("mrk-abc", "mrk-def") == false
    end

    test "returns false for MRKs with different accounts" do
      arn1 = "arn:aws:kms:us-west-2:111111111111:key/mrk-abc"
      arn2 = "arn:aws:kms:us-west-2:222222222222:key/mrk-abc"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns false for MRKs with different partitions" do
      arn1 = "arn:aws:kms:us-west-2:123:key/mrk-abc"
      arn2 = "arn:aws-cn:kms:cn-north-1:123:key/mrk-abc"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns false for aliases even with matching mrk- in name" do
      alias1 = "arn:aws:kms:us-west-2:123:alias/mrk-lookalike"
      alias2 = "arn:aws:kms:us-east-1:123:alias/mrk-lookalike"
      assert KmsKeyArn.mrk_match?(alias1, alias2) == false
    end

    test "returns false for MRK ARN vs non-MRK raw identifier" do
      arn = "arn:aws:kms:us-west-2:123:key/mrk-abc"
      raw = "key-123"
      assert KmsKeyArn.mrk_match?(arn, raw) == false
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
- [x] Quality checks: `mix quality --quick`

#### Manual Verification:
- [x] Verify MRK matching in IEx:
  ```elixir
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  KmsKeyArn.mrk_match?(
    "arn:aws:kms:us-west-2:123:key/mrk-abc",
    "arn:aws:kms:us-east-1:123:key/mrk-abc"
  )  # => true
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 4: Utility Functions and Polish

### Overview
Add the `to_string/1` function for ARN reconstruction and ensure complete test coverage with all test data from keys.json.

### Spec Requirements Addressed
- MAY provide a function to construct ARNs from components

### Changes Required:

#### 1. Add to_string Function
**File**: `lib/aws_encryption_sdk/keyring/kms_key_arn.ex`
**Changes**: Add `to_string/1` function, implement String.Chars protocol

```elixir
  @doc """
  Reconstructs an ARN string from a parsed `KmsKeyArn` struct.

  ## Examples

      iex> {:ok, arn} = AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/abc")
      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.to_string(arn)
      "arn:aws:kms:us-west-2:123:key/abc"

  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = arn) do
    "arn:#{arn.partition}:#{arn.service}:#{arn.region}:#{arn.account}:#{arn.resource_type}/#{arn.resource_id}"
  end

  defimpl String.Chars do
    def to_string(arn) do
      AwsEncryptionSdk.Keyring.KmsKeyArn.to_string(arn)
    end
  end
```

#### 2. Add Complete Test Coverage from keys.json
**File**: `test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
**Changes**: Add tests using actual test vector data

```elixir
  describe "to_string/1" do
    test "reconstructs ARN from parsed struct" do
      original = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      {:ok, parsed} = KmsKeyArn.parse(original)
      assert KmsKeyArn.to_string(parsed) == original
    end

    test "works with String.Chars protocol" do
      {:ok, parsed} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/abc")
      assert "#{parsed}" == "arn:aws:kms:us-west-2:123:key/abc"
    end
  end

  describe "keys.json test vector validation" do
    # Valid ARNs from keys.json
    @valid_arns [
      {"us-west-2-decryptable", "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f", false},
      {"us-west-2-encrypt-only", "arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad", false},
      {"us-west-2-mrk", "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7", true},
      {"us-east-1-mrk", "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7", true}
    ]

    for {name, arn, is_mrk} <- @valid_arns do
      test "parses valid ARN: #{name}" do
        assert {:ok, parsed} = KmsKeyArn.parse(unquote(arn))
        assert KmsKeyArn.mrk?(parsed) == unquote(is_mrk)
        assert KmsKeyArn.to_string(parsed) == unquote(arn)
      end
    end

    # Invalid ARNs from keys.json that should fail parsing
    @invalid_arns [
      "aws:kms:us-west-2:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      ":aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn-not:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn::kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws::us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms-not:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms::658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2::key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:key-not/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:key",
      "arn:aws:kms:us-west-2:658956600833:key/"
    ]

    for arn <- @invalid_arns do
      test "rejects invalid ARN: #{arn}" do
        assert {:error, _reason} = KmsKeyArn.parse(unquote(arn))
      end
    end

    # These are valid ARNs but NOT MRKs
    @valid_non_mrk_arns [
      "arn:aws:kms:us-west-2:658956600833:alias/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7-not"
    ]

    for arn <- @valid_non_mrk_arns do
      test "parses but identifies as non-MRK: #{arn}" do
        assert {:ok, parsed} = KmsKeyArn.parse(unquote(arn))
        assert KmsKeyArn.mrk?(parsed) == false
      end
    end

    # MRK matching tests from keys.json
    test "us-west-2-mrk and us-east-1-mrk match" do
      arn_west = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_east = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_west, arn_east) == true
    end

    test "MRK does not match non-MRK key" do
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_key = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn_mrk, arn_key) == false
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/kms_key_arn_test.exs`
- [x] Full quality checks: `mix quality`
- [x] Doctests pass: `mix test --only doctest`

#### Manual Verification:
- [x] Verify round-trip parsing in IEx:
  ```elixir
  alias AwsEncryptionSdk.Keyring.KmsKeyArn
  original = "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123"
  {:ok, parsed} = KmsKeyArn.parse(original)
  "#{parsed}" == original  # => true
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the final verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All tests pass: `mix test`
- [x] Dialyzer passes: `mix dialyzer`

### Manual:
- [x] End-to-end verification in IEx with real-world ARN examples
- [x] Verify error messages are clear and helpful

## Testing Strategy

### Unit Tests:
- ARN parsing for valid and invalid inputs
- MRK identification for ARNs and raw identifiers
- MRK matching for various combinations
- Round-trip serialization

### Test Data Integration:
Tests use actual data from `test/fixtures/test_vectors/vectors/awses-decrypt/keys.json` to ensure compatibility with the broader test vector framework.

### Doctest Examples:
All public functions include doctest examples that serve as both documentation and automated tests.

### Manual Testing Steps:
1. Load module in IEx: `alias AwsEncryptionSdk.Keyring.KmsKeyArn`
2. Parse valid ARN and inspect all fields
3. Test MRK detection with various identifier formats
4. Test MRK matching with cross-region MRKs
5. Verify error handling with invalid inputs

## References

- Issue: #47
- Research: `thoughts/shared/research/2026-01-27-GH47-kms-key-arn-utilities.md`
- Spec - KMS Key ARN: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
- Spec - MRK Match: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md
- Test Vectors: `test/fixtures/test_vectors/vectors/awses-decrypt/keys.json`
