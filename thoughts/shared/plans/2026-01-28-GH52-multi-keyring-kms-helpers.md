# Multi-Keyring KMS Helpers Implementation Plan

## Overview

Add generator validation to prevent discovery keyrings from being used as generators, and implement convenience constructors for common KMS multi-keyring patterns.

**Issue**: #52

## Current State Analysis

### Already Complete
The core dispatch functionality is already implemented:
- Default CMM (`lib/aws_encryption_sdk/cmm/default.ex:91-156`) has pattern matches for all 4 KMS keyring types
- Multi-Keyring (`lib/aws_encryption_sdk/keyring/multi.ex:219-250, 303-334`) has pattern matches for all 4 KMS keyring types
- Discovery keyrings return `{:error, :discovery_keyring_cannot_encrypt}` from `wrap_key/2`

### Remaining Work
1. **Generator validation** - Multi.new/1 should reject discovery keyrings as generators at construction time (fail-fast)
2. **Helper constructors** - Convenience functions for common KMS patterns

### Key Discoveries
- Discovery keyrings (`AwsKmsDiscovery`, `AwsKmsMrkDiscovery`) are decrypt-only
- Using them as generators would fail at `wrap_key` time, but it's better to fail at construction time
- The `Multi.new/1` function already validates that at least one keyring is provided (`lib/aws_encryption_sdk/keyring/multi.ex:114-116`)

## Desired End State

After implementation:
1. `Multi.new(generator: discovery_keyring)` returns `{:error, :discovery_keyring_cannot_be_generator}`
2. `Multi.new_with_kms_generator/3` creates a multi-keyring with KMS generator in one call
3. `Multi.new_mrk_aware/3` creates a multi-region aware multi-keyring for cross-region scenarios
4. All existing tests continue to pass

## What We're NOT Doing

- Not modifying the dispatch functions (already complete)
- Not adding new keyring types
- Not changing the keyring behaviour interface
- Not adding integration tests with real AWS KMS (would require credentials)

---

## Phase 1: Generator Validation

### Overview
Add validation to `Multi.new/1` that rejects discovery keyrings as generators at construction time.

### Changes Required

#### 1. Multi-Keyring Validation
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add validation function and call it in `new/1`

```elixir
# After line 126, add new validation function:
defp validate_generator_can_encrypt(nil), do: :ok

defp validate_generator_can_encrypt(%AwsKmsDiscovery{}) do
  {:error, :discovery_keyring_cannot_be_generator}
end

defp validate_generator_can_encrypt(%AwsKmsMrkDiscovery{}) do
  {:error, :discovery_keyring_cannot_be_generator}
end

defp validate_generator_can_encrypt(_generator), do: :ok
```

```elixir
# Modify new/1 to add validation (around line 114):
def new(opts \\ []) when is_list(opts) do
  generator = Keyword.get(opts, :generator)
  children = Keyword.get(opts, :children, [])

  with :ok <- validate_at_least_one_keyring(generator, children),
       :ok <- validate_generator_when_no_children(generator, children),
       :ok <- validate_generator_can_encrypt(generator) do  # NEW
    {:ok, %__MODULE__{generator: generator, children: children}}
  end
end
```

#### 2. Unit Tests
**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add tests for generator validation

```elixir
describe "new/1 generator validation" do
  test "rejects AwsKmsDiscovery as generator" do
    {:ok, client} = KmsClient.Mock.new(%{})
    {:ok, discovery} = AwsKmsDiscovery.new(client)

    assert {:error, :discovery_keyring_cannot_be_generator} =
      Multi.new(generator: discovery)
  end

  test "rejects AwsKmsMrkDiscovery as generator" do
    {:ok, client} = KmsClient.Mock.new(%{})
    {:ok, mrk_discovery} = AwsKmsMrkDiscovery.new(client, "us-west-2")

    assert {:error, :discovery_keyring_cannot_be_generator} =
      Multi.new(generator: mrk_discovery)
  end

  test "allows discovery keyrings as children" do
    {:ok, client} = KmsClient.Mock.new(%{})
    {:ok, kms} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", client)
    {:ok, discovery} = AwsKmsDiscovery.new(client)

    assert {:ok, multi} = Multi.new(generator: kms, children: [discovery])
    assert multi.children == [discovery]
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, verify `Multi.new(generator: discovery_keyring)` returns the expected error

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Helper Constructor - new_with_kms_generator

### Overview
Add `Multi.new_with_kms_generator/4` for the common pattern of using a KMS key as generator with additional child keyrings.

### API Design

```elixir
@doc """
Creates a Multi-Keyring with an AWS KMS keyring as the generator.

Convenience function for the common pattern of using a KMS key as the
primary generator with additional child keyrings for backup decryption.

## Parameters

- `kms_key_id` - AWS KMS key identifier for the generator
- `kms_client` - KMS client struct
- `child_keyrings` - List of child keyrings (can be empty)
- `opts` - Optional keyword list:
  - `:grant_tokens` - Grant tokens for the KMS generator keyring

## Examples

    {:ok, multi} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      kms_client,
      [backup_keyring]
    )

"""
@spec new_with_kms_generator(String.t(), struct(), [keyring()], keyword()) ::
        {:ok, t()} | {:error, term()}
def new_with_kms_generator(kms_key_id, kms_client, child_keyrings, opts \\ [])
```

### Changes Required

#### 1. Multi-Keyring Helper
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add `new_with_kms_generator/4` function

```elixir
@doc """
Creates a Multi-Keyring with an AWS KMS keyring as the generator.

Convenience function for the common pattern of using a KMS key as the
primary generator with additional child keyrings for backup decryption.

## Parameters

- `kms_key_id` - AWS KMS key identifier for the generator
- `kms_client` - KMS client struct
- `child_keyrings` - List of child keyrings (can be empty)
- `opts` - Optional keyword list:
  - `:grant_tokens` - Grant tokens for the KMS generator keyring

## Returns

- `{:ok, multi_keyring}` on success
- `{:error, reason}` if KMS keyring creation fails or validation fails

## Examples

    {:ok, multi} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      kms_client,
      [backup_keyring]
    )

"""
@spec new_with_kms_generator(String.t(), struct(), [keyring()], keyword()) ::
        {:ok, t()} | {:error, term()}
def new_with_kms_generator(kms_key_id, kms_client, child_keyrings, opts \\ [])
    when is_list(child_keyrings) and is_list(opts) do
  grant_tokens = Keyword.get(opts, :grant_tokens, [])

  with {:ok, kms_keyring} <- AwsKms.new(kms_key_id, kms_client, grant_tokens: grant_tokens) do
    new(generator: kms_keyring, children: child_keyrings)
  end
end
```

#### 2. Unit Tests
**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add tests for `new_with_kms_generator/4`

```elixir
describe "new_with_kms_generator/4" do
  test "creates multi-keyring with KMS generator" do
    {:ok, client} = KmsClient.Mock.new(%{})

    assert {:ok, multi} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      client,
      []
    )

    assert %AwsKms{} = multi.generator
    assert multi.generator.kms_key_id == "arn:aws:kms:us-west-2:123:key/abc"
    assert multi.children == []
  end

  test "creates multi-keyring with KMS generator and children" do
    {:ok, client} = KmsClient.Mock.new(%{})
    child = create_aes_keyring("child")

    assert {:ok, multi} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      client,
      [child]
    )

    assert %AwsKms{} = multi.generator
    assert multi.children == [child]
  end

  test "passes grant tokens to KMS keyring" do
    {:ok, client} = KmsClient.Mock.new(%{})

    assert {:ok, multi} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      client,
      [],
      grant_tokens: ["token1", "token2"]
    )

    assert multi.generator.grant_tokens == ["token1", "token2"]
  end

  test "returns error for invalid key_id" do
    {:ok, client} = KmsClient.Mock.new(%{})

    assert {:error, :key_id_required} = Multi.new_with_kms_generator(nil, client, [])
    assert {:error, :key_id_empty} = Multi.new_with_kms_generator("", client, [])
  end

  test "returns error for invalid client" do
    assert {:error, :client_required} = Multi.new_with_kms_generator(
      "arn:aws:kms:us-west-2:123:key/abc",
      nil,
      []
    )
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, verify `Multi.new_with_kms_generator/4` creates a working multi-keyring

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Helper Constructor - new_mrk_aware

### Overview
Add `Multi.new_mrk_aware/4` for creating a multi-region aware multi-keyring that enables cross-region encryption/decryption scenarios.

### API Design

```elixir
@doc """
Creates a Multi-Region Key (MRK) aware Multi-Keyring.

Creates a multi-keyring optimized for cross-region scenarios using MRK replicas.
The primary key is used as the generator, and MRK keyrings for each replica
region are added as children for cross-region decryption.

## Parameters

- `primary_key_id` - Primary MRK key identifier (should be an mrk-* key)
- `primary_client` - KMS client for the primary region
- `replicas` - List of `{region, kms_client}` tuples for replica regions
- `opts` - Optional keyword list:
  - `:grant_tokens` - Grant tokens for all KMS keyrings

## Examples

    # Primary in us-west-2, replicas in us-east-1 and eu-west-1
    {:ok, multi} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123:key/mrk-abc",
      west_client,
      [
        {"us-east-1", east_client},
        {"eu-west-1", eu_client}
      ]
    )

"""
@spec new_mrk_aware(String.t(), struct(), [{String.t(), struct()}], keyword()) ::
        {:ok, t()} | {:error, term()}
def new_mrk_aware(primary_key_id, primary_client, replicas, opts \\ [])
```

### Changes Required

#### 1. Multi-Keyring Helper
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add `new_mrk_aware/4` function

```elixir
@doc """
Creates a Multi-Region Key (MRK) aware Multi-Keyring.

Creates a multi-keyring optimized for cross-region scenarios using MRK replicas.
The primary key is used as the generator (using AwsKmsMrk keyring), and MRK
keyrings for each replica region are added as children for cross-region decryption.

## Parameters

- `primary_key_id` - Primary MRK key identifier (should be an mrk-* key for cross-region functionality)
- `primary_client` - KMS client for the primary region
- `replicas` - List of `{region, kms_client}` tuples for replica regions
- `opts` - Optional keyword list:
  - `:grant_tokens` - Grant tokens for all KMS keyrings

## Returns

- `{:ok, multi_keyring}` on success
- `{:error, reason}` if any keyring creation fails

## Examples

    # Primary in us-west-2, replicas in us-east-1 and eu-west-1
    {:ok, multi} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123:key/mrk-abc",
      west_client,
      [
        {"us-east-1", east_client},
        {"eu-west-1", eu_client}
      ]
    )

## Notes

For true cross-region MRK functionality, the key_id should be an MRK
(key ID starting with `mrk-`). Non-MRK keys will work but won't provide
cross-region decryption capability.

"""
@spec new_mrk_aware(String.t(), struct(), [{String.t(), struct()}], keyword()) ::
        {:ok, t()} | {:error, term()}
def new_mrk_aware(primary_key_id, primary_client, replicas, opts \\ [])
    when is_list(replicas) and is_list(opts) do
  grant_tokens = Keyword.get(opts, :grant_tokens, [])
  kms_opts = [grant_tokens: grant_tokens]

  with {:ok, generator} <- AwsKmsMrk.new(primary_key_id, primary_client, kms_opts),
       {:ok, children} <- create_replica_keyrings(primary_key_id, replicas, kms_opts) do
    new(generator: generator, children: children)
  end
end

defp create_replica_keyrings(primary_key_id, replicas, kms_opts) do
  results =
    Enum.reduce_while(replicas, {:ok, []}, fn {region, client}, {:ok, acc} ->
      # Reconstruct ARN with replica region
      case reconstruct_arn_for_region(primary_key_id, region) do
        {:ok, replica_key_id} ->
          case AwsKmsMrk.new(replica_key_id, client, kms_opts) do
            {:ok, keyring} -> {:cont, {:ok, [keyring | acc]}}
            {:error, reason} -> {:halt, {:error, {:replica_keyring_failed, region, reason}}}
          end

        {:error, reason} ->
          {:halt, {:error, {:invalid_replica_region, region, reason}}}
      end
    end)

  case results do
    {:ok, keyrings} -> {:ok, Enum.reverse(keyrings)}
    error -> error
  end
end

defp reconstruct_arn_for_region(key_id, region) do
  case KmsKeyArn.parse(key_id) do
    {:ok, arn} ->
      {:ok, KmsKeyArn.to_string(%{arn | region: region})}

    {:error, _reason} ->
      # Not a full ARN - can't reconstruct for different region
      {:error, :primary_key_must_be_arn}
  end
end
```

#### 2. Add KmsKeyArn alias
**File**: `lib/aws_encryption_sdk/keyring/multi.ex`
**Changes**: Add alias at top of file

```elixir
alias AwsEncryptionSdk.Keyring.KmsKeyArn
```

#### 3. Unit Tests
**File**: `test/aws_encryption_sdk/keyring/multi_test.exs`
**Changes**: Add tests for `new_mrk_aware/4`

```elixir
describe "new_mrk_aware/4" do
  test "creates MRK-aware multi-keyring with primary and replicas" do
    {:ok, primary_client} = KmsClient.Mock.new(%{})
    {:ok, east_client} = KmsClient.Mock.new(%{})
    {:ok, eu_client} = KmsClient.Mock.new(%{})

    assert {:ok, multi} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
      primary_client,
      [
        {"us-east-1", east_client},
        {"eu-west-1", eu_client}
      ]
    )

    assert %AwsKmsMrk{} = multi.generator
    assert multi.generator.kms_key_id == "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123"
    assert length(multi.children) == 2

    [east_keyring, eu_keyring] = multi.children
    assert %AwsKmsMrk{} = east_keyring
    assert %AwsKmsMrk{} = eu_keyring
    assert east_keyring.kms_key_id == "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123"
    assert eu_keyring.kms_key_id == "arn:aws:kms:eu-west-1:123456789012:key/mrk-abc123"
  end

  test "creates MRK-aware multi-keyring with no replicas" do
    {:ok, client} = KmsClient.Mock.new(%{})

    assert {:ok, multi} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
      client,
      []
    )

    assert %AwsKmsMrk{} = multi.generator
    assert multi.children == []
  end

  test "passes grant tokens to all keyrings" do
    {:ok, primary_client} = KmsClient.Mock.new(%{})
    {:ok, replica_client} = KmsClient.Mock.new(%{})

    assert {:ok, multi} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
      primary_client,
      [{"us-east-1", replica_client}],
      grant_tokens: ["token1"]
    )

    assert multi.generator.grant_tokens == ["token1"]
    [replica] = multi.children
    assert replica.grant_tokens == ["token1"]
  end

  test "returns error for non-ARN primary key" do
    {:ok, client} = KmsClient.Mock.new(%{})

    # Alias names can't be reconstructed for different regions
    assert {:error, {:invalid_replica_region, "us-east-1", :primary_key_must_be_arn}} =
      Multi.new_mrk_aware(
        "alias/my-key",
        client,
        [{"us-east-1", client}]
      )
  end

  test "returns error for invalid primary client" do
    assert {:error, :client_required} = Multi.new_mrk_aware(
      "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
      nil,
      []
    )
  end

  test "returns error for invalid replica client" do
    {:ok, primary_client} = KmsClient.Mock.new(%{})

    assert {:error, {:replica_keyring_failed, "us-east-1", :client_required}} =
      Multi.new_mrk_aware(
        "arn:aws:kms:us-west-2:123456789012:key/mrk-abc123",
        primary_client,
        [{"us-east-1", nil}]
      )
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/keyring/multi_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, verify `Multi.new_mrk_aware/4` creates a working multi-keyring with correct ARN reconstruction

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Final Verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All multi-keyring tests pass
- [x] All CMM tests still pass

### Manual:
- [x] Verify discovery keyring rejection works in IEx
- [x] Verify helper constructors create valid keyrings

## Testing Strategy

### Unit Tests
- Generator validation: reject discovery keyrings
- `new_with_kms_generator/4`: success and error cases
- `new_mrk_aware/4`: success, ARN reconstruction, and error cases

### Integration Tests (Manual)
With mock KMS client:
1. Create multi-keyring with KMS generator, encrypt/decrypt round-trip
2. Create MRK-aware multi-keyring, verify ARN reconstruction

### What We're NOT Testing
- Real AWS KMS integration (requires credentials)
- Cross-SDK interoperability (separate test suite)

## References

- Issue: #52
- Multi-Keyring: `lib/aws_encryption_sdk/keyring/multi.ex`
- KMS Keyring: `lib/aws_encryption_sdk/keyring/aws_kms.ex`
- MRK Keyring: `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex`
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/multi-keyring.md
