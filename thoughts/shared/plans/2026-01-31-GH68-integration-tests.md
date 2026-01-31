# Integration Tests & Coverage Ignores Implementation Plan

## Overview

Enable integration tests to run by default (removing the `:integration` exclusion) so CI jobs with AWS credentials will automatically run them, and remove temporary `# coveralls-ignore` markers to restore proper test coverage.

**Issue**: #68

## Current State Analysis

### Integration Test Files

| File | Has `:integration` tag | Requires AWS |
|------|------------------------|--------------|
| `test/aws_encryption_sdk/integration_test.exs` | No | No |
| `test/aws_encryption_sdk/client_commitment_policy_integration_test.exs` | No | No |
| `test/aws_encryption_sdk/stream/integration_test.exs` | No | No |
| `test/aws_encryption_sdk/keyring/kms_client/ex_aws_integration_test.exs` | **Yes** | **Yes** |

Only `ex_aws_integration_test.exs` is tagged with `:integration` and requires real AWS credentials (`KMS_KEY_ARN`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`).

### Current test_helper.exs Configuration

```elixir
ExUnit.configure(exclude: [:skip, :integration])
```

### Coveralls Ignore Markers

- `lib/aws_encryption_sdk/stream.ex`: 20 markers (10 start/stop pairs)
- `lib/aws_encryption_sdk/stream/decryptor.ex`: 18 markers (9 start/stop pairs)
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex`: 4 markers (2 start/stop pairs)
- **Total**: 42 markers (21 regions)

### CI Configuration

The CI workflow runs `mix quality` which includes tests. AWS credentials are configured via GitHub secrets.

## Desired End State

1. **Integration tests run by default** - Remove `:integration` from default exclusions
2. **Local development friendly** - Tests skip gracefully when AWS credentials are missing
3. **Coverage ignores removed** - All temporary `# coveralls-ignore` markers removed
4. **Coverage maintained** - ≥92% coverage threshold met with new tests

### Verification

- `mix quality` passes with all integration tests enabled
- Coverage report shows ≥92% without ignore markers
- Developers without AWS credentials can run `mix test --exclude integration` locally

## What We're NOT Doing

- Not adding new CI jobs or workflow changes (CI already has AWS creds)
- Not mocking AWS services (tests already exist for that)
- Not changing the tagged file naming convention

---

## Phase 1: Enable Integration Tests by Default

### Overview

Remove the default exclusion of `:integration` tests and update the KMS integration tests to skip properly when credentials are missing.

### Changes Required:

#### 1. Update test_helper.exs

**File**: `test/test_helper.exs`
**Changes**: Remove `:integration` from default exclusions

```elixir
# Before
ExUnit.configure(exclude: [:skip, :integration])

# After
ExUnit.configure(exclude: [:skip])
```

#### 2. Fix KMS Integration Test Skip Behavior

**File**: `test/aws_encryption_sdk/keyring/kms_client/ex_aws_integration_test.exs`
**Changes**: Use `@moduletag skip: true` pattern to properly skip when credentials are missing

The current `setup_all` returns `{:ok, skip: true}` but this doesn't actually skip tests - they fail on pattern match. Need to use `@tag :skip` or a different approach.

```elixir
# Add at module level, after @moduletag :integration
@moduletag skip: System.get_env("KMS_KEY_ARN") == nil

# Remove the skip logic from setup_all since it's handled at module level
setup_all do
  key_arn = System.get_env("KMS_KEY_ARN")
  region = System.get_env("AWS_REGION", "us-east-1")
  {:ok, key_arn: key_arn, region: region}
end
```

#### 3. Update Comment in test_helper.exs

Update the comment explaining how to exclude integration tests locally:

```elixir
# Configure ExUnit
# Exclude :skip by default
# To exclude integration tests locally: mix test --exclude integration
ExUnit.configure(exclude: [:skip])
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test` (with AWS credentials available)
- [x] Tests skip gracefully: `KMS_KEY_ARN= mix test` (without credentials)
- [x] Developers can exclude: `mix test --exclude integration`

#### Manual Verification:
- [x] Verify CI job still passes with AWS credentials
- [x] Verify local development without AWS credentials works

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: Remove Coveralls Ignore Markers and Add Tests

### Overview

Remove all `# coveralls-ignore` markers and add missing test coverage for the error paths and CMM dispatch code.

### Test Coverage Needed

Based on the ignored regions, we need tests for:

**stream.ex:**
- CMM dispatch for `RequiredEncryptionContext` CMM
- CMM dispatch for `Caching` CMM
- Error: `:cmm_get_encryption_materials_failed`
- Error: `:cmm_decrypt_materials_failed`
- Error: `:unsupported_cmm_type`

**stream/decryptor.ex:**
- Error: `:signed_algorithm_suite_not_allowed` (fail_on_signed)
- Error: `:header_authentication_failed`
- Error: `:commitment_mismatch`
- Error: `:frame_authentication_failed`
- Error: `:signature_verification_failed`
- Error: `:trailing_bytes`
- Error: `{:incomplete_message, state}`
- Legacy suite handling (NO_KDF)

**keyring/kms_client/ex_aws.ex:**
- Error normalization paths (already has unit tests, may just need ignore removal)

### Changes Required:

#### 1. Add Streaming Error Tests

**File**: `test/aws_encryption_sdk/stream/error_test.exs` (new file)

```elixir
defmodule AwsEncryptionSdk.Stream.ErrorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Stream
  # Tests for each error condition...
end
```

Tests to add:
- `fail_on_signed: true` with signed algorithm suite
- Header authentication failure (corrupted header)
- Commitment mismatch (corrupted commitment)
- Frame authentication failure (corrupted frame)
- Signature verification failure (corrupted signature)
- Trailing bytes after message
- Incomplete message (truncated ciphertext)

#### 2. Add CMM Dispatch Tests

**File**: `test/aws_encryption_sdk/stream/cmm_dispatch_test.exs` (new file)

Tests for streaming with:
- `RequiredEncryptionContext` CMM
- `Caching` CMM
- Both encrypt and decrypt paths

#### 3. Remove Coveralls Ignore Markers

**Files**:
- `lib/aws_encryption_sdk/stream.ex`
- `lib/aws_encryption_sdk/stream/decryptor.ex`
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex`

Remove all `# coveralls-ignore-start` and `# coveralls-ignore-stop` comments.

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix quality` (with AWS credentials)
- [x] Coverage improved: 92.6% (from 90.8% without AWS creds)
- [x] No coveralls-ignore markers remain

#### Manual Verification:
- [x] Review coverage report to ensure all critical paths are tested

**Note**: Coverage is at 92.6% with AWS credentials (vs 90.8% locally). Remaining uncovered code (stream.ex defensive raises) requires complex error injection to test. CI with AWS credentials provides significantly better coverage than local development.

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the final verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full quality suite: `mix quality`
- [x] Coverage report: `mix coveralls` shows ≥92% (92.6% achieved)
- [x] CI passes with integration tests enabled

### Manual:
- [x] Local development without AWS credentials works smoothly
- [x] CI job with AWS credentials runs integration tests successfully

## References

- Issue: #68
- Streaming PR: #69
