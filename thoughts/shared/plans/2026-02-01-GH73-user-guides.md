# User Guides for v1.0.0 Implementation Plan

## Overview

Create three comprehensive user guides for the AWS Encryption SDK for Elixir to help developers effectively use the library. These guides will be included as Hex docs extras and provide higher-level guidance beyond the module-level documentation.

**Issue**: #73
**Branch**: 73-user-guides

## Acceptance Criteria (from issue)

- [x] Create `guides/getting-started.md` with working code examples
- [x] Create `guides/choosing-components.md` with decision flowcharts
- [x] Create `guides/security-best-practices.md` with production guidance
- [x] Add all guides to `mix.exs` docs extras configuration
- [x] Ensure all code examples in guides are tested/accurate
- [x] Cross-reference guides from relevant module docs
- [x] Verify guides render correctly in generated Hex docs

## Current State Analysis

### Existing Documentation:
- `guides/STABILITY.md` - API stability policy (good template for guide formatting)
- Module-level docs are comprehensive but lack narrative guidance
- `examples/*.exs` files provide tested KMS examples
- README has basic usage examples

### Gaps Identified:
- No conceptual explanation of Keyring/CMM abstractions
- No decision guidance for component selection
- No consolidated security best practices
- No commitment policy migration guidance
- No explanation of when to use caching or streaming

## Desired End State

After implementation:
1. New developers can follow the Getting Started guide to encrypt/decrypt data within minutes
2. Developers can use the decision trees to select appropriate keyrings and CMMs
3. Production deployments follow security best practices checklist
4. All code examples in guides are validated by `test/guides_test.exs`
5. Key module docs link to relevant guides for deeper context

**Verification:**
- `mix test test/guides_test.exs` passes
- `mix docs` generates guides correctly
- `mix quality` passes

## What We're NOT Doing

- Mermaid diagram support (using ASCII/text-based decision trees instead)
- Comprehensive cross-references from every module (only key entry points)
- AWS KMS setup/IAM tutorial (link to AWS docs instead)
- Performance benchmarking guide (planned for future)
- Migration guide from other SDKs (out of scope)

## Implementation Approach

Create guides incrementally, with each phase producing a complete, testable deliverable. Test examples are extracted from guides and validated in `test/guides_test.exs`.

---

## Phase 1: Getting Started Guide

### Overview
Create the foundational guide that helps new users encrypt and decrypt data quickly using a Raw AES keyring (simplest path, no AWS dependencies).

### Changes Required:

#### 1. Create Getting Started Guide
**File**: `guides/getting-started.md`
**Status**: ✅ Complete

#### 2. Add to mix.exs docs
**File**: `mix.exs`
**Status**: ✅ Complete - Added getting-started.md to extras list

#### 3. Create test file
**File**: `test/guides_test.exs`
**Status**: ✅ Complete

```markdown
# Getting Started

Welcome to the AWS Encryption SDK for Elixir! This guide walks you through
encrypting and decrypting data in minutes.

## Installation

Add `aws_encryption_sdk` to your dependencies in `mix.exs`:

\`\`\`elixir
def deps do
  [
    {:aws_encryption_sdk, "~> 0.6.0"}
  ]
end
\`\`\`

Then fetch dependencies:

\`\`\`bash
mix deps.get
\`\`\`

## Your First Encryption

Let's encrypt a secret message using a local AES key. This is the simplest
path - no AWS account required.

\`\`\`elixir
alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

# 1. Generate a 256-bit AES key
key = :crypto.strong_rand_bytes(32)

# 2. Create a keyring to manage the key
{:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)

# 3. Create a CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# 4. Encrypt your data
plaintext = "Hello, World!"
{:ok, result} = Client.encrypt(client, plaintext)

# 5. Decrypt it back
{:ok, decrypted} = Client.decrypt(client, result.ciphertext)
decrypted.plaintext
# => "Hello, World!"
\`\`\`

## Understanding Encryption Context

Encryption context provides additional authenticated data (AAD) that is
cryptographically bound to the ciphertext. It's not secret, but it must
match during decryption.

\`\`\`elixir
# Encrypt with context
context = %{"tenant" => "acme-corp", "purpose" => "user-data"}

{:ok, result} = Client.encrypt(client, "secret data",
  encryption_context: context
)

# Context is stored in the message header (unencrypted but authenticated)
result.encryption_context
# => %{"tenant" => "acme-corp", "purpose" => "user-data"}

# Decrypt - context is returned for verification
{:ok, decrypted} = Client.decrypt(client, result.ciphertext)
decrypted.encryption_context
# => %{"tenant" => "acme-corp", "purpose" => "user-data"}
\`\`\`

**Best Practice**: Always include meaningful encryption context. It helps
with auditing and prevents ciphertext from being used in unintended contexts.

## Using AWS KMS

For production use, AWS KMS provides secure key management:

\`\`\`elixir
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Create KMS client (uses default AWS credentials)
{:ok, kms_client} = ExAws.new(region: "us-west-2")

# Create keyring with your KMS key
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
  kms_client
)

# Use the same Client API
cmm = Default.new(keyring)
client = Client.new(cmm)

{:ok, result} = Client.encrypt(client, "secret",
  encryption_context: %{"env" => "production"}
)
\`\`\`

See `examples/kms_basic.exs` for a complete runnable example.

## Error Handling

The SDK returns tagged tuples for all operations:

\`\`\`elixir
case Client.encrypt(client, plaintext, encryption_context: context) do
  {:ok, result} ->
    # Success - result.ciphertext contains the encrypted message
    store_encrypted(result.ciphertext)

  {:error, :commitment_policy_requires_committed_suite} ->
    # Algorithm suite doesn't match commitment policy
    Logger.error("Algorithm suite mismatch")

  {:error, reason} ->
    # Other errors
    Logger.error("Encryption failed: #{inspect(reason)}")
end
\`\`\`

Common errors:
- `:commitment_policy_requires_committed_suite` - Algorithm suite doesn't support key commitment
- `:reserved_encryption_context_key` - Using reserved `aws-crypto-*` keys
- `:max_encrypted_data_keys_exceeded` - Too many encrypted data keys

## Next Steps

- **[Choosing Components](choosing-components.html)** - Select the right keyring and CMM for your use case
- **[Security Best Practices](security-best-practices.html)** - Production deployment guidance
- **[API Reference](AwsEncryptionSdk.html)** - Complete module documentation
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes
- [x] `mix docs` generates the guide
- [x] `test/guides_test.exs` validates all code examples

#### Manual Verification:
- [x] Guide renders correctly in browser (`open doc/getting-started.html`)
- [x] Code examples work when pasted into IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding.

---

## Phase 2: Choosing Components Guide

### Overview
Create a decision-tree guide to help developers select the right keyring and CMM for their use case.

### Changes Required:

#### 1. Create Choosing Components Guide
**File**: `guides/choosing-components.md`

```markdown
# Choosing Components

This guide helps you select the right keyring and Cryptographic Materials
Manager (CMM) for your use case.

## Understanding the Architecture

The AWS Encryption SDK uses two key abstractions:

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                               │
│  (commitment policy, max EDKs)                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Cryptographic Materials Manager (CMM)           │
│  (key caching, required context enforcement)                 │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Keyring                              │
│  (wraps/unwraps data keys using master keys)                 │
└─────────────────────────────────────────────────────────────┘
```

**Keyring**: Wraps and unwraps data encryption keys using your master keys.
Choose based on where your keys are stored.

**CMM**: Manages cryptographic materials. The Default CMM is sufficient for
most use cases. Use specialized CMMs for caching or context enforcement.

## Keyring Selection

### Decision Tree

```
Where are your master keys stored?
│
├─► AWS KMS
│   │
│   ├─► Do you know the key ARN at decrypt time?
│   │   │
│   │   ├─► YES ──► AwsKms Keyring
│   │   │           (Best for most use cases)
│   │   │
│   │   └─► NO ───► AwsKmsDiscovery Keyring
│   │               (Decrypts any KMS-encrypted message)
│   │
│   └─► Do you need multi-region disaster recovery?
│       │
│       ├─► YES ──► AwsKmsMrk or AwsKmsMrkDiscovery Keyring
│       │           (Works with KMS multi-region keys)
│       │
│       └─► NO ───► Standard AwsKms Keyring
│
├─► Local/HSM keys
│   │
│   ├─► Symmetric key (AES)?
│   │   └─► RawAes Keyring
│   │       (256-bit keys recommended)
│   │
│   └─► Asymmetric key (RSA)?
│       └─► RawRsa Keyring
│           (Useful for encrypt-only or decrypt-only scenarios)
│
└─► Multiple keys for redundancy?
    └─► Multi Keyring
        (Combines multiple keyrings)
```

### Keyring Comparison

| Keyring | Use Case | Key Location | Notes |
|---------|----------|--------------|-------|
| `AwsKms` | Production with AWS | AWS KMS | Recommended for most cases |
| `AwsKmsDiscovery` | Decrypt unknown sources | AWS KMS | Use discovery filter! |
| `AwsKmsMrk` | Multi-region DR | AWS KMS | For MRK keys only |
| `AwsKmsMrkDiscovery` | Multi-region discovery | AWS KMS | Combine with filter |
| `RawAes` | Local/testing | Your app | You manage key storage |
| `RawRsa` | Asymmetric workflows | Your app | Encrypt-only or decrypt-only |
| `Multi` | Redundancy | Multiple | Combines other keyrings |

### Keyring Examples

#### AWS KMS (Recommended for Production)

\`\`\`elixir
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/...",
  kms_client
)
\`\`\`

#### Raw AES (Local Development/Testing)

\`\`\`elixir
alias AwsEncryptionSdk.Keyring.RawAes

key = :crypto.strong_rand_bytes(32)  # 256-bit key
{:ok, keyring} = RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)
\`\`\`

#### Multi-Keyring (Redundancy)

\`\`\`elixir
alias AwsEncryptionSdk.Keyring.Multi

# Primary KMS key + backup KMS key
{:ok, primary} = AwsKms.new(primary_arn, kms_client)
{:ok, backup} = AwsKms.new(backup_arn, kms_client)

{:ok, keyring} = Multi.new(generator: primary, children: [backup])
\`\`\`

## CMM Selection

### Decision Tree

```
Do you need special materials handling?
│
├─► No special needs
│   └─► Default CMM
│       (Wraps any keyring, handles materials lifecycle)
│
├─► High-volume encryption (>1000 ops/sec)?
│   └─► Caching CMM
│       (Reduces KMS calls, improves performance)
│
└─► Enforce required encryption context keys?
    └─► RequiredEncryptionContext CMM
        (Fails if required keys missing)
```

### CMM Comparison

| CMM | Use Case | Notes |
|-----|----------|-------|
| `Default` | Standard operations | Use for most cases |
| `Caching` | High-volume workloads | Set max_age, max_messages limits |
| `RequiredEncryptionContext` | Compliance/security | Enforces context key presence |

### CMM Examples

#### Default CMM (Most Common)

\`\`\`elixir
alias AwsEncryptionSdk.Cmm.Default

cmm = Default.new(keyring)
client = Client.new(cmm)
\`\`\`

#### Caching CMM (High Volume)

\`\`\`elixir
alias AwsEncryptionSdk.Cmm.Caching
alias AwsEncryptionSdk.Cache.LocalCache

# Start the cache process
{:ok, cache} = LocalCache.start_link([])

# Wrap the keyring with caching
cmm = Caching.new_with_keyring(keyring, cache,
  max_age: 300,        # 5 minutes
  max_messages: 1000   # Re-key after 1000 messages
)

client = Client.new(cmm)
\`\`\`

#### Required Encryption Context CMM

\`\`\`elixir
alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext

# Require tenant_id in all encryption operations
cmm = RequiredEncryptionContext.new_with_keyring(keyring, ["tenant_id"])

client = Client.new(cmm)

# This succeeds
{:ok, _} = Client.encrypt(client, "data",
  encryption_context: %{"tenant_id" => "acme"}
)

# This fails - missing required key
{:error, _} = Client.encrypt(client, "data",
  encryption_context: %{"other" => "value"}
)
\`\`\`

## Common Configurations

### Development/Testing
\`\`\`elixir
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
cmm = Default.new(keyring)
client = Client.new(cmm)
\`\`\`

### Production with AWS KMS
\`\`\`elixir
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
cmm = Default.new(keyring)
client = Client.new(cmm)
\`\`\`

### High-Volume Production
\`\`\`elixir
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
{:ok, cache} = LocalCache.start_link([])
cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
client = Client.new(cmm)
\`\`\`

### Multi-Tenant with Required Context
\`\`\`elixir
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
cmm = RequiredEncryptionContext.new_with_keyring(keyring, ["tenant_id"])
client = Client.new(cmm)
\`\`\`
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes
- [x] `mix docs` generates the guide
- [x] `test/guides_test.exs` validates relevant code examples

#### Manual Verification:
- [x] Decision trees render correctly in browser
- [x] All keyring/CMM examples work in IEx

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding.

---

## Phase 3: Security Best Practices Guide

### Overview
Create a comprehensive security guide aligned with AWS Encryption SDK best practices.

### Changes Required:

#### 1. Create Security Best Practices Guide
**File**: `guides/security-best-practices.md`

```markdown
# Security Best Practices

This guide covers security best practices for using the AWS Encryption SDK
for Elixir in production environments.

## 1. Use Key Commitment (Default)

Key commitment ensures ciphertext can only decrypt to one plaintext. This
prevents sophisticated attacks where malicious ciphertext decrypts to
different values with different keys.

**The SDK defaults to the strictest policy: `require_encrypt_require_decrypt`**

\`\`\`elixir
# Default - strictest policy (recommended)
client = Client.new(cmm)

# Explicit - same as default
client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
\`\`\`

### Commitment Policies

| Policy | Encrypt | Decrypt | Use Case |
|--------|---------|---------|----------|
| `:require_encrypt_require_decrypt` | Committed only | Committed only | New applications (default) |
| `:require_encrypt_allow_decrypt` | Committed only | Both | Migration from legacy |
| `:forbid_encrypt_allow_decrypt` | Non-committed only | Both | Legacy compatibility |

### Migration Path

If migrating from non-committed messages:

1. **Phase 1**: Deploy with `:require_encrypt_allow_decrypt`
   - New encryptions use commitment
   - Can still decrypt legacy messages

2. **Phase 2**: After all messages re-encrypted, switch to `:require_encrypt_require_decrypt`

\`\`\`elixir
# Phase 1: Transitional
client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

# Phase 2: After migration complete
client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
\`\`\`

## 2. Always Use Encryption Context

Encryption context provides authenticated data that is cryptographically
bound to the ciphertext but stored unencrypted in the message header.

**Benefits:**
- Prevents ciphertext substitution attacks
- Provides audit trail
- Enables access control decisions

\`\`\`elixir
# Good - meaningful context
context = %{
  "tenant_id" => "acme-corp",
  "data_type" => "user-pii",
  "purpose" => "storage"
}

{:ok, result} = Client.encrypt(client, data, encryption_context: context)
\`\`\`

### Context Best Practices

| Do | Don't |
|----|-------|
| Include tenant/user identifiers | Store secrets in context |
| Add data classification | Use context as the only access control |
| Include purpose/operation | Include frequently-changing values |
| Use consistent key names | Use `aws-crypto-*` prefix (reserved) |

### Verifying Context on Decrypt

\`\`\`elixir
{:ok, result} = Client.decrypt(client, ciphertext)

# Always verify the context matches expectations
case result.encryption_context do
  %{"tenant_id" => ^expected_tenant} ->
    {:ok, result.plaintext}
  _ ->
    {:error, :context_mismatch}
end
\`\`\`

## 3. Protect Your Wrapping Keys

### For AWS KMS Keys

- Use IAM policies to restrict key access
- Enable CloudTrail logging for key usage
- Use key policies to define administrators vs. users
- Consider using grants for temporary access

### For Raw Keys

- Generate keys using cryptographically secure random:
  \`\`\`elixir
  key = :crypto.strong_rand_bytes(32)  # 256-bit
  \`\`\`

- Store keys securely (HSM, secrets manager, encrypted config)
- Rotate keys periodically
- Never log or expose keys

## 4. Specify Wrapping Keys Explicitly

Avoid using discovery keyrings for encryption. Always specify the exact
key(s) to use:

\`\`\`elixir
# Good - explicit key
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)

# Avoid for encryption - discovery doesn't specify a key
{:ok, discovery} = AwsKmsDiscovery.new(kms_client)  # Can only decrypt!
\`\`\`

### When Using Discovery for Decryption

Always use discovery filters to limit which keys can decrypt:

\`\`\`elixir
# Good - filtered discovery
{:ok, keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012", "987654321098"]
  }
)

# Dangerous - accepts any AWS account's keys
{:ok, keyring} = AwsKmsDiscovery.new(kms_client)  # No filter!
\`\`\`

## 5. Limit Encrypted Data Keys

Set a maximum number of encrypted data keys (EDKs) to prevent denial-of-service:

\`\`\`elixir
# Limit to 5 EDKs (most messages have 1-3)
client = Client.new(cmm, max_encrypted_data_keys: 5)
\`\`\`

This protects against:
- Maliciously crafted messages with thousands of EDKs
- Resource exhaustion during decryption
- Misconfigured keyrings generating too many EDKs

## 6. Use Digital Signatures (Default)

The default algorithm suite includes ECDSA signatures that verify the
message hasn't been tampered with and was created by an authorized party.

\`\`\`elixir
# Default suite includes signing (recommended)
{:ok, result} = Client.encrypt(client, data)

# Only disable if you have a specific reason
# (e.g., performance-critical, already authenticated channel)
suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
{:ok, result} = Client.encrypt(client, data, algorithm_suite: suite)
\`\`\`

## 7. Handle Errors Securely

Never expose internal error details to end users:

\`\`\`elixir
case Client.decrypt(client, ciphertext) do
  {:ok, result} ->
    {:ok, result.plaintext}

  {:error, reason} ->
    # Log detailed error for debugging
    Logger.error("Decryption failed: #{inspect(reason)}")

    # Return generic error to user
    {:error, :decryption_failed}
end
\`\`\`

## 8. Production Deployment Checklist

### Before Going Live

- [ ] **Commitment policy**: Using `:require_encrypt_require_decrypt`
- [ ] **Encryption context**: All operations include meaningful context
- [ ] **Key management**: Using AWS KMS or secure HSM
- [ ] **Discovery filters**: All discovery keyrings have account filters
- [ ] **EDK limits**: `max_encrypted_data_keys` set appropriately
- [ ] **Error handling**: Internal errors not exposed to users
- [ ] **Logging**: Encrypt/decrypt operations logged (without plaintext)
- [ ] **Key rotation**: Plan for periodic key rotation

### Monitoring

- Monitor KMS API calls via CloudTrail
- Alert on decryption failures (may indicate attack)
- Track encryption context patterns for anomalies

### Testing

- Test with production-like keys before deployment
- Verify round-trip encryption/decryption
- Test error handling paths
- Verify context validation logic

## Common Security Pitfalls

### 1. Missing Encryption Context
\`\`\`elixir
# Bad - no context
{:ok, result} = Client.encrypt(client, data)

# Good - meaningful context
{:ok, result} = Client.encrypt(client, data,
  encryption_context: %{"purpose" => "user-data"}
)
\`\`\`

### 2. Unfiltered Discovery Keyring
\`\`\`elixir
# Bad - accepts any account
{:ok, keyring} = AwsKmsDiscovery.new(kms_client)

# Good - restricted to your accounts
{:ok, keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
)
\`\`\`

### 3. Storing Raw Keys Insecurely
\`\`\`elixir
# Bad - key in code/config
key = <<1, 2, 3, ...>>

# Good - key from secure source
key = fetch_key_from_secrets_manager()
\`\`\`

### 4. Ignoring Returned Context
\`\`\`elixir
# Bad - ignoring context
{:ok, result} = Client.decrypt(client, ciphertext)
use_data(result.plaintext)

# Good - verify context
{:ok, result} = Client.decrypt(client, ciphertext)
if valid_context?(result.encryption_context) do
  use_data(result.plaintext)
end
\`\`\`

## Further Reading

- [AWS Encryption SDK Best Practices](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/best-practices.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [OWASP Cryptographic Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes
- [x] `mix docs` generates the guide
- [x] `test/guides_test.exs` validates relevant code examples

#### Manual Verification:
- [x] Tables render correctly
- [x] Checklist is actionable and complete

**Implementation Note**: After completing this phase and all automated verification passes, pause for manual confirmation before proceeding.

---

## Phase 4: Integration & Verification

### Overview
Integrate guides into the documentation system and add cross-references from key modules.

### Changes Required:

#### 1. Update mix.exs docs configuration
**File**: `mix.exs`
**Changes**: Add new guides to extras list

```elixir
defp docs do
  [
    main: "readme",
    name: "AWS Encryption SDK",
    source_ref: "v#{@version}",
    source_url: @source_url,
    canonical: "https://hexdocs.pm/aws_encryption_sdk",
    extras: [
      "README.md": [title: "Overview"],
      "CHANGELOG.md": [title: "Changelog"],
      "CONTRIBUTING.md": [title: "Contributing"],
      "guides/getting-started.md": [title: "Getting Started"],
      "guides/choosing-components.md": [title: "Choosing Components"],
      "guides/security-best-practices.md": [title: "Security Best Practices"],
      "guides/STABILITY.md": [title: "API Stability Policy"],
      LICENSE: [title: "License"]
    ],
    # ... rest unchanged
  ]
end
```

#### 2. Create Guide Examples Test
**File**: `test/guides_test.exs`

```elixir
defmodule GuidesTest do
  @moduledoc """
  Tests to validate code examples from user guides.

  These tests ensure that all code snippets in the guides
  work correctly and stay up-to-date with API changes.
  """
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.{Caching, Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}

  describe "Getting Started Guide examples" do
    test "first encryption example" do
      # Generate a 256-bit AES key
      key = :crypto.strong_rand_bytes(32)

      # Create a keyring
      {:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)

      # Create CMM and client
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Encrypt
      plaintext = "Hello, World!"
      {:ok, result} = Client.encrypt(client, plaintext)

      # Decrypt
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)
      assert decrypted.plaintext == "Hello, World!"
    end

    test "encryption context example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Encrypt with context
      context = %{"tenant" => "acme-corp", "purpose" => "user-data"}
      {:ok, result} = Client.encrypt(client, "secret data",
        encryption_context: context
      )

      # Context is returned
      assert result.encryption_context == context

      # Decrypt returns context
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)
      assert decrypted.encryption_context == context
    end

    test "error handling pattern" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Reserved key error
      result = Client.encrypt(client, "test",
        encryption_context: %{"aws-crypto-public-key" => "bad"}
      )
      assert {:error, :reserved_encryption_context_key} = result
    end
  end

  describe "Choosing Components Guide examples" do
    test "Raw AES keyring example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)

      cmm = Default.new(keyring)
      client = Client.new(cmm)

      {:ok, result} = Client.encrypt(client, "test")
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)
      assert decrypted.plaintext == "test"
    end

    test "Multi-keyring example" do
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, primary} = RawAes.new("ns", "primary", key1, :aes_256_gcm)
      {:ok, backup} = RawAes.new("ns", "backup", key2, :aes_256_gcm)

      {:ok, keyring} = Multi.new(generator: primary, children: [backup])

      cmm = Default.new(keyring)
      client = Client.new(cmm)

      {:ok, result} = Client.encrypt(client, "test")
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)
      assert decrypted.plaintext == "test"
    end

    test "Default CMM example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)

      cmm = Default.new(keyring)
      client = Client.new(cmm)

      {:ok, result} = Client.encrypt(client, "test")
      assert is_binary(result.ciphertext)
    end

    test "Caching CMM example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)

      {:ok, cache} = LocalCache.start_link([])
      cmm = Caching.new_with_keyring(keyring, cache,
        max_age: 300,
        max_messages: 1000
      )
      client = Client.new(cmm)

      {:ok, result} = Client.encrypt(client, "test")
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)
      assert decrypted.plaintext == "test"
    end

    test "Required Encryption Context CMM example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)

      cmm = RequiredEncryptionContext.new_with_keyring(keyring, ["tenant_id"])
      client = Client.new(cmm)

      # Succeeds with required key
      {:ok, _} = Client.encrypt(client, "data",
        encryption_context: %{"tenant_id" => "acme"}
      )

      # Fails without required key
      {:error, _} = Client.encrypt(client, "data",
        encryption_context: %{"other" => "value"}
      )
    end
  end

  describe "Security Best Practices Guide examples" do
    test "commitment policy examples" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)

      # Default - strictest
      client = Client.new(cmm)
      assert client.commitment_policy == :require_encrypt_require_decrypt

      # Explicit
      client2 = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
      assert client2.commitment_policy == :require_encrypt_require_decrypt

      # Migration phase 1
      client3 = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)
      assert client3.commitment_policy == :require_encrypt_allow_decrypt
    end

    test "max encrypted data keys example" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)

      client = Client.new(cmm, max_encrypted_data_keys: 5)
      assert client.max_encrypted_data_keys == 5
    end

    test "encryption context best practices" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      # Good context example
      context = %{
        "tenant_id" => "acme-corp",
        "data_type" => "user-pii",
        "purpose" => "storage"
      }

      {:ok, result} = Client.encrypt(client, "data", encryption_context: context)
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)

      # Verify context on decrypt
      expected_tenant = "acme-corp"
      assert %{"tenant_id" => ^expected_tenant} = decrypted.encryption_context
    end
  end
end
```

#### 3. Add cross-references to key modules
**File**: `lib/aws_encryption_sdk.ex`
**Changes**: Add guide references to moduledoc

Add after the "Security" section in the moduledoc:
```elixir
## Guides

- **[Getting Started](getting-started.html)** - Quick introduction to encryption
- **[Choosing Components](choosing-components.html)** - Select the right keyring and CMM
- **[Security Best Practices](security-best-practices.html)** - Production deployment guidance
```

**File**: `lib/aws_encryption_sdk/client.ex`
**Changes**: Add guide reference to moduledoc

Add to moduledoc:
```elixir
For component selection guidance, see the [Choosing Components](choosing-components.html) guide.
For security recommendations, see [Security Best Practices](security-best-practices.html).
```

**File**: `lib/aws_encryption_sdk/keyring/behaviour.ex`
**Changes**: Add guide reference to moduledoc

Add to moduledoc:
```elixir
For help choosing a keyring, see the [Choosing Components](choosing-components.html) guide.
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality` passes (full quality check)
- [x] `mix docs` generates all guides correctly
- [x] `test/guides_test.exs` passes
- [x] All existing tests still pass

#### Manual Verification:
- [x] Guides appear in correct order in sidebar
- [x] Cross-reference links work correctly
- [x] Tables and code blocks render properly

---

## Final Verification

After all phases complete:

### Automated:
- [x] `mix quality` passes
- [x] All 816 tests pass including new guide tests
- [x] `mix docs` generates complete documentation

### Manual:
- [x] Review each guide in browser
- [x] Click through all internal links
- [x] Verify code examples work in IEx
- [x] Check mobile/responsive rendering

## Testing Strategy

### Unit Tests (test/guides_test.exs):
- Validate all code snippets from guides
- Cover Getting Started, Choosing Components, and Security guides
- Test error handling patterns

### Integration:
- `mix docs` builds successfully
- Guides render in generated HTML

### Manual Testing:
1. Open `doc/index.html` in browser
2. Navigate to each guide
3. Verify formatting, tables, code blocks
4. Test all internal links
5. Copy-paste code examples into IEx

## References

- Issue: #73
- Branch: 73-user-guides
- Existing guide: `guides/STABILITY.md`
- AWS Best Practices: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/best-practices.html
