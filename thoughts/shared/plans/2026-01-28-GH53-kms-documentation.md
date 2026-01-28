# KMS Keyrings Documentation Implementation Plan

## Overview

Create comprehensive documentation and examples for the AWS KMS keyrings, including enhanced moduledocs, README updates, example scripts, and security guidance.

**Issue**: #53
**Type**: Documentation

## Current State Analysis

### Existing KMS Keyring Modules
- `lib/aws_encryption_sdk/keyring/aws_kms.ex` - Basic moduledoc with example
- `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex` - Basic moduledoc with discovery filter example
- `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex` - Basic moduledoc with MRK example
- `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex` - Basic moduledoc with region example

### Existing KMS Client Modules
- `lib/aws_encryption_sdk/keyring/kms_client/ex_aws.ex` - Production ExAws implementation with configuration examples
- `lib/aws_encryption_sdk/keyring/kms_client/mock.ex` - Test mock with usage example

### README Status
- Currently shows "❌ AWS KMS keyring" as not implemented (outdated)
- No KMS integration section
- Basic usage example doesn't show keyrings

### Missing Components
- No `examples/` directory
- No IAM permissions documentation
- No security considerations guide
- No keyring selection decision matrix

## Desired End State

After implementation:
- README accurately reflects implemented features with KMS section
- All KMS keyring modules have comprehensive moduledocs with:
  - Purpose and use cases
  - Configuration options
  - Multiple code examples
  - Security considerations
  - IAM permissions needed
  - Common patterns
- `examples/` directory with runnable example scripts
- Users can quickly determine which keyring to use for their scenario

## What We're NOT Doing

- Adding new features or changing existing behavior
- Creating full tutorial documentation (just moduledocs and examples)
- Writing integration tests
- Implementing additional keyrings

## Implementation Approach

Documentation-focused: Each phase enhances documentation for specific components.
All changes are to documentation (moduledocs, README, example files).

---

## Phase 1: Update README

### Overview
Update README to accurately reflect implemented features and add KMS integration section.

### Changes Required

#### File: `README.md`

1. **Update "Current Status" section** - Mark KMS keyrings as implemented:

```markdown
### Implemented Features

- ✅ Algorithm suite definitions (all 11 ESDK suites)
- ✅ HKDF key derivation per [RFC 5869](https://tools.ietf.org/html/rfc5869)
- ✅ Message format serialization/deserialization (v1 and v2 headers)
- ✅ Basic encrypt/decrypt operations
- ✅ Framed and non-framed body formats
- ✅ Key commitment verification for committed algorithm suites
- ✅ Test vector harness for cross-SDK compatibility testing
- ✅ Keyring behaviour interface
- ✅ Raw AES keyring
- ✅ Raw RSA keyring (all 5 padding schemes)
- ✅ Multi-keyring composition
- ✅ Cryptographic Materials Manager (CMM) with Default implementation
- ✅ Client module with commitment policy enforcement
- ✅ ECDSA signing for signed algorithm suites (P-384)
- ✅ Support for all 17 algorithm suites
- ✅ AWS KMS Keyring
- ✅ AWS KMS Discovery Keyring
- ✅ AWS KMS MRK Keyring
- ✅ AWS KMS MRK Discovery Keyring

### Not Yet Implemented

- ❌ Streaming encryption/decryption
- ❌ Caching CMM
- ❌ Required Encryption Context CMM
```

2. **Update "Not Yet Implemented" section** - Remove KMS, add Milestone 5 items

3. **Add new "AWS KMS Integration" section** after Usage:

```markdown
## AWS KMS Integration

The SDK provides four KMS keyring types for different use cases:

| Scenario | Recommended Keyring |
|----------|---------------------|
| Single key, known at encrypt/decrypt | `AwsKms` |
| Unknown key at decrypt time | `AwsKmsDiscovery` |
| Cross-region disaster recovery | `AwsKmsMrk` |
| Cross-region discovery | `AwsKmsMrkDiscovery` |
| Multiple keys for redundancy | `Multi` with KMS generator |

### Basic KMS Encryption

```elixir
alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Create KMS client
{:ok, kms_client} = ExAws.new(region: "us-west-2")

# Create keyring with your KMS key ARN
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
  kms_client
)

# Create CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Encrypt data
{:ok, ciphertext} = Client.encrypt(client, "Hello, World!",
  encryption_context: %{"purpose" => "example"}
)

# Decrypt data
{:ok, {plaintext, _context}} = Client.decrypt(client, ciphertext)
```

### AWS Credentials

The SDK uses ExAws for AWS integration. Configure credentials via:

1. **Environment variables**: `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
2. **Instance profile**: Automatic on EC2/ECS/Lambda
3. **Explicit configuration**:

```elixir
{:ok, client} = ExAws.new(
  region: "us-west-2",
  config: [
    access_key_id: "AKIAIOSFODNN7EXAMPLE",
    secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  ]
)
```

See [examples/](examples/) for complete working examples.
```

4. **Update "What's Next" section** - Remove outdated items:

```markdown
## What's Next

See [CHANGELOG.md](CHANGELOG.md) for detailed change history.

**Planned for future releases:**

1. **Streaming** - Large file encryption/decryption
2. **Caching CMM** - Performance optimization for repeated operations
3. **Required Encryption Context CMM** - Enforce required context keys
```

### Success Criteria

#### Automated Verification:
- [x] No broken markdown links
- [x] Example code is valid Elixir syntax

#### Manual Verification:
- [x] README accurately reflects implemented features
- [x] KMS section is clear and helpful
- [x] Code examples are realistic and correct

---

## Phase 2: Enhance AWS KMS Keyring Moduledoc

### Overview
Add comprehensive documentation to the primary `AwsKms` keyring module.

### Changes Required

#### File: `lib/aws_encryption_sdk/keyring/aws_kms.ex`

Replace the existing `@moduledoc` with enhanced version:

```elixir
@moduledoc """
AWS KMS Keyring implementation.

Encrypts and decrypts data keys using AWS Key Management Service (KMS).
This is the primary keyring for AWS-based encryption workflows.

## Use Cases

- **Server-side encryption**: Encrypt data at rest with KMS-managed keys
- **Multi-party encryption**: Use with Multi-keyring for redundant key access
- **Compliance**: Leverage KMS audit trails and key policies

## Key Identifier Formats

The keyring accepts various KMS key identifier formats:

| Format | Example | Recommended |
|--------|---------|-------------|
| Key ARN | `arn:aws:kms:us-west-2:123:key/abc` | Yes |
| Alias ARN | `arn:aws:kms:us-west-2:123:alias/my-key` | Yes |
| Key ID | `12345678-1234-1234-1234-123456789012` | No* |
| Alias Name | `alias/my-key` | No* |

*Non-ARN formats work but limit portability and explicit region control.

## Operations

### Encryption (wrap_key)

When no plaintext data key exists:
1. Calls KMS `GenerateDataKey` to create a new data key
2. Returns both plaintext and encrypted data key

When plaintext data key already exists (multi-keyring scenario):
1. Calls KMS `Encrypt` to wrap the existing key
2. Returns additional encrypted data key (EDK)

### Decryption (unwrap_key)

1. Filters EDKs to find those with provider ID "aws-kms"
2. Validates EDK key ARN matches configured key (supports MRK matching)
3. Calls KMS `Decrypt` with the first matching EDK
4. Returns decrypted plaintext data key

## IAM Permissions Required

The IAM principal must have these KMS permissions:

### For Encryption

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GenerateDataKey",
    "kms:Encrypt"
  ],
  "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
}
```

### For Decryption

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
}
```

### For Both (Recommended)

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GenerateDataKey",
    "kms:Encrypt",
    "kms:Decrypt"
  ],
  "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID"
}
```

## Security Considerations

- **Key Access**: Anyone with KMS Decrypt permission for the key can decrypt data
- **Encryption Context**: Use encryption context to bind ciphertext to specific contexts
- **Audit Trail**: All KMS operations are logged to CloudTrail
- **Key Rotation**: Enable automatic key rotation in KMS for long-lived keys
- **Grant Tokens**: Use for temporary, fine-grained access control

## Examples

### Basic Usage

```elixir
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Client

# Create KMS client for your region
{:ok, kms_client} = ExAws.new(region: "us-west-2")

# Create keyring with KMS key ARN
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
  kms_client
)

# Create CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Encrypt
{:ok, ciphertext} = Client.encrypt(client, "sensitive data",
  encryption_context: %{"tenant" => "acme", "purpose" => "storage"}
)

# Decrypt
{:ok, {plaintext, context}} = Client.decrypt(client, ciphertext)
```

### With Grant Tokens

```elixir
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123:key/abc",
  kms_client,
  grant_tokens: ["grant-token-from-create-grant-api"]
)
```

### With Multi-Keyring for Redundancy

```elixir
alias AwsEncryptionSdk.Keyring.Multi

# Primary KMS key (generator)
{:ok, primary} = AwsKms.new("arn:aws:kms:us-west-2:123:key/primary", west_client)

# Backup KMS key (child)
{:ok, backup} = AwsKms.new("arn:aws:kms:us-east-1:123:key/backup", east_client)

# Multi-keyring: encrypts with both, can decrypt with either
{:ok, multi} = Multi.new(generator: primary, children: [backup])
```

## Spec Reference

https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
"""
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix docs` generates documentation

---

## Phase 3: Enhance Discovery Keyring Moduledocs

### Overview
Add comprehensive documentation to both discovery keyring modules.

### Changes Required

#### File: `lib/aws_encryption_sdk/keyring/aws_kms_discovery.ex`

Replace the existing `@moduledoc`:

```elixir
@moduledoc """
AWS KMS Discovery Keyring implementation.

A decrypt-only keyring that can decrypt data encrypted with ANY KMS key
the caller has access to. Unlike the standard `AwsKms` keyring, this keyring
does not require knowing the key ARN in advance.

## Use Cases

- **Decryption services**: Services that decrypt data from multiple sources
- **Migration**: Decrypt data while transitioning between KMS keys
- **Flexible decryption**: When the encrypting key is not known at decrypt time

## Security Warning

Discovery keyrings will attempt to decrypt using ANY KMS key ARN found in
the encrypted data keys. Use a discovery filter to restrict which keys
can be used:

```elixir
{:ok, keyring} = AwsKmsDiscovery.new(client,
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012"]  # Only allow keys from this account
  }
)
```

## Operations

### Encryption

Discovery keyrings **cannot encrypt**. `wrap_key/2` always returns
`{:error, :discovery_keyring_cannot_encrypt}`.

For encryption, use:
- `AwsKms` keyring if you know the key ARN
- `Multi` keyring with an `AwsKms` generator for encryption + discovery for decryption

### Decryption (unwrap_key)

1. Filters EDKs by provider ID "aws-kms"
2. Validates each EDK's key ARN format
3. Applies discovery filter (if configured)
4. Attempts KMS Decrypt using the ARN from each EDK
5. Returns on first successful decryption

## Discovery Filter

Restrict which KMS keys can be used for decryption:

| Field | Description | Required |
|-------|-------------|----------|
| `partition` | AWS partition ("aws", "aws-cn", "aws-us-gov") | Yes |
| `accounts` | List of allowed AWS account IDs | Yes |

## IAM Permissions Required

The principal needs `kms:Decrypt` on ALL keys that might be encountered:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": [
    "arn:aws:kms:*:123456789012:key/*",
    "arn:aws:kms:*:987654321098:key/*"
  ]
}
```

Or use a condition to limit to specific accounts:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": "*",
  "Condition": {
    "StringEquals": {
      "kms:CallerAccount": ["123456789012", "987654321098"]
    }
  }
}
```

## Examples

### Basic Discovery Decryption

```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsDiscovery
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Client

# Create discovery keyring
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKmsDiscovery.new(kms_client)

# Create client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Decrypt data (encrypted with any accessible KMS key)
{:ok, {plaintext, context}} = Client.decrypt(client, ciphertext)
```

### With Discovery Filter (Recommended)

```elixir
{:ok, keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012", "987654321098"]
  }
)
```

### Encrypt with KMS, Decrypt with Discovery

```elixir
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery, Multi}

# Encryption keyring - knows the key
{:ok, encrypt_keyring} = AwsKms.new("arn:aws:kms:us-west-2:123:key/abc", kms_client)

# Decryption keyring - discovery mode
{:ok, decrypt_keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
)

# Use different clients for encrypt vs decrypt
encrypt_client = Client.new(Default.new(encrypt_keyring))
decrypt_client = Client.new(Default.new(decrypt_keyring))
```

## Spec Reference

https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md
"""
```

#### File: `lib/aws_encryption_sdk/keyring/aws_kms_mrk_discovery.ex`

Replace the existing `@moduledoc`:

```elixir
@moduledoc """
AWS KMS MRK Discovery Keyring implementation.

Combines discovery keyring behavior with Multi-Region Key (MRK) awareness.
Enables cross-region decryption of data encrypted with MRK keys without
knowing the specific key ARN in advance.

## Use Cases

- **Cross-region disaster recovery**: Decrypt in any region with MRK replicas
- **Global applications**: Access encrypted data from any region
- **Region failover**: Transparent failover to replica regions

## MRK vs Non-MRK Behavior

| Key Type | Behavior |
|----------|----------|
| MRK (mrk-*) | Reconstructs ARN with keyring's region, enables cross-region |
| Non-MRK | Only decrypts if key is in same region as keyring |

### Example: MRK Cross-Region

Data encrypted with `arn:aws:kms:us-east-1:123:key/mrk-abc` can be decrypted
by a keyring configured for `us-west-2` because:
1. Keyring detects MRK key ID (mrk-abc)
2. Reconstructs ARN: `arn:aws:kms:us-west-2:123:key/mrk-abc`
3. Calls KMS Decrypt in us-west-2 using the regional replica

## Operations

### Encryption

MRK Discovery keyrings **cannot encrypt**. `wrap_key/2` always returns
`{:error, :discovery_keyring_cannot_encrypt}`.

### Decryption (unwrap_key)

1. Filters EDKs by provider ID "aws-kms"
2. Validates ARN format and applies discovery filter
3. For MRK keys: reconstructs ARN with configured region
4. For non-MRK keys: only proceeds if regions match
5. Calls KMS Decrypt with the (possibly reconstructed) ARN

## Required Parameters

Unlike standard discovery keyring, MRK discovery requires a region:

| Parameter | Description |
|-----------|-------------|
| `kms_client` | KMS client for API calls |
| `region` | AWS region for MRK ARN reconstruction |

## IAM Permissions Required

The principal needs `kms:Decrypt` on both the original key AND any
MRK replicas that might be used:

```json
{
  "Effect": "Allow",
  "Action": "kms:Decrypt",
  "Resource": [
    "arn:aws:kms:us-east-1:123456789012:key/mrk-*",
    "arn:aws:kms:us-west-2:123456789012:key/mrk-*"
  ]
}
```

## Examples

### Basic MRK Discovery

```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Client

# Create MRK discovery keyring for us-west-2
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKmsMrkDiscovery.new(kms_client, "us-west-2")

# Create client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Decrypt data encrypted in ANY region with an MRK
{:ok, {plaintext, context}} = Client.decrypt(client, ciphertext)
```

### With Discovery Filter

```elixir
{:ok, keyring} = AwsKmsMrkDiscovery.new(kms_client, "us-west-2",
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012"]
  }
)
```

### Cross-Region Decryption Setup

```elixir
# Data was encrypted in us-east-1 with:
# arn:aws:kms:us-east-1:123:key/mrk-abc

# Decrypt in us-west-2 (DR region)
{:ok, west_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKmsMrkDiscovery.new(west_client, "us-west-2",
  discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
)

# This works because mrk-abc has a replica in us-west-2
{:ok, {plaintext, _}} = Client.decrypt(Client.new(Default.new(keyring)), ciphertext)
```

## Spec Reference

https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-discovery-keyring.md
"""
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix docs` generates documentation

---

## Phase 4: Enhance MRK Keyring Moduledoc

### Overview
Add comprehensive documentation to the MRK keyring module.

### Changes Required

#### File: `lib/aws_encryption_sdk/keyring/aws_kms_mrk.ex`

Replace the existing `@moduledoc`:

```elixir
@moduledoc """
AWS KMS Multi-Region Key (MRK) Keyring implementation.

Enables cross-region encryption and decryption using KMS Multi-Region Keys.
MRKs are KMS keys that are replicated across AWS regions with the same key
material but different regional ARNs.

## Use Cases

- **Disaster recovery**: Encrypt in primary region, decrypt in DR region
- **Global applications**: Access data from any region with MRK replica
- **Data locality**: Keep encrypted data close to users while maintaining access

## Multi-Region Keys (MRKs)

MRKs have special key IDs starting with `mrk-`:

| Key Type | Key ID Format | Cross-Region |
|----------|---------------|--------------|
| Single-region | `12345678-...` | No |
| Multi-region | `mrk-12345678-...` | Yes |

## MRK Matching

This keyring uses MRK matching to determine if it can decrypt an EDK:

| Configured Key | EDK Key | Match? |
|----------------|---------|--------|
| `mrk-abc` in us-west-2 | `mrk-abc` in us-east-1 | Yes |
| `mrk-abc` in us-west-2 | `mrk-xyz` in us-west-2 | No |
| `12345` in us-west-2 | `12345` in us-east-1 | No |

## Operations

### Encryption (wrap_key)

Identical to standard `AwsKms` keyring - MRK awareness only affects decryption.

### Decryption (unwrap_key)

Uses MRK matching to allow decryption with any regional replica:
1. Filters EDKs by provider ID "aws-kms"
2. Uses MRK matching to find compatible EDKs
3. Calls KMS Decrypt with the configured key ARN
4. Returns decrypted plaintext data key

## IAM Permissions Required

Same as standard KMS keyring, but grant on all regional replicas:

```json
{
  "Effect": "Allow",
  "Action": [
    "kms:GenerateDataKey",
    "kms:Encrypt",
    "kms:Decrypt"
  ],
  "Resource": [
    "arn:aws:kms:us-west-2:123456789012:key/mrk-*",
    "arn:aws:kms:us-east-1:123456789012:key/mrk-*"
  ]
}
```

## Examples

### Basic MRK Usage

```elixir
alias AwsEncryptionSdk.Keyring.AwsKmsMrk
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Client

# Create keyring with MRK in us-west-2
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKmsMrk.new(
  "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
  kms_client
)

# Encrypt in us-west-2
cmm = Default.new(keyring)
client = Client.new(cmm)
{:ok, ciphertext} = Client.encrypt(client, "sensitive data")
```

### Cross-Region Decryption

```elixir
# Original encryption in us-west-2 (above)

# Decrypt in us-east-1 using the regional replica
{:ok, east_client} = ExAws.new(region: "us-east-1")
{:ok, east_keyring} = AwsKmsMrk.new(
  "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
  east_client
)

# This works because MRK matching recognizes same key in different region
{:ok, {plaintext, _}} = Client.decrypt(Client.new(Default.new(east_keyring)), ciphertext)
```

### Multi-Keyring for Multi-Region

```elixir
alias AwsEncryptionSdk.Keyring.Multi

# Use Multi.new_mrk_aware/4 for easy multi-region setup
{:ok, multi} = Multi.new_mrk_aware(
  "arn:aws:kms:us-west-2:123:key/mrk-abc",
  west_client,
  [
    {"us-east-1", east_client},
    {"eu-west-1", eu_client}
  ]
)

# Encrypts with us-west-2, can decrypt in any region
```

## Spec Reference

https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
"""
```

### Success Criteria

#### Automated Verification:
- [x] `mix compile` succeeds
- [x] `mix docs` generates documentation

---

## Phase 5: Create Example Scripts

### Overview
Create runnable example scripts demonstrating KMS keyring usage patterns.

### Changes Required

#### Create Directory: `examples/`

#### File: `examples/README.md`

```markdown
# AWS Encryption SDK Examples

Example scripts demonstrating various encryption scenarios.

## Prerequisites

1. AWS credentials configured (environment variables, instance profile, or ~/.aws/credentials)
2. KMS key(s) with appropriate permissions
3. Dependencies installed: `mix deps.get`

## Running Examples

```bash
# Set your KMS key ARN
export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."

# Run an example
mix run examples/kms_basic.exs
```

## Examples

| File | Description |
|------|-------------|
| `kms_basic.exs` | Basic encryption/decryption with KMS keyring |
| `kms_discovery.exs` | Discovery keyring for flexible decryption |
| `kms_multi_keyring.exs` | Multi-keyring with KMS generator |
| `kms_cross_region.exs` | Cross-region decryption with MRK keyrings |
```

#### File: `examples/kms_basic.exs`

```elixir
# Basic KMS Encryption Example
#
# Prerequisites:
#   - AWS credentials configured
#   - KMS key with GenerateDataKey and Decrypt permissions
#
# Usage:
#   export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."
#   export AWS_REGION="us-west-2"  # optional, defaults to key's region
#   mix run examples/kms_basic.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Get configuration from environment
kms_key_arn = System.get_env("KMS_KEY_ARN") ||
  raise "Set KMS_KEY_ARN environment variable"

region = System.get_env("AWS_REGION") ||
  # Extract region from ARN
  case Regex.run(~r/arn:aws:kms:([^:]+):/, kms_key_arn) do
    [_, region] -> region
    _ -> raise "Could not determine region - set AWS_REGION"
  end

IO.puts("Using KMS key: #{kms_key_arn}")
IO.puts("Region: #{region}")

# Create KMS client and keyring
{:ok, kms_client} = ExAws.new(region: region)
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)

# Create CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Original data
plaintext = "Hello, AWS Encryption SDK!"
encryption_context = %{
  "purpose" => "example",
  "environment" => "development"
}

IO.puts("\nOriginal: #{plaintext}")
IO.puts("Encryption context: #{inspect(encryption_context)}")

# Encrypt
IO.puts("\nEncrypting...")
{:ok, ciphertext} = Client.encrypt(client, plaintext,
  encryption_context: encryption_context
)
IO.puts("Encrypted! Ciphertext size: #{byte_size(ciphertext)} bytes")

# Decrypt
IO.puts("\nDecrypting...")
{:ok, {decrypted, returned_context}} = Client.decrypt(client, ciphertext)

IO.puts("Decrypted: #{decrypted}")
IO.puts("Returned context: #{inspect(returned_context)}")

# Verify
if decrypted == plaintext do
  IO.puts("\n✓ Success! Round-trip encryption/decryption verified.")
else
  IO.puts("\n✗ Error: Decrypted data doesn't match original!")
  System.halt(1)
end
```

#### File: `examples/kms_discovery.exs`

```elixir
# KMS Discovery Keyring Example
#
# Demonstrates decrypt-only discovery keyring that can decrypt data
# encrypted with any KMS key the caller has access to.
#
# Prerequisites:
#   - AWS credentials configured
#   - KMS key with GenerateDataKey permission (for encryption)
#   - kms:Decrypt permission on keys in discovery filter
#
# Usage:
#   export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."
#   export AWS_ACCOUNT_ID="123456789012"
#   mix run examples/kms_discovery.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery}
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
kms_key_arn = System.get_env("KMS_KEY_ARN") ||
  raise "Set KMS_KEY_ARN environment variable"

account_id = System.get_env("AWS_ACCOUNT_ID") ||
  case Regex.run(~r/arn:aws:kms:[^:]+:(\d+):/, kms_key_arn) do
    [_, account] -> account
    _ -> raise "Could not determine account - set AWS_ACCOUNT_ID"
  end

region = System.get_env("AWS_REGION") ||
  case Regex.run(~r/arn:aws:kms:([^:]+):/, kms_key_arn) do
    [_, region] -> region
    _ -> raise "Could not determine region - set AWS_REGION"
  end

IO.puts("Encryption key: #{kms_key_arn}")
IO.puts("Discovery filter account: #{account_id}")

# ============================================================
# Step 1: Encrypt with known KMS key
# ============================================================

{:ok, kms_client} = ExAws.new(region: region)
{:ok, encrypt_keyring} = AwsKms.new(kms_key_arn, kms_client)

encrypt_client = Client.new(Default.new(encrypt_keyring))

plaintext = "Secret message for discovery example"

IO.puts("\nEncrypting with known key...")
{:ok, ciphertext} = Client.encrypt(encrypt_client, plaintext,
  encryption_context: %{"example" => "discovery"}
)
IO.puts("Encrypted! Size: #{byte_size(ciphertext)} bytes")

# ============================================================
# Step 2: Decrypt with discovery keyring
# ============================================================

# Create discovery keyring with filter (recommended for security)
{:ok, discovery_keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{
    partition: "aws",
    accounts: [account_id]
  }
)

decrypt_client = Client.new(Default.new(discovery_keyring))

IO.puts("\nDecrypting with discovery keyring...")
IO.puts("(Discovery keyring doesn't know which key was used)")

{:ok, {decrypted, _context}} = Client.decrypt(decrypt_client, ciphertext)
IO.puts("Decrypted: #{decrypted}")

IO.puts("\n✓ Discovery decryption successful!")
IO.puts("The discovery keyring found the correct key automatically.")
```

#### File: `examples/kms_multi_keyring.exs`

```elixir
# Multi-Keyring with KMS Example
#
# Demonstrates encrypting with multiple KMS keys for redundancy.
# Data can be decrypted with ANY of the keys.
#
# Prerequisites:
#   - AWS credentials configured
#   - Two KMS keys with appropriate permissions
#
# Usage:
#   export KMS_KEY_ARN_1="arn:aws:kms:us-west-2:123:key/primary"
#   export KMS_KEY_ARN_2="arn:aws:kms:us-west-2:123:key/backup"
#   mix run examples/kms_multi_keyring.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.{AwsKms, Multi}
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
key_arn_1 = System.get_env("KMS_KEY_ARN_1") ||
  raise "Set KMS_KEY_ARN_1 environment variable"

key_arn_2 = System.get_env("KMS_KEY_ARN_2") ||
  raise "Set KMS_KEY_ARN_2 environment variable"

# Extract region from first key
region = case Regex.run(~r/arn:aws:kms:([^:]+):/, key_arn_1) do
  [_, region] -> region
  _ -> System.get_env("AWS_REGION") || raise "Could not determine region"
end

IO.puts("Primary key: #{key_arn_1}")
IO.puts("Backup key: #{key_arn_2}")
IO.puts("Region: #{region}")

# Create clients
{:ok, kms_client} = ExAws.new(region: region)

# Create keyrings
{:ok, primary_keyring} = AwsKms.new(key_arn_1, kms_client)
{:ok, backup_keyring} = AwsKms.new(key_arn_2, kms_client)

# Create multi-keyring
# - Primary is the generator (creates the data key)
# - Backup is a child (wraps the same data key)
{:ok, multi_keyring} = Multi.new(
  generator: primary_keyring,
  children: [backup_keyring]
)

IO.puts("\nMulti-keyring created with 2 keys")

# ============================================================
# Encrypt with multi-keyring
# ============================================================

encrypt_client = Client.new(Default.new(multi_keyring))

plaintext = "Critical data protected by multiple keys"

IO.puts("\nEncrypting with multi-keyring...")
{:ok, ciphertext} = Client.encrypt(encrypt_client, plaintext)
IO.puts("Encrypted! Data key wrapped by both keys.")

# ============================================================
# Decrypt with primary key only
# ============================================================

IO.puts("\nDecrypting with primary key only...")
primary_client = Client.new(Default.new(primary_keyring))
{:ok, {decrypted, _}} = Client.decrypt(primary_client, ciphertext)
IO.puts("✓ Decrypted with primary: #{decrypted}")

# ============================================================
# Decrypt with backup key only
# ============================================================

IO.puts("\nDecrypting with backup key only...")
backup_client = Client.new(Default.new(backup_keyring))
{:ok, {decrypted, _}} = Client.decrypt(backup_client, ciphertext)
IO.puts("✓ Decrypted with backup: #{decrypted}")

IO.puts("\n✓ Multi-keyring example complete!")
IO.puts("Data can be decrypted with either key for redundancy.")
```

#### File: `examples/kms_cross_region.exs`

```elixir
# Cross-Region MRK Decryption Example
#
# Demonstrates encrypting with an MRK in one region and decrypting
# with the replica in another region.
#
# Prerequisites:
#   - AWS credentials configured
#   - Multi-Region Key (mrk-*) replicated across regions
#
# Usage:
#   export MRK_KEY_ARN="arn:aws:kms:us-west-2:123:key/mrk-..."
#   export REPLICA_REGION="us-east-1"
#   mix run examples/kms_cross_region.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.AwsKmsMrk
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
mrk_key_arn = System.get_env("MRK_KEY_ARN") ||
  raise "Set MRK_KEY_ARN environment variable (must be mrk-* key)"

replica_region = System.get_env("REPLICA_REGION") || "us-east-1"

# Validate it's an MRK
unless String.contains?(mrk_key_arn, "/mrk-") do
  raise "Key must be a Multi-Region Key (key ID starting with mrk-)"
end

# Extract primary region and construct replica ARN
primary_region = case Regex.run(~r/arn:aws:kms:([^:]+):/, mrk_key_arn) do
  [_, region] -> region
  _ -> raise "Invalid key ARN format"
end

replica_key_arn = String.replace(mrk_key_arn, primary_region, replica_region)

IO.puts("Primary key (#{primary_region}): #{mrk_key_arn}")
IO.puts("Replica key (#{replica_region}): #{replica_key_arn}")

# ============================================================
# Step 1: Encrypt in primary region
# ============================================================

{:ok, primary_client} = ExAws.new(region: primary_region)
{:ok, primary_keyring} = AwsKmsMrk.new(mrk_key_arn, primary_client)

encrypt_client = Client.new(Default.new(primary_keyring))

plaintext = "Data encrypted in #{primary_region}, to be decrypted in #{replica_region}"

IO.puts("\nEncrypting in #{primary_region}...")
{:ok, ciphertext} = Client.encrypt(encrypt_client, plaintext,
  encryption_context: %{"source_region" => primary_region}
)
IO.puts("Encrypted! Size: #{byte_size(ciphertext)} bytes")

# ============================================================
# Step 2: Decrypt in replica region
# ============================================================

IO.puts("\nDecrypting in #{replica_region} using MRK replica...")

{:ok, replica_client} = ExAws.new(region: replica_region)
{:ok, replica_keyring} = AwsKmsMrk.new(replica_key_arn, replica_client)

decrypt_client = Client.new(Default.new(replica_keyring))

{:ok, {decrypted, context}} = Client.decrypt(decrypt_client, ciphertext)

IO.puts("Decrypted: #{decrypted}")
IO.puts("Context shows source: #{context["source_region"]}")

IO.puts("\n✓ Cross-region decryption successful!")
IO.puts("Data encrypted in #{primary_region} was decrypted in #{replica_region}")
```

### Success Criteria

#### Automated Verification:
- [x] All example files have valid Elixir syntax: `mix compile`
- [x] README.md exists with instructions

#### Manual Verification:
- [ ] Examples run successfully with valid AWS credentials
- [ ] Each example demonstrates a distinct use case
- [ ] Error messages are helpful when prerequisites aren't met

---

## Final Verification

After all phases complete:

### Automated:
- [x] `mix compile` succeeds
- [x] `mix docs` generates documentation
- [x] No broken markdown links in README

### Manual:
- [ ] README accurately reflects all implemented features
- [ ] All KMS keyring modules have comprehensive moduledocs
- [ ] At least one example runs successfully
- [ ] IAM permissions are documented for each keyring type
- [ ] Security considerations are prominently documented

## Testing Strategy

This is a documentation-only change. Testing is manual verification:

1. **Documentation builds**: `mix docs` and review generated HTML
2. **README accuracy**: Compare claims against actual implementation
3. **Example execution**: Run examples with valid AWS credentials
4. **Code review**: Verify documentation matches actual module behavior

## References

- Issue: #53
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/tree/master/framework/aws-kms
- Related issues: #48, #49, #50, #51, #52
