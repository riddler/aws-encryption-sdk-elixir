# AWS Encryption SDK Examples

Example scripts demonstrating various encryption scenarios, organized by complexity.

## Quick Start (No AWS Required)

```bash
# Basic AES encryption
mix run examples/01_basics/raw_aes_basic.exs

# RSA encryption with all padding schemes
mix run examples/01_basics/raw_rsa.exs

# Multi-keyring for redundancy
mix run examples/01_basics/multi_keyring_local.exs

# Streaming large file encryption
mix run examples/02_advanced/streaming_file.exs

# Caching CMM for high throughput
mix run examples/02_advanced/caching_cmm.exs

# Required encryption context enforcement
mix run examples/02_advanced/required_encryption_context.exs
```

## AWS KMS Examples

These examples require AWS credentials and KMS keys:

### Prerequisites

1. AWS credentials configured (environment variables, instance profile, or ~/.aws/credentials)
2. KMS key(s) with appropriate permissions
3. Dependencies installed: `mix deps.get`

### Running KMS Examples

```bash
# Set your KMS key ARN
export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."

# Run an example
mix run examples/03_aws_kms/kms_basic.exs
```

## Examples by Category

### 01_basics/ - Getting Started (No AWS Required)

| File | Description |
|------|-------------|
| `raw_aes_basic.exs` | AES-GCM encryption with local key, all key sizes |
| `raw_rsa.exs` | RSA encryption, all padding schemes, PEM key support |
| `multi_keyring_local.exs` | Multi-keyring for redundancy and key rotation |

### 02_advanced/ - Advanced Features (No AWS Required)

| File | Description |
|------|-------------|
| `streaming_file.exs` | Memory-efficient encryption of large files |
| `caching_cmm.exs` | Cached materials for high-throughput encryption |
| `required_encryption_context.exs` | Enforce mandatory encryption context keys |

### 03_aws_kms/ - AWS KMS Integration

| File | Description |
|------|-------------|
| `kms_basic.exs` | Basic encryption/decryption with KMS keyring |
| `kms_discovery.exs` | Discovery keyring for flexible decryption |
| `kms_multi_keyring.exs` | Multi-keyring with KMS for redundancy |
| `kms_cross_region.exs` | Cross-region decryption with MRK keyrings |

## Environment Variables

### RSA Example

| Variable | Description |
|----------|-------------|
| `RSA_PRIVATE_KEY_PEM` | PEM-encoded RSA private key (optional) |
| `RSA_PUBLIC_KEY_PEM` | PEM-encoded RSA public key (optional) |

If both are set, the example uses these keys. If neither is set, keys are generated.

### KMS Examples

| Variable | Description |
|----------|-------------|
| `KMS_KEY_ARN` | ARN of your KMS key |
| `KMS_KEY_ARN_1` | Primary KMS key (for multi-keyring) |
| `KMS_KEY_ARN_2` | Backup KMS key (for multi-keyring) |
| `AWS_REGION` | AWS region (optional, extracted from ARN) |

## Security Notes

- **Never hardcode keys** in production code
- **Protect private keys** with appropriate file permissions
- **Use a key management system** for production deployments
- The local key examples are for development and testing
