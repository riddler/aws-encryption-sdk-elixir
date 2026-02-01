# AWS Encryption SDK Examples

Example scripts demonstrating various encryption scenarios.

## Quick Start (No AWS Required)

These examples work without AWS credentials:

```bash
# Basic AES encryption
mix run examples/raw_aes_basic.exs

# RSA encryption with all padding schemes (generates keys)
mix run examples/raw_rsa.exs

# RSA with existing PEM keys
export RSA_PRIVATE_KEY_PEM="$(cat private.pem)"
export RSA_PUBLIC_KEY_PEM="$(cat public.pem)"
mix run examples/raw_rsa.exs

# Multi-keyring for redundancy
mix run examples/multi_keyring_local.exs
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
mix run examples/kms_basic.exs
```

## Examples

### Local Key Examples (No AWS Required)

| File | Description |
|------|-------------|
| `raw_aes_basic.exs` | AES-GCM encryption with local key, all key sizes |
| `raw_rsa.exs` | RSA encryption, all padding schemes, env var PEM support |
| `multi_keyring_local.exs` | Multi-keyring for redundancy and key rotation |

### AWS KMS Examples

| File | Description |
|------|-------------|
| `kms_basic.exs` | Basic encryption/decryption with KMS keyring |
| `kms_discovery.exs` | Discovery keyring for flexible decryption |
| `kms_multi_keyring.exs` | Multi-keyring with KMS generator |
| `kms_cross_region.exs` | Cross-region decryption with MRK keyrings |

## Environment Variables

### RSA Example

| Variable | Description |
|----------|-------------|
| `RSA_PRIVATE_KEY_PEM` | PEM-encoded RSA private key (optional) |
| `RSA_PUBLIC_KEY_PEM` | PEM-encoded RSA public key (optional) |

If both are set, the example uses these keys. If neither is set, keys are generated.

## Security Notes

- **Never hardcode keys** in production code
- **Protect private keys** with appropriate file permissions
- **Use a key management system** for production deployments
- The local key examples are for development and testing
