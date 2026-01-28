> ⚠️ **WORK IN PROGRESS** ⚠️
>
> This project is in active development and **not ready for production use**.
> The API is subject to change, and security audits have not been performed.
> Use at your own risk in development/testing environments only.

[![CI](https://github.com/riddler/aws-encryption-sdk-elixir/actions/workflows/ci.yml/badge.svg)](https://github.com/riddler/aws-encryption-sdk-elixir/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/riddler/aws-encryption-sdk-elixir/branch/main/graph/badge.svg)](https://codecov.io/gh/riddler/aws-encryption-sdk-elixir)

# AWS Encryption SDK for Elixir

An Elixir implementation of the [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html), providing client-side encryption compatible with all other AWS Encryption SDK implementations (Python, Java, JavaScript, C, CLI).

## Current Status

**Version**: 0.4.0 (pre-release)

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

### Test Coverage

- 469 tests passing
- 93.8% code coverage

## Installation

Add `aws_encryption_sdk` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:aws_encryption_sdk, "~> 0.4.0"}
  ]
end
```

## Usage

### Basic Encryption with Raw Keyring

```elixir
alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

# Create a raw AES keyring
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = RawAes.new(key: key, namespace: "my-app", name: "data-key-1")

# Create CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Encrypt data
plaintext = "Hello, World!"
{:ok, ciphertext} = Client.encrypt(client, plaintext,
  encryption_context: %{"purpose" => "example"}
)

# Decrypt data
{:ok, {decrypted, context}} = Client.decrypt(client, ciphertext)
# decrypted == "Hello, World!"
```

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

## Requirements

- Elixir 1.16 or later
- Erlang/OTP 26 or later

## What's Next

See [CHANGELOG.md](CHANGELOG.md) for detailed change history.

**Planned for future releases:**

1. **Streaming** - Large file encryption/decryption
2. **Caching CMM** - Performance optimization for repeated operations
3. **Required Encryption Context CMM** - Enforce required context keys

## Related Projects

### Official AWS Encryption SDKs
- [Python](https://github.com/aws/aws-encryption-sdk-python)
- [Java](https://github.com/aws/aws-encryption-sdk-java)
- [JavaScript](https://github.com/aws/aws-encryption-sdk-javascript)
- [C](https://github.com/aws/aws-encryption-sdk-c)
- [CLI](https://github.com/aws/aws-encryption-sdk-cli)

### Specification
- [AWS Encryption SDK Specification](https://github.com/awslabs/aws-encryption-sdk-specification)
- [Test Vectors](https://github.com/awslabs/aws-encryption-sdk-test-vectors)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
