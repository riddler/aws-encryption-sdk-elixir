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

**Version**: 0.2.0 (pre-release)

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

### Not Yet Implemented

- ❌ Keyrings (Raw RSA, AWS KMS)
- ❌ Cryptographic Materials Manager (CMM)
- ❌ Streaming encryption/decryption
- ❌ ECDSA signing for signed algorithm suites

### Test Coverage

- 230 tests passing
- 91.1% code coverage

## Installation

Add `aws_encryption_sdk` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:aws_encryption_sdk, "~> 0.2.0"}
  ]
end
```

## Usage

> **Note**: The current implementation requires you to provide your own key material.
> Keyring support (including AWS KMS integration) is coming in a future release.

### Basic Encryption

```elixir
alias AwsEncryptionSdk.AlgorithmSuite
alias AwsEncryptionSdk.Encrypt
alias AwsEncryptionSdk.Decrypt
alias AwsEncryptionSdk.Materials.{EncryptionMaterials, DecryptionMaterials}

# Get the default algorithm suite (AES-256-GCM with key commitment)
suite = AlgorithmSuite.default_suite()

# Create encryption materials with your data key
materials = %EncryptionMaterials{
  algorithm_suite: suite,
  plaintext_data_key: :crypto.strong_rand_bytes(32),
  encryption_context: %{"purpose" => "example", "tenant" => "test"},
  encrypted_data_keys: []  # Would normally come from a keyring
}

# Encrypt data
plaintext = "Hello, World!"
{:ok, ciphertext} = Encrypt.encrypt(materials, plaintext)

# Decrypt data
decryption_materials = %DecryptionMaterials{
  algorithm_suite: suite,
  plaintext_data_key: materials.plaintext_data_key,
  encryption_context: materials.encryption_context
}

{:ok, decrypted} = Decrypt.decrypt(decryption_materials, ciphertext)
# decrypted == "Hello, World!"
```

## Requirements

- Elixir 1.16 or later
- Erlang/OTP 26 or later

## What's Next

See [CHANGELOG.md](CHANGELOG.md) for detailed change history.

**Planned for future releases:**

1. **Keyrings** - Raw RSA and AWS KMS keyrings
2. **CMM** - Cryptographic Materials Manager with caching
3. **Streaming** - Large file encryption/decryption
4. **Signatures** - ECDSA signing for signed algorithm suites

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
