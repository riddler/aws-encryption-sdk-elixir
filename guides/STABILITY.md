# API Stability Policy

This document describes the API stability guarantees for the AWS Encryption SDK for Elixir.

## Semantic Versioning

The AWS Encryption SDK for Elixir follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR version** (X.0.0) - Incompatible API changes
- **MINOR version** (0.X.0) - New functionality, backward compatible
- **PATCH version** (0.0.X) - Bug fixes, backward compatible

### Version Format

Given a version number `MAJOR.MINOR.PATCH`:

- **MAJOR**: Incremented for breaking changes
- **MINOR**: Incremented for new features (backward compatible)
- **PATCH**: Incremented for bug fixes (backward compatible)

## Stability Guarantees

### Public API (Stable)

The following modules and functions are considered **public API** and follow strict backward compatibility:

#### Core Encryption/Decryption
- `AwsEncryptionSdk` - Main module facade
- `AwsEncryptionSdk.Client` - Client configuration and operations
- `AwsEncryptionSdk.Encrypt` - Encryption operations
- `AwsEncryptionSdk.Decrypt` - Decryption operations

#### Streaming API
- `AwsEncryptionSdk.Stream` - High-level streaming API
- `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption state machine
- `AwsEncryptionSdk.Stream.Decryptor` - Streaming decryption state machine

#### Keyrings
- `AwsEncryptionSdk.Keyring.Behaviour` - Keyring interface
- `AwsEncryptionSdk.Keyring.RawAes` - Raw AES keyring
- `AwsEncryptionSdk.Keyring.RawRsa` - Raw RSA keyring
- `AwsEncryptionSdk.Keyring.AwsKms` - AWS KMS keyring
- `AwsEncryptionSdk.Keyring.AwsKmsDiscovery` - KMS discovery keyring
- `AwsEncryptionSdk.Keyring.AwsKmsMrk` - KMS multi-region key keyring
- `AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery` - KMS MRK discovery keyring
- `AwsEncryptionSdk.Keyring.Multi` - Multi-keyring composition
- `AwsEncryptionSdk.Keyring.KmsClient` - KMS client interface

#### Cryptographic Materials Managers
- `AwsEncryptionSdk.Cmm.Behaviour` - CMM interface
- `AwsEncryptionSdk.Cmm.Default` - Default CMM
- `AwsEncryptionSdk.Cmm.Caching` - Caching CMM
- `AwsEncryptionSdk.Cmm.RequiredEncryptionContext` - Required context CMM

#### Caching
- `AwsEncryptionSdk.Cache.CryptographicMaterialsCache` - Cache interface
- `AwsEncryptionSdk.Cache.LocalCache` - Local in-memory cache

#### Data Structures
- `AwsEncryptionSdk.Materials.EncryptionMaterials` - Encryption materials
- `AwsEncryptionSdk.Materials.DecryptionMaterials` - Decryption materials
- `AwsEncryptionSdk.Materials.EncryptedDataKey` - Encrypted data key
- `AwsEncryptionSdk.AlgorithmSuite` - Algorithm suite definitions

**Guarantee**: Public API functions will not change signatures or behavior in backward-incompatible ways within the same MAJOR version.

### Internal API (Unstable)

The following modules are considered **internal implementation details** and may change without notice:

- `AwsEncryptionSdk.Format.*` - Message format serialization (internal)
- `AwsEncryptionSdk.Crypto.*` - Low-level cryptographic operations (internal)
- `AwsEncryptionSdk.Keyring.KmsKeyArn` - KMS ARN parsing (internal utility)
- `AwsEncryptionSdk.Cache.CacheEntry` - Cache entry implementation (internal)
- `AwsEncryptionSdk.Stream.SignatureAccumulator` - Internal to streaming (advanced use only)

**Warning**: Internal modules may change in MINOR or PATCH versions. Use at your own risk.

### Message Format Stability

The binary message format produced by encryption is **stable** and follows the [AWS Encryption SDK Specification](https://github.com/awslabs/aws-encryption-sdk-specification):

- Messages encrypted with this SDK can be decrypted by other AWS Encryption SDK implementations
- Messages encrypted by other SDKs can be decrypted by this SDK
- Message format compatibility is maintained across all MAJOR, MINOR, and PATCH versions
- Algorithm suites and message versions follow the official specification

## Breaking Change Policy

### What Constitutes a Breaking Change

A **breaking change** requires a MAJOR version bump and includes:

1. **Function signature changes**:
   - Removing required function parameters
   - Changing parameter types
   - Changing return type structure
   - Removing public functions

2. **Behavior changes**:
   - Changing error conditions
   - Modifying security guarantees
   - Altering algorithm suite defaults
   - Changing commitment policy behavior

3. **Data structure changes**:
   - Removing struct fields used in public API
   - Changing struct field types in breaking ways
   - Modifying validation rules for inputs

### What Is NOT a Breaking Change

The following changes are **backward compatible** and only require MINOR or PATCH bumps:

1. **Additions**:
   - Adding new optional parameters
   - Adding new functions
   - Adding new modules
   - Adding new struct fields (with defaults)

2. **Fixes**:
   - Bug fixes that correct incorrect behavior
   - Security fixes
   - Performance improvements
   - Documentation improvements

3. **Internal changes**:
   - Refactoring internal modules
   - Optimizing implementation details
   - Updating dependencies (within semver constraints)

## Deprecation Process

When we need to make breaking changes, we follow this deprecation timeline:

### Step 1: Deprecation Warning (MINOR release)

- Add `@deprecated` attribute to affected functions
- Update documentation with migration guide
- Add compile-time warnings
- Maintain full backward compatibility

Example:

```elixir
@deprecated "Use Client.encrypt/3 instead. This will be removed in v2.0.0"
def old_encrypt(data) do
  # ... implementation
end
```

### Step 2: Deprecation Period (at least 6 months)

- Deprecated functions remain available for at least 6 months
- Multiple MINOR releases may occur during this period
- Migration guides and examples are provided
- Community feedback is collected

### Step 3: Removal (MAJOR release)

- Deprecated functions are removed
- MAJOR version is bumped (e.g., v1.5.0 → v2.0.0)
- CHANGELOG documents all breaking changes
- Migration guide is updated with complete upgrade path

## Dependency Policy

### Elixir and OTP

- **Minimum Elixir version**: We support Elixir versions for 2 years from their release
- **Minimum OTP version**: We support OTP versions that are actively maintained by the Erlang team
- **Current minimums**: Elixir 1.16+, OTP 26+

Raising minimum Elixir or OTP versions is considered a **breaking change** requiring a MAJOR bump.

### External Dependencies

- Production dependencies follow semver constraints
- We may update dependencies in MINOR releases if:
  - Changes are backward compatible
  - No API changes are required
  - Security updates are needed

## Security Policy

Security fixes are prioritized and may be released as:

- **PATCH releases** - If the fix doesn't break backward compatibility
- **MAJOR releases** - If the fix requires breaking changes (rare)

Critical security issues may warrant backporting fixes to older MAJOR versions.

## Specification Compliance

This SDK follows the [AWS Encryption SDK Specification](https://github.com/awslabs/aws-encryption-sdk-specification):

- **Specification updates** that maintain backward compatibility → MINOR release
- **Specification updates** that break compatibility → MAJOR release
- **Algorithm suite deprecations** follow the official AWS guidance and our deprecation process

## Feedback and Questions

If you have questions about API stability or need clarification on whether a change is breaking:

- Open an issue on [GitHub](https://github.com/riddler/aws-encryption-sdk-elixir/issues)
- Ask in discussions
- Check the [CHANGELOG](../CHANGELOG.md) for detailed change documentation

## Version History

- **v0.x.x** (Pre-1.0): Development releases, API may change
- **v1.0.0** (Planned): First stable release with API stability guarantees
