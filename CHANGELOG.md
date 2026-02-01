# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Non-AWS encryption examples for local key usage without AWS credentials (#74)
- Raw AES example demonstrating all key sizes (128/192/256-bit) with encryption context
- Raw RSA example with all 5 padding schemes and PEM key loading from environment variables
- Multi-keyring local example showing key redundancy and rotation patterns
- API Stability Policy guide documenting semantic versioning and breaking change policy (#72)
- Comprehensive module grouping in Hex docs for all keyrings, CMMs, caching, and streaming modules (#72)
- User guides for Getting Started, Choosing Components, and Security Best Practices (#73)
- Automated testing for guide code examples with extraction and validation (#73)
- Advanced feature examples demonstrating streaming, caching, and required encryption context (#75)
- Streaming file encryption example with 10MB test file and memory-efficient processing
- Caching CMM example showing 2x performance improvement for high-throughput scenarios
- Required Encryption Context example enforcing mandatory context keys for compliance

### Changed
- Consolidated CHANGELOG entries to improve readability and scannability (#81)
- Enhanced streaming module documentation with usage guidance, memory efficiency details, and verification handling (#72)
- Examples reorganized into complexity-based subdirectories (01_basics, 02_advanced, 03_aws_kms) (#75)
- Examples README updated with category-based navigation and quick start commands

### Fixed
- RSA keyring PEM loading to correctly decode keys using `pem_entry_decode` instead of `der_decode` (#74)
- All KMS examples updated to use correct Client API format (map-based return values)
- Client module now supports Caching CMM in dispatch clauses for encryption and decryption (#75)

## [0.6.0] - 2026-01-31

### Added
- Streaming encryption and decryption APIs for memory-efficient processing of large data (#60)
- Caching CMM for reducing expensive key provider calls with TTL and usage limits (#61)
- Required Encryption Context CMM for enforcing critical AAD keys during encryption/decryption (#62)

### Changed
- Integration tests now run by default in CI (#68)
- Coverage threshold adjusted from 94% to 92%

### Fixed
- KMS integration tests skip gracefully when AWS credentials unavailable (#68)

### Removed
- Temporary coveralls-ignore markers (#68)

## [0.5.0] - 2026-01-28

### Added
- AWS KMS Keyring for encrypting/decrypting data keys with AWS KMS (#48)
- AWS KMS Discovery Keyring for decrypt-only operations without specifying key ARN (#49)
- AWS KMS MRK Keyrings for cross-region Multi-Region Key decryption and disaster recovery (#50, #51)
- Multi-keyring enhancements: KMS generator validation, convenience constructors for MRK scenarios (#52)
- KMS client abstraction layer with ExAws implementation and mock for testing (#46, #47)
- Comprehensive documentation for AWS KMS keyrings with examples and usage guide (#53)

### Changed
- Increased minimum code coverage requirement from 93% to 94%

## [0.4.0] - 2026-01-27

### Added
- CMM (Cryptographic Materials Manager) behaviour interface with commitment policy support (#36)
- Default CMM implementation with keyring orchestration and ECDSA signing (#37)
- Client module with encrypt/decrypt APIs and commitment policy enforcement (#38, #39)
- Support for all 17 algorithm suites including signing and non-signing variants
- EDK count limit enforcement (max_encrypted_data_keys configuration)

### Changed
- Main API now recommends Client-based encryption workflow
- Renamed encrypt/decrypt to encrypt_with_materials/decrypt_with_materials
- Increased minimum code coverage requirement from 92% to 93%

## [0.3.0] - 2026-01-26

### Added
- Multi-Keyring for composing multiple keyrings with generator and child key support (#28)
- Raw RSA Keyring with support for PKCS1 v1.5 and OAEP padding schemes (#27)

### Changed
- Increased minimum code coverage requirement from 90% to 92%

## [0.2.0] - 2026-01-25

### Added
- Keyring behaviour interface with on_encrypt/on_decrypt callbacks (#25)
- Raw AES Keyring with AES-128/192/256 support (#26)
- GitHub Actions CI workflow with Elixir 1.16-1.18 and OTP 26-27 test matrix (#15)
- `/release` skill for automated version releases (#30)

### Changed
- Minimum Elixir version requirement from 1.18 to 1.16
- Minimum OTP version requirement to 26

## [0.1.0] - 2025-01-12

### Added
- Initial project structure with Apache License 2.0 and contribution guidelines (#20)
- Algorithm suite definitions for all 11 ESDK suites with commitment and signing support (#7)
- HKDF key derivation implementation per RFC 5869 (#8)
- Message format serialization supporting header v1/v2, framed/non-framed body, and footer (#9)
- Basic encryption and decryption operations with AES-GCM and key commitment (#10)
- Test vector harness for AWS Encryption SDK compatibility testing (#13)

[Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
