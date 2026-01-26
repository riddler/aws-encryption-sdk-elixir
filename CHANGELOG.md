# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `/release` skill for automated version releases (#30)
- GitHub Actions CI workflow with multi-version testing matrix (#15)
- Test matrix for Elixir 1.16-1.18 and OTP 26-27
- Codecov integration for coverage reporting
- CI and coverage status badges in README
- `:crypto` application to extra_applications for proper OTP loading
- Keyring behaviour interface with on_encrypt/on_decrypt callbacks (#25)
- Helper functions for data key generation and provider ID validation
- Support for optional plaintext_data_key in materials structs
- DecryptionMaterials.new_for_decrypt/3 and set_plaintext_data_key/2
- EncryptionMaterials.new_for_encrypt/3, set_plaintext_data_key/2, and add_encrypted_data_key/2
- Comprehensive test coverage for keyring behaviour (20 new tests)
- Raw AES keyring implementation with AES-128/192/256 support (#26)
- Provider info serialization for keyring metadata (key name, IV, tag length)
- wrap_key/2 function for encrypting data keys with AES-GCM
- unwrap_key/3 function for decrypting EDKs with provider ID and key name matching
- Comprehensive unit tests (25 tests) and test vector validation (4 vectors)
- Edge case tests for empty/large contexts, unicode, and all key sizes

### Changed
- Minimum Elixir version requirement from 1.18 to 1.16
- Minimum OTP version requirement to 26

## [0.1.0] - 2025-01-12

### Added
- Apache License 2.0 (#20)
- CONTRIBUTING.md with development setup and contribution guidelines (#20)
- Comprehensive README with project documentation for v0.1.0 release (#20)
- WIP banner warning about pre-production status
- Current status section listing implemented and planned features
- Installation instructions for Hex.pm
- Basic encryption/decryption usage example
- Links to AWS Encryption SDK specification and related implementations
- Initial project structure
- Claude Code agents and commands for development workflow
- Algorithm suite definitions for all 11 ESDK suites (#7)
- Suite lookup by ID with reserved ID validation
- Predicate functions (committed?, signed?, deprecated?, allows_encryption?)
- Deprecation warnings for NO_KDF suites
- Comprehensive test coverage (26 tests, 100% coverage)
- HKDF key derivation implementation per RFC 5869 (#8)
- Support for SHA-256, SHA-384, and SHA-512 hash algorithms
- HKDF extract/expand/derive functions for key derivation
- Comprehensive test suite with RFC 5869 and Wycheproof vectors
- Algorithm suite compatibility tests for committed suites
- ex_doc dependency for documentation generation
- Message format serialization and deserialization (#9)
- EncryptedDataKey struct with list serialization
- Encryption context serialization with UTF-8 key sorting
- Reserved key validation (aws-crypto-* prefix)
- Body AAD generation for AES-GCM operations
- Header v1 and v2 serialization (both framed/non-framed)
- Non-framed body serialization with 64 GiB limit
- Framed body with sequence validation and final frame marker
- Footer serialization for ECDSA signatures
- Complete message deserialization with automatic footer detection
- 119 tests with 87.6% coverage
- Test vector harness for AWS Encryption SDK compatibility testing (#13)
- TestVectorHarness module for loading and parsing test vector manifests
- Support for keys manifest version 3 and decrypt manifest versions 2, 3, 4
- TestVectorSetup module with availability checks and setup instructions
- ExUnit tests for message structure validation against test vectors
- 9 test vector validation tests (manifest loading, parsing, key material)
- Jason dependency for JSON parsing of test vector manifests
- Test fixtures documentation with setup instructions
- Basic encryption and decryption operations (#10)
- AES-GCM encryption/decryption module with AAD support
- EncryptionMaterials and DecryptionMaterials structs
- Encrypt module with framed/non-framed message support
- Decrypt module with header/body authentication
- Key commitment verification for committed algorithm suites
- Integration tests for encrypt/decrypt round-trips
- AES KeyWrap test support module

[Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
