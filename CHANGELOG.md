# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed
- Updated CLAUDE.md milestone checkboxes to reflect completed Milestone 1
- Updated CLAUDE.md to use "Milestones" terminology consistently
- Updated Claude commands to use test vector harness API (#17)
- research_issue.md: Use TestVectorHarness instead of manual curl downloads
- create_plan.md: Include harness setup patterns in plan templates
- implement_plan.md: Replace File.read! examples with harness API calls

### Fixed
- Credo consistency warnings for unused variable naming
- Header serialization to properly separate version bytes from body
- Frame deserialization error atom naming consistency
