# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

### Changed
- Updated CLAUDE.md to use "Milestones" terminology consistently

### Fixed
- Credo consistency warnings for unused variable naming
