# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Caching CMM for reducing expensive key provider calls (#61)
- CacheEntry struct with TTL and usage limit tracking
- CryptographicMaterialsCache behaviour defining cache interface
- LocalCache ETS-based implementation with atomic operations
- Encryption materials caching with cache ID computation (SHA-384)
- Decryption materials caching based on EDKs and context
- Identity KDF bypass for deprecated NO_KDF algorithm suites
- Partition ID isolation enabling multiple CMMs to share cache
- Usage limits enforcement (max_messages and max_bytes)
- TTL-based expiration with automatic cleanup on retrieval
- Support for wrapping Default and RequiredEncryptionContext CMMs
- Comprehensive test suite with 42 tests (94.2% coverage)
- Required Encryption Context CMM for enforcing critical AAD keys (#62)
- Wrapping CMM validating required keys in encryption and decryption
- new/2 constructor accepting required keys and underlying CMM
- new_with_keyring/2 constructor auto-wrapping keyring in Default CMM
- Validation ensuring required keys present in caller's context
- Validation ensuring required keys present in reproduced context
- Support for nested CMM composition with layered validation
- Client dispatcher integration for RequiredEncryptionContext CMM
- Comprehensive test suite with 21 tests covering all scenarios
- Streaming encryption and decryption APIs for processing large data incrementally (#60)
- Stream.Encryptor state machine with incremental frame generation
- Stream.Decryptor state machine with incremental frame parsing
- Stream.SignatureAccumulator for ECDSA signing without buffering entire message
- encrypt_stream/3 and decrypt_stream/3 high-level APIs using Elixir Streams
- Support for both signed and unsigned algorithm suites in streaming mode
- fail_on_signed option to reject signed suites during streaming decryption
- Incremental plaintext release for unsigned suites (frame-by-frame)
- Deferred final frame release for signed suites (after signature verification)
- Header authentication module for v1/v2 header tag computation
- Commitment key derivation module for key commitment verification
- Comprehensive test suite with 41 streaming tests (edge cases, integration, signed suites)
- Edge case tests for empty plaintext, single byte, exact frame multiples, byte-by-byte input

## [0.5.0] - 2026-01-28

### Added
- Multi-keyring generator validation rejecting discovery keyrings (#52)
- Multi.new_with_kms_generator/4 convenience constructor for KMS generators
- Multi.new_mrk_aware/4 convenience constructor for cross-region MRK scenarios
- ARN reconstruction utilities for replica region keyring creation
- AWS KMS MRK Discovery Keyring for cross-region MRK decryption (#51)
- MRK-aware discovery keyring reconstructing ARNs with configured region
- Cross-region MRK decryption enabling disaster recovery scenarios
- Non-MRK key filtering by region match for security
- Optional discovery filter for partition and account restrictions
- Integration with Default CMM and Multi-keyring dispatch clauses
- Comprehensive test suite with 28 tests
- KMS client abstraction layer with behaviour interface (#46)
- KmsClient behaviour defining generate_data_key/5, encrypt/5, and decrypt/5 callbacks
- Mock KMS client implementation for testing without AWS credentials
- ExAws KMS client implementation for production use with AWS
- ExAws configuration in config/config.exs with environment variable support
- Integration test suite for real AWS KMS operations (9 tests)
- Test documentation in test/README.md with setup and usage instructions
- Manual verification script (scripts/verify_kms_client.exs)
- Environment variable template (.env.example)
- AWS SDK dependencies: ex_aws, ex_aws_kms, hackney, sweet_xml
- KMS Key ARN utilities for parsing and validation (#47)
- parse/1 function with comprehensive ARN validation per AWS spec
- mrk?/1 function for Multi-Region Key identification
- mrk_match?/2 function for cross-region MRK matching
- arn?/1 helper for ARN format detection
- to_string/1 function for ARN reconstruction
- String.Chars protocol implementation for idiomatic usage
- Support for all AWS partitions (aws, aws-cn, aws-us-gov)
- Comprehensive test suite with 64 tests covering valid/invalid ARNs
- Test vector validation using keys.json test data
- AWS KMS Keyring implementation for encrypting/decrypting data keys with AWS KMS (#48)
- wrap_key/2 function with dual paths: GenerateDataKey (new keys) and Encrypt (existing keys)
- unwrap_key/3 function with EDK filtering by provider ID, ARN validation, and key matching
- Support for MRK (Multi-Region Key) cross-region matching
- Grant tokens support for KMS API calls
- Integration with Default CMM and Multi-keyring for seamless composition
- Comprehensive test suite with 27 tests using Mock KMS client (96.1% coverage)
- AWS KMS Discovery Keyring for decrypt-only operations (#49)
- Discovery keyring decrypts data keys using ARN from EDK provider info
- Optional discovery filter for partition and account restrictions
- wrap_key/2 implementation that always fails (discovery cannot encrypt)
- unwrap_key/3 with provider ID filtering, ARN validation, and KMS decrypt
- Integration with Default CMM and Multi-keyring dispatch clauses
- Comprehensive test suite with 30 tests (94.2% coverage)
- AWS KMS Multi-Region Key (MRK) Keyring for cross-region decryption (#50)
- MRK-aware keyring enabling data decryption with regional MRK replicas
- wrap_key/2 and unwrap_key/3 functions delegating to AwsKms keyring
- Cross-region MRK matching for disaster recovery scenarios
- Integration with Default CMM and Multi-keyring dispatch clauses
- Comprehensive test suite with 28 tests covering cross-region scenarios
- Comprehensive documentation for AWS KMS keyrings (#53)
- Enhanced moduledocs for AwsKms, AwsKmsDiscovery, AwsKmsMrk, and AwsKmsMrkDiscovery
- Use cases, IAM permissions, and security considerations for each keyring type
- Code examples for basic usage, grant tokens, and multi-keyring patterns
- Examples directory with 4 runnable scripts demonstrating KMS integration
- kms_basic.exs for basic encryption/decryption workflow
- kms_discovery.exs for discovery keyring usage
- kms_multi_keyring.exs for redundant key protection
- kms_cross_region.exs for MRK disaster recovery scenarios
- AWS KMS Integration section in README with keyring selection guide
- Updated README to reflect all implemented KMS keyrings

### Changed
- Excluded examples directory from Credo analysis
- Increased minimum code coverage requirement from 93% to 94%

## [0.4.0] - 2026-01-27

### Added
- CMM (Cryptographic Materials Manager) behaviour interface (#36)
- get_encryption_materials/2 and get_decryption_materials/2 callbacks
- Commitment policy type definitions (forbid/require encrypt/decrypt)
- Helper functions for commitment policy validation
- Helper functions for materials validation (encryption and decryption)
- Helper functions for encryption context validation
- Reserved key constant for signature verification (aws-crypto-public-key)
- Default algorithm suite selection based on commitment policy
- Reproduced encryption context validation and merging
- Comprehensive test suite (54 tests, 100% coverage)
- Default CMM implementation with keyring orchestration (#37)
- ECDSA crypto module for P-384 key pair generation
- Support for all 17 algorithm suites (signing and non-signing)
- Algorithm suite selection based on commitment policy
- Signing key generation for ECDSA algorithm suites
- Public key encoding/storage in encryption context
- Verification key extraction from encryption context
- Reproduced encryption context validation and merging
- Comprehensive test suite (25 unit tests, 4 error handling tests)
- Round-trip encryption/decryption tests with signing suites
- Multi-keyring integration tests
- Test vector support framework (harness setup)
- Client module with commitment policy enforcement (#38)
- encrypt/3 and encrypt_with_keyring/3 APIs with policy validation
- Support for three commitment policies per spec (forbid/require/allow)
- Default policy of :require_encrypt_require_decrypt (strictest)
- max_encrypted_data_keys configuration option
- ECDSA sign/verify functions for signature operations
- Round-trip encryption/decryption tests for signed suites
- Client commitment policy test suite (47 tests, 100% coverage)
- Client test vector validation (3 encrypt test cases)
- Client.decrypt/3 with commitment policy enforcement for decryption (#39)
- Client.decrypt_with_keyring/3 convenience function for keyring-based decryption
- AwsEncryptionSdk.decrypt/2-3 public API accepting Client or DecryptionMaterials
- AwsEncryptionSdk.decrypt_with_keyring/3 public API delegation
- Commitment policy validation during decryption (strictest policy rejects non-committed suites)
- EDK count limit enforcement during decryption (max_encrypted_data_keys)
- Comprehensive integration test suite with 9 tests covering all three commitment policies
- 16 new tests for Client-based and public API decryption (469 total tests, 93.8% coverage)

### Changed
- Increased minimum code coverage requirement from 92% to 93%
- Added edge case tests for encryption context and encrypted data keys
- Main API now recommends Client-based encryption workflow
- Renamed encrypt/decrypt to encrypt_with_materials/decrypt_with_materials
- Removed encryption context validation from Encrypt module
- Updated documentation with Client usage examples

## [0.3.0] - 2026-01-26

### Added
- Multi-Keyring implementation for composing multiple keyrings (#28)
- Support for generator keyring that generates plaintext data keys
- Support for child keyrings that wrap existing data keys
- wrap_key/2 function with generator + children chaining (fail-fast)
- unwrap_key/3 function with sequential keyring iteration (first-success)
- Comprehensive unit tests (31 tests) covering all edge cases
- Test vector validation for all 7 multi-RSA test vectors
- Nested multi-keyring support for complex key hierarchies
- Error collection when all keyrings fail during decryption
- Raw RSA keyring implementation with encrypt/decrypt support (#27)
- Support for all 5 padding schemes: PKCS1 v1.5, OAEP-SHA1/256/384/512
- PEM key loading for X.509 SubjectPublicKeyInfo and PKCS#8 PrivateKeyInfo
- wrap_key/2 function for encrypting data keys with RSA public keys
- unwrap_key/3 function for decrypting EDKs with RSA private keys
- Comprehensive unit tests (28 tests) and test vector validation (5 vectors)
- Edge case tests for unicode key names and empty encryption contexts
- MGF1 hash matching for OAEP padding per spec requirements
- :public_key application to extra_applications for OTP loading

### Changed
- Increased minimum code coverage requirement from 90% to 92%

## [0.2.0] - 2026-01-25

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

[Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
