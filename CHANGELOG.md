# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-10-07

### Changed
- CI and the release workflow fetch the test vectors
  (awslabs/aws-encryption-sdk-test-vectors) at one pinned commit,
  `b6a6c91e62cc67f891b5dc3d11b0f047d10baf76`, instead of a shallow clone
  of its default branch, and CI's test-vectors cache is keyed on that
  commit with no fallback key. Before, the cache key hashed `ci.yml`, so
  every workflow edit missed it, and its fallback could restore a clone
  the setup step then kept.

### Fixed
- Messages with required encryption context keys no longer store those
  keys in the header, as the specification requires; messages written by
  earlier versions still decrypt. The keys are still authenticated (the
  tail of the header-authentication AAD) and still bound into the encrypted
  data keys. A message another SDK writes with required keys left out of
  the header now decrypts: the default CMM appends the reproduced pairs
  absent from the header before the keyring unwraps and puts their keys in
  the required set. The read retries once under the stored context alone
  when that unwrap fails, or, on a keyring that does not bind the
  encryption context (raw RSA), when header authentication fails instead.
  The retry keeps a message readable when a caller passes a key the message
  never carried; when it fails too, the first failure is returned. A wrong
  value for a key the writer bound is still refused on every keyring. A
  message written before this version is read through
  `Cmm.RequiredEncryptionContext`, whose configured keys still join the
  decrypt-side required set.
- Signed suites write the signature verification key
  (`aws-crypto-public-key`) as the SEC 1 compressed point the specification
  requires, instead of the uncompressed point; both forms still read, so
  every signed message an earlier version wrote still verifies. Another SDK
  can now read a signed message this SDK writes.
- `Cmm.Caching` checks a decryption cache hit against the reproduced
  encryption context before serving it (#96): the hit is served only when
  the request agrees with everything the entry bound (the stored values
  agree, every key in the entry's required set is reproduced, and the
  reproduced pairs the header does not store are exactly the ones the entry
  bound). Otherwise the request goes the cache-miss way and
  the cold read decides, so a disagreeing reader is refused as on a cold
  read, and a failed read that populated the cache never makes a correct
  reader fail. The cache id is unchanged.
- Decrypt returns `{:error, :trailing_bytes}` for a message followed by
  trailing bytes, through `Client.decrypt/3`, `decrypt_with_keyring/3` and
  decrypt with materials, instead of a three-element `{:ok, message, rest}`
  tuple. The streaming decryptor already refused them.
- The header bytes change for every new message with required encryption
  context keys (the required pairs leave the stored context) and for every
  new message on a signed suite (the engine generates a P-384 verification
  key, which is now 68 base64 characters instead of 132).
- A 1.0.x reader cannot decrypt a message this version writes with required
  encryption context keys. Upgrade every reader before any writer; a
  rollback to 1.0.x strands those messages until the reader is upgraded
  again (nothing is lost: this version reads them).

## [1.0.1] - 2026-10-06

### Added
- A `hackney-1x` CI job on Elixir 1.18 / OTP 26: a fixture host on
  hackney 1.x (`test/fixtures/hackney1_host`, no committed lock) resolves
  the SDK and compiles a call into its ExAws KMS client, and the SDK's own
  suite runs on ex_aws 2.6 with hackney 1.x through the CI-only
  `HACKNEY_1X` switch in `mix.exs`.
- A release workflow (`.github/workflows/release.yml`): pushing a `v*.*.*`
  tag publishes to Hex only when the tagged commit is on the default
  branch, the tag names the `@version` in `mix.exs`, Hex does not already
  show that version, and the full quality gate is green there.

### Changed
- The optional KMS client stack now accepts hackney 1.x with ex_aws 2.6
  as well as hackney 4.x with ex_aws 2.7 (`{:hackney, "~> 1.21 or ~> 4.0"}`,
  `{:ex_aws, "~> 2.6"}`), and ex_aws_kms 2.5 (`{:ex_aws_kms, "~> 2.5"}`).
  A host already on hackney 1.x can resolve this package again; 1.0.0
  refused it. The README's "With AWS KMS" snippet shows the new ranges and
  the current `~> 1.0` requirement.

### Security
- The three hackney advisories 1.0.0 cites (GHSA-j9wq-vxxc-94wf,
  GHSA-mp55-p8c9-rfw2, GHSA-pj7v-xfvx-wmjq) are fixed only in hackney
  4.0.1 and later; a host on hackney 1.x keeps them. The SDK does not
  install hackney 1.x, it stops refusing hosts that already hold it, and
  its KMS requests use none of the affected options: no cookie options,
  no caller-built query strings, no proxy allowlist, no SOCKS5. hackney
  4.x stays the recommended pair.
- hackney 1.x also carries GHSA-gp9c-pm5m-5cxr (a SOCKS5 TLS upgrade that
  ignores the caller's timeout), reported by `mix deps.get` when a host
  resolves hackney 1.x. The SDK configures no SOCKS5 proxy, so its KMS
  requests do not reach it either.

## [1.0.0] - 2026-08-26

### Changed
- The AWS client stack (`ex_aws`, `ex_aws_kms`, `hackney`, `sweet_xml`) is
  now **optional**. Raw-keyring consumers get a lean dependency tree with no
  AWS, HTTP, or XML libraries; using the KMS keyrings now requires adding
  the four dependencies to your own `deps` (see the README's "With AWS KMS"
  section). The `AwsEncryptionSdk.Keyring.KmsClient.ExAws` module is
  compiled only when they are present. CI proves the raw-keyring path
  compiles and passes with none of them installed.

### Fixed
- README's Raw AES example used a keyword-argument form of `RawAes.new`
  that does not exist; it now shows the real positional
  `RawAes.new(namespace, name, key, algorithm)` arity, matching the
  moduledoc.
- Caching CMM `max_bytes` is now enforced: `AwsEncryptionSdk.Client.encrypt/3` passes the
  plaintext size to the CMM, and cache entries refresh before serving a
  request that would push cumulative bytes past the limit (previously the
  byte limit never tripped, and entries could overshoot it by one message).
  Deployments with a low `max_bytes` will see more key provider (KMS) calls -
  this is the intended security behavior, but may be a cost surprise.
- Streaming encrypt bypasses the Caching CMM cache unless the new
  `:plaintext_length` option is passed to `AwsEncryptionSdk.Stream.encrypt/3`, since the byte
  limit cannot be enforced without a declared length. Callers who know the
  total size can pass the option to keep caching.

### Removed
- `CacheEntry.exceeded_limits?/3`, replaced by `CacheEntry.can_serve?/4`,
  which checks the prospective total rather than already-recorded usage.

### Fixed
- AWS KMS integration tests are now excluded automatically when `KMS_KEY_ARN`
  is unset or when AWS rejects the configured credentials as unrecognized,
  instead of failing the suite with errors unrelated to this library.
  Signature and permission errors still fail, since those can indicate a real
  regression.
- Broken `examples/` links in the rendered Hex docs now point to the GitHub
  repository.

### Security
- Updated hackney to 4.x (with ex_aws 2.7 and ex_aws_kms 2.6) to resolve
  CR/LF injection and SSRF allowlist bypass advisories (GHSA-j9wq-vxxc-94wf,
  GHSA-mp55-p8c9-rfw2, GHSA-pj7v-xfvx-wmjq).
- Updated doctor to 0.23 to pull decimal 3.x, resolving the unbounded
  exponent DoS advisory (GHSA-rhv4-8758-jx7v).

## [0.7.0] - 2026-02-01

### Added
- Error test vector validation suite with 4,240 negative test cases (#77)
- Compressed EC public key decompression for P-256 and P-384 curves (#77)
- Multi-curve ECDSA signature verification supporting SHA-256/secp256r1 and SHA-384/secp384r1 (#77)
- API mismatch test validating unsigned-only streaming decryption mode (#77)
- Comprehensive error categorization (bit flip, truncation, API mismatch, other) (#77)
- Full test vector runner executing 2,861 success test vectors via complete decrypt flow (#76)
- Comprehensive test coverage for all 11 ESDK algorithm suites including committed suites (0x0478, 0x0578)
- Test vector filtering helpers (success/error tests, raw key tests, encryption algorithm filters)
- Automatic test vector execution in CI with caching for performance
- EDK-based key name extraction for accurate keyring configuration
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
- README updated for v1.0.0 preparation with pre-release messaging removed (#79)
- Feature list converted to clean presentation without checkmark indicators (#79)
- Test statistics updated to reflect current 852 passing tests (#79)
- Documentation section added with links to guides, examples, and API reference (#79)
- Test vectors now run by default when available, improving from 91.8% to 92.6% code coverage (#76)
- Header authentication now uses full encryption context with required key filtering for spec compliance (#76)
- Algorithm suite deprecation warnings removed for cleaner test output (#76)
- Consolidated CHANGELOG entries to improve readability and scannability (#81)
- Enhanced streaming module documentation with usage guidance, memory efficiency details, and verification handling (#72)
- Examples reorganized into complexity-based subdirectories (01_basics, 02_advanced, 03_aws_kms) (#75)
- Examples README updated with category-based navigation and quick start commands

### Fixed
- ECDSA signature verification now handles compressed EC public keys (0x02/0x03 prefix) (#77)
- Signature verification uses correct hash algorithm and curve based on algorithm suite (#77)
- Header body serialization to include version/type bytes in AAD computation per spec (#76)
- Required encryption context filtering in header authentication tag computation (#76)
- CMM test vector helpers to extract key names from EDK provider_info (#76)
- Dialyzer typespec for `compute_header_auth_tag/4` to allow nil for optional parameter (#76)
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

## [0.1.0] - 2026-01-12

### Added
- Initial project structure with Apache License 2.0 and contribution guidelines (#20)
- Algorithm suite definitions for all 11 ESDK suites with commitment and signing support (#7)
- HKDF key derivation implementation per RFC 5869 (#8)
- Message format serialization supporting header v1/v2, framed/non-framed body, and footer (#9)
- Basic encryption and decryption operations with AES-GCM and key commitment (#10)
- Test vector harness for AWS Encryption SDK compatibility testing (#13)

[Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.7.0...v1.0.0
[0.7.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
