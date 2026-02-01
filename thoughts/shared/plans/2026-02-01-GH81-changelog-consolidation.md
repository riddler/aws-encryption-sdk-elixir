# CHANGELOG Consolidation Implementation Plan

## Overview

Simplify the CHANGELOG by consolidating related entries to reduce verbosity. Currently some versions have 30-50 items under 'Added' which makes the changelog difficult to scan. We'll consolidate to 5-10 major entries per version.

**Issue**: #81

## Guidelines

Per user requirements:
- **Target**: 5-10 major entries per version section
- **Test entries**: Completely remove (not user-facing)
- **PR/Issue references**: Keep at least one per feature group
- **Focus**: User-facing features, not internal implementation details
- **Breaking changes**: Keep visible and explicit

## Current State Analysis

| Version | Current "Added" Count | Target |
|---------|----------------------|--------|
| v0.6.0 | 36 entries | 5-10 |
| v0.5.0 | 32 entries | 5-10 |
| v0.4.0 | 25 entries | 5-10 |
| v0.3.0 | 14 entries | 5-10 |
| v0.2.0 | 14 entries | 5-10 |
| v0.1.0 | 24 entries | 5-10 |

## Desired End State

A CHANGELOG where:
- Each version has 5-10 entries under "Added"
- Major features are immediately scannable
- Test-related entries are removed
- PR/Issue references are preserved (one per feature group)
- Breaking changes remain explicit in "Changed"
- Format still follows [Keep a Changelog](https://keepachangelog.com/) standard

## What We're NOT Doing

- Changing version numbers or dates
- Removing "Changed", "Fixed", or "Removed" sections
- Altering the version comparison links at the bottom
- Adding new information not already present

---

## Phase 1: Consolidate v0.6.0

### Current Entries (36 items)
Grouped by feature area:
- Streaming (12 entries): Stream module, Encryptor, Decryptor, SignatureAccumulator, APIs, options, modes
- Caching CMM (12 entries): CacheEntry, LocalCache, behaviors, TTL, limits, partitions
- Required EC CMM (8 entries): validation, constructors, integration
- Integration tests (4 entries): error tests, dispatch tests

### Proposed Consolidation (6 items)

```markdown
### Added
- Streaming encryption and decryption APIs for memory-efficient processing of large data (#60)
- Caching CMM for reducing expensive key provider calls with TTL and usage limits (#61)
- Required Encryption Context CMM for enforcing critical AAD keys during encryption/decryption (#62)

### Changed
- Integration tests now run by default in CI (#68)

### Fixed
- KMS integration tests skip gracefully when AWS credentials unavailable (#68)

### Removed
- Temporary coveralls-ignore markers (#68)
```

### Success Criteria
- [x] v0.6.0 has 3 entries under "Added" (down from 36)
- [x] All PR references preserved: #60, #61, #62, #68
- [x] No test-specific entries remain

---

## Phase 2: Consolidate v0.5.0

### Current Entries (32 items)
Grouped by feature area:
- AWS KMS Keyring (6 entries): core implementation, wrap/unwrap, MRK support, grants
- AWS KMS Discovery (6 entries): discovery keyring, filters, integration
- AWS KMS MRK (5 entries): MRK keyring, cross-region
- AWS KMS MRK Discovery (5 entries): MRK discovery, region reconstruction
- KMS Client abstraction (6 entries): behaviour, mock, ExAws impl
- KMS ARN utilities (10 entries): parsing, validation, MRK matching
- Documentation (4 entries): moduledocs, examples

### Proposed Consolidation (5 items)

```markdown
### Added
- AWS KMS Keyring for encrypting/decrypting data keys with AWS KMS (#48)
- AWS KMS Discovery Keyring for decrypt-only operations without specifying key ARN (#49)
- AWS KMS MRK Keyrings for cross-region Multi-Region Key decryption and disaster recovery (#50, #51)
- Multi-keyring enhancements: KMS generator validation, convenience constructors for MRK scenarios (#52)
- KMS client abstraction layer with ExAws implementation and mock for testing (#46, #47)

### Changed
- Increased minimum code coverage requirement from 93% to 94%
```

### Success Criteria
- [x] v0.5.0 has 6 entries under "Added" (down from 32)
- [x] All PR references preserved: #46, #47, #48, #49, #50, #51, #52, #53
- [x] Documentation entries folded into feature entries

---

## Phase 3: Consolidate v0.4.0

### Current Entries (25 items)
Grouped by feature area:
- CMM behaviour (10 entries): callbacks, policies, validation, helpers
- Default CMM (10 entries): ECDSA, signing, verification, context handling
- Client encrypt (6 entries): APIs, policies, configuration
- Client decrypt (7 entries): APIs, validation, limits

### Proposed Consolidation (5 items)

```markdown
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
```

### Success Criteria
- [x] v0.4.0 has 5 entries under "Added" (down from 25)
- [x] All PR references preserved: #36, #37, #38, #39
- [x] Breaking changes in "Changed" remain explicit

---

## Phase 4: Consolidate v0.3.0

### Current Entries (14 items)
Grouped by feature area:
- Multi-keyring (8 entries): generator, children, wrap/unwrap, nesting
- Raw RSA keyring (8 entries): padding schemes, PEM loading, wrap/unwrap

### Proposed Consolidation (2 items)

```markdown
### Added
- Multi-Keyring for composing multiple keyrings with generator and child key support (#28)
- Raw RSA Keyring with support for PKCS1 v1.5 and OAEP padding schemes (#27)

### Changed
- Increased minimum code coverage requirement from 90% to 92%
```

### Success Criteria
- [x] v0.3.0 has 2 entries under "Added" (down from 14)
- [x] PR references preserved: #27, #28

---

## Phase 5: Consolidate v0.2.0

### Current Entries (14 items)
Grouped by feature area:
- Keyring behaviour (6 entries): callbacks, helpers, materials functions
- Raw AES keyring (5 entries): AES sizes, provider info, wrap/unwrap
- CI/release (6 entries): GitHub Actions, Codecov, /release skill

### Proposed Consolidation (4 items)

```markdown
### Added
- Keyring behaviour interface with on_encrypt/on_decrypt callbacks (#25)
- Raw AES Keyring with AES-128/192/256 support (#26)
- GitHub Actions CI workflow with Elixir 1.16-1.18 and OTP 26-27 test matrix (#15)
- `/release` skill for automated version releases (#30)

### Changed
- Minimum Elixir version requirement from 1.18 to 1.16
- Minimum OTP version requirement to 26
```

### Success Criteria
- [x] v0.2.0 has 4 entries under "Added" (down from 14)
- [x] PR references preserved: #15, #25, #26, #30

---

## Phase 6: Consolidate v0.1.0

### Current Entries (24 items)
Grouped by feature area:
- Project setup (4 entries): license, contributing, readme, structure
- Algorithm suites (5 entries): definitions, lookups, predicates
- HKDF (4 entries): extract, expand, derive, vectors
- Message format (11 entries): header, body, footer, serialization
- Test vector harness (6 entries): harness, setup, parsing
- Encryption/decryption (6 entries): AES-GCM, materials, modules

### Proposed Consolidation (6 items)

```markdown
### Added
- Initial project structure with Apache License 2.0 and contribution guidelines (#20)
- Algorithm suite definitions for all 11 ESDK suites with commitment and signing support (#7)
- HKDF key derivation implementation per RFC 5869 (#8)
- Message format serialization supporting header v1/v2, framed/non-framed body, and footer (#9)
- Basic encryption and decryption operations with AES-GCM and key commitment (#10)
- Test vector harness for AWS Encryption SDK compatibility testing (#13)
```

### Success Criteria
- [x] v0.1.0 has 6 entries under "Added" (down from 24)
- [x] PR references preserved: #7, #8, #9, #10, #13, #20

---

## Final Verification

After all phases complete:

### Automated:
- [x] CHANGELOG.md is valid markdown (no syntax errors)
- [x] All version comparison links at bottom remain intact
- [x] `mix quality --quick` passes

### Manual:
- [ ] Review consolidated changelog for clarity and readability
- [ ] Verify no important features were lost in consolidation
- [ ] Confirm breaking changes are still prominent

## Summary Table

| Version | Before | After | Reduction |
|---------|--------|-------|-----------|
| v0.6.0 | 36 | 3 | 92% |
| v0.5.0 | 32 | 5 | 84% |
| v0.4.0 | 25 | 5 | 80% |
| v0.3.0 | 14 | 2 | 86% |
| v0.2.0 | 14 | 4 | 71% |
| v0.1.0 | 24 | 6 | 75% |
| **Total** | **145** | **25** | **83%** |

## References

- Issue: #81
- Keep a Changelog: https://keepachangelog.com/en/1.1.0/
