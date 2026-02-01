# Complete Hex Docs Organization for v1.0.0

## Overview

Organize all modules into logical groups in the Hex documentation and add comprehensive module documentation for streaming components. Create API stability policy documentation for v1.0.0 release.

**Issue**: #72

## Current State

The current `mix.exs` docs configuration (lines 79-118) includes only 4 module groups:
- Core API (4 modules)
- Materials (3 modules)
- Message Format (4 modules)
- Cryptography (4 modules)

**Missing from docs organization:**
- 10 keyring modules (Behaviour + 7 keyrings + 2 KMS utilities)
- 4 CMM modules (Behaviour + 3 CMMs)
- 3 cache modules
- 4 streaming modules (Stream + 3 submodules)

**Stream submodules have basic documentation but need enhancement:**
- `Stream.Encryptor` - Has state machine docs, needs usage guidance
- `Stream.Decryptor` - Has state machine docs, needs usage guidance
- `Stream.SignatureAccumulator` - Has basic docs, needs context

**No API stability policy documented**

## Desired End State

1. All modules organized into logical groups in Hex docs
2. Stream submodules have comprehensive @moduledoc with usage guidance
3. API stability policy documented in `guides/STABILITY.md`
4. Docs generate cleanly with `mix docs`
5. Professional documentation ready for v1.0.0 release

## What We're NOT Doing

- Not changing any code functionality
- Not adding new API features
- Not reorganizing module structure (only docs)
- Not adding test vectors (pure documentation task)

## Implementation Approach

This is a documentation-focused task with no code changes. We'll update docs configuration, enhance module documentation, and create stability guidelines.

---

## Phase 1: Update mix.exs Docs Configuration

### Overview
Add 4 new module groups to organize keyrings, CMMs, caching, and streaming modules.

### Changes Required:

#### 1. Add Keyring Module Groups
**File**: `mix.exs` (lines 92-115)

Add after the existing `Cryptography` group:

```elixir
"Keyring Interface": [
  AwsEncryptionSdk.Keyring.Behaviour
],
"Raw Keyrings": [
  AwsEncryptionSdk.Keyring.RawAes,
  AwsEncryptionSdk.Keyring.RawRsa,
  AwsEncryptionSdk.Keyring.Multi
],
"KMS Keyrings": [
  AwsEncryptionSdk.Keyring.AwsKms,
  AwsEncryptionSdk.Keyring.AwsKmsDiscovery,
  AwsEncryptionSdk.Keyring.AwsKmsMrk,
  AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery
],
"KMS Client Interface": [
  AwsEncryptionSdk.Keyring.KmsClient,
  AwsEncryptionSdk.Keyring.KmsKeyArn
]
```

#### 2. Add CMM Group
```elixir
"Cryptographic Materials Managers": [
  AwsEncryptionSdk.Cmm.Behaviour,
  AwsEncryptionSdk.Cmm.Default,
  AwsEncryptionSdk.Cmm.Caching,
  AwsEncryptionSdk.Cmm.RequiredEncryptionContext
]
```

#### 3. Add Caching Group
```elixir
"Caching": [
  AwsEncryptionSdk.Cache.CryptographicMaterialsCache,
  AwsEncryptionSdk.Cache.LocalCache,
  AwsEncryptionSdk.Cache.CacheEntry
]
```

#### 4. Add Streaming Group
```elixir
"Streaming": [
  AwsEncryptionSdk.Stream,
  AwsEncryptionSdk.Stream.Encryptor,
  AwsEncryptionSdk.Stream.Decryptor,
  AwsEncryptionSdk.Stream.SignatureAccumulator
]
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] Docs compile: `mix docs`
- [x] No ExDoc warnings

#### Manual Verification:
- [x] Open `doc/index.html` and verify all 12 module groups appear in sidebar
- [x] Verify modules are listed in logical order within each group
- [x] Verify no modules appear in "Modules" (ungrouped) section

---

## Phase 2: Enhance Stream Submodule Documentation

### Overview
Add comprehensive @moduledoc to streaming components explaining when to use streaming, memory benefits, and usage patterns.

### Changes Required:

#### 1. Enhance Stream.Encryptor @moduledoc
**File**: `lib/aws_encryption_sdk/stream/encryptor.ex` (lines 2-25)

**Current state**: Has state machine docs and basic example
**Enhancement needed**: Add "When to Use", "Memory Efficiency", and cross-references

Add to the existing @moduledoc after line 2:

```elixir
@moduledoc """
Streaming encryptor state machine for incremental plaintext processing.

## When to Use Streaming

Use `Stream.Encryptor` instead of `Client.encrypt/2` when:

- Encrypting large files that don't fit in memory
- Processing data from network streams or pipes
- Working with data sources that produce chunks incrementally
- Memory constraints require bounded memory usage

For small messages (< 1MB), the simpler `Client.encrypt/2` API is recommended.

## Memory Efficiency

The streaming encryptor maintains constant memory usage regardless of input size:

- Buffers only one frame's worth of plaintext (default: 4096 bytes)
- Emits ciphertext incrementally as complete frames
- No need to load entire plaintext into memory

For a 1GB file with 4KB frames, memory usage is ~4KB regardless of file size,
compared to ~1GB for non-streaming encryption.

## Integration with Elixir Streams

Designed to work seamlessly with `Stream` module:

    File.stream!("large-file.bin", [], 4096)
    |> AwsEncryptionSdk.Stream.encrypt(client)
    |> Stream.into(File.stream!("output.encrypted"))
    |> Stream.run()

See `AwsEncryptionSdk.Stream` for high-level streaming API.

## State Machine

The encryptor progresses through these states:

1. `:init` - Not started, awaiting first input
2. `:encrypting` - Processing frames
3. `:done` - Encryption complete

## Low-Level Example

For custom streaming logic, use the state machine directly:

    # Initialize encryptor
    {:ok, enc} = Encryptor.init(materials, frame_length: 4096)

    # Process chunks, collecting output
    {:ok, enc, header_bytes} = Encryptor.start(enc)
    {:ok, enc, frame1_bytes} = Encryptor.update(enc, chunk1)
    {:ok, enc, frame2_bytes} = Encryptor.update(enc, chunk2)
    {:ok, enc, final_bytes} = Encryptor.finalize(enc)

    # Concatenate: header_bytes <> frame1_bytes <> frame2_bytes <> final_bytes

## See Also

- `AwsEncryptionSdk.Stream` - High-level streaming API
- `AwsEncryptionSdk.Stream.Decryptor` - Streaming decryption
- `AwsEncryptionSdk.Client` - Non-streaming encryption API
"""
```

#### 2. Enhance Stream.Decryptor @moduledoc
**File**: `lib/aws_encryption_sdk/stream/decryptor.ex` (lines 2-21)

**Current state**: Has state machine docs and security notes
**Enhancement needed**: Add "When to Use", "Memory Efficiency", and plaintext verification guidance

Replace the existing @moduledoc:

```elixir
@moduledoc """
Streaming decryptor state machine for incremental ciphertext processing.

## When to Use Streaming

Use `Stream.Decryptor` instead of `Client.decrypt/2` when:

- Decrypting large files that don't fit in memory
- Processing encrypted data from network streams
- Working with ciphertext sources that produce chunks incrementally
- Memory constraints require bounded memory usage

For small messages (< 1MB), the simpler `Client.decrypt/2` API is recommended.

## Memory Efficiency

The streaming decryptor maintains constant memory usage:

- Buffers only data needed to parse the current frame
- Emits plaintext incrementally after frame authentication
- No need to load entire ciphertext into memory

Memory usage is bounded by the frame size plus header size, regardless of
total message size.

## Plaintext Verification Status

Decrypted plaintext is tagged with verification status:

- **`:verified`** - Plaintext is authenticated and safe to use
  - For unsigned suites: immediately after frame authentication
  - For signed suites: after signature verification completes

- **`:unverified`** - Plaintext not yet cryptographically verified
  - Only for signed algorithm suites
  - Signature verification happens at end of stream
  - **Do not use unverified plaintext** until signature validates

### Handling Signed Suites

For signed algorithm suites (ECDSA P-384), you must handle verification:

**Option 1: Fail immediately** (safest):

    {:ok, dec} = Decryptor.init(
      get_materials: materials_fn,
      fail_on_signed: true
    )

**Option 2: Buffer unverified plaintext** (for streaming):

    plaintexts = []
    for {plaintext, status} <- decrypted_chunks do
      case status do
        :verified -> use_plaintext(plaintext)
        :unverified -> plaintexts = [plaintext | plaintexts]
      end
    end
    # At end of stream, all buffered plaintext is verified

**Option 3: Use high-level API** (recommended):

Use `AwsEncryptionSdk.Stream.decrypt/3` which handles verification automatically.

## Integration with Elixir Streams

Designed to work seamlessly with `Stream` module:

    File.stream!("encrypted.bin", [], 4096)
    |> AwsEncryptionSdk.Stream.decrypt(client)
    |> Stream.map(fn {plaintext, _status} -> plaintext end)
    |> Stream.into(File.stream!("decrypted.bin"))
    |> Stream.run()

See `AwsEncryptionSdk.Stream` for high-level streaming API.

## State Machine

The decryptor progresses through these states:

1. `:init` - Not started, awaiting ciphertext
2. `:reading_header` - Accumulating header bytes
3. `:decrypting` - Processing frames
4. `:reading_footer` - Accumulating footer (signed suites only)
5. `:done` - Decryption complete

## Low-Level Example

For custom streaming logic, use the state machine directly:

    get_materials = fn header ->
      # Obtain decryption materials from CMM
      cmm.get_decryption_materials(...)
    end

    {:ok, dec} = Decryptor.init(get_materials: get_materials)

    # Process ciphertext chunks
    {:ok, dec, plaintexts1} = Decryptor.update(dec, chunk1)
    {:ok, dec, plaintexts2} = Decryptor.update(dec, chunk2)
    {:ok, dec, final_plaintexts} = Decryptor.finalize(dec)

    # Each plaintexts is a list of {binary, :verified | :unverified} tuples

## Security

- Never release unauthenticated plaintext to untrusted contexts
- For signed suites, verify signature before using plaintext
- The decryptor validates authentication tags before emitting plaintext
- Commitment verification happens during header processing

## See Also

- `AwsEncryptionSdk.Stream` - High-level streaming API
- `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption
- `AwsEncryptionSdk.Client` - Non-streaming decryption API
"""
```

#### 3. Enhance Stream.SignatureAccumulator @moduledoc
**File**: `lib/aws_encryption_sdk/stream/signature_accumulator.ex` (lines 2-16)

**Current state**: Has basic example
**Enhancement needed**: Explain purpose, memory benefits, and context within streaming

Replace the existing @moduledoc:

```elixir
@moduledoc """
Incremental signature accumulation for streaming ECDSA operations.

## Purpose

Enables ECDSA signing/verification for large messages without buffering
the entire message in memory. Used internally by streaming encryption and
decryption for signed algorithm suites.

## Memory Efficiency

Instead of buffering the entire message for signing:

- Accumulates SHA-384 hash state incrementally
- Hash state size is constant (64 bytes) regardless of message size
- Final signature is computed from hash digest

This allows signing/verifying messages of any size with constant memory usage.

## Signed Algorithm Suites

The AWS Encryption SDK includes algorithm suites with ECDSA P-384 signatures:

- `AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384` (0x0578, default)
- `AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384` (0x0378)

For these suites, the entire message (header + all frames) is signed.

## Usage Context

You typically don't use this module directly. It's used internally by:

- `AwsEncryptionSdk.Stream.Encryptor` - Accumulates hash during encryption
- `AwsEncryptionSdk.Stream.Decryptor` - Verifies signature during decryption

## Low-Level Example

If implementing custom streaming or signature logic:

    # During encryption
    acc = SignatureAccumulator.init()
    acc = SignatureAccumulator.update(acc, header_bytes)
    acc = SignatureAccumulator.update(acc, frame1_bytes)
    acc = SignatureAccumulator.update(acc, frame2_bytes)
    signature = SignatureAccumulator.sign(acc, private_key)

    # During decryption
    acc = SignatureAccumulator.init()
    acc = SignatureAccumulator.update(acc, header_bytes)
    acc = SignatureAccumulator.update(acc, frame1_bytes)
    acc = SignatureAccumulator.update(acc, frame2_bytes)
    valid? = SignatureAccumulator.verify(acc, signature, public_key)

## Hash Algorithm

Uses SHA-384 for hash accumulation, matching the ECDSA P-384 curve
used by signed algorithm suites.

## See Also

- `AwsEncryptionSdk.Stream.Encryptor` - Streaming encryption
- `AwsEncryptionSdk.Stream.Decryptor` - Streaming decryption
- `AwsEncryptionSdk.AlgorithmSuite` - Algorithm suite definitions
"""
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] Docs compile: `mix docs`
- [x] No ExDoc warnings

#### Manual Verification:
- [x] Open `doc/AwsEncryptionSdk.Stream.Encryptor.html` and verify enhanced documentation renders correctly
- [x] Open `doc/AwsEncryptionSdk.Stream.Decryptor.html` and verify plaintext verification guidance is clear
- [x] Open `doc/AwsEncryptionSdk.Stream.SignatureAccumulator.html` and verify purpose and context is explained
- [x] Verify cross-references ("See Also" links) work correctly

---

## Phase 3: Create API Stability Policy Guide

### Overview
Document semantic versioning commitment, breaking change policy, and deprecation process.

### Changes Required:

#### 1. Create guides directory
```bash
mkdir -p guides
```

#### 2. Create guides/STABILITY.md

**File**: `guides/STABILITY.md`

```markdown
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
```

#### 3. Add stability guide to mix.exs docs extras

**File**: `mix.exs` (lines 86-91)

Add to the `extras` list:

```elixir
extras: [
  "README.md": [title: "Overview"],
  "CHANGELOG.md": [title: "Changelog"],
  "CONTRIBUTING.md": [title: "Contributing"],
  "guides/STABILITY.md": [title: "API Stability Policy"],
  LICENSE: [title: "License"]
]
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`
- [x] Docs compile: `mix docs`
- [x] guides/STABILITY.md exists

#### Manual Verification:
- [x] Open `doc/index.html` and verify "API Stability Policy" appears in guides sidebar
- [x] Verify the stability policy renders correctly with all sections
- [x] Verify markdown formatting is correct
- [x] Verify links to GitHub and CHANGELOG work

---

## Phase 4: Final Verification

### Overview
Verify all documentation changes render correctly and completely.

### Verification Steps:

#### 1. Generate documentation
```bash
mix docs
```

#### 2. Verify module organization
- Open `doc/index.html`
- Verify all 12 module groups appear in sidebar:
  - Core API
  - Materials
  - Message Format
  - Cryptography
  - Keyring Interface
  - Raw Keyrings
  - KMS Keyrings
  - KMS Client Interface
  - Cryptographic Materials Managers
  - Caching
  - Streaming
- Verify no modules in ungrouped "Modules" section

#### 3. Verify streaming documentation
- Open `doc/AwsEncryptionSdk.Stream.html`
- Open `doc/AwsEncryptionSdk.Stream.Encryptor.html`
- Open `doc/AwsEncryptionSdk.Stream.Decryptor.html`
- Open `doc/AwsEncryptionSdk.Stream.SignatureAccumulator.html`
- Verify all enhanced content appears
- Verify "See Also" cross-references work

#### 4. Verify stability guide
- Open `doc/api-stability-policy.html` (or check guides section)
- Verify all sections render correctly
- Verify table of contents works
- Verify code examples format correctly

#### 5. Check for warnings
```bash
mix docs 2>&1 | grep -i warning
```
Should return no warnings.

### Success Criteria:

#### Automated Verification:
- [x] `mix quality` passes completely
- [x] `mix docs` completes with no warnings
- [x] All files compile successfully

#### Manual Verification:
- [x] All 12 module groups present in docs
- [x] All streaming modules have comprehensive documentation
- [x] API stability policy is complete and readable
- [x] All cross-references work
- [x] Documentation is professional and ready for v1.0.0

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] Docs generation: `mix docs` (no warnings)

### Manual:
- [x] Complete review of generated docs in browser
- [x] All acceptance criteria from issue #72 met

## Testing Strategy

This is a pure documentation task with no code changes, so testing focuses on:

### Documentation Verification:
- Compile all documentation without warnings
- Manually review generated HTML docs
- Verify all module groups appear correctly
- Verify enhanced @moduledoc content is comprehensive
- Verify stability guide renders correctly

### Quality Checks:
- Run `mix quality --quick` after each phase
- Run `mix quality` for final verification
- Ensure no new compilation warnings introduced

## References

- Issue: #72
- ExDoc documentation: https://hexdocs.pm/ex_doc/readme.html
- Semantic Versioning: https://semver.org/
- AWS Encryption SDK Spec: https://github.com/awslabs/aws-encryption-sdk-specification
