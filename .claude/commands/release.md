---
description: Automate version releases with CHANGELOG analysis and multi-file updates
model: sonnet
---

# Release New Version

This command automates the release process for the AWS Encryption SDK for Elixir.

## Process:

### Step 0: Pre-flight Checks

1. **Verify git working directory is clean**:
   ```bash
   git status --porcelain
   ```
   - If output is not empty, STOP and inform user: "Working directory has uncommitted changes. Please commit or stash changes before releasing."

2. **Run quality checks**:
   ```bash
   mix quality
   ```
   - If any checks fail, STOP and inform user: "Quality checks failed. Please fix issues before releasing."

3. **Verify CHANGELOG has unreleased changes**:
   - Read CHANGELOG.md
   - Check that `## [Unreleased]` section has content (not just empty categories)
   - If empty, STOP and inform user: "No unreleased changes found in CHANGELOG.md"

### Step 1: Analyze CHANGELOG

1. **Read CHANGELOG.md** to understand current state
2. **Extract unreleased changes** by category:
   - Added
   - Changed
   - Deprecated
   - Removed
   - Fixed
   - Security

3. **Get current version** from the most recent version heading (e.g., `## [0.1.0]`)

4. **Determine suggested version bump**:
   - If "Added" has substantial new features → suggest MINOR bump (0.X.0 → 0.Y.0)
   - If only "Fixed" or "Changed" entries → suggest PATCH bump (0.X.Y → 0.X.Z)
   - Breaking changes in pre-1.0 can be MINOR bumps

5. **Validate version < 1.0.0**:
   - This skill only supports pre-1.0 releases
   - If calculated version would be >= 1.0.0, inform user this requires manual handling

### Step 2: Calculate and Confirm Version

1. **Parse current version**:
   - Extract from last version heading: `## [X.Y.Z] - YYYY-MM-DD`
   - Parse into major, minor, patch components

2. **Apply version bump rules**:
   ```
   Current: 0.MINOR.PATCH

   If unreleased has "Added" entries with new features:
     → Suggested: 0.(MINOR+1).0

   If unreleased only has "Fixed", "Changed", or "Security":
     → Suggested: 0.MINOR.(PATCH+1)
   ```

3. **Present to user for confirmation**:
   ```
   Based on the unreleased changes, I suggest version 0.2.0:

   **Unreleased Changes:**
   ### Added
   - Feature A (#XX)
   - Feature B (#YY)

   ### Changed
   - Change description

   **Current version**: 0.1.0
   **Suggested version**: 0.2.0 (minor bump due to new features)

   Please confirm the version number or provide an alternative:
   ```

4. **Validate user-provided version**:
   - Must be valid semver format (X.Y.Z)
   - Must be greater than current version
   - Must be < 1.0.0
   - If invalid, explain and ask again

5. **Create release branch**:
   - Create a new git branch named 'vX.Y.Z' (fill in the actual version numbers, but prefix with 'v')

### Step 3: Update CHANGELOG.md

After version confirmation, update CHANGELOG.md:

1. **Get today's date** in ISO 8601 format (YYYY-MM-DD)

2. **Insert new version heading** after `## [Unreleased]`:
   - Find the line `## [Unreleased]`
   - The content between `## [Unreleased]` and the next `## [X.Y.Z]` heading is the unreleased content
   - Insert `## [NEW_VERSION] - YYYY-MM-DD` after the unreleased content
   - Keep the `## [Unreleased]` heading with empty subsections for future changes

3. **Restructure to**:
   ```markdown
   ## [Unreleased]

   ## [0.2.0] - 2026-01-25

   ### Added
   - (moved content from unreleased)

   ### Changed
   - (moved content from unreleased)

   ## [0.1.0] - 2025-01-12
   ...
   ```

4. **Update comparison links** at bottom of file:
   - Find the links section (starts with `[Unreleased]:`)
   - Add new version link BEFORE existing version links
   - Update Unreleased link to compare from new version

   **Before:**
   ```markdown
   [Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...HEAD
   [0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
   ```

   **After:**
   ```markdown
   [Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.2.0...HEAD
   [0.2.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...v0.2.0
   [0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
   ```

   Note: New version uses compare URL (previous...new), only the initial release uses releases/tag URL

### Step 4: Update mix.exs

1. **Find the @version attribute** (should be near top of file, around line 4)
2. **Update to new version**:

   **Before:**
   ```elixir
   @version "0.1.0"
   ```

   **After:**
   ```elixir
   @version "0.2.0"
   ```

### Step 5: Update README.md Version

1. **Update Current Status version** (around line 16):

   **Before:**
   ```markdown
   **Version**: 0.1.0 (pre-release)
   ```

   **After:**
   ```markdown
   **Version**: 0.2.0 (pre-release)
   ```

2. **Update installation instructions** (around line 47):

   **Before:**
   ```elixir
   {:aws_encryption_sdk, "~> 0.1.0"}
   ```

   **After:**
   ```elixir
   {:aws_encryption_sdk, "~> 0.2.0"}
   ```

### Step 6: Sync README.md Features with CHANGELOG

Based on the CHANGELOG "Added" entries, update the feature lists:

1. **Identify newly implemented features** from CHANGELOG ### Added section

2. **For each new feature, check if it matches a "Not Yet Implemented" item**:
   - Use fuzzy matching on key terms
   - Examples of matches:
     - CHANGELOG: "Keyring behaviour interface" → README: "Keyrings (Raw AES, Raw RSA, AWS KMS)"
     - CHANGELOG: "Raw AES keyring implementation" → README: "Keyrings (Raw AES, Raw RSA, AWS KMS)"

3. **Move matched items** from "Not Yet Implemented" to "Implemented Features":
   - Change `- ❌` to `- ✅`
   - Update description if needed to match what was actually implemented
   - If only partial implementation (e.g., just Raw AES keyring, not all keyrings), update the description accordingly

4. **Add new implemented features** if not already in either list:
   - Add to "Implemented Features" section with `- ✅` prefix

**Matching Keywords Table:**

| CHANGELOG Terms | README "Not Yet Implemented" Item |
|-----------------|-----------------------------------|
| keyring behaviour, keyring interface | Keyrings (Raw AES, Raw RSA, AWS KMS) |
| raw aes keyring | Keyrings (Raw AES, Raw RSA, AWS KMS) |
| raw rsa keyring | Keyrings (Raw AES, Raw RSA, AWS KMS) |
| aws kms keyring | Keyrings (Raw AES, Raw RSA, AWS KMS) |
| cmm, materials manager | Cryptographic Materials Manager (CMM) |
| streaming | Streaming encryption/decryption |
| ecdsa, signing, signature | ECDSA signing for signed algorithm suites |

5. **Present changes for approval** before applying

### Step 7: Update CLAUDE.md Milestones

Based on the CHANGELOG "Added" entries, check off completed milestone items:

1. **Read CLAUDE.md** and find the "Development Milestones" section (lines 245-279)

2. **For each CHANGELOG "Added" entry, check if it matches a milestone item**:

**Matching Table:**

| CHANGELOG Terms | CLAUDE.md Milestone Item |
|-----------------|--------------------------|
| algorithm suite | Algorithm suite definitions |
| hkdf | HKDF implementation |
| message format, serialization, header, body | Message format serialization |
| encrypt, decrypt (basic) | Basic encryption/decryption (non-streaming) |
| keyring behaviour, keyring interface | Keyring behaviour |
| raw aes keyring | Raw AES Keyring |
| raw rsa keyring | Raw RSA Keyring |
| multi-keyring, multi keyring | Multi-Keyring |
| cmm behaviour | CMM behaviour |
| default cmm | Default CMM |
| encrypt api, commitment policy (encrypt) | Encrypt API with commitment policy |
| decrypt api, commitment policy (decrypt) | Decrypt API with commitment policy |
| aws kms keyring | AWS KMS Keyring |
| kms discovery | AWS KMS Discovery Keyring |
| mrk, multi-region | AWS KMS MRK-aware keyrings |
| streaming | Streaming encryption/decryption |
| caching cmm | Caching CMM |
| required encryption context | Required encryption context CMM |
| test vector | Full test vector suite |
| interoperability, cross-sdk | Cross-SDK interoperability |
| benchmark, performance | Performance benchmarks |
| security review, audit | Security review |

3. **Update matched items** from `- [ ]` to `- [x]`

4. **Present changes for approval** before applying

### Step 8: Review Changes

Before committing, present all changes for user review:

1. **Show summary of changes**:
   ```
   ## Release Summary: v0.2.0

   **Files to be updated:**
   - CHANGELOG.md: New version section, updated links
   - mix.exs: Version 0.1.0 → 0.2.0
   - README.md: Version updated, X features moved to implemented
   - CLAUDE.md: X milestone items checked off

   **Changes from CHANGELOG:**
   ### Added
   - (list items)

   ### Changed
   - (list items)
   ```

2. **Show diff preview**:
   - Use the Edit tool to make changes
   - After all edits, run `git diff` to show what changed

3. **Ask for final approval**:
   ```
   Ready to create release commit for v0.2.0.

   Please review the changes above and confirm to proceed.
   ```

### Step 9: Create Release Commit

After user approval:

1. **Stage all modified files**:
   ```bash
   git add CHANGELOG.md mix.exs README.md CLAUDE.md
   ```

2. **Create commit** with release message:
   ```bash
   git commit -m "$(cat <<'EOF'
   Releases v0.2.0

   ### Added
   - Feature A (#XX)
   - Feature B (#YY)

   ### Changed
   - Change description
   EOF
   )"
   ```

   **Important:**
   - Title format: `Releases vX.Y.Z`
   - Body: Copy the changelog entries for this version
   - Do NOT include co-authored-by or any attribution

3. **Verify commit**:
   ```bash
   git log --oneline -n 1
   ```

4. **Inform user of next steps**:
   ```
   Release v0.2.0 committed successfully!

   Next steps:
   1. Push to remote: `git push`
   2. Create GitHub release (optional): `gh release create v0.2.0`
   3. Publish to Hex.pm: `mix hex.publish`
   ```

## Important Guidelines

- **NEVER add co-author information or Claude attribution** to release commits
- **Always get user confirmation** before making any file changes
- **Always get user confirmation** before creating the commit
- **Validate all inputs** (version format, git state, etc.)
- **Show diffs** so user can verify changes before committing
- **Handle errors gracefully** with clear messages
