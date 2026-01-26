# /release Skill Implementation Plan

## Overview

Create a `/release` Claude Code skill that automates the entire release process, including version determination, file updates across 4 files (CHANGELOG.md, mix.exs, README.md, CLAUDE.md), and commit creation.

**Issue**: #30
**Skill Location**: `.claude/commands/release.md`

## Current State Analysis

### Existing Skill Pattern
The `/commit` skill at `.claude/commands/commit.md` provides the template pattern:
- Frontmatter with `description` and `model` fields
- Step-by-step process with clear headers
- User approval gates before making changes
- HEREDOC pattern for git commits

### Files to Update

| File | Location | What to Update |
|------|----------|----------------|
| CHANGELOG.md | Lines 8-26, 79-80 | Version heading, move unreleased content, update links |
| mix.exs | Line 4 | `@version` module attribute |
| README.md | Lines 16, 47 | Version in status and installation sections |
| README.md | Lines 18-34 | Move features between implemented/not-implemented |
| CLAUDE.md | Lines 247-279 | Check off completed milestone items |

### Current Versions & Formats

**CHANGELOG.md structure:**
```markdown
## [Unreleased]

### Added
- Feature description (#XX)

### Changed
- Change description

## [0.1.0] - 2025-01-12
...

[Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/releases/tag/v0.1.0
```

**mix.exs format:**
```elixir
@version "0.1.0"
```

**README.md version locations:**
- Line 16: `**Version**: 0.1.0 (pre-release)`
- Line 47: `{:aws_encryption_sdk, "~> 0.1.0"}`

**README.md feature sections:**
- Lines 18-27: `### Implemented Features` with `- ✅ Feature description`
- Lines 28-34: `### Not Yet Implemented` with `- ❌ Feature description`

**CLAUDE.md milestone format:**
- `- [x] Completed item`
- `- [ ] Pending item`

## Desired End State

After this plan is complete:
1. A new skill file exists at `.claude/commands/release.md`
2. Running `/release` will:
   - Verify git is clean and tests pass
   - Analyze CHANGELOG to suggest version bump
   - Get user confirmation on version
   - Update all 4 files correctly
   - Show diff for review
   - Create a properly formatted release commit

### Verification
- Skill appears in `/help` or skill list
- Can be invoked with `/release`
- All file updates follow existing format conventions
- Commit message follows expected format

## What We're NOT Doing

- Hex.pm publishing (separate manual step)
- Git tagging (can be added later)
- GitHub release creation (can be added later)
- Support for versions >= 1.0.0 (pre-1.0 only for now)
- Rollback functionality (user can `git checkout` if needed)

## Implementation Approach

Model the skill after `/commit` with a multi-step process:
1. Pre-flight validation
2. Analysis and suggestion
3. User confirmation
4. File modifications
5. Review and commit

The skill will be a markdown file with detailed instructions for Claude to follow, not executable code.

---

## Phase 1: Create Basic Skill Structure

### Overview
Create the skill file with frontmatter, pre-flight checks, and CHANGELOG parsing logic.

### Changes Required:

#### 1. Create Skill File
**File**: `.claude/commands/release.md`
**Action**: Create new file

```markdown
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
```

### Success Criteria:

#### Automated Verification:
- [x] File exists at `.claude/commands/release.md`
- [x] File has valid frontmatter with `description` and `model` fields

#### Manual Verification:
- [x] Skill appears when listing available skills
- [x] Invoking `/release` on a dirty git repo shows appropriate error
- [x] Invoking `/release` with failing tests shows appropriate error

**Implementation Note**: After completing this phase, pause for manual confirmation before proceeding.

---

## Phase 2: Version Determination Logic

### Overview
Add the logic for calculating version bumps and getting user confirmation.

### Changes Required:

#### 1. Add Version Calculation Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

### Success Criteria:

#### Automated Verification:
- [x] Skill file contains version calculation logic

#### Manual Verification:
- [x] Running `/release` correctly parses current version from CHANGELOG
- [x] Version suggestion logic works (minor for features, patch for fixes)
- [x] User can confirm or override suggested version

**Implementation Note**: After completing this phase, pause for manual confirmation before proceeding.

---

## Phase 3: CHANGELOG Update Logic

### Overview
Add the logic for updating CHANGELOG.md with the new version.

### Changes Required:

#### 1. Add CHANGELOG Update Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

### Success Criteria:

#### Automated Verification:
- [x] Skill file contains CHANGELOG update logic

#### Manual Verification:
- [x] New version heading is inserted correctly with today's date
- [x] Unreleased section is preserved but emptied
- [x] Comparison links are updated correctly
- [x] Link format is correct (compare for new versions, releases/tag for initial)

**Implementation Note**: After completing this phase, pause for manual confirmation before proceeding.

---

## Phase 4: Secondary File Updates

### Overview
Add logic for updating mix.exs, README.md (version + features), and CLAUDE.md (milestones).

### Changes Required:

#### 1. Add mix.exs Update Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

#### 2. Add README.md Version Update Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

#### 3. Add README.md Feature Sync Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

#### 4. Add CLAUDE.md Milestone Update Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

### Success Criteria:

#### Automated Verification:
- [x] Skill file contains all update sections (mix.exs, README version, README features, CLAUDE.md milestones)

#### Manual Verification:
- [x] mix.exs version updates correctly
- [x] README.md version updates in both locations
- [x] README.md feature sync works with fuzzy matching
- [x] CLAUDE.md milestone checkboxes update correctly
- [x] All changes are presented for approval before applying

**Implementation Note**: After completing this phase, pause for manual confirmation before proceeding.

---

## Phase 5: Review, Commit & Finalize

### Overview
Add the final review, diff display, and commit creation logic.

### Changes Required:

#### 1. Add Review and Commit Section
**File**: `.claude/commands/release.md`
**Action**: Append to existing content

```markdown
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
```

### Success Criteria:

#### Automated Verification:
- [x] Complete skill file exists at `.claude/commands/release.md`
- [x] Skill file has all 9 steps documented

#### Manual Verification:
- [x] Full `/release` workflow works end-to-end
- [x] Diff is shown before commit
- [x] Commit message follows correct format (no co-author)
- [x] All 4 files are updated correctly
- [x] Next steps are shown after commit

**Implementation Note**: After completing this phase, pause for manual confirmation before proceeding.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Run `mix quality --quick` to ensure no issues introduced
- [x] Verify skill file exists and has correct structure

### Manual:
- [x] Test `/release` on a branch with unreleased CHANGELOG entries
- [x] Verify version suggestion logic works correctly
- [x] Verify all 4 files are updated properly
- [x] Verify commit is created with correct format
- [x] Test error cases (dirty git, failing tests, empty CHANGELOG)

## Testing Strategy

### Manual Testing Steps:

1. **Test pre-flight checks:**
   - Make a local change without committing, run `/release`, expect error
   - Break a test, run `/release`, expect error
   - Empty the Unreleased section, run `/release`, expect error

2. **Test version suggestion:**
   - Add only "Fixed" entries, expect patch bump suggestion
   - Add "Added" entries, expect minor bump suggestion
   - Verify user can override suggestion

3. **Test file updates:**
   - Run full release, verify CHANGELOG format is correct
   - Verify mix.exs version matches
   - Verify README.md versions match in both locations
   - Verify README.md feature lists updated appropriately
   - Verify CLAUDE.md milestones updated appropriately

4. **Test commit:**
   - Verify commit message has correct title format
   - Verify no co-author line
   - Verify CHANGELOG content is in commit body

## References

- Issue: #30
- Similar skill: `.claude/commands/commit.md`
- CHANGELOG format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
- Version format: [Semantic Versioning](https://semver.org/)
