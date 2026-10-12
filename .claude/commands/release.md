---
description: Prepare a version release (bump, CHANGELOG, README) for a CI publish on a tag push
model: sonnet
---

# Release New Version

This command prepares a release of the AWS Encryption SDK for Elixir: the
version bump, the CHANGELOG promotion and the README status line, committed
as one `Releases vX.Y.Z` commit and opened as a pull request.

It does not publish. Publishing is done by `.github/workflows/release.yml`,
which runs when a `v*.*.*` tag is pushed. The workflow checks that the
tagged commit is on `main`, that the tag names the `@version` in `mix.exs`,
and that Hex does not already show the version, then runs the quality gate
and publishes. Nobody runs the Hex publish command by hand, from this
command or from a shell.

## Process:

### Step 0: Pre-flight Checks

1. **Verify git working directory is clean**:
   ```bash
   git status --porcelain
   ```
   - If output is not empty, STOP and inform user: "Working directory has uncommitted changes. Please commit or stash changes before releasing."

2. **Start from the latest main**:
   ```bash
   git fetch origin
   git switch -c release-prep origin/main
   ```
   - Once the version is confirmed in Step 2, rename it: `git branch -m release-vX.Y.Z`.

3. **Run quality checks**:
   ```bash
   mix quality
   ```
   - If any checks fail, STOP and inform user: "Quality checks failed. Please fix issues before releasing."

4. **Verify CHANGELOG has unreleased changes**:
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

3. **Get current version** from the most recent version heading (e.g., `## [1.1.0]`)

4. **Determine suggested version bump** (see `guides/STABILITY.md` for what counts as breaking):
   - Breaking changes to the public API -> MAJOR bump (X.0.0)
   - "Added" with new features, or a "Deprecated" entry -> MINOR bump (X.Y.0)
   - Only "Fixed", "Changed" or "Security" entries that keep the public API -> PATCH bump (X.Y.Z)

   There is no version ceiling. The version is the maintainer's call; the suggestion is only a starting point.

### Step 2: Calculate and Confirm Version

1. **Parse current version**:
   - Extract from last version heading: `## [X.Y.Z] - YYYY-MM-DD`
   - Parse into major, minor, patch components

2. **Present to user for confirmation**:
   ```
   Based on the unreleased changes, I suggest version 1.2.0:

   **Unreleased Changes:**
   ### Added
   - Feature A (#XX)

   ### Changed
   - Change description

   **Current version**: 1.1.0
   **Suggested version**: 1.2.0 (minor bump due to new features)

   Please confirm the version number or provide an alternative:
   ```

3. **Validate user-provided version**:
   - Must be valid semver format (X.Y.Z)
   - Must be greater than current version
   - If invalid, explain and ask again

4. **Check the tag is free**:
   ```bash
   git rev-parse -q --verify refs/tags/vX.Y.Z
   ```
   - If it prints a commit, STOP: a released tag is never moved, deleted or reused.

### Step 3: Update CHANGELOG.md

After version confirmation, update CHANGELOG.md:

1. **Get today's date** in ISO 8601 format (YYYY-MM-DD)

2. **Insert new version heading** after `## [Unreleased]`:
   - Find the line `## [Unreleased]`
   - The content between `## [Unreleased]` and the next `## [X.Y.Z]` heading is the unreleased content
   - Insert `## [NEW_VERSION] - YYYY-MM-DD` after the unreleased content
   - Keep the `## [Unreleased]` heading, empty, for future changes

3. **Restructure to**:
   ```markdown
   ## [Unreleased]

   ## [1.2.0] - 2026-01-25

   ### Added
   - (moved content from unreleased)

   ### Changed
   - (moved content from unreleased)

   ## [1.1.0] - 2026-10-07
   ...
   ```

4. **Update comparison links** at bottom of file:
   - Find the links section (starts with `[Unreleased]:`)
   - Add new version link BEFORE existing version links
   - Update Unreleased link to compare from new version

   **Before:**
   ```markdown
   [Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.1.0...HEAD
   [1.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.0.1...v1.1.0
   ```

   **After:**
   ```markdown
   [Unreleased]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.2.0...HEAD
   [1.2.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.1.0...v1.2.0
   [1.1.0]: https://github.com/riddler/aws-encryption-sdk-elixir/compare/v1.0.1...v1.1.0
   ```

   Note: New version uses compare URL (previous...new), only the initial release uses releases/tag URL

### Step 4: Update mix.exs

1. **Find the @version attribute** (should be near top of file, around line 4)
2. **Update to new version**. The release workflow refuses a tag that does not name this value.

   **Before:**
   ```elixir
   @version "1.1.0"
   ```

   **After:**
   ```elixir
   @version "1.2.0"
   ```

### Step 5: Update README.md Version

1. **Update the Current Status version line** (around line 14):

   **Before:**
   ```markdown
   **Version**: 1.1.0
   ```

   **After:**
   ```markdown
   **Version**: 1.2.0
   ```

2. **Update the installation pins** (the minimal and the KMS deps blocks) only when the MAJOR or MINOR component changed and the old pin would no longer resolve the new version, or when the release needs a newer minimum. A patch release leaves the pins alone.

   **Before:**
   ```elixir
   {:aws_encryption_sdk, "~> 1.1"}
   ```

   **After (a minor that needs it):**
   ```elixir
   {:aws_encryption_sdk, "~> 1.2"}
   ```

### Step 6: Update CLAUDE.md Milestones

Based on the CHANGELOG "Added" entries, check off completed milestone items:

1. **Read CLAUDE.md** and find the "Development Milestones" section

2. **For each CHANGELOG "Added" entry, check if it matches an unchecked milestone item**:

| CHANGELOG Terms | CLAUDE.md Milestone Item |
|-----------------|--------------------------|
| test vector | Full test vector suite |
| interoperability, cross-sdk | Cross-SDK interoperability |
| benchmark, performance | Performance benchmarks |
| security review | Security review |

3. **Update matched items** from `- [ ]` to `- [x]`. The evidence is worded honestly: a self-review is never recorded as an audit.

4. **Present changes for approval** before applying. Skip this step when nothing matches.

### Step 7: Review Changes

Before committing, present all changes for user review:

1. **Show summary of changes**:
   ```
   ## Release Summary: v1.2.0

   **Files to be updated:**
   - CHANGELOG.md: New version section, updated links
   - mix.exs: Version 1.1.0 -> 1.2.0
   - README.md: Version line (and install pins if they moved)
   - CLAUDE.md: milestone items checked off, if any

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
   Ready to create release commit for v1.2.0.

   Please review the changes above and confirm to proceed.
   ```

### Step 8: Create Release Commit

After user approval:

1. **Stage the modified files** (name them, never `git add -A`):
   ```bash
   git add CHANGELOG.md mix.exs README.md
   ```
   Add `CLAUDE.md` only if Step 6 changed it.

2. **Create commit** with release message, in the repo's own commit style (see `.claude/commands/commit.md`):
   ```bash
   git commit -m "$(cat <<'EOF'
   Releases v1.2.0

   - Bumps @version to 1.2.0 and the README's status line to match
   - Promotes the CHANGELOG's Unreleased entries to 1.2.0 and updates
     the compare links; the entries are unchanged
   EOF
   )"
   ```

   **Important:**
   - Title format: `Releases vX.Y.Z`
   - Body: present-tense bullets wrapped at 72 characters that say what the release commit changed (version bump, README line and pins, CHANGELOG promotion); a long release may copy the CHANGELOG entries instead
   - Do NOT include co-authored-by or any attribution

3. **Verify commit**:
   ```bash
   git log --oneline -n 1
   ```

### Step 9: Open the Pull Request

1. **Push the branch and open a pull request** against `main`. The release commit lands on `main` through the pull request, like any other change; the checks must be green first.

2. **Tell the user the next steps**:
   ```
   Release v1.2.0 committed and the pull request is open.

   Next steps:
   1. Merge the pull request once its checks are green.
   2. Pull main, then tag the merge commit and push the tag:
      git switch main && git pull
      git tag v1.2.0
      git push origin v1.2.0
   3. The Release workflow publishes to Hex from the tag push. Follow it on the Actions page.
   ```

### Step 10: After the Tag Push

- The workflow verifies and publishes; nothing is run locally.
- If the publish step fails on a registry or network error, re-run that workflow run from the Actions page. Never work round a failure with a local publish.
- If a check before the publish step fails (not on `main`, tag and `@version` differ, the version is already on Hex, or the gate is red), nothing was published. Fix the cause on a new commit through a pull request; a tag that already reached a published version is never moved or deleted.

## Important Guidelines

- **NEVER add co-author information or Claude attribution** to release commits
- **Never run the Hex publish command by hand**; the tag push is the only publish path
- **Always get user confirmation** before making any file changes
- **Always get user confirmation** before creating the commit
- **Validate all inputs** (version format, git state, etc.)
- **Show diffs** so user can verify changes before committing
- **Handle errors gracefully** with clear messages
