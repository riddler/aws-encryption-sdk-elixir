# GitHub Actions CI Implementation Plan

## Overview

Add GitHub Actions workflow for automated linting, testing, and code verification on PRs and main branch pushes. Includes multi-version Elixir/OTP testing matrix and Codecov integration.

**Issue**: #15

## Current State Analysis

- **Elixir version**: Currently `~> 1.18` in `mix.exs:11` - needs to change to `~> 1.16`
- **Quality tooling**: `mix quality` already configured via `ex_quality` - runs credo, doctor, dialyzer, tests/coverage, and dependency audit in parallel
- **Coverage**: ExCoveralls configured with 90% minimum threshold in `coveralls.json`
- **No existing CI**: `.github/workflows/` directory doesn't exist

## Desired End State

After implementation:
1. CI runs on all PRs to main and pushes to main
2. Tests run on matrix: Elixir 1.16-1.18 × OTP 26-27 (valid combinations)
3. Coverage uploads to Codecov on latest Elixir/OTP only
4. README shows CI status and coverage badges
5. `mix.exs` supports Elixir 1.16+

## What We're NOT Doing

- Branch protection configuration (GitHub UI task, not workflow)
- Deployment/release automation
- Dependabot configuration
- Separate jobs per quality check (using unified `mix quality` instead)

## Implementation Approach

Single workflow file with:
1. **Fast-fail compile job** - catches compilation errors quickly
2. **Quality matrix job** - runs `mix quality` on all Elixir/OTP combinations
3. **Coverage conditional** - uploads to Codecov only on one matrix entry

---

## Phase 1: Create CI Workflow

### Overview
Create the GitHub Actions workflow file with compilation check, quality matrix, and Codecov integration.

### Changes Required:

#### 1. Create workflow directory and file
**File**: `.github/workflows/ci.yml`

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  MIX_ENV: test

jobs:
  compile:
    name: Compile
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Elixir
        uses: erlef/setup-beam@v1
        with:
          elixir-version: "1.18"
          otp-version: "27"

      - name: Cache deps
        uses: actions/cache@v4
        with:
          path: deps
          key: deps-${{ runner.os }}-${{ hashFiles('**/mix.lock') }}
          restore-keys: deps-${{ runner.os }}-

      - name: Install dependencies
        run: mix deps.get

      - name: Compile
        run: mix compile --warnings-as-errors

  quality:
    name: Quality (Elixir ${{ matrix.elixir }} / OTP ${{ matrix.otp }})
    needs: compile
    runs-on: ubuntu-latest

    strategy:
      fail-fast: false
      matrix:
        include:
          # Oldest supported
          - elixir: "1.16"
            otp: "26"
          # Middle ground
          - elixir: "1.17"
            otp: "26"
          # Latest (with coverage upload)
          - elixir: "1.18"
            otp: "27"
            coverage: true

    steps:
      - uses: actions/checkout@v4

      - name: Set up Elixir
        uses: erlef/setup-beam@v1
        with:
          elixir-version: ${{ matrix.elixir }}
          otp-version: ${{ matrix.otp }}

      - name: Cache deps
        uses: actions/cache@v4
        with:
          path: deps
          key: deps-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-${{ hashFiles('**/mix.lock') }}
          restore-keys: |
            deps-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-
            deps-${{ runner.os }}-

      - name: Cache _build
        uses: actions/cache@v4
        with:
          path: _build
          key: build-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-${{ hashFiles('**/mix.lock') }}
          restore-keys: |
            build-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-

      - name: Cache PLT
        uses: actions/cache@v4
        with:
          path: priv/plts
          key: plt-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-${{ hashFiles('**/mix.lock') }}
          restore-keys: |
            plt-${{ runner.os }}-${{ matrix.elixir }}-${{ matrix.otp }}-

      - name: Install dependencies
        run: mix deps.get

      - name: Run quality checks
        run: mix quality

      - name: Generate coverage report
        if: matrix.coverage
        run: mix coveralls.json

      - name: Upload coverage to Codecov
        if: matrix.coverage
        uses: codecov/codecov-action@v4
        with:
          files: cover/excoveralls.json
          fail_ci_if_error: true
          token: ${{ secrets.CODECOV_TOKEN }}
```

### Success Criteria:

#### Automated Verification:
- [x] Workflow file is valid YAML (GitHub will validate on push)
- [x] Local `mix quality` still passes

#### Manual Verification:
- [ ] Push branch and verify CI runs
- [ ] Check all three matrix jobs execute
- [ ] Verify caching works on second run

**Implementation Note**: After completing this phase, push to a test branch to verify the workflow runs correctly before proceeding.

---

## Phase 2: Update mix.exs Version Requirements

### Overview
Update the Elixir version requirement to support 1.16+.

### Changes Required:

#### 1. Update Elixir version constraint
**File**: `mix.exs:11`

Change:
```elixir
elixir: "~> 1.18",
```

To:
```elixir
elixir: "~> 1.16",
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes locally

#### Manual Verification:
- [x] N/A - automated check sufficient

---

## Phase 3: Update README with Badges

### Overview
Add CI status and Codecov coverage badges to README, and update the requirements section.

### Changes Required:

#### 1. Add badges after the warning block
**File**: `README.md`

After line 6 (after the warning blockquote), add:

```markdown
[![CI](https://github.com/riddler/aws-encryption-sdk-elixir/actions/workflows/ci.yml/badge.svg)](https://github.com/riddler/aws-encryption-sdk-elixir/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/riddler/aws-encryption-sdk-elixir/branch/main/graph/badge.svg)](https://codecov.io/gh/riddler/aws-encryption-sdk-elixir)

```

#### 2. Update Requirements section
**File**: `README.md:88-91`

Change:
```markdown
## Requirements

- Elixir ~> 1.18
- Erlang/OTP with `:crypto` application
```

To:
```markdown
## Requirements

- Elixir 1.16 or later
- Erlang/OTP 26 or later
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes

#### Manual Verification:
- [ ] Badges render correctly on GitHub after merge
- [ ] CI badge shows status after first workflow run
- [ ] Coverage badge shows after Codecov integration

---

## Phase 4: Codecov Setup

### Overview
Configure Codecov to receive coverage uploads. This requires repository setup on codecov.io.

### Changes Required:

#### 1. Add CODECOV_TOKEN secret
This is a manual step in GitHub repository settings:
1. Sign up/login to [codecov.io](https://codecov.io) with GitHub
2. Add the repository
3. Copy the upload token
4. Add as `CODECOV_TOKEN` secret in GitHub repo settings (Settings → Secrets → Actions)

#### 2. Add codecov.yml for configuration
**File**: `codecov.yml` (repository root)

```yaml
coverage:
  status:
    project:
      default:
        target: 90%
        threshold: 1%
    patch:
      default:
        target: 90%

comment:
  layout: "reach,diff,flags,files"
  behavior: default
  require_changes: true
```

### Success Criteria:

#### Automated Verification:
- [ ] N/A - external service setup

#### Manual Verification:
- [ ] Codecov receives upload after CI runs on main
- [ ] Coverage badge displays percentage
- [ ] PR comments show coverage diff (after first PR with codecov configured)

---

## Final Verification

After all phases complete:

### Automated:
- [x] `mix quality` passes locally
- [ ] CI workflow runs successfully on all matrix entries
- [ ] Coverage uploads to Codecov

### Manual:
- [ ] Create test PR to verify full workflow
- [ ] Verify badges display correctly on README
- [ ] Check Codecov PR comment appears

## Testing Strategy

### Local Testing:
1. Run `mix quality` to verify nothing breaks
2. Validate YAML syntax with a linter or by pushing

### CI Testing:
1. Push to a feature branch first
2. Verify all matrix jobs pass
3. Merge to main to test coverage upload

## Files Summary

| File | Action | Purpose |
|------|--------|---------|
| `.github/workflows/ci.yml` | Create | CI workflow |
| `mix.exs` | Edit | Update Elixir version to ~> 1.16 |
| `README.md` | Edit | Add badges, update requirements |
| `codecov.yml` | Create | Codecov configuration |

## References

- Issue: #15
- [GitHub Actions for Elixir](https://github.com/erlef/setup-beam)
- [Codecov GitHub Action](https://github.com/codecov/codecov-action)
- [ExCoveralls](https://github.com/parroty/excoveralls)
