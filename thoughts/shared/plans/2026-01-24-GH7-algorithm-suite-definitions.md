# Algorithm Suite Definitions Implementation Plan

## Overview

Implement all 11 ESDK algorithm suite definitions as a foundational module that other SDK components will depend on. Each suite defines cryptographic algorithms and parameters for encryption/decryption operations per the AWS Encryption SDK specification.

**Issue**: #7
**Research**: `thoughts/shared/research/2026-01-24-GH7-algorithm-suite-definitions.md`

## Specification Requirements

### Source Documents
- [framework/algorithm-suites.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md) - Complete algorithm suite definitions (v0.4.0)

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Reserved ID `0x0000` must never be accepted | algorithm-suites.md | MUST |
| Encryption key length must equal suite's data_key_length | algorithm-suites.md | MUST |
| IV length must equal suite's iv_length (12 bytes) | algorithm-suites.md | MUST |
| Auth tag length must equal suite's auth_tag_length (16 bytes) | algorithm-suites.md | MUST |
| Identity KDF must return input unchanged | algorithm-suites.md | MUST |
| Signatures only for suites with signature algorithm | algorithm-suites.md | MUST |

## Test Vectors

### Validation Strategy
Algorithm suite definitions are validated indirectly through encrypt/decrypt test vectors. For this foundational module, we focus on unit tests validating:
- Correct suite ID mappings
- Correct parameter values per spec
- Predicate functions returning correct results
- Lookup functions finding correct suites

### Test Vector Summary
| Phase | Validation | Purpose |
|-------|------------|---------|
| 1-2 | Unit tests | Struct definition correctness |
| 3 | Unit tests | Lookup and predicate behavior |
| 4 | Unit tests | All 11 suites defined correctly |
| 5 | Unit tests + `mix quality` | Complete coverage |

## Current State Analysis

**Greenfield implementation.** The codebase contains only:
- `lib/aws_encryption_sdk.ex` - Placeholder module with `hello/0` function
- No `lib/aws_encryption_sdk/` subdirectory exists

### Key Discoveries:
- Credo strict mode enabled with specs required (`Credo.Check.Readability.Specs`)
- Strict module layout enforced (`Credo.Check.Readability.StrictModuleLayout`)
- Max line length: 120 characters
- No existing patterns to follow - this sets the pattern for future modules

## Desired End State

After this plan is complete:

1. **File exists**: `lib/aws_encryption_sdk/algorithm_suite.ex`
2. **All 11 ESDK suites** are defined with correct parameters
3. **Lookup functions** work correctly:
   - `by_id/1` returns `{:ok, suite}` or `{:error, reason}`
   - `default/0` returns `0x0578` (AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384)
4. **Predicate functions** work correctly:
   - `committed?/1` - true for 0x0478, 0x0578
   - `signed?/1` - true for suites with ECDSA
   - `allows_encryption?/1` - false for NO_KDF suites (deprecated)
   - `deprecated?/1` - true for NO_KDF suites
5. **Deprecated suite warnings** are logged when deprecated suites are accessed
6. **Tests pass**: `mix quality` succeeds with full coverage

### Verification Commands:
```bash
mix quality          # All checks pass
mix test             # All tests pass
```

## What We're NOT Doing

- S3EC algorithm suites (3 suites) - out of scope per decision
- DBE algorithm suites (2 suites) - out of scope per decision
- HKDF implementation - separate issue #8
- Key commitment verification - uses suites but implemented elsewhere
- Signature generation/verification - uses suites but implemented elsewhere

---

## Phase 1: Core Struct & Directory Setup

### Overview
Create the module file with struct definition, typespecs, and module documentation.

### Spec Requirements Addressed
- Define struct fields matching all suite parameters from spec

### Changes Required:

#### 1. Create directory and module file
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Create new file with struct definition

```elixir
defmodule AwsEncryptionSdk.AlgorithmSuite do
  @moduledoc """
  Algorithm suite definitions for the AWS Encryption SDK.

  Each algorithm suite defines the cryptographic algorithms and parameters used for
  encryption and decryption operations. The SDK supports 11 ESDK algorithm suites
  across three categories:

  - **Committed suites** (recommended): 0x0578, 0x0478 - Include key commitment
  - **Legacy HKDF suites**: 0x0378, 0x0346, 0x0214, 0x0178, 0x0146, 0x0114
  - **Deprecated NO_KDF suites** (decrypt only): 0x0078, 0x0046, 0x0014

  ## Default Suite

  The default and recommended suite is `0x0578`
  (AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384), which provides:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation
  - Key commitment for enhanced security
  - ECDSA P-384 message signing
  """

  require Logger

  @typedoc "Algorithm suite identifier (2-byte big-endian integer)"
  @type suite_id :: non_neg_integer()

  @typedoc "Encryption algorithm for AES-GCM operations"
  @type encryption_algorithm :: :aes_128_gcm | :aes_192_gcm | :aes_256_gcm

  @typedoc "Key derivation function type"
  @type kdf_type :: :hkdf | :identity

  @typedoc "Hash algorithm for KDF operations"
  @type kdf_hash :: :sha256 | :sha384 | :sha512 | nil

  @typedoc "ECDSA signature algorithm"
  @type signature_algorithm :: :ecdsa_p256 | :ecdsa_p384 | nil

  @typedoc "Hash algorithm for signature operations"
  @type signature_hash :: :sha256 | :sha384 | nil

  @typedoc """
  Algorithm suite struct containing all cryptographic parameters.

  ## Fields

  - `:id` - Suite identifier (e.g., 0x0578)
  - `:name` - Human-readable name
  - `:message_format_version` - Message format version (1 or 2)
  - `:encryption_algorithm` - AES-GCM variant for Erlang :crypto
  - `:data_key_length` - Data key length in bits (128, 192, or 256)
  - `:iv_length` - Initialization vector length in bytes (always 12)
  - `:auth_tag_length` - Authentication tag length in bytes (always 16)
  - `:kdf_type` - Key derivation function (:hkdf or :identity)
  - `:kdf_hash` - Hash algorithm for HKDF (nil for identity KDF)
  - `:kdf_input_length` - KDF input key length in bytes
  - `:signature_algorithm` - ECDSA curve (nil if unsigned)
  - `:signature_hash` - Hash for signatures (nil if unsigned)
  - `:suite_data_length` - Suite data in header (32 for committed, 0 otherwise)
  - `:commitment_length` - Commitment key length (32 for committed, 0 otherwise)
  """
  @type t :: %__MODULE__{
          id: suite_id(),
          name: String.t(),
          message_format_version: 1 | 2,
          encryption_algorithm: encryption_algorithm(),
          data_key_length: 128 | 192 | 256,
          iv_length: 12,
          auth_tag_length: 16,
          kdf_type: kdf_type(),
          kdf_hash: kdf_hash(),
          kdf_input_length: pos_integer(),
          signature_algorithm: signature_algorithm(),
          signature_hash: signature_hash(),
          suite_data_length: 0 | 32,
          commitment_length: 0 | 32
        }

  @enforce_keys [
    :id,
    :name,
    :message_format_version,
    :encryption_algorithm,
    :data_key_length,
    :iv_length,
    :auth_tag_length,
    :kdf_type,
    :kdf_hash,
    :kdf_input_length,
    :signature_algorithm,
    :signature_hash,
    :suite_data_length,
    :commitment_length
  ]

  defstruct @enforce_keys
end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] Credo passes: `mix credo --strict`
- [x] Formatter passes: `mix format --check-formatted`

#### Manual Verification:
- [x] Module loads in IEx: `iex -S mix` then `h AwsEncryptionSdk.AlgorithmSuite`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the module loads correctly before proceeding to the next phase.

---

## Phase 2: High-Priority Suite Definitions

### Overview
Define the 4 most important suites: committed suites (0x0478, 0x0578) and common legacy suites (0x0178, 0x0378).

### Spec Requirements Addressed
- Committed suites use message format version 2
- Committed suites have 32-byte suite_data_length and commitment_length
- HKDF suites with SHA-512 for committed, SHA-384/SHA-256 for legacy
- ECDSA signatures for 0x0578 and 0x0378

### Changes Required:

#### 1. Add suite ID constants and suite definitions
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add module attributes for suite IDs and private functions returning suite structs

Add after the `defstruct` line:

```elixir
  # Suite ID constants
  @aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384 0x0578
  @aes_256_gcm_hkdf_sha512_commit_key 0x0478
  @aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 0x0378
  @aes_256_gcm_iv12_tag16_hkdf_sha256 0x0178

  @doc """
  Returns the default algorithm suite (0x0578).

  The default suite is AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384, which provides
  the highest level of security with key commitment and message signing.
  """
  @spec default() :: t()
  def default do
    aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
  end

  @doc """
  Returns the AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 suite (0x0578).

  This is the recommended suite providing:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation with 32-byte input
  - Key commitment (32 bytes)
  - ECDSA P-384 message signing
  """
  @spec aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384() :: t()
  def aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384 do
    %__MODULE__{
      id: @aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384,
      name: "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
      message_format_version: 2,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha512,
      kdf_input_length: 32,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 32,
      commitment_length: 32
    }
  end

  @doc """
  Returns the AES_256_GCM_HKDF_SHA512_COMMIT_KEY suite (0x0478).

  A committed suite without message signing:
  - AES-256-GCM encryption
  - HKDF-SHA512 key derivation with 32-byte input
  - Key commitment (32 bytes)
  - No message signing
  """
  @spec aes_256_gcm_hkdf_sha512_commit_key() :: t()
  def aes_256_gcm_hkdf_sha512_commit_key do
    %__MODULE__{
      id: @aes_256_gcm_hkdf_sha512_commit_key,
      name: "AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
      message_format_version: 2,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha512,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 32,
      commitment_length: 32
    }
  end

  @doc """
  Returns the AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 suite (0x0378).

  A legacy suite with message signing (no commitment):
  - AES-256-GCM encryption
  - HKDF-SHA384 key derivation
  - No key commitment
  - ECDSA P-384 message signing
  """
  @spec aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384() :: t()
  def aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384,
      name: "AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha384,
      kdf_input_length: 32,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_256_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0178).

  A common legacy suite without signing or commitment:
  - AES-256-GCM encryption
  - HKDF-SHA256 key derivation
  - No key commitment
  - No message signing
  """
  @spec aes_256_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_256_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_256_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] Credo passes: `mix credo --strict`

#### Manual Verification:
- [x] In IEx, `AwsEncryptionSdk.AlgorithmSuite.default()` returns correct struct
- [x] In IEx, `AwsEncryptionSdk.AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key().id == 0x0478`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 3: Lookup & Predicate Functions

### Overview
Add `by_id/1` lookup function and predicate functions (`committed?/1`, `signed?/1`, `allows_encryption?/1`, `deprecated?/1`). Include deprecation warnings for NO_KDF suites.

### Spec Requirements Addressed
- Reserved ID `0x0000` must not be accepted
- Signatures only for suites with signature algorithm specified
- NO_KDF suites are deprecated and should only be used for decryption

### Changes Required:

#### 1. Add lookup and predicate functions
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add functions after the suite definition functions

```elixir
  @doc """
  Looks up an algorithm suite by its ID.

  Returns `{:ok, suite}` if found, or `{:error, reason}` if the ID is invalid
  or reserved.

  ## Examples

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x0578)
      {:ok, %AwsEncryptionSdk.AlgorithmSuite{id: 0x0578, ...}}

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x0000)
      {:error, :reserved_suite_id}

      iex> AwsEncryptionSdk.AlgorithmSuite.by_id(0x9999)
      {:error, :unknown_suite_id}

  Note: Accessing deprecated suites (NO_KDF) will log a warning.
  """
  @spec by_id(suite_id()) :: {:ok, t()} | {:error, :reserved_suite_id | :unknown_suite_id}
  def by_id(0x0000), do: {:error, :reserved_suite_id}

  def by_id(@aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384) do
    {:ok, aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()}
  end

  def by_id(@aes_256_gcm_hkdf_sha512_commit_key) do
    {:ok, aes_256_gcm_hkdf_sha512_commit_key()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384) do
    {:ok, aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_256_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(_id), do: {:error, :unknown_suite_id}

  @doc """
  Returns true if the suite uses key commitment.

  Committed suites (0x0478, 0x0578) use message format version 2 and include
  a 32-byte commitment value that binds the data key to the message.
  """
  @spec committed?(t()) :: boolean()
  def committed?(%__MODULE__{commitment_length: length}), do: length > 0

  @doc """
  Returns true if the suite uses message signing.

  Signed suites include an ECDSA signature in the message footer that
  authenticates the entire message.
  """
  @spec signed?(t()) :: boolean()
  def signed?(%__MODULE__{signature_algorithm: nil}), do: false
  def signed?(%__MODULE__{signature_algorithm: _}), do: true

  @doc """
  Returns true if the suite can be used for encryption.

  Deprecated suites (NO_KDF) should only be used for decryption of existing
  messages, not for encrypting new messages.
  """
  @spec allows_encryption?(t()) :: boolean()
  def allows_encryption?(%__MODULE__{} = suite), do: not deprecated?(suite)

  @doc """
  Returns true if the suite is deprecated.

  Deprecated suites are the NO_KDF suites (0x0014, 0x0046, 0x0078) which do not
  use key derivation. These should only be used for decrypting legacy messages.
  """
  @spec deprecated?(t()) :: boolean()
  def deprecated?(%__MODULE__{kdf_type: :identity}), do: true
  def deprecated?(%__MODULE__{kdf_type: _}), do: false
```

#### 2. Add test file
**File**: `test/aws_encryption_sdk/algorithm_suite_test.exs`
**Changes**: Create comprehensive test file

```elixir
defmodule AwsEncryptionSdk.AlgorithmSuiteTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite

  describe "default/0" do
    test "returns the recommended suite 0x0578" do
      suite = AlgorithmSuite.default()

      assert suite.id == 0x0578
      assert suite.name == "AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"
      assert suite.message_format_version == 2
      assert suite.encryption_algorithm == :aes_256_gcm
      assert suite.data_key_length == 256
      assert suite.kdf_type == :hkdf
      assert suite.kdf_hash == :sha512
      assert suite.signature_algorithm == :ecdsa_p384
      assert suite.commitment_length == 32
    end
  end

  describe "by_id/1" do
    test "returns error for reserved ID 0x0000" do
      assert {:error, :reserved_suite_id} = AlgorithmSuite.by_id(0x0000)
    end

    test "returns error for unknown ID" do
      assert {:error, :unknown_suite_id} = AlgorithmSuite.by_id(0x9999)
    end

    test "returns committed suite 0x0578" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert suite.id == 0x0578
      assert suite.commitment_length == 32
    end

    test "returns committed suite 0x0478" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      assert suite.id == 0x0478
      assert suite.commitment_length == 32
      assert suite.signature_algorithm == nil
    end

    test "returns legacy suite 0x0378" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      assert suite.id == 0x0378
      assert suite.message_format_version == 1
      assert suite.signature_algorithm == :ecdsa_p384
    end

    test "returns legacy suite 0x0178" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      assert suite.id == 0x0178
      assert suite.kdf_hash == :sha256
      assert suite.signature_algorithm == nil
    end
  end

  describe "committed?/1" do
    test "returns true for committed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert AlgorithmSuite.committed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      assert AlgorithmSuite.committed?(suite)
    end

    test "returns false for non-committed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      refute AlgorithmSuite.committed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      refute AlgorithmSuite.committed?(suite)
    end
  end

  describe "signed?/1" do
    test "returns true for signed suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      assert AlgorithmSuite.signed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0378)
      assert AlgorithmSuite.signed?(suite)
    end

    test "returns false for unsigned suites" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0478)
      refute AlgorithmSuite.signed?(suite)

      assert {:ok, suite} = AlgorithmSuite.by_id(0x0178)
      refute AlgorithmSuite.signed?(suite)
    end
  end

  describe "allows_encryption?/1 and deprecated?/1" do
    test "non-deprecated suites allow encryption" do
      assert {:ok, suite} = AlgorithmSuite.by_id(0x0578)
      refute AlgorithmSuite.deprecated?(suite)
      assert AlgorithmSuite.allows_encryption?(suite)
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test`
- [x] Credo passes: `mix credo --strict`

#### Manual Verification:
- [x] In IEx, `AwsEncryptionSdk.AlgorithmSuite.by_id(0x0000)` returns `{:error, :reserved_suite_id}`
- [x] In IEx, predicates work on returned suites

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 4: Remaining Suite Definitions

### Overview
Add the remaining 7 ESDK suites: 128/192-bit HKDF variants and deprecated NO_KDF suites. Include deprecation warnings for NO_KDF suites.

### Spec Requirements Addressed
- Identity KDF must return input unchanged (NO_KDF suites)
- 192-bit key support for AES-192-GCM
- 128-bit key support for AES-128-GCM
- ECDSA P-256 for 128-bit signed suite

### Changes Required:

#### 1. Add remaining suite ID constants
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add module attributes after existing suite ID constants

```elixir
  # Additional HKDF suites (192-bit and 128-bit)
  @aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 0x0346
  @aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256 0x0214
  @aes_192_gcm_iv12_tag16_hkdf_sha256 0x0146
  @aes_128_gcm_iv12_tag16_hkdf_sha256 0x0114

  # Deprecated NO_KDF suites (decrypt only)
  @aes_256_gcm_iv12_tag16_no_kdf 0x0078
  @aes_192_gcm_iv12_tag16_no_kdf 0x0046
  @aes_128_gcm_iv12_tag16_no_kdf 0x0014
```

#### 2. Add HKDF suite functions (192-bit and 128-bit)
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add after existing suite functions

```elixir
  @doc """
  Returns the AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 suite (0x0346).

  A legacy 192-bit suite with message signing.
  """
  @spec aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384() :: t()
  def aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384 do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384,
      name: "AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha384,
      kdf_input_length: 24,
      signature_algorithm: :ecdsa_p384,
      signature_hash: :sha384,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 suite (0x0214).

  A legacy 128-bit suite with ECDSA P-256 message signing.
  """
  @spec aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256() :: t()
  def aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256 do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256,
      name: "AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 16,
      signature_algorithm: :ecdsa_p256,
      signature_hash: :sha256,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_192_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0146).

  A legacy 192-bit suite without message signing.
  """
  @spec aes_192_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_192_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_192_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 24,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_HKDF_SHA256 suite (0x0114).

  A legacy 128-bit suite without message signing.
  """
  @spec aes_128_gcm_iv12_tag16_hkdf_sha256() :: t()
  def aes_128_gcm_iv12_tag16_hkdf_sha256 do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_hkdf_sha256,
      name: "AES_128_GCM_IV12_TAG16_HKDF_SHA256",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :hkdf,
      kdf_hash: :sha256,
      kdf_input_length: 16,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end
```

#### 3. Add deprecated NO_KDF suite functions with warnings
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add after HKDF suite functions

```elixir
  @doc """
  Returns the AES_256_GCM_IV12_TAG16_NO_KDF suite (0x0078).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_256_gcm_iv12_tag16_no_kdf() :: t()
  def aes_256_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_256_gcm_iv12_tag16_no_kdf,
      name: "AES_256_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_256_gcm,
      data_key_length: 256,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 32,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_192_GCM_IV12_TAG16_NO_KDF suite (0x0046).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_192_gcm_iv12_tag16_no_kdf() :: t()
  def aes_192_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_192_gcm_iv12_tag16_no_kdf,
      name: "AES_192_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_192_gcm,
      data_key_length: 192,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 24,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end

  @doc """
  Returns the AES_128_GCM_IV12_TAG16_NO_KDF suite (0x0014).

  **DEPRECATED**: This suite does not use key derivation and should only be used
  for decrypting legacy messages. Use a committed suite for new encryptions.
  """
  @spec aes_128_gcm_iv12_tag16_no_kdf() :: t()
  def aes_128_gcm_iv12_tag16_no_kdf do
    %__MODULE__{
      id: @aes_128_gcm_iv12_tag16_no_kdf,
      name: "AES_128_GCM_IV12_TAG16_NO_KDF",
      message_format_version: 1,
      encryption_algorithm: :aes_128_gcm,
      data_key_length: 128,
      iv_length: 12,
      auth_tag_length: 16,
      kdf_type: :identity,
      kdf_hash: nil,
      kdf_input_length: 16,
      signature_algorithm: nil,
      signature_hash: nil,
      suite_data_length: 0,
      commitment_length: 0
    }
  end
```

#### 4. Update by_id/1 with remaining suites and deprecation warnings
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add clauses to `by_id/1` before the catch-all clause

```elixir
  def by_id(@aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384) do
    {:ok, aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256) do
    {:ok, aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()}
  end

  def by_id(@aes_192_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_192_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_hkdf_sha256) do
    {:ok, aes_128_gcm_iv12_tag16_hkdf_sha256()}
  end

  def by_id(@aes_256_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_256_gcm_iv12_tag16_no_kdf)
    {:ok, aes_256_gcm_iv12_tag16_no_kdf()}
  end

  def by_id(@aes_192_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_192_gcm_iv12_tag16_no_kdf)
    {:ok, aes_192_gcm_iv12_tag16_no_kdf()}
  end

  def by_id(@aes_128_gcm_iv12_tag16_no_kdf) do
    log_deprecation_warning(@aes_128_gcm_iv12_tag16_no_kdf)
    {:ok, aes_128_gcm_iv12_tag16_no_kdf()}
  end
```

#### 5. Add deprecation warning helper
**File**: `lib/aws_encryption_sdk/algorithm_suite.ex`
**Changes**: Add private function at the end of the module

```elixir
  @spec log_deprecation_warning(suite_id()) :: :ok
  defp log_deprecation_warning(suite_id) do
    Logger.warning(
      "Algorithm suite 0x#{Integer.to_string(suite_id, 16)} (NO_KDF) is deprecated. " <>
        "Use a committed algorithm suite for new encryptions."
    )
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Tests pass: `mix test`
- [x] Credo passes: `mix credo --strict`

#### Manual Verification:
- [x] In IEx, `AwsEncryptionSdk.AlgorithmSuite.by_id(0x0014)` logs a warning and returns the suite
- [x] In IEx, deprecated suites return `deprecated?: true` and `allows_encryption?: false`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 5: Complete Tests & Validation

### Overview
Add comprehensive tests covering all 11 suites, all predicates, and edge cases. Ensure full test coverage.

### Changes Required:

#### 1. Expand test file with complete coverage
**File**: `test/aws_encryption_sdk/algorithm_suite_test.exs`
**Changes**: Add additional test cases

```elixir
  # Add to existing test file

  describe "all ESDK suites" do
    @all_suite_ids [
      0x0578,
      0x0478,
      0x0378,
      0x0346,
      0x0214,
      0x0178,
      0x0146,
      0x0114,
      0x0078,
      0x0046,
      0x0014
    ]

    test "all 11 ESDK suites are accessible via by_id/1" do
      for suite_id <- @all_suite_ids do
        assert {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert suite.id == suite_id
      end
    end

    test "all suites have required fields" do
      for suite_id <- @all_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)

        assert is_integer(suite.id)
        assert is_binary(suite.name)
        assert suite.message_format_version in [1, 2]
        assert suite.encryption_algorithm in [:aes_128_gcm, :aes_192_gcm, :aes_256_gcm]
        assert suite.data_key_length in [128, 192, 256]
        assert suite.iv_length == 12
        assert suite.auth_tag_length == 16
        assert suite.kdf_type in [:hkdf, :identity]
      end
    end

    test "all suites have consistent iv_length of 12" do
      for suite_id <- @all_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert suite.iv_length == 12
      end
    end

    test "all suites have consistent auth_tag_length of 16" do
      for suite_id <- @all_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert suite.auth_tag_length == 16
      end
    end
  end

  describe "committed suites" do
    @committed_suite_ids [0x0578, 0x0478]

    test "only 0x0578 and 0x0478 are committed" do
      for suite_id <- @committed_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert AlgorithmSuite.committed?(suite)
        assert suite.commitment_length == 32
        assert suite.suite_data_length == 32
        assert suite.message_format_version == 2
      end
    end
  end

  describe "signed suites" do
    @signed_suite_ids [0x0578, 0x0378, 0x0346, 0x0214]
    @unsigned_suite_ids [0x0478, 0x0178, 0x0146, 0x0114, 0x0078, 0x0046, 0x0014]

    test "signed suites have signature algorithm" do
      for suite_id <- @signed_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert AlgorithmSuite.signed?(suite)
        assert suite.signature_algorithm in [:ecdsa_p256, :ecdsa_p384]
        assert suite.signature_hash in [:sha256, :sha384]
      end
    end

    test "unsigned suites have no signature algorithm" do
      for suite_id <- @unsigned_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        refute AlgorithmSuite.signed?(suite)
        assert suite.signature_algorithm == nil
        assert suite.signature_hash == nil
      end
    end
  end

  describe "deprecated (NO_KDF) suites" do
    @deprecated_suite_ids [0x0078, 0x0046, 0x0014]
    @non_deprecated_suite_ids [0x0578, 0x0478, 0x0378, 0x0346, 0x0214, 0x0178, 0x0146, 0x0114]

    test "NO_KDF suites are deprecated" do
      for suite_id <- @deprecated_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert AlgorithmSuite.deprecated?(suite)
        refute AlgorithmSuite.allows_encryption?(suite)
        assert suite.kdf_type == :identity
        assert suite.kdf_hash == nil
      end
    end

    test "HKDF suites are not deprecated" do
      for suite_id <- @non_deprecated_suite_ids do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        refute AlgorithmSuite.deprecated?(suite)
        assert AlgorithmSuite.allows_encryption?(suite)
        assert suite.kdf_type == :hkdf
        assert suite.kdf_hash != nil
      end
    end

    import ExUnit.CaptureLog

    test "accessing deprecated suite logs warning" do
      log =
        capture_log(fn ->
          {:ok, _suite} = AlgorithmSuite.by_id(0x0014)
        end)

      assert log =~ "deprecated"
      assert log =~ "0x14"
    end
  end

  describe "data key length consistency" do
    test "encryption algorithm matches data_key_length" do
      {:ok, suite_256} = AlgorithmSuite.by_id(0x0578)
      assert suite_256.encryption_algorithm == :aes_256_gcm
      assert suite_256.data_key_length == 256

      {:ok, suite_192} = AlgorithmSuite.by_id(0x0346)
      assert suite_192.encryption_algorithm == :aes_192_gcm
      assert suite_192.data_key_length == 192

      {:ok, suite_128} = AlgorithmSuite.by_id(0x0214)
      assert suite_128.encryption_algorithm == :aes_128_gcm
      assert suite_128.data_key_length == 128
    end

    test "kdf_input_length matches data_key_length in bytes" do
      for suite_id <- [0x0578, 0x0478, 0x0378, 0x0178, 0x0078] do
        {:ok, suite} = AlgorithmSuite.by_id(suite_id)
        assert suite.kdf_input_length == div(suite.data_key_length, 8)
      end
    end
  end

  describe "direct suite functions" do
    test "each suite has a direct accessor function" do
      assert AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384().id == 0x0578
      assert AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key().id == 0x0478
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384().id == 0x0378
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_hkdf_sha384_ecdsa_p384().id == 0x0346
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256().id == 0x0214
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256().id == 0x0178
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_hkdf_sha256().id == 0x0146
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256().id == 0x0114
      assert AlgorithmSuite.aes_256_gcm_iv12_tag16_no_kdf().id == 0x0078
      assert AlgorithmSuite.aes_192_gcm_iv12_tag16_no_kdf().id == 0x0046
      assert AlgorithmSuite.aes_128_gcm_iv12_tag16_no_kdf().id == 0x0014
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] Full test suite passes: `mix quality`
- [x] All 11 suites tested
- [x] All predicates tested
- [x] Deprecation warning logging tested

#### Manual Verification:
- [x] Review test output shows all tests passing
- [x] No Credo warnings or errors

**Implementation Note**: After completing this phase and all automated verification passes, pause here for final manual confirmation.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full quality suite: `mix quality`
- [x] All tests pass with good coverage (26 tests, 100% coverage)

### Manual:
- [x] Load module in IEx and test `default/0`, `by_id/1`, predicates
- [x] Verify deprecation warning appears for NO_KDF suites
- [x] Verify all 11 suites are accessible

## Testing Strategy

### Unit Tests:
- All 11 suite IDs return correct structs
- Reserved ID 0x0000 returns error
- Unknown IDs return error
- Predicates return correct values for all suites
- Deprecation warnings are logged for NO_KDF suites

### Property-Based Tests (future):
- Could use StreamData to verify struct field constraints

### Manual Testing Steps:
1. `iex -S mix`
2. `AwsEncryptionSdk.AlgorithmSuite.default()` - verify returns 0x0578 suite
3. `AwsEncryptionSdk.AlgorithmSuite.by_id(0x0014)` - verify warning logged and suite returned
4. Test predicates on various suites

## References

- Issue: #7
- Research: `thoughts/shared/research/2026-01-24-GH7-algorithm-suite-definitions.md`
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- AWS Docs: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
