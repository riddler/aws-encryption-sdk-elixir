# HKDF Key Derivation Implementation Plan

## Overview

Implement HKDF (HMAC-based Key Derivation Function) per RFC 5869 for key derivation in encryption operations. HKDF is required by 8 of 11 algorithm suites for deriving data encryption keys and commitment keys from plaintext data keys.

**Issue**: #8
**Research**: `thoughts/shared/research/2026-01-24-GH8-hkdf-key-derivation.md`

## Specification Requirements

### Source Documents
- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869) - Base HKDF specification
- [Algorithm Suites Spec](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md) - KDF parameters per suite

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| HKDF-Extract: `PRK = HMAC-Hash(salt, IKM)` | RFC 5869 §2.2 | MUST |
| HKDF-Expand: Iterative HMAC with counter | RFC 5869 §2.3 | MUST |
| Output length limit: `L <= 255 * HashLen` | RFC 5869 §2.3 | MUST |
| Support SHA-256, SHA-384, SHA-512 | algorithm-suites.md | MUST |
| Empty salt uses HashLen zero bytes | RFC 5869 §2.2 | MUST |

## Test Vectors

### Validation Strategy
Each phase uses specific test vectors from RFC 5869 and Wycheproof to validate correctness.

### Test Vector Summary
| Phase | Test Vectors | Purpose |
|-------|--------------|---------|
| 1 | RFC 5869 Test 1 | Basic SHA-256 correctness |
| 2 | RFC 5869 Tests 2, 3 | Edge cases (empty salt, long inputs) |
| 3 | Wycheproof SHA-512 | Critical for committed suites (0x0478, 0x0578) |
| 4 | Wycheproof SHA-384, edge cases | Full coverage |

## Current State Analysis

### Existing Code
- `lib/aws_encryption_sdk/algorithm_suite.ex` - Defines `kdf_hash` (`:sha256`, `:sha384`, `:sha512`) directly compatible with `:crypto.mac/4`
- No `lib/aws_encryption_sdk/crypto/` directory exists yet

### Key Discoveries
- Hash atoms from algorithm suites can be passed directly to Erlang `:crypto` functions
- `suite.kdf_input_length` provides input key length in bytes (16, 24, or 32)
- `suite.commitment_length > 0` indicates committed suites needing DERIVEKEY/COMMITKEY labels

### Dependencies
- **Depends on**: Algorithm suite definitions (#7) - ✅ Complete
- **Depended on by**: Encryption/decryption operations, key commitment verification

## Desired End State

After this plan is complete:

1. `lib/aws_encryption_sdk/crypto/hkdf.ex` exists with:
   - `extract/3` - HKDF-Extract step
   - `expand/4` - HKDF-Expand step
   - `derive/5` - Combined Extract-then-Expand

2. All functions support `:sha256`, `:sha384`, `:sha512`

3. Tests pass for:
   - All 3 RFC 5869 SHA-256 test cases
   - Wycheproof SHA-512 test vectors (valid cases)
   - Wycheproof SHA-384 test vectors (valid cases)
   - Edge cases (empty salt, max output length, exceeded length)

4. `mix quality` passes

### Verification
```bash
mix test test/aws_encryption_sdk/crypto/hkdf_test.exs
mix quality
```

## What We're NOT Doing

- **KeyDerivation module**: The research shows a `KeyDerivation` module for AWS ESDK-specific derivation (with DERIVEKEY/COMMITKEY labels). This is a separate concern and will be implemented when needed for encrypt/decrypt operations.
- **Wycheproof invalid test cases**: We'll focus on valid test vectors. Invalid cases test error handling which is straightforward.
- **SHA-1 support**: Not used by any AWS ESDK algorithm suite.

## Implementation Approach

1. Create the crypto directory and HKDF module
2. Implement core functions with proper typespecs
3. Validate incrementally with test vectors
4. Use RFC 5869 vectors first (official), then Wycheproof for extended coverage

---

## Phase 1: Core HKDF Module with Basic SHA-256

### Overview
Create the HKDF module with `extract/3`, `expand/4`, and `derive/5` functions. Validate with RFC 5869 Test Case 1.

### Spec Requirements Addressed
- HKDF-Extract: `PRK = HMAC-Hash(salt, IKM)` (RFC 5869 §2.2)
- HKDF-Expand: Iterative HMAC expansion (RFC 5869 §2.3)
- Output length validation: `L <= 255 * HashLen` (RFC 5869 §2.3)

### Test Vectors for This Phase
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| RFC 5869 Test 1 | Basic SHA-256, 22-byte IKM, 13-byte salt, 10-byte info, 42-byte output | PRK and OKM match expected values |

**RFC 5869 Test Case 1 Values**:
```elixir
hash = :sha256
ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
salt = Base.decode16!("000102030405060708090A0B0C")
info = Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
length = 42

expected_prk = Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
expected_okm = Base.decode16!("3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865")
```

### Changes Required:

#### 1. Create crypto directory
```bash
mkdir -p lib/aws_encryption_sdk/crypto
mkdir -p test/aws_encryption_sdk/crypto
```

#### 2. Create HKDF module
**File**: `lib/aws_encryption_sdk/crypto/hkdf.ex`

```elixir
defmodule AwsEncryptionSdk.Crypto.HKDF do
  @moduledoc """
  HKDF (HMAC-based Key Derivation Function) implementation per RFC 5869.

  HKDF is used by the AWS Encryption SDK to derive data encryption keys and
  commitment keys from plaintext data keys. It consists of two steps:

  1. **Extract**: Takes input keying material (IKM) and an optional salt,
     producing a pseudorandom key (PRK)
  2. **Expand**: Takes the PRK and optional context info, producing output
     keying material (OKM) of the desired length

  ## Supported Hash Algorithms

  - `:sha256` - Used by algorithm suites 0x0114, 0x0146, 0x0178, 0x0214
  - `:sha384` - Used by algorithm suites 0x0346, 0x0378
  - `:sha512` - Used by committed suites 0x0478, 0x0578

  ## References

  - [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
  - [AWS Encryption SDK Algorithm Suites](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md)
  """

  @typedoc "Supported hash algorithms for HKDF operations"
  @type hash :: :sha256 | :sha384 | :sha512

  @hash_lengths %{
    sha256: 32,
    sha384: 48,
    sha512: 64
  }

  @doc """
  HKDF-Extract: Extract a pseudorandom key from input keying material.

  Per RFC 5869 Section 2.2:
  ```
  PRK = HMAC-Hash(salt, IKM)
  ```

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `salt` - Optional salt value (non-secret random value). If `nil` or empty
    binary, defaults to a string of `HashLen` zero bytes.
  - `ikm` - Input keying material

  ## Returns

  The pseudorandom key (PRK) as a binary of `HashLen` bytes.

  ## Examples

      iex> prk = AwsEncryptionSdk.Crypto.HKDF.extract(:sha256, <<0, 1, 2>>, <<0x0b::8, 0x0b::8>>)
      iex> byte_size(prk)
      32
  """
  @spec extract(hash(), binary() | nil, binary()) :: binary()
  def extract(hash, salt, ikm) when hash in [:sha256, :sha384, :sha512] do
    effective_salt = effective_salt(hash, salt)
    :crypto.mac(:hmac, hash, effective_salt, ikm)
  end

  @doc """
  HKDF-Expand: Expand a pseudorandom key to the desired length.

  Per RFC 5869 Section 2.3:
  ```
  N = ceil(L/HashLen)
  T = T(1) | T(2) | T(3) | ... | T(N)
  OKM = first L octets of T

  where:
  T(0) = empty string
  T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
  ```

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `prk` - Pseudorandom key (typically output from `extract/3`)
  - `info` - Optional context and application specific information (can be empty)
  - `length` - Desired output length in bytes (must be <= 255 * HashLen)

  ## Returns

  - `{:ok, okm}` - Output keying material of the requested length
  - `{:error, :output_length_exceeded}` - If length > 255 * HashLen

  ## Examples

      iex> prk = :crypto.strong_rand_bytes(32)
      iex> {:ok, okm} = AwsEncryptionSdk.Crypto.HKDF.expand(:sha256, prk, "context", 32)
      iex> byte_size(okm)
      32
  """
  @spec expand(hash(), binary(), binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :output_length_exceeded}
  def expand(hash, prk, info, length)
      when hash in [:sha256, :sha384, :sha512] and is_binary(prk) and is_binary(info) and
             is_integer(length) and length >= 0 do
    hash_len = @hash_lengths[hash]
    max_length = 255 * hash_len

    if length > max_length do
      {:error, :output_length_exceeded}
    else
      okm = do_expand(hash, prk, info, length, hash_len)
      {:ok, okm}
    end
  end

  @doc """
  Combined HKDF: Extract-then-Expand in a single call.

  This is the standard way to use HKDF - it combines the extract and expand
  steps for convenience.

  ## Parameters

  - `hash` - Hash algorithm (`:sha256`, `:sha384`, or `:sha512`)
  - `ikm` - Input keying material
  - `salt` - Optional salt value (if `nil` or empty, uses HashLen zero bytes)
  - `info` - Optional context and application specific information
  - `length` - Desired output length in bytes

  ## Returns

  - `{:ok, okm}` - Output keying material of the requested length
  - `{:error, :output_length_exceeded}` - If length > 255 * HashLen

  ## Examples

      iex> ikm = :crypto.strong_rand_bytes(32)
      iex> {:ok, key} = AwsEncryptionSdk.Crypto.HKDF.derive(:sha256, ikm, nil, "label", 32)
      iex> byte_size(key)
      32
  """
  @spec derive(hash(), binary(), binary() | nil, binary(), non_neg_integer()) ::
          {:ok, binary()} | {:error, :output_length_exceeded}
  def derive(hash, ikm, salt, info, length)
      when hash in [:sha256, :sha384, :sha512] and is_binary(ikm) and is_binary(info) and
             is_integer(length) and length >= 0 do
    prk = extract(hash, salt, ikm)
    expand(hash, prk, info, length)
  end

  @doc """
  Returns the output length in bytes for a given hash algorithm.

  ## Examples

      iex> AwsEncryptionSdk.Crypto.HKDF.hash_length(:sha256)
      32

      iex> AwsEncryptionSdk.Crypto.HKDF.hash_length(:sha512)
      64
  """
  @spec hash_length(hash()) :: pos_integer()
  def hash_length(:sha256), do: 32
  def hash_length(:sha384), do: 48
  def hash_length(:sha512), do: 64

  # Private functions

  @spec effective_salt(hash(), binary() | nil) :: binary()
  defp effective_salt(hash, nil), do: :binary.copy(<<0>>, @hash_lengths[hash])
  defp effective_salt(hash, <<>>), do: :binary.copy(<<0>>, @hash_lengths[hash])
  defp effective_salt(_hash, salt) when is_binary(salt), do: salt

  @spec do_expand(hash(), binary(), binary(), non_neg_integer(), pos_integer()) :: binary()
  defp do_expand(_hash, _prk, _info, 0, _hash_len), do: <<>>

  defp do_expand(hash, prk, info, length, hash_len) do
    iterations = ceil(length / hash_len)

    {_last_t, okm} =
      Enum.reduce(1..iterations, {<<>>, <<>>}, fn i, {prev_t, acc} ->
        # T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
        t = :crypto.mac(:hmac, hash, prk, [prev_t, info, <<i::8>>])
        {t, <<acc::binary, t::binary>>}
      end)

    binary_part(okm, 0, length)
  end
end
```

#### 3. Create test file
**File**: `test/aws_encryption_sdk/crypto/hkdf_test.exs`

```elixir
defmodule AwsEncryptionSdk.Crypto.HKDFTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.HKDF

  describe "hash_length/1" do
    test "returns 32 for sha256" do
      assert HKDF.hash_length(:sha256) == 32
    end

    test "returns 48 for sha384" do
      assert HKDF.hash_length(:sha384) == 48
    end

    test "returns 64 for sha512" do
      assert HKDF.hash_length(:sha512) == 64
    end
  end

  describe "RFC 5869 Test Case 1 (SHA-256 basic)" do
    # Test Case 1 from RFC 5869 Appendix A.1
    @ikm Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
    @salt Base.decode16!("000102030405060708090A0B0C")
    @info Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
    @length 42

    @expected_prk Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
    @expected_okm Base.decode16!(
                    "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865"
                  )

    test "extract/3 produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "expand/4 produces correct OKM" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 produces correct OKM (combined extract-then-expand)" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix compile` succeeds with no warnings
- [x] `mix test test/aws_encryption_sdk/crypto/hkdf_test.exs` passes
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] In IEx, verify `HKDF.extract(:sha256, salt, ikm)` returns expected PRK
- [x] In IEx, verify `HKDF.derive(:sha256, ikm, salt, info, 42)` returns expected OKM

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 2: SHA-256 Edge Cases (RFC 5869 Tests 2 & 3)

### Overview
Add remaining RFC 5869 SHA-256 test cases to validate edge cases: empty salt/info and longer inputs requiring multiple expand iterations.

### Spec Requirements Addressed
- Empty salt uses HashLen zero bytes (RFC 5869 §2.2)
- Multi-iteration expand works correctly (RFC 5869 §2.3)

### Test Vectors for This Phase
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| RFC 5869 Test 2 | Long inputs (80 bytes each), 82-byte output | OKM matches expected |
| RFC 5869 Test 3 | Empty salt, empty info, 42-byte output | OKM matches expected (uses zero salt internally) |

**RFC 5869 Test Case 2 Values** (longer inputs):
```elixir
hash = :sha256
ikm = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F")
salt = Base.decode16!("606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF")
info = Base.decode16!("B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF")
length = 82

expected_prk = Base.decode16!("06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244")
expected_okm = Base.decode16!("B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87")
```

**RFC 5869 Test Case 3 Values** (empty salt and info):
```elixir
hash = :sha256
ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
salt = <<>>  # Empty - should use 32 zero bytes internally
info = <<>>  # Empty
length = 42

expected_prk = Base.decode16!("19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04")
expected_okm = Base.decode16!("8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8")
```

### Changes Required:

#### 1. Add test cases to test file
**File**: `test/aws_encryption_sdk/crypto/hkdf_test.exs`
**Changes**: Add two new describe blocks for Test Cases 2 and 3

```elixir
  describe "RFC 5869 Test Case 2 (SHA-256 longer inputs)" do
    # Test Case 2 from RFC 5869 Appendix A.2
    # Tests longer inputs (80 bytes each) and output requiring 3 iterations
    @ikm Base.decode16!(
           "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F"
         )
    @salt Base.decode16!(
            "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAF"
          )
    @info Base.decode16!(
            "B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF"
          )
    @length 82

    @expected_prk Base.decode16!(
                    "06A6B88C5853361A06104C9CEB35B45CEF760014904671014A193F40C15FC244"
                  )
    @expected_okm Base.decode16!(
                    "B11E398DC80327A1C8E7F78C596A49344F012EDA2D4EFAD8A050CC4C19AFA97C59045A99CAC7827271CB41C65E590E09DA3275600C2F09B8367793A9ACA3DB71CC30C58179EC3E87C14C01D5C1F3434F1D87"
                  )

    test "extract/3 produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "expand/4 produces correct OKM (requires 3 iterations)" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
      # Verify length: 82 bytes requires ceil(82/32) = 3 iterations
      assert byte_size(okm) == 82
    end

    test "derive/5 produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end
  end

  describe "RFC 5869 Test Case 3 (SHA-256 empty salt and info)" do
    # Test Case 3 from RFC 5869 Appendix A.3
    # Tests zero-length salt and info
    @ikm Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
    @salt <<>>
    @info <<>>
    @length 42

    @expected_prk Base.decode16!(
                    "19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04"
                  )
    @expected_okm Base.decode16!(
                    "8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8"
                  )

    test "extract/3 with empty salt produces correct PRK" do
      prk = HKDF.extract(:sha256, @salt, @ikm)
      assert prk == @expected_prk
    end

    test "extract/3 with nil salt produces same PRK as empty salt" do
      prk_empty = HKDF.extract(:sha256, <<>>, @ikm)
      prk_nil = HKDF.extract(:sha256, nil, @ikm)
      assert prk_empty == prk_nil
      assert prk_empty == @expected_prk
    end

    test "expand/4 with empty info produces correct OKM" do
      {:ok, okm} = HKDF.expand(:sha256, @expected_prk, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 with empty salt and info produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, @salt, @info, @length)
      assert okm == @expected_okm
    end

    test "derive/5 with nil salt produces correct OKM" do
      {:ok, okm} = HKDF.derive(:sha256, @ikm, nil, @info, @length)
      assert okm == @expected_okm
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test test/aws_encryption_sdk/crypto/hkdf_test.exs` passes (all 3 test cases)
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] In IEx, verify `HKDF.derive(:sha256, ikm, nil, <<>>, 42)` works with empty salt/info

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 3: SHA-512 Support (Critical for Committed Suites)

### Overview
Add SHA-512 test coverage using Wycheproof test vectors. SHA-512 is critical because committed algorithm suites (0x0478, 0x0578) use HKDF-SHA512.

### Spec Requirements Addressed
- SHA-512 support for committed suites (algorithm-suites.md)

### Test Vectors for This Phase
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| Wycheproof SHA-512 tcId 1 | Empty salt, 20-byte output | OKM matches |
| Wycheproof SHA-512 tcId 2 | Empty salt, 42-byte output | OKM matches |
| Wycheproof SHA-512 tcId 3 | Empty salt, 64-byte output (single iteration) | OKM matches |

**Wycheproof SHA-512 Test Values**:
```elixir
# tcId 1
hash = :sha512
ikm = Base.decode16!("24AEFF2645E3E0F5494A9A102778C43A", case: :lower)
salt = <<>>
info = <<>>
length = 20
expected_okm = Base.decode16!("DD2599840B09699C6200B5CBA79002B3AA75C61B", case: :lower)

# tcId 2
ikm = Base.decode16!("A23632E18EC76B59B1C87008DA3F8A7E", case: :lower)
salt = <<>>
info = <<>>
length = 42
expected_okm = Base.decode16!("C4AF93D4BAE9CA2B45F590CD3D2F539FF5749D7B0864FBE44A438D38A2F8E5AFE01641145E389C989766", case: :lower)

# tcId 3
ikm = Base.decode16!("A4748031A14D3E6AAFE42AA20C568F5F", case: :lower)
salt = <<>>
info = <<>>
length = 64
expected_okm = Base.decode16!("62EA97E06051E40B79DEB127A4DA294F557CAFA3D7A90A75C02064571DFBBE4699129BDCEC4B39EED7757CE8E3571589F7D8F5523C0DC3FD6A56B099FB4BFD51", case: :lower)
```

### Changes Required:

#### 1. Add SHA-512 tests
**File**: `test/aws_encryption_sdk/crypto/hkdf_test.exs`
**Changes**: Add describe block for SHA-512 tests

```elixir
  describe "SHA-512 support (Wycheproof vectors)" do
    # SHA-512 is critical for committed algorithm suites 0x0478 and 0x0578
    # Test vectors from Wycheproof hkdf_sha512_test.json

    test "tcId 1: empty salt, 20-byte output" do
      ikm = Base.decode16!("24AEFF2645E3E0F5494A9A102778C43A", case: :lower)
      expected_okm = Base.decode16!("DD2599840B09699C6200B5CBA79002B3AA75C61B", case: :lower)

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 20)
      assert okm == expected_okm
    end

    test "tcId 2: empty salt, 42-byte output" do
      ikm = Base.decode16!("A23632E18EC76B59B1C87008DA3F8A7E", case: :lower)
      expected_okm =
        Base.decode16!(
          "C4AF93D4BAE9CA2B45F590CD3D2F539FF5749D7B0864FBE44A438D38A2F8E5AFE01641145E389C989766",
          case: :lower
        )

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 42)
      assert okm == expected_okm
    end

    test "tcId 3: empty salt, 64-byte output (single iteration max)" do
      ikm = Base.decode16!("A4748031A14D3E6AAFE42AA20C568F5F", case: :lower)
      expected_okm =
        Base.decode16!(
          "62EA97E06051E40B79DEB127A4DA294F557CAFA3D7A90A75C02064571DFBBE4699129BDCEC4B39EED7757CE8E3571589F7D8F5523C0DC3FD6A56B099FB4BFD51",
          case: :lower
        )

      {:ok, okm} = HKDF.derive(:sha512, ikm, <<>>, <<>>, 64)
      assert okm == expected_okm
      # 64 bytes = exactly one SHA-512 iteration
      assert byte_size(okm) == HKDF.hash_length(:sha512)
    end

    test "extract/3 produces correct PRK length for SHA-512" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(64)

      prk = HKDF.extract(:sha512, salt, ikm)
      assert byte_size(prk) == 64
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test test/aws_encryption_sdk/crypto/hkdf_test.exs` passes (including SHA-512 tests)
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] In IEx, verify `HKDF.derive(:sha512, ikm, nil, <<>>, 32)` produces 32-byte output
- [x] Verify SHA-512 hash length is 64 bytes via `HKDF.hash_length(:sha512)`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Phase 4: SHA-384 Support & Edge Cases

### Overview
Add SHA-384 test coverage and edge case tests (output length exceeded, zero-length output). SHA-384 is used by algorithm suites 0x0346 and 0x0378.

### Spec Requirements Addressed
- SHA-384 support for legacy suites (algorithm-suites.md)
- Output length validation (RFC 5869 §2.3)

### Test Vectors for This Phase
| Test ID | Description | Expected Result |
|---------|-------------|-----------------|
| SHA-384 basic | Empty salt, 32-byte output | OKM correct length |
| Max output length | L = 255 * HashLen | Success |
| Output exceeded | L > 255 * HashLen | `{:error, :output_length_exceeded}` |
| Zero-length output | L = 0 | `{:ok, <<>>}` |

### Changes Required:

#### 1. Add SHA-384 and edge case tests
**File**: `test/aws_encryption_sdk/crypto/hkdf_test.exs`
**Changes**: Add describe blocks for SHA-384 and edge cases

```elixir
  describe "SHA-384 support" do
    # SHA-384 is used by algorithm suites 0x0346 and 0x0378

    test "derive/5 produces correct output length" do
      ikm = :crypto.strong_rand_bytes(32)
      {:ok, okm} = HKDF.derive(:sha384, ikm, nil, <<>>, 32)
      assert byte_size(okm) == 32
    end

    test "extract/3 produces correct PRK length for SHA-384" do
      ikm = :crypto.strong_rand_bytes(32)
      salt = :crypto.strong_rand_bytes(48)

      prk = HKDF.extract(:sha384, salt, ikm)
      assert byte_size(prk) == 48
    end

    test "expand/4 with multiple iterations" do
      prk = :crypto.strong_rand_bytes(48)
      # Request 100 bytes = ceil(100/48) = 3 iterations
      {:ok, okm} = HKDF.expand(:sha384, prk, "info", 100)
      assert byte_size(okm) == 100
    end
  end

  describe "edge cases" do
    test "expand/4 returns error when output length exceeds maximum" do
      prk = :crypto.strong_rand_bytes(32)

      # SHA-256 max: 255 * 32 = 8160
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha256, prk, <<>>, 8161)

      # SHA-384 max: 255 * 48 = 12240
      prk384 = :crypto.strong_rand_bytes(48)
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha384, prk384, <<>>, 12241)

      # SHA-512 max: 255 * 64 = 16320
      prk512 = :crypto.strong_rand_bytes(64)
      assert {:error, :output_length_exceeded} = HKDF.expand(:sha512, prk512, <<>>, 16321)
    end

    test "expand/4 succeeds at maximum output length" do
      prk = :crypto.strong_rand_bytes(32)

      # SHA-256 max: 255 * 32 = 8160
      assert {:ok, okm} = HKDF.expand(:sha256, prk, <<>>, 8160)
      assert byte_size(okm) == 8160
    end

    test "expand/4 with zero length returns empty binary" do
      prk = :crypto.strong_rand_bytes(32)
      assert {:ok, <<>>} = HKDF.expand(:sha256, prk, <<>>, 0)
    end

    test "derive/5 returns error when output length exceeds maximum" do
      ikm = :crypto.strong_rand_bytes(32)
      assert {:error, :output_length_exceeded} = HKDF.derive(:sha256, ikm, nil, <<>>, 8161)
    end

    test "derive/5 with zero length returns empty binary" do
      ikm = :crypto.strong_rand_bytes(32)
      assert {:ok, <<>>} = HKDF.derive(:sha256, ikm, nil, <<>>, 0)
    end

    test "extract/3 with empty IKM succeeds" do
      # RFC 5869 doesn't prohibit empty IKM
      prk = HKDF.extract(:sha256, nil, <<>>)
      assert byte_size(prk) == 32
    end
  end

  describe "algorithm suite compatibility" do
    # Verify HKDF works with parameters from actual algorithm suites

    test "works with suite 0x0578 parameters (SHA-512, 32-byte input)" do
      # AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
      ikm = :crypto.strong_rand_bytes(32)
      message_id = :crypto.strong_rand_bytes(32)

      {:ok, data_key} = HKDF.derive(:sha512, ikm, message_id, "DERIVEKEY", 32)
      {:ok, commit_key} = HKDF.derive(:sha512, ikm, message_id, "COMMITKEY", 32)

      assert byte_size(data_key) == 32
      assert byte_size(commit_key) == 32
      # Keys should be different due to different info
      assert data_key != commit_key
    end

    test "works with suite 0x0178 parameters (SHA-256, 32-byte input)" do
      # AES_256_GCM_IV12_TAG16_HKDF_SHA256
      ikm = :crypto.strong_rand_bytes(32)
      message_id = :crypto.strong_rand_bytes(16)
      # Non-committed suites use algorithm_id || message_id as info
      info = <<0x01, 0x78, message_id::binary>>

      {:ok, data_key} = HKDF.derive(:sha256, ikm, nil, info, 32)
      assert byte_size(data_key) == 32
    end

    test "works with suite 0x0346 parameters (SHA-384, 24-byte input)" do
      # AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
      ikm = :crypto.strong_rand_bytes(24)
      message_id = :crypto.strong_rand_bytes(16)
      info = <<0x03, 0x46, message_id::binary>>

      {:ok, data_key} = HKDF.derive(:sha384, ikm, nil, info, 24)
      assert byte_size(data_key) == 24
    end
  end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test test/aws_encryption_sdk/crypto/hkdf_test.exs` passes (all tests)
- [x] `mix quality` passes (full quality check)

#### Manual Verification:
- [x] In IEx, verify HKDF works with committed suite parameters:
  ```elixir
  ikm = :crypto.strong_rand_bytes(32)
  msg_id = :crypto.strong_rand_bytes(32)
  {:ok, dk} = AwsEncryptionSdk.Crypto.HKDF.derive(:sha512, ikm, msg_id, "DERIVEKEY", 32)
  {:ok, ck} = AwsEncryptionSdk.Crypto.HKDF.derive(:sha512, ikm, msg_id, "COMMITKEY", 32)
  dk != ck  # Should be true
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation from the human that the manual testing was successful before proceeding to the next phase.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All HKDF tests pass: `mix test test/aws_encryption_sdk/crypto/hkdf_test.exs --trace`

### Manual:
- [x] Verify module documentation renders correctly: `mix docs` and check `doc/AwsEncryptionSdk.Crypto.HKDF.html`
- [x] Verify all three hash algorithms work in IEx session

## Testing Strategy

### Unit Tests
- RFC 5869 official test vectors (3 SHA-256 cases)
- Wycheproof vectors for SHA-512 (3 cases)
- SHA-384 length verification
- Edge cases (empty inputs, max length, exceeded length)
- Algorithm suite compatibility tests

### Test Vector Integration
- RFC 5869 vectors validate core correctness
- Wycheproof vectors validate SHA-512 (critical for committed suites)
- Algorithm suite compatibility tests ensure integration readiness

### Manual Testing Steps
1. Start IEx: `iex -S mix`
2. Test basic derive: `AwsEncryptionSdk.Crypto.HKDF.derive(:sha256, <<1,2,3>>, nil, <<>>, 32)`
3. Test all hash algorithms with `hash_length/1`
4. Test committed suite pattern with DERIVEKEY/COMMITKEY labels

## References

- Issue: #8
- Research: `thoughts/shared/research/2026-01-24-GH8-hkdf-key-derivation.md`
- RFC 5869: https://datatracker.ietf.org/doc/html/rfc5869
- Algorithm Suites Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- Wycheproof HKDF: https://github.com/C2SP/wycheproof/blob/master/testvectors_v1/hkdf_sha512_test.json
