# Research: Implement HKDF key derivation (RFC 5869)

**Issue**: #8 - Implement HKDF key derivation (RFC 5869)
**Date**: 2026-01-24
**Status**: Research complete

## Issue Summary

Implement HKDF (HMAC-based Key Derivation Function) per RFC 5869 for key derivation in encryption operations. HKDF is required by most algorithm suites for deriving data encryption keys and commitment keys from plaintext data keys. Erlang's `:crypto` module doesn't provide HKDF directly, so it must be implemented using HMAC primitives.

## Current Implementation State

### Existing Code

- `lib/aws_encryption_sdk/algorithm_suite.ex` - Defines 11 algorithm suites with KDF parameters (`kdf_type`, `kdf_hash`, `kdf_input_length`). Eight suites use HKDF, three use identity KDF (deprecated).
- `test/aws_encryption_sdk/algorithm_suite_test.exs` - Tests algorithm suite definitions including KDF type validation.

### Files to Create

- `lib/aws_encryption_sdk/crypto/hkdf.ex` - HKDF implementation (new)
- `test/aws_encryption_sdk/crypto/hkdf_test.exs` - HKDF tests (new)
- `test/fixtures/wycheproof/` - Wycheproof test vectors (new directory)

### Relevant Patterns

The algorithm suite module provides direct access to KDF parameters:
- `suite.kdf_type` - `:hkdf` or `:identity`
- `suite.kdf_hash` - `:sha256`, `:sha384`, or `:sha512`
- `suite.kdf_input_length` - Key input length in bytes (16, 24, or 32)

Hash algorithm atoms (`:sha256`, `:sha384`, `:sha512`) can be passed directly to `:crypto.mac/4`.

### Dependencies

- **Depends on**: Algorithm suite definitions (#7) - ✅ Complete
- **Depended on by**: Encryption/decryption operations, key commitment verification

## Specification Requirements

### Source Documents

- [RFC 5869 - HKDF](https://datatracker.ietf.org/doc/html/rfc5869) - Base HKDF specification
- [Algorithm Suites Spec](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md) - Algorithm suite definitions
- [Encrypt API Spec](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - HKDF usage during encryption
- [Decrypt API Spec](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - HKDF usage during decryption

### MUST Requirements

1. **HKDF-Extract Implementation** (RFC 5869 Section 2.2)
   > PRK = HMAC-Hash(salt, IKM)

   Implementation: Use `:crypto.mac(:hmac, hash, salt, ikm)`. If salt is empty, use HashLen zero octets.

2. **HKDF-Expand Implementation** (RFC 5869 Section 2.3)
   > T(0) = empty string
   > T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
   > OKM = first L octets of T(1) | T(2) | ... | T(N)

   Implementation: Iterative HMAC expansion with counter byte (1-255).

3. **Output Length Limit** (RFC 5869 Section 2.3)
   > L <= 255 * HashLen

   Implementation: Validate length parameter:
   - SHA-256: max 8160 bytes (255 × 32)
   - SHA-384: max 12240 bytes (255 × 48)
   - SHA-512: max 16320 bytes (255 × 64)

4. **Hash Algorithm Support** (algorithm-suites.md)
   > For committed suites: "The hash function used is SHA-512"

   Implementation: Support `:sha256`, `:sha384`, `:sha512`.

5. **Data Key Derivation - Non-Committed Suites** (algorithms-reference.html)
   > Salt: String of zeros (HashLen bytes)
   > Info: algorithm_id (2 bytes) || message_id (16 bytes)

   Implementation: Use zero salt, construct info from algorithm ID and message ID.

6. **Data Key Derivation - Committed Suites** (algorithms-reference.html)
   > Salt: 256-bit cryptographically secure random value stored in MessageID field
   > Info: algorithm_id (2 bytes) || "DERIVEKEY" (UTF-8 bytes)

   Implementation: Use message ID as salt, append "DERIVEKEY" label to info.

7. **Commit Key Derivation** (decrypt.md)
   > "The commit key MUST be derived from the plaintext data key using the commit key derivation"
   > Info: "COMMITKEY" (UTF-8 bytes)
   > Length: 256 bits (32 bytes)

   Implementation: Use same salt/PRK as data key, different info label.

8. **Commit Key Verification** (decrypt.md)
   > "The derived commit key MUST equal the commit key stored in the message header"

   Implementation: Compare derived commit key with stored value during decryption.

### SHOULD Requirements

1. **Salt Security** (RFC 5869 Section 3.1)
   > Salt values "should not be chosen or manipulated by an attacker"

   Implementation: Use cryptographically secure random for committed suites.

2. **Info Independence** (RFC 5869 Section 3.2)
   > Info parameter should remain "independent of the input key material value IKM"

   Implementation: Use application-specific info (suite ID, labels), not derived from IKM.

### SHOULD NOT Requirements

1. **Don't Skip Extract** (RFC 5869 Section 3.3)
   > For Diffie-Hellman inputs, the extract part "SHOULD NOT be skipped"

   Implementation: Always use full HKDF (extract + expand).

2. **Don't Use PRK Directly** (RFC 5869 Section 3.3)
   > Using PRK directly without expansion "is NOT RECOMMENDED"

   Implementation: Always call expand after extract.

## Algorithm Suite HKDF Parameters

| Suite ID | Name | KDF Hash | Input Length | Commitment |
|----------|------|----------|--------------|------------|
| 0x0578 | AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 | :sha512 | 32 bytes | Yes |
| 0x0478 | AES_256_GCM_HKDF_SHA512_COMMIT_KEY | :sha512 | 32 bytes | Yes |
| 0x0378 | AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | :sha384 | 32 bytes | No |
| 0x0346 | AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | :sha384 | 24 bytes | No |
| 0x0214 | AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256 | :sha256 | 16 bytes | No |
| 0x0178 | AES_256_GCM_IV12_TAG16_HKDF_SHA256 | :sha256 | 32 bytes | No |
| 0x0146 | AES_192_GCM_IV12_TAG16_HKDF_SHA256 | :sha256 | 24 bytes | No |
| 0x0114 | AES_128_GCM_IV12_TAG16_HKDF_SHA256 | :sha256 | 16 bytes | No |

## Test Vectors

### Applicable Test Vector Sources

1. **RFC 5869 Appendix A** - 7 official test vectors (SHA-256, SHA-1)
2. **Wycheproof Project** - Comprehensive test vectors (SHA-256, SHA-384, SHA-512)
3. **AWS ESDK decrypt vectors** - Indirect HKDF validation through full decryption

### Implementation Order

#### Phase 1: Basic SHA-256 (RFC 5869)

| Test ID | Description | Priority |
|---------|-------------|----------|
| RFC 5869 Test 1 | Basic SHA-256 with all parameters | **Start here** |
| RFC 5869 Test 3 | Empty salt and info | **Critical edge case** |
| RFC 5869 Test 2 | Long inputs (80 octets) | Multi-iteration expand |

**RFC 5869 Test Case 1** (implement first):
```elixir
hash = :sha256
ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
salt = Base.decode16!("000102030405060708090A0B0C")
info = Base.decode16!("F0F1F2F3F4F5F6F7F8F9")
length = 42

expected_prk = Base.decode16!("077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5")
expected_okm = Base.decode16!("3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865")
```

**RFC 5869 Test Case 3** (empty salt/info edge case):
```elixir
hash = :sha256
ikm = Base.decode16!("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B")
salt = <<>>  # Empty - should use 32 zero bytes internally
info = <<>>  # Empty
length = 42

expected_prk = Base.decode16!("19EF24A32C717B167F33A91D6F648BDF96596776AFDB6377AC434C1C293CCB04")
expected_okm = Base.decode16!("8DA4E775A563C18F715F802A063C5A31B8A11F5C5EE1879EC3454E5F3C738D2D9D201395FAA4B61A96C8")
```

#### Phase 2: SHA-512 Support (AWS ESDK Critical)

| Test ID | Description | Priority |
|---------|-------------|----------|
| Wycheproof SHA-512 tcId 1 | Empty salt, simple case | **Critical for 0x0478, 0x0578** |
| Wycheproof SHA-512 tcId 2 | Medium output (42 bytes) | Common case |
| Wycheproof SHA-512 tcId 3 | Max single iteration (64 bytes) | Edge case |

**Wycheproof SHA-512 Test 1**:
```elixir
hash = :sha512
ikm = Base.decode16!("24AEFF2645E3E0F5494A9A102778C43A", case: :lower)
salt = <<>>
info = <<>>
length = 20

expected_okm = Base.decode16!("DD2599840B09699C6200B5CBA79002B3AA75C61B", case: :lower)
```

#### Phase 3: SHA-384 Support

| Test ID | Description | Priority |
|---------|-------------|----------|
| Wycheproof SHA-384 valid tests | Full SHA-384 coverage | For suite 0x0378, 0x0346 |

#### Phase 4: Edge Cases

| Test ID | Description | Expected |
|---------|-------------|----------|
| Max output length | L = 255 * HashLen | Success |
| Output length exceeded | L > 255 * HashLen | Error |
| Zero-length IKM | ikm = <<>> | Success (RFC allows) |
| Invalid tests | Wycheproof invalid cases | Error |

### Test Vector Downloads

```bash
# Create test fixtures directory
mkdir -p test/fixtures/wycheproof

# Download Wycheproof vectors (SHA-512 is CRITICAL)
curl -o test/fixtures/wycheproof/hkdf_sha256_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/hkdf_sha256_test.json

curl -o test/fixtures/wycheproof/hkdf_sha512_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/hkdf_sha512_test.json

curl -o test/fixtures/wycheproof/hkdf_sha384_test.json \
  https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/hkdf_sha384_test.json
```

## Implementation Considerations

### Technical Approach

```elixir
defmodule AwsEncryptionSdk.Crypto.HKDF do
  @moduledoc """
  HKDF (HMAC-based Key Derivation Function) per RFC 5869.
  """

  @type hash :: :sha256 | :sha384 | :sha512

  @hash_lengths %{sha256: 32, sha384: 48, sha512: 64}

  @doc """
  HKDF-Extract: Extract a pseudorandom key from input keying material.
  """
  @spec extract(hash(), binary() | nil, binary()) :: binary()
  def extract(hash, salt, ikm) do
    salt = salt || :binary.copy(<<0>>, @hash_lengths[hash])
    :crypto.mac(:hmac, hash, salt, ikm)
  end

  @doc """
  HKDF-Expand: Expand PRK to desired output length.
  """
  @spec expand(hash(), binary(), binary(), pos_integer()) ::
    {:ok, binary()} | {:error, :output_length_exceeded}
  def expand(hash, prk, info, length) do
    hash_len = @hash_lengths[hash]
    max_length = 255 * hash_len

    if length > max_length do
      {:error, :output_length_exceeded}
    else
      n = ceil(length / hash_len)
      okm = do_expand(hash, prk, info, n)
      {:ok, binary_part(okm, 0, length)}
    end
  end

  defp do_expand(hash, prk, info, n) do
    Enum.reduce(1..n, {<<>>, <<>>}, fn i, {prev, acc} ->
      t = :crypto.mac(:hmac, hash, prk, <<prev::binary, info::binary, i::8>>)
      {t, <<acc::binary, t::binary>>}
    end)
    |> elem(1)
  end

  @doc """
  Combined HKDF: Extract-then-Expand in one call.
  """
  @spec derive(hash(), binary(), binary() | nil, binary(), pos_integer()) ::
    {:ok, binary()} | {:error, :output_length_exceeded}
  def derive(hash, ikm, salt, info, length) do
    prk = extract(hash, salt, ikm)
    expand(hash, prk, info, length)
  end
end
```

### Key Derivation Integration

```elixir
defmodule AwsEncryptionSdk.Crypto.KeyDerivation do
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.AlgorithmSuite

  @derive_key_label "DERIVEKEY"
  @commit_key_label "COMMITKEY"

  @doc """
  Derive data encryption key for non-committed suites.
  """
  def derive_data_key(%AlgorithmSuite{commitment_length: 0} = suite, data_key, message_id) do
    info = <<suite.id::16-big, message_id::binary>>
    key_length = div(suite.data_key_length, 8)
    HKDF.derive(suite.kdf_hash, data_key, nil, info, key_length)
  end

  @doc """
  Derive data encryption key for committed suites.
  """
  def derive_data_key(%AlgorithmSuite{commitment_length: 32} = suite, data_key, message_id) do
    info = <<suite.id::16-big, @derive_key_label::binary>>
    key_length = div(suite.data_key_length, 8)
    HKDF.derive(suite.kdf_hash, data_key, message_id, info, key_length)
  end

  @doc """
  Derive commitment key for committed suites.
  """
  def derive_commit_key(%AlgorithmSuite{commitment_length: 32} = suite, data_key, message_id) do
    info = <<suite.id::16-big, @commit_key_label::binary>>
    HKDF.derive(suite.kdf_hash, data_key, message_id, info, 32)
  end
end
```

### Potential Challenges

1. **Empty Salt Handling**: RFC 5869 specifies using HashLen zero bytes when salt is empty. Must handle `nil` and `<<>>` correctly.

2. **Info String Construction**: Different between committed and non-committed suites. Labels are UTF-8 bytes, algorithm ID is big-endian.

3. **Counter Byte**: The expand step uses a single byte counter (1-255), limiting iterations. Ensure `i` doesn't exceed 255.

4. **Binary Operations**: Elixir binary concatenation in the expand loop must be efficient for larger outputs.

### Open Questions

1. **Label Encoding**: Are "DERIVEKEY" and "COMMITKEY" just raw UTF-8 bytes? (Likely yes - UTF-8 doesn't have endianness)

2. **Message ID Length**: Non-committed uses 16-byte message_id in info, committed uses 32-byte message_id as salt. The algorithm suite `message_format_version` determines this.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-24-GH8-hkdf-key-derivation.md`
2. Download Wycheproof test vectors
3. Implement `lib/aws_encryption_sdk/crypto/hkdf.ex`
4. Write tests starting with RFC 5869 Test Case 1
5. Validate SHA-512 support with Wycheproof vectors

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/8
- RFC 5869: https://datatracker.ietf.org/doc/html/rfc5869
- Algorithm Suites Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- AWS Algorithms Reference: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/algorithms-reference.html
- Wycheproof HKDF Tests: https://github.com/C2SP/wycheproof/tree/master/testvectors_v1
- Python SDK Reference: https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/internal/crypto/data_keys.py
