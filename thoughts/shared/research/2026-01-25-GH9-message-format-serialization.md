# Research: Implement Message Format Serialization

**Issue**: #9 - Implement message format serialization
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

Implement binary serialization and deserialization for the AWS Encryption SDK message format, including:
- Headers (v1 and v2)
- Body (framed and non-framed)
- Footer (signature)

The message format defines how encrypted data is structured for storage and transmission. Elixir's binary pattern matching makes it well-suited for implementing binary format parsing and construction.

## Current Implementation State

### Existing Code

| File | Description | Relevance |
|------|-------------|-----------|
| `lib/aws_encryption_sdk/algorithm_suite.ex` | Complete algorithm suite definitions with `message_format_version` field (1 or 2) | Provides algorithm suite lookup, version info, commitment/signing flags |
| `lib/aws_encryption_sdk/crypto/hkdf.ex` | HKDF key derivation per RFC 5869 | Needed for key commitment derivation |

### What Exists
- Algorithm suite definitions with 14 fields including `message_format_version`, `commitment_length`, `suite_data_length`
- HKDF implementation supporting `:sha256`, `:sha384`, `:sha512`
- Project documentation outlining planned architecture
- Branch `9-message-format` ready for implementation

### What Does NOT Exist
- All message format implementation files (`lib/aws_encryption_sdk/format/`)
- Materials modules (`lib/aws_encryption_sdk/materials/`)
- Encryption context serialization code
- Frame sequence handling code
- Any binary message serialization/deserialization code

### Relevant Patterns

**Module Organization** (from existing code):
```elixir
defmodule AwsEncryptionSdk.ModuleName do
  @moduledoc "..."

  @typedoc "..."
  @type t :: %__MODULE__{...}

  @enforce_keys [...]
  defstruct @enforce_keys

  @spec function(params) :: return_type
  def function(params), do: ...
end
```

**Error Handling**: Tagged tuples `{:ok, value}` | `{:error, :reason_atom}`

**Binary Operations**: Big-endian encoding, `binary_part/3`, pattern matching

### Dependencies

- **Algorithm Suite** (#11) - Complete ✓
- **HKDF** (#12) - Complete ✓

## Specification Requirements

### Source Documents

- [data-format/message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md) - Header v1 and v2 format specifications
- [data-format/message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md) - Framed and non-framed body formats
- [data-format/message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md) - Signature footer format
- [framework/structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Encryption context and encrypted data key structures

### MUST Requirements

#### Message Header - General

1. **Byte Order** (message-header.md)
   > "The message header is a sequence of bytes that MUST be in big-endian format"

   Implementation: All multi-byte fields use `::16-big`, `::32-big`, etc.

2. **Version Field** (message-header.md)
   > Version field determines structure: v1.0 uses `01` hex, v2.0 uses `02` hex

   Implementation: First byte must be `0x01` or `0x02`

3. **Type Field - v1 only** (message-header.md)
   > Type field "MUST be a value that exists" in supported types table (only `80` for authenticated encryption)

   Implementation: For v1, second byte must be `0x80`

4. **Algorithm Suite ID** (message-header.md)
   > Algorithm Suite ID "MUST be a value that exists in the Supported Algorithm Suites table"

   Implementation: Validate against `AlgorithmSuite.by_id/1`

5. **Message ID Uniqueness** (message-header.md)
   > "A Message ID MUST uniquely identify the message"
   > Implementations "MUST use a good source of randomness"

   Implementation:
   - v1: 16 random bytes via `:crypto.strong_rand_bytes(16)`
   - v2: 32 random bytes via `:crypto.strong_rand_bytes(32)`

6. **Encrypted Data Key Count** (message-header.md)
   > "This value MUST be greater than 0"

   Implementation: Validate `count > 0` before serializing

7. **Content Type** (message-header.md)
   > "MUST be a value that exists" in supported content types

   Implementation: `0x01` for non-framed, `0x02` for framed

8. **Reserved Field - v1 only** (message-header.md)
   > "MUST have the value (hex) of `00 00 00 00`"

   Implementation: `<<0::32>>` for v1 messages

9. **Frame Length for Non-Framed** (message-header.md)
   > "When the content type is non-framed, the value of this field MUST be 0"

   Implementation: `<<0::32>>` when content type is non-framed

#### Header Version 1.0 Byte Layout

```elixir
# Version 1.0 Header Body
<<
  0x01::8,                              # Version
  0x80::8,                              # Type
  algorithm_suite_id::16-big,           # Algorithm Suite ID
  message_id::binary-size(16),          # Message ID (16 bytes for v1)
  aad_length::16-big,                   # AAD Length
  aad_pairs::binary,                    # AAD Key-Value Pairs (if length > 0)
  edk_count::16-big,                    # Encrypted Data Key Count
  edk_entries::binary,                  # Encrypted Data Key Entries
  content_type::8,                      # Content Type (0x01 or 0x02)
  0::32,                                # Reserved (must be 0x00000000)
  iv_length::8,                         # IV Length
  frame_length::32-big                  # Frame Length (0 for non-framed)
>>

# Version 1.0 Header Authentication
<<
  iv::binary-size(iv_length),           # IV
  auth_tag::binary-size(16)             # Authentication Tag
>>
```

#### Header Version 2.0 Byte Layout

```elixir
# Version 2.0 Header Body
<<
  0x02::8,                              # Version
  algorithm_suite_id::16-big,           # Algorithm Suite ID (Type field removed)
  message_id::binary-size(32),          # Message ID (32 bytes for v2)
  aad_length::16-big,                   # AAD Length
  aad_pairs::binary,                    # AAD Key-Value Pairs (if length > 0)
  edk_count::16-big,                    # Encrypted Data Key Count
  edk_entries::binary,                  # Encrypted Data Key Entries
  content_type::8,                      # Content Type (0x01 or 0x02)
  frame_length::32-big,                 # Frame Length (moved earlier)
  algorithm_suite_data::binary-size(32) # Algorithm Suite Data (commitment key)
>>

# Version 2.0 Header Authentication
<<
  auth_tag::binary-size(16)             # Authentication Tag only (no IV - uses zero IV)
>>
```

#### Encryption Context Serialization (structures.md)

1. **UTF-8 Encoding**
   > "The encryption context is a key-value mapping of arbitrary, non-secret, UTF-8 encoded strings."

2. **Empty Context**
   > If empty, serialization must be an empty byte sequence

   Implementation: Return `<<>>` when map is empty

3. **Non-Empty Format**
   > 2-byte key-value pair count (UInt16) followed by entries

   Implementation: `<<count::16-big, entries::binary>>`

4. **No Duplicates**
   > Entry sequence cannot contain duplicate pairs

5. **Sorted Order**
   > Entries must be sorted ascending by UTF-8 encoded key binary values

   Implementation: `Enum.sort_by(context, fn {k, _v} -> k end)`

6. **Entry Format**
   ```elixir
   <<
     key_length::16-big,
     key::binary-size(key_length),
     value_length::16-big,
     value::binary-size(value_length)
   >>
   ```

#### Encrypted Data Key Entry Format (message-header.md)

```elixir
<<
  provider_id_length::16-big,
  provider_id::binary-size(provider_id_length),    # UTF-8 encoded
  provider_info_length::16-big,
  provider_info::binary-size(provider_info_length),
  ciphertext_length::16-big,
  ciphertext::binary-size(ciphertext_length)
>>
```

#### Message Body - Non-Framed (message-body.md)

1. **Content Length Limit**
   > "The length MUST NOT be greater than `2^36 - 32`, or 64 gibibytes (64 GiB)"

   Implementation: Validate `content_length <= 68_719_476_704`

2. **IV Uniqueness**
   > "The IV MUST be a unique IV within the message"

3. **Non-Framed Structure**
   ```elixir
   <<
     iv::binary-size(12),
     encrypted_content_length::64-big,
     encrypted_content::binary-size(encrypted_content_length),
     auth_tag::binary-size(16)
   >>
   ```

#### Message Body - Framed (message-body.md)

1. **Sequence Number Start**
   > "Framed Data MUST start at Sequence Number 1"

2. **Sequence Number Ordering**
   > Subsequent frames "MUST be in order and MUST contain an increment of 1"

3. **Frame Count Limit**
   > Number of frames "MUST be less than or equal to `2^32 - 1`"

4. **Final Frame Requirement**
   > "Framed data MUST contain exactly one final frame"
   > "The final frame MUST be the last frame"

5. **Final Frame Sequence End**
   > Sequence Number End value "MUST be encoded as the 4 bytes `FF FF FF FF`"

6. **Regular Frame Structure**
   ```elixir
   <<
     sequence_number::32-big,
     iv::binary-size(12),
     encrypted_content::binary-size(frame_length),
     auth_tag::binary-size(16)
   >>
   ```

7. **Final Frame Structure**
   ```elixir
   <<
     0xFFFFFFFF::32,                          # Sequence Number End marker
     sequence_number::32-big,
     iv::binary-size(12),
     encrypted_content_length::32-big,
     encrypted_content::binary-size(encrypted_content_length),
     auth_tag::binary-size(16)
   >>
   ```

#### Message Footer (message-footer.md)

1. **Footer Requirement**
   > "When an algorithm suite includes a signature algorithm, the message MUST contain a footer."

2. **Signature Scope**
   > "The signature MUST be calculated over both the message header and the message body, in the order of serialization."

3. **Footer Structure**
   ```elixir
   <<
     signature_length::16-big,
     signature::binary-size(signature_length)
   >>
   ```

### SHOULD Requirements

1. **Signing Key Context** (structures.md)
   > If encryption materials contain a signing key, context should include the reserved key `aws-crypto-public-key` mapped to the signature verification key

2. **Final Frame Content Length** (message-body.md)
   > Final frame encrypted content "SHOULD be equal to the frame length" when plaintext is exact multiple of frame length

### MAY Requirements

1. **Zero-Length Final Frame** (message-body.md)
   > Final frame encrypted content "MAY be 0" when plaintext is exact multiple of frame length

## Test Vectors

### Applicable Test Vector Sets

- **awses-decrypt**: Primary test vectors in `vectors/awses-decrypt/python-2.3.0.zip`
- Test vectors organized by algorithm ID, plaintext size, and frame length

### How to Fetch

```bash
mkdir -p test/fixtures/test_vectors
cd test/fixtures/test_vectors
curl -L -o python-2.3.0.zip \
  https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip
unzip python-2.3.0.zip
```

### Implementation Order

#### Phase 1: Basic Implementation (Start Here)

| Test Characteristics | Description | Priority |
|---------------------|-------------|----------|
| Algorithm: **0x0478** | AES-256-GCM with commitment, no signature | **Start here** |
| Frame Length: **0** | Non-framed (single content block) | Simplest body |
| Key Type: Raw AES | Static symmetric key | Simplest keyring |
| Message Size: Small | < 1KB plaintext | Minimal data |
| Header Version: v2 | 32-byte message ID | Current standard |

**Why Start Here?**
- Simplest message structure
- Single encryption/decryption operation
- No frame management complexity
- No signature verification needed
- Tests core serialization/deserialization

#### Phase 2: Add Framing Support

| Test Characteristics | Description | Priority |
|---------------------|-------------|----------|
| Algorithm: **0x0478** | Same as Phase 1 | Second |
| Frame Length: **4096** | Multiple frames | Frame parsing |
| Message Size: Medium | 10KB - 100KB plaintext | Multiple frames |

**Tests**: Frame parsing, sequence number validation, final frame detection

#### Phase 3: Add Signature Support

| Test Characteristics | Description | Priority |
|---------------------|-------------|----------|
| Algorithm: **0x0578** | AES-256-GCM with commitment AND ECDSA | Third |
| Frame Length: 0 or 4096 | Both variants | Footer parsing |
| Signature: ECDSA P-384 | Must verify footer signature | Crypto integration |

**Tests**: Footer parsing, ECDSA verification over header + body

#### Phase 4: Header v1 (Legacy Support)

| Test Characteristics | Description | Priority |
|---------------------|-------------|----------|
| Algorithm: **0x0178** or **0x0378** | Legacy suites | Fourth |
| Header Version: v1 | 16-byte message ID | Backward compat |
| Frame Length: Various | Both framed and non-framed | Full coverage |

**Tests**: v1 header structure, different field positions

#### Phase 5: Edge Cases

| Test Case | Description | Expected |
|-----------|-------------|----------|
| Empty plaintext | Zero-length plaintext | Valid message with zero-length body |
| Single byte | 1-byte plaintext | Minimal valid message |
| Empty encryption context | No AAD key-value pairs | AAD Length = 0x0000 |
| Large encryption context | Many key-value pairs | Large AAD field |
| Many frames | 1000+ frames | Sequence number handling |

#### Phase 6: Negative Tests (Error Cases)

| Test Case | Expected Error |
|-----------|----------------|
| Wrong key | Authentication failure |
| Tampered header | Header auth verification fails |
| Tampered body | GCM tag verification fails |
| Invalid sequence | Sequence validation error |
| Truncated message | Parsing error |
| Invalid version | Unsupported version error |

### Key Material Needed

From `keys.json` in test vectors:
- `aes-256-key-*` - 256-bit symmetric keys for Raw AES keyring
- `rsa-4096-*` - RSA keys for Raw RSA keyring

## Implementation Considerations

### Technical Approach

#### Recommended Module Structure

```
lib/aws_encryption_sdk/format/
├── message.ex           # Complete message handling (serialize/deserialize)
├── header.ex            # Header v1/v2 serialization
├── body.ex              # Body framed/non-framed serialization
├── footer.ex            # Footer (signature) serialization
└── encryption_context.ex # Encryption context serialization
```

#### Data Structures

```elixir
# Encrypted Data Key
defmodule AwsEncryptionSdk.Materials.EncryptedDataKey do
  @enforce_keys [:key_provider_id, :key_provider_info, :ciphertext]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
    key_provider_id: String.t(),
    key_provider_info: binary(),
    ciphertext: binary()
  }
end

# Message Header
defmodule AwsEncryptionSdk.Format.Header do
  @type t :: %__MODULE__{
    version: 1 | 2,
    algorithm_suite: AlgorithmSuite.t(),
    message_id: binary(),
    encryption_context: %{String.t() => String.t()},
    encrypted_data_keys: [EncryptedDataKey.t()],
    content_type: :framed | :non_framed,
    frame_length: non_neg_integer(),
    algorithm_suite_data: binary() | nil,    # v2 only: commitment key
    header_iv: binary() | nil,               # v1 only
    header_auth_tag: binary()
  }
end
```

#### Binary Parsing Pattern

```elixir
def deserialize(<<0x02::8, rest::binary>>) do
  parse_v2_header(rest)
end

def deserialize(<<0x01::8, 0x80::8, rest::binary>>) do
  parse_v1_header(rest)
end

def deserialize(_) do
  {:error, :invalid_message_format}
end
```

### Potential Challenges

1. **Variable-length fields**: Encrypted data keys and encryption context have variable lengths requiring careful parsing
2. **Version differences**: v1 and v2 headers have different field positions and presence
3. **Frame detection**: Need to detect final frame via `0xFFFFFFFF` marker
4. **Error handling**: Must fail fast on any authentication or format errors
5. **Large messages**: Non-framed messages can be up to 64 GiB

### Open Questions

1. **Message Body AAD Structure**: The exact byte layout of the message body AAD for frame authentication needs further investigation
2. **Signature Encoding Format**: For ECDSA signatures in the footer, is it DER or raw r||s encoding?
3. **Reserved Encryption Context Keys**: What is the complete list beyond `aws-crypto-public-key`?

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-25-GH9-message-format-serialization.md`
2. Implement encryption context serialization first (simplest, used by all other components)
3. Implement header v2 next (committed suites are the current standard)
4. Add non-framed body format
5. Add framed body format
6. Add footer for signed messages
7. Add header v1 for backward compatibility

## References

- Issue: https://github.com/aws_encryption_sdk/issues/9
- Spec: https://github.com/awslabs/aws-encryption-sdk-specification
  - [message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md)
  - [message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md)
  - [message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md)
  - [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md)
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
