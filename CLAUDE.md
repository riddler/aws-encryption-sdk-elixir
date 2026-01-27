# CLAUDE.md - AWS Encryption SDK for Elixir

## Project Overview

This project implements the [AWS Encryption SDK](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html) for Elixir, providing client-side encryption following the official [AWS Encryption SDK Specification](https://github.com/awslabs/aws-encryption-sdk-specification).

The goal is to create a Hex package that enables Elixir/Erlang applications to encrypt and decrypt data compatible with all other AWS Encryption SDK implementations (Python, Java, JavaScript, C, CLI).

## Specification References

### Primary Sources
- **Specification**: https://github.com/awslabs/aws-encryption-sdk-specification
- **Test Vector Framework**: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
- **Test Vectors**: https://github.com/awslabs/aws-encryption-sdk-test-vectors

### Key Specification Documents
- `client-apis/encrypt.md` - Encrypt operation
- `client-apis/decrypt.md` - Decrypt operation
- `client-apis/client.md` - Client configuration & commitment policy
- `framework/structures.md` - Core data structures
- `framework/algorithm-suites.md` - All 17 algorithm suites
- `framework/keyring-interface.md` - Keyring behaviour
- `framework/cmm-interface.md` - CMM behaviour
- `framework/raw-aes-keyring.md` - Raw AES keyring
- `framework/raw-rsa-keyring.md` - Raw RSA keyring
- `framework/aws-kms/aws-kms-keyring.md` - AWS KMS keyring
- `framework/multi-keyring.md` - Multi-keyring composition
- `data-format/message-header.md` - Header format (v1 & v2)
- `data-format/message-body.md` - Body format (framed & non-framed)

## Architecture

### Module Structure

```
lib/
├── aws_encryption_sdk.ex              # Main public API
├── aws_encryption_sdk/
│   ├── client.ex                      # Client configuration
│   ├── encrypt.ex                     # Encrypt operation
│   ├── decrypt.ex                     # Decrypt operation
│   ├── materials/
│   │   ├── encryption_materials.ex    # Encryption materials struct
│   │   ├── decryption_materials.ex    # Decryption materials struct
│   │   └── encrypted_data_key.ex      # EDK struct
│   ├── algorithm_suite.ex             # Algorithm suite definitions
│   ├── crypto/
│   │   ├── aes_gcm.ex                 # AES-GCM operations
│   │   ├── hkdf.ex                    # HKDF key derivation
│   │   ├── ecdsa.ex                   # ECDSA signing/verification
│   │   └── commitment.ex              # Key commitment
│   ├── format/
│   │   ├── message.ex                 # Complete message handling
│   │   ├── header.ex                  # Header serialization
│   │   ├── body.ex                    # Body serialization (frames)
│   │   └── footer.ex                  # Footer (signature)
│   ├── keyring/
│   │   ├── behaviour.ex               # Keyring behaviour
│   │   ├── raw_aes.ex                 # Raw AES keyring
│   │   ├── raw_rsa.ex                 # Raw RSA keyring
│   │   ├── aws_kms.ex                 # AWS KMS keyring
│   │   ├── aws_kms_discovery.ex       # KMS discovery keyring
│   │   └── multi.ex                   # Multi-keyring
│   └── cmm/
│       ├── behaviour.ex               # CMM behaviour
│       └── default.ex                 # Default CMM implementation
```

### Key Data Structures

```elixir
# Encryption Context - key-value string pairs (AAD)
@type encryption_context :: %{String.t() => String.t()}

# Encrypted Data Key
defstruct [:key_provider_id, :key_provider_info, :ciphertext]

# Encryption Materials
defstruct [
  :algorithm_suite,
  :encryption_context,
  :encrypted_data_keys,        # list of EDKs
  :plaintext_data_key,         # binary, secret
  :signing_key,                # optional, for ECDSA suites
  :required_encryption_context_keys
]

# Decryption Materials
defstruct [
  :algorithm_suite,
  :encryption_context,
  :plaintext_data_key,
  :verification_key,           # optional, for ECDSA suites
  :required_encryption_context_keys
]
```

### Algorithm Suites

Support all ESDK algorithm suites (focus on committed suites first):

| ID | Name | Priority |
|----|------|----------|
| `0x0578` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384 | High (default) |
| `0x0478` | AES_256_GCM_HKDF_SHA512_COMMIT_KEY | High |
| `0x0378` | AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384 | Medium |
| `0x0178` | AES_256_GCM_IV12_TAG16_HKDF_SHA256 | Medium |
| `0x0078` | AES_256_GCM_IV12_TAG16_NO_KDF | Low (legacy) |

## Implementation Guidelines

### Erlang :crypto Usage

AES-GCM encryption/decryption:
```elixir
# Encrypt
{ciphertext, tag} = :crypto.crypto_one_time_aead(
  :aes_256_gcm, key, iv, plaintext, aad, true
)

# Decrypt
plaintext = :crypto.crypto_one_time_aead(
  :aes_256_gcm, key, iv, ciphertext, aad, tag, false
)
```

ECDSA operations:
```elixir
# Sign
signature = :crypto.sign(:ecdsa, :sha384, message, {private_key, :secp384r1})

# Verify
:crypto.verify(:ecdsa, :sha384, message, signature, {public_key, :secp384r1})
```

### HKDF Implementation

HKDF is not directly available in `:crypto` - implement per RFC 5869:
```elixir
def hkdf_extract(hash, salt, ikm) do
  :crypto.mac(:hmac, hash, salt, ikm)
end

def hkdf_expand(hash, prk, info, length) do
  # Iterative HMAC expansion
end
```

### Binary Message Format

Use Elixir binary pattern matching for serialization:
```elixir
# Header v2 parsing
<<
  0x02::8,                           # version
  algorithm_id::16-big,              # algorithm suite
  message_id::binary-size(32),       # 32-byte message ID
  rest::binary
>> = header_bytes
```

### Commitment Policy

Support three policies per spec:
- `:forbid_encrypt_allow_decrypt` - Legacy compatibility
- `:require_encrypt_allow_decrypt` - Transitional
- `:require_encrypt_require_decrypt` - Strictest (default)

## Testing Strategy

### Unit Tests
- Algorithm suite selection
- HKDF derivation vectors
- Message serialization/deserialization
- Individual keyring operations

### Integration Tests (Test Vectors)
Parse and execute test vectors from aws-encryption-sdk-test-vectors:

```elixir
# Test vector manifest structure
%{
  "manifest" => %{"type" => "awses-decrypt", "version" => 3},
  "keys" => "file://keys.json",
  "tests" => %{
    "test-id" => %{
      "ciphertext" => "file://ciphertext.bin",
      "master-keys" => [...],
      "result" => %{"output" => %{"plaintext" => "file://plaintext.bin"}}
    }
  }
}
```

### Interoperability Tests
1. Encrypt with Elixir SDK, decrypt with Python/Java SDK
2. Encrypt with Python/Java SDK, decrypt with Elixir SDK

## Dependencies

```elixir
# mix.exs
defp deps do
  [
    # AWS integration (choose one)
    {:ex_aws, "~> 2.5"},
    {:ex_aws_kms, "~> 2.0"},
    # or
    {:aws, "~> 1.0"},  # aws-elixir

    # HTTP client for AWS
    {:hackney, "~> 1.20"},

    # JSON parsing
    {:jason, "~> 1.4"},

    # Testing
    {:stream_data, "~> 1.0", only: [:test, :dev]}
  ]
end
```

## Build Commands

```bash
# Install dependencies
mix deps.get

# Run tests
mix test

# Run tests with coverage
mix test --cover

# Type checking
mix dialyzer

# Documentation
mix docs

# Publish to Hex
mix hex.publish
```

## Development Milestones

### Milestone 1: Core Foundation
- [x] Algorithm suite definitions
- [x] HKDF implementation
- [x] Message format serialization
- [x] Basic encryption/decryption (non-streaming)

### Milestone 2: Keyrings
- [x] Keyring behaviour
- [x] Raw AES Keyring
- [x] Raw RSA Keyring
- [x] Multi-Keyring

### Milestone 3: CMM & Full API
- [x] CMM behaviour
- [x] Default CMM
- [x] Encrypt API with commitment policy
- [x] Decrypt API with commitment policy

### Milestone 4: AWS Integration
- [ ] AWS KMS Keyring
- [ ] AWS KMS Discovery Keyring
- [ ] AWS KMS MRK-aware keyrings

### Milestone 5: Advanced Features
- [ ] Streaming encryption/decryption
- [ ] Caching CMM
- [ ] Required encryption context CMM

### Milestone 6: Validation
- [ ] Full test vector suite
- [ ] Cross-SDK interoperability
- [ ] Performance benchmarks
- [ ] Security review

## Key Implementation Notes

### Encryption Context Serialization
Must be sorted by UTF-8 key bytes ascending:
```elixir
def serialize_encryption_context(context) when map_size(context) == 0, do: <<0::16>>
def serialize_encryption_context(context) do
  sorted = Enum.sort_by(context, fn {k, _v} -> k end)
  count = length(sorted)
  entries = Enum.map(sorted, &serialize_entry/1) |> IO.iodata_to_binary()
  <<count::16-big, entries::binary>>
end
```

### Frame Sequence Numbers
- Start at 1, increment by 1
- Final frame marker: `0xFFFFFFFF`
- Max frames: `2^32 - 1`

### Key Commitment (v2 Messages)
For committed algorithm suites, derive commitment key and compare with stored value:
```elixir
# HKDF-SHA512 with label "DERIVEKEY" for data key
# HKDF-SHA512 with label "COMMITKEY" for commitment
```

### Security Requirements
- Never release unauthenticated plaintext
- Zero plaintext keys after use
- Validate all algorithm parameters
- Enforce commitment policy strictly

## Resources

- [AWS Encryption SDK Developer Guide](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/)
- [Python SDK Reference](https://github.com/aws/aws-encryption-sdk-python)
- [JavaScript SDK Reference](https://github.com/aws/aws-encryption-sdk-javascript)
- [Erlang :crypto docs](https://www.erlang.org/doc/apps/crypto/crypto.html)
- [RFC 5869 - HKDF](https://tools.ietf.org/html/rfc5869)
