# Research: Implement Streaming Encryption/Decryption

**Issue**: #60 - Implement Streaming Encryption/Decryption
**Date**: 2026-01-29
**Status**: Research complete

## Issue Summary

Implement streaming encryption and decryption APIs that process data incrementally without loading the entire plaintext or ciphertext into memory. This enables handling large files and memory-constrained environments through Elixir's Stream/Enum abstractions.

## Current Implementation State

### Existing Code

**Core Non-Streaming Implementation:**
- `lib/aws_encryption_sdk/encrypt.ex` - Non-streaming encryption (explicitly noted: "requires the entire plaintext to be in memory")
- `lib/aws_encryption_sdk/decrypt.ex` - Non-streaming decryption (explicitly noted: "requires the entire ciphertext to be in memory")
- `lib/aws_encryption_sdk.ex` - Main public API entry point

**Frame/Body Serialization (Critical for Streaming):**
- `lib/aws_encryption_sdk/format/body.ex` - Frame serialization/deserialization
  - `serialize_regular_frame/4` (line 162) - Outputs individual frame binary
  - `serialize_final_frame/4` (line 184) - Outputs final frame binary
  - `deserialize_frame/2` (line 204) - Parses single frame, returns `{:ok, frame, rest}`
  - `deserialize_all_frames/2` (line 260) - Recursive parsing of all frames
- `lib/aws_encryption_sdk/format/header.ex` - Header serialization
  - `serialize/1` (line 121) - Complete header binary
  - `deserialize/1` (line 140) - Parses header, returns `{:ok, header, rest}`
- `lib/aws_encryption_sdk/format/footer.ex` - Footer/signature serialization
- `lib/aws_encryption_sdk/format/body_aad.ex` - AAD generation for frames

**Cryptographic Primitives:**
- `lib/aws_encryption_sdk/crypto/aes_gcm.ex` - AES-GCM encrypt/decrypt with sequence-number-based IV
- `lib/aws_encryption_sdk/crypto/ecdsa.ex` - ECDSA signing/verification (no incremental API)
- `lib/aws_encryption_sdk/crypto/hkdf.ex` - HKDF key derivation

**CMM/Materials:**
- `lib/aws_encryption_sdk/cmm/behaviour.ex` - CMM behaviour (stateless, no changes needed)
- `lib/aws_encryption_sdk/cmm/default.ex` - Default CMM implementation
- `lib/aws_encryption_sdk/materials/encryption_materials.ex` - Encryption materials struct
- `lib/aws_encryption_sdk/materials/decryption_materials.ex` - Decryption materials struct

### Relevant Patterns

**Current Encryption Flow (encrypt.ex):**
1. Get materials from CMM
2. Generate message ID, derive keys
3. Build and serialize header
4. Chunk plaintext with `chunk_plaintext_loop/3` (recursive binary slicing)
5. Encrypt each frame with `encrypt_frame/5` (sequence numbers start at 1)
6. For signed suites: accumulate entire header+body, sign with ECDSA
7. Concatenate header + body + footer

**Current Decryption Flow (decrypt.ex):**
1. Parse complete message with `Message.deserialize/1`
2. Derive keys, verify commitment
3. Verify header auth tag
4. Decrypt all frames with `Enum.reduce_while/3`
5. Verify ECDSA signature (if signed suite)
6. Return accumulated plaintext

**Frame Structure Constants (format/body.ex):**
- Final frame marker: `0xFFFFFFFF`
- IV length: 12 bytes
- Auth tag length: 16 bytes

### Dependencies

**What streaming depends on:**
- Existing frame serialization/deserialization in `format/body.ex`
- Existing header handling in `format/header.ex`
- AES-GCM primitives in `crypto/aes_gcm.ex`
- CMM for materials acquisition

**Critical limitation:** ECDSA in Erlang `:crypto` has no incremental API. Signature accumulation requires either:
1. Using `:crypto.hash_init/update/final` for SHA-384, then sign the digest
2. Buffering entire header+body for signed suites (defeats streaming purpose)

## Specification Requirements

### Source Documents
- [encrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - Streaming encryption
- [decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Streaming decryption
- [message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md) - Frame format
- [message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md) - Header format
- [message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md) - Footer format

### MUST Requirements

#### Encryption Output Release (encrypt.md)

1. **Header Release Timing**
   > The serialized bytes MUST NOT be released until the entire message header has been serialized.

   Implementation: Buffer entire header before releasing any bytes.

2. **Frame Release Timing**
   > The above serialized bytes MUST NOT be released until the entire frame has been serialized.

   Implementation: Complete frame serialization before releasing to output stream.

3. **Signature Input Requirement**
   > If streaming with signatures, this operation MUST input the serialized header to the signature algorithm as soon as it is serialized, such that the serialized header isn't required to remain in memory.

   Implementation: Feed header bytes to signature algorithm immediately after serialization.

4. **Footer Release Timing**
   > The above serialized bytes MUST NOT be released until the entire message footer has been serialized.

   Implementation: Buffer entire footer before release.

5. **Final Release Requirement**
   > After footer completion, this operation MUST release any previously unreleased serialized bytes from previous steps and MUST release the message footer.

   Implementation: Flush all buffered bytes after footer completes.

#### Decryption Input/Output (decrypt.md)

6. **Non-streaming Output Constraint**
   > all output MUST NOT be released until after these steps complete successfully.

   Implementation: In non-streaming mode, buffer all plaintext until complete verification.

7. **Signed Data Release Constraint**
   > With signature algorithms, released early output MUST NOT be considered signed data until this operation successfully completes.

   Implementation: Mark early-released plaintext as unverified; only consider signed after footer verification.

8. **Final Frame Release Constraint**
   > plaintext from unframed data or final frames MUST NOT be released until [signature verification] successfully completes.

   Implementation: Hold final frame plaintext until signature verified.

9. **Immediate Failure Configuration**
   > The ESDK MUST provide a configuration option that causes the decryption operation to fail immediately after parsing the header if a signed algorithm suite is used.

   Implementation: Add `:fail_on_signed` configuration flag to reject signed messages in streaming mode.

10. **Trailing Bytes Failure**
    > If streaming is active and bytes remain after completing all steps, the operation MUST fail.

    Implementation: Verify no extra bytes after final frame.

#### Frame Sequence Numbers (message-body.md)

11. **Starting Sequence Number**
    > Framed data must start at Sequence Number 1.

    Implementation: Initialize frame counter to 1.

12. **Sequential Ordering**
    > Subsequent frames must be in sequential order with increments of 1.

    Implementation: Increment counter by 1 for each frame.

13. **Final Frame Sequence Number**
    > The Final Frame Sequence number MUST be equal to the total number of frames.

    Implementation: Verify final frame number matches total frame count.

14. **Final Frame Marker**
    > The value MUST be encoded as the 4 bytes `FF FF FF FF` in hexadecimal notation.

    Implementation: Use `0xFFFFFFFF` as final frame sequence number marker.

15. **Maximum Frame Count**
    > The number of frames in a single message cannot exceed `2^32 - 1`.

    Implementation: Enforce 4,294,967,295 frame limit.

16. **One Final Frame Requirement**
    > Messages must contain exactly one final frame.

    Implementation: Ensure exactly one frame with final marker.

17. **Final Frame Position**
    > The final frame must be the last frame in the sequence.

    Implementation: No frames after final frame marker.

#### Footer/Signature (message-footer.md)

18. **Signature Scope**
    > This signature MUST be calculated over both the message header and the message body, in the order of serialization.

    Implementation: Sign concatenation of serialized header + body.

19. **Footer Requirement**
    > When an algorithm suite includes a signature algorithm component, the message MUST contain a footer.

    Implementation: Include footer for all signed algorithm suites.

### SHOULD Requirements

20. **Header Release After Serialization** (encrypt.md)
    > Once complete, the serialized message header SHOULD be released.

    Implementation: Release header bytes immediately after serialization completes.

21. **Frame Release After Serialization** (encrypt.md)
    > If streaming, the serialized frame SHOULD be released after complete serialization.

    Implementation: Release frame bytes immediately after each frame completes.

22. **Regular Frame Release (Unsigned)** (decrypt.md)
    > For regular frames with unsigned algorithm suites: plaintext SHOULD be released as soon as the above calculation, including tag verification, succeeds.

    Implementation: Stream regular frame plaintext immediately for unsigned suites.

23. **Signed Regular Frame Release** (decrypt.md)
    > For signed algorithm suites: plaintext from regular frames SHOULD be released after authentication.

    Implementation: Stream regular frames even for signed suites (but mark as unverified).

24. **Signature Input Optimization** (decrypt.md)
    > The operation SHOULD input the serialized header and frame data to signature algorithms during deserialization to avoid retaining these bytes in memory.

    Implementation: Feed bytes to signature algorithm during parsing, don't buffer.

### MAY Requirements

25. **Input/Output Streaming** (encrypt.md, decrypt.md)
    > This input MAY be streamed to this operation (plaintext).
    > This operation MAY stream the encrypted message.
    > The encrypted message input MAY be [streamed] to this operation.

    Implementation: Streaming is optional but highly beneficial for large messages.

## Test Vectors

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
manifest_path = "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets

- **awses-decrypt**: Decrypt test vectors for validating streaming decryption
- Manifest version: 2 (generated by aws-encryption-sdk-python 2.2.0)
- Keys version: 3
- Total tests: 100+ test vectors

### Test Vector Categories for Streaming

**Frame Structure Categories:**
- Non-framed (`content_type: :non_framed`, `frame_length: 0`) - Not ideal for streaming
- Single frame - One frame messages
- Few frames (2-5) - Basic streaming validation
- Many frames (6-20) - Standard streaming scenarios
- Very many frames (20+) - Large message streaming

### Implementation Order

#### Phase 1: Basic Framed Decryption (Start Here)

| Priority | Algorithm | Description | Validation Goal |
|----------|-----------|-------------|-----------------|
| HIGH | `0x0478` | AES-256-GCM-HKDF-SHA512-COMMIT-KEY | Committed, unsigned streaming |
| HIGH | `0x0578` | Above + ECDSA-P384 | Signed suite footer handling |

**Key Types:** Start with Raw AES (simplest, no AWS dependencies)

#### Phase 2: Multi-Frame Validation

| Scenario | Frame Size | Plaintext | Expected Frames |
|----------|------------|-----------|-----------------|
| Single frame | 4096 | 100 bytes | 1 |
| Multiple small frames | 512 | 4096 bytes | 8-9 |
| Many frames | 4096 | 50KB | 13+ |
| Very large | 4096 | 1MB | 256+ |

#### Phase 3: Edge Cases

| Scenario | Description | Expected Result |
|----------|-------------|-----------------|
| Empty plaintext | Zero-length message | 1 empty final frame |
| Single byte | Minimum non-empty | 1 frame with 1 byte |
| Exact frame multiple | Plaintext = N * frame_size | Optional empty final frame |
| Off-by-one | Plaintext = N * frame_size + 1 | Tiny final frame |

#### Phase 4: Algorithm Suite Coverage

| Algorithm ID | Name | Priority |
|--------------|------|----------|
| `0x0478` | AES-256-GCM-HKDF-SHA512-COMMIT-KEY | HIGH |
| `0x0578` | Above + ECDSA-P384 | HIGH |
| `0x0346` | AES-192-GCM-HKDF-SHA256-COMMIT-KEY | MEDIUM |
| `0x0214` | AES-128-GCM-HKDF-SHA256-COMMIT-KEY | MEDIUM |
| `0x0378` | AES-256-GCM-IV12-TAG16-HKDF-SHA384-ECDSA-P384 | LOW (legacy) |

### Test Vector Setup

If test vectors are not present, run:

```elixir
TestVectorSetup.ensure_test_vectors()
```

Or manually:

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

### Key Material

Keys are loaded from the manifest's keys.json:

```elixir
# Get key metadata
{:ok, key_data} = TestVectorHarness.get_key(harness, "aes-256-key-id")

# Decode key material
{:ok, raw_key} = TestVectorHarness.decode_key_material(key_data)
```

### Analyzing Test Vectors for Streaming

Use this script to categorize test vectors by frame count:

```elixir
alias AwsEncryptionSdk.TestSupport.TestVectorHarness
alias AwsEncryptionSdk.Format.Message

manifest_path = "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

for test_id <- TestVectorHarness.list_test_ids(harness) do
  {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
  {:ok, message, _} = Message.deserialize(ciphertext)

  case message.header.content_type do
    :framed ->
      frame_count = length(message.body)
      algorithm = Integer.to_string(message.header.algorithm_suite.algorithm_id, 16)
      IO.puts("#{test_id}: #{frame_count} frames, algo: 0x#{algorithm}")
    :non_framed ->
      IO.puts("#{test_id}: non-framed")
  end
end
```

## Implementation Considerations

### Technical Approach

#### State Machine Design

**Encryptor States:**
1. `:init` - Not started, need materials from CMM
2. `:header_written` - Header serialized and written
3. `:encrypting` - Processing frames (track sequence number)
4. `:footer_pending` - All plaintext consumed, need footer
5. `:done` - Encryption complete

**Decryptor States:**
1. `:init` - Not started
2. `:reading_header` - Accumulating header bytes
3. `:header_parsed` - Header complete, get materials from CMM
4. `:decrypting_frames` - Processing frames (track sequence number)
5. `:reading_footer` - Accumulating signature (signed suites)
6. `:done` - Decryption complete

#### Proposed Module Structure

```
lib/aws_encryption_sdk/stream/
├── encryptor.ex           # Streaming encryptor state machine
├── decryptor.ex           # Streaming decryptor state machine
├── buffer.ex              # Buffer management utilities
└── signature_accumulator.ex  # Incremental signature computation
```

#### Signature Accumulation Strategy

Since Erlang `:crypto` doesn't support incremental ECDSA signing/verification, use:

```elixir
# Initialize SHA-384 hash context
hash_ctx = :crypto.hash_init(:sha384)

# Update with header bytes
hash_ctx = :crypto.hash_update(hash_ctx, header_bytes)

# Update with each frame
hash_ctx = :crypto.hash_update(hash_ctx, frame_bytes)

# Finalize hash
digest = :crypto.hash_final(hash_ctx)

# Sign/verify the digest
signature = :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [private_key, :secp384r1])
:crypto.verify(:ecdsa, :sha384, {:digest, digest}, signature, [public_key, :secp384r1])
```

### Potential Challenges

1. **ECDSA Streaming Limitation**: Erlang `:crypto` requires complete message for ECDSA. Solution: Use hash accumulation with `{:digest, hash}` form.

2. **Header Parsing with Incomplete Data**: Header has variable-length fields (encryption context, EDKs). Need to buffer until complete header received.

3. **Frame Boundary Detection**: Must detect final frame marker (`0xFFFFFFFF`) to know when body is complete.

4. **Signed Suite Final Frame**: For signed suites, final frame plaintext cannot be released until signature verified. May need to buffer final frame.

5. **Memory Management**: Must carefully manage buffers to avoid memory accumulation during streaming.

6. **Error Recovery**: If signature verification fails for signed suites, all "released" plaintext becomes invalid.

### Open Questions

1. **Enumerable Protocol**: Should the streaming API implement Elixir's `Enumerable` protocol for seamless integration with `Stream` functions?

2. **Backpressure Handling**: How should the streaming implementation handle backpressure when the consumer is slower than the producer?

3. **Error Semantics**: For signed suites with early plaintext release, how should errors be communicated if signature verification fails?

4. **GenServer vs Pure Functions**: Should encryptor/decryptor be GenServers for stateful operation, or pure functions with explicit state threading?

## Recommended Next Steps

1. Create implementation plan:
   ```
   /create_plan thoughts/shared/research/2026-01-29-GH60-streaming-encryption-decryption.md
   ```

2. Implement in phases:
   - Phase 1: Stream infrastructure (buffer, state machine scaffolding)
   - Phase 2: Streaming encryptor for unsigned suites
   - Phase 3: Streaming decryptor for unsigned suites
   - Phase 4: Add signature accumulation for signed suites
   - Phase 5: Enumerable protocol and high-level API
   - Phase 6: `:fail_on_signed` configuration option

3. Validate with test vectors after each phase

## References

- Issue: https://github.com/johnnyt/aws_encryption_sdk/issues/60
- Encrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md
- Decrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Frame Format: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md
- Header Format: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md
- Footer Format: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md
- Python SDK Streaming: https://github.com/aws/aws-encryption-sdk-python/blob/master/src/aws_encryption_sdk/streaming_client.py
