# Research: Create test vector harness and integrate with workflow commands

**Issue**: #13 - Create test vector harness and integrate with workflow commands
**Date**: 2026-01-25
**Status**: Research complete

## Issue Summary

This issue establishes the foundation for test-driven development against the official AWS Encryption SDK test vectors. The deliverables are:

1. **Test Vector Repository Setup**: Clone and manage `aws-encryption-sdk-test-vectors` locally
2. **Test Harness Implementation**: Parse manifests, load keys, execute tests, validate results
3. **Integration Tests**: ExUnit test modules that run test vector suites
4. **Workflow Command Updates**: Enhance `/research_issue`, `/create_plan`, `/implement_plan` with test vector awareness

## Current Implementation State

### Existing Code

#### Test Infrastructure
- `test/test_helper.exs:1` - Minimal ExUnit setup (`ExUnit.start()` only)
- No `test/support/` directory exists
- No `test/fixtures/` directory exists
- All tests use `async: true` for parallel execution

#### Test Files (Current)
- `test/aws_encryption_sdk_test.exs` - Main module tests
- `test/aws_encryption_sdk/algorithm_suite_test.exs` - Algorithm suite tests (267 lines)
- `test/aws_encryption_sdk/crypto/hkdf_test.exs` - HKDF with RFC 5869 vectors (290 lines)
- `test/aws_encryption_sdk/format/*.exs` - Message format tests (6 files)
- `test/aws_encryption_sdk/materials/encrypted_data_key_test.exs` - EDK tests

#### JSON Parsing
- **Jason not explicitly declared** in `mix.exs`
- Available as transitive dependency from `excoveralls`, `credo`, `mix_audit`
- Should add explicit dependency for production use

#### Existing Test Patterns
From `test/aws_encryption_sdk/crypto/hkdf_test.exs:22-132`:
- Test vectors hardcoded as module attributes using `Base.decode16!/1`
- RFC 5869 and Wycheproof vectors inline (not from external files)
- No file I/O in tests currently

### Relevant Patterns

#### Message Format Modules (For Test Vector Execution)
- `lib/aws_encryption_sdk/format/message.ex:45-58` - Complete message deserialization
- `lib/aws_encryption_sdk/format/header.ex:140-145` - Version-aware header parsing
- `lib/aws_encryption_sdk/format/body.ex` - Frame/non-frame body parsing

#### Algorithm Suite Helpers (For Test Filtering)
- `AlgorithmSuite.committed?/1` (line 498) - Check if suite has commitment
- `AlgorithmSuite.signed?/1` (line 507) - Check if suite requires ECDSA
- `AlgorithmSuite.deprecated?/1` (line 526) - Check if suite is legacy
- `AlgorithmSuite.by_id/1` (lines 440-490) - Lookup suite by hex ID

### Dependencies

**What exists**:
- Message format parsing (header, body, footer)
- Algorithm suite definitions (all 11 suites)
- HKDF key derivation
- Encrypted data key serialization

**What's missing (required for full test vector execution)**:
- Keyrings (raw AES, raw RSA, AWS KMS)
- CMM implementation
- AES-GCM encryption/decryption wrappers
- ECDSA signature verification
- Commitment key validation

**Note**: The harness can still be built and tested with message parsing/validation even without full decryption capability. Some test vectors can partially validate (structure, headers, etc.) before full crypto is implemented.

## Specification Requirements

### Source Documents

- [aws-crypto-tools-test-vector-framework](https://github.com/awslabs/aws-crypto-tools-test-vector-framework) - Framework specification
- [aws-encryption-sdk-test-vectors](https://github.com/awslabs/aws-encryption-sdk-test-vectors) - Actual test vectors
- [0002-keys.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0002-keys.md) - Keys manifest format
- [0004-awses-message-decryption.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md) - Decrypt manifest format

### MUST Requirements

1. **Version Support** (0004-awses-message-decryption.md)
   > Implementations MUST identify which manifest versions they support.

   Keys manifest: Version 3 (current)
   Decrypt manifest: Versions 2, 3, 4 supported

2. **URI Resolution** (Framework spec)
   > Implementations MUST resolve `file://` URIs relative to the parent directory of the manifest file.

   Implementation: Strip `file://` prefix, join with manifest's parent directory.

3. **Type Validation** (0001-meta.md)
   > Manifest `type` field MUST match the expected manifest type when processing.

   Validate `manifest.type` equals `"awses-decrypt"` or `"keys"` as appropriate.

4. **Result Validation** (0004-awses-message-decryption.md)
   > For success cases: MUST validate that decryption produces the expected plaintext.
   > For error cases: MUST verify that decryption fails (exact error message is NOT validated).

### SHOULD Requirements

1. **Graceful Degradation**
   > Implementations SHOULD skip tests gracefully when dependencies are unavailable.

   Skip AWS KMS tests when no credentials; warn when test vectors not cloned.

### MAY Requirements

1. **Error Descriptions**
   > Error descriptions in failure test cases MAY be used for documentation and debugging, but implementations MAY NOT require specific error types or messages.

2. **Decryption Method**
   > When `decryption-method` is omitted, handlers MAY attempt multiple decryption variations.

## Test Vectors

### Applicable Test Vector Sets

- **awses-decrypt**: Pre-generated ciphertexts with expected plaintexts for decrypt validation
  - Location: `vectors/awses-decrypt/` in test vectors repo
  - Format: ZIP files (e.g., `python-2.3.0.zip` - 48.4 MB, most comprehensive)

- **awses-legacy**: Older format test vectors
  - Location: `vectors/awses-legacy/`
  - Not recommended for initial implementation

### Manifest File Format (Version 3)

#### Keys Manifest (`keys.json`)
```json
{
  "manifest": {
    "type": "keys",
    "version": 3
  },
  "keys": {
    "aes-256": {
      "type": "symmetric",
      "algorithm": "aes",
      "bits": 256,
      "encoding": "base64",
      "material": "base64-encoded-key-bytes",
      "encrypt": true,
      "decrypt": true
    },
    "rsa-4096-private": {
      "type": "private",
      "algorithm": "rsa",
      "bits": 4096,
      "encoding": "pem",
      "material": "-----BEGIN RSA PRIVATE KEY-----\n..."
    },
    "us-west-2-kms": {
      "type": "aws-kms",
      "key-id": "arn:aws:kms:us-west-2:...",
      "encrypt": true,
      "decrypt": true
    }
  }
}
```

#### Decrypt Manifest (`manifest.json`)
```json
{
  "manifest": {
    "type": "awses-decrypt",
    "version": 3
  },
  "client": {
    "name": "awslabs/aws-encryption-sdk-python",
    "version": "2.3.0"
  },
  "keys": "file://keys.json",
  "tests": {
    "test-uuid-001": {
      "description": "Test case description",
      "ciphertext": "file://ciphertexts/test-uuid-001.bin",
      "master-keys": [
        {
          "type": "raw",
          "key": "aes-256",
          "provider-id": "aws-raw-vectors-persistant",
          "encryption-algorithm": "aes"
        }
      ],
      "result": {
        "output": {
          "plaintext": "file://plaintexts/small.bin"
        }
      }
    }
  }
}
```

### Master Key Types

| Type | Fields | Use Case |
|------|--------|----------|
| `raw` + `aes` | `key`, `provider-id`, `encryption-algorithm` | Raw AES keyring |
| `raw` + `rsa` | `key`, `provider-id`, `encryption-algorithm`, `padding-algorithm`, `padding-hash` | Raw RSA keyring |
| `aws-kms` | `key` | AWS KMS keyring |
| `aws-kms-mrk-aware` | `key` | Multi-region key keyring |
| `aws-kms-mrk-aware-discovery` | `default-mrk-region`, `aws-kms-discovery-filter` | Discovery keyring |

### Implementation Order

#### Phase 1: Test Harness Core (No External Dependencies)

| Component | Description | Priority |
|-----------|-------------|----------|
| `TestVectorHarness` module | Core harness with manifest parsing | Start here |
| `file://` URI resolution | Resolve paths relative to manifest | Start here |
| JSON manifest parsing | Parse `manifest.json` and `keys.json` | Start here |
| Test setup script | Clone test vectors to `test/fixtures/test_vectors/` | Start here |

#### Phase 2: Basic Test Execution

| Test ID Category | Algorithm | Key Type | Description |
|------------------|-----------|----------|-------------|
| Raw AES + 0x0478 | Committed, unsigned | AES-256 | Simplest committed suite |
| Raw AES + 0x0014 | Legacy, no KDF | AES-128 | Simplest overall (canonical uses this) |
| Non-framed messages | Various | AES | Single body, no frames |

#### Phase 3: Extended Coverage

| Test ID Category | Algorithm | Key Type | Description |
|------------------|-----------|----------|-------------|
| Raw AES + 0x0578 | Committed, ECDSA signed | AES-256 | Adds signature verification |
| Raw RSA | Various | RSA-4096 | OAEP and PKCS1 padding |
| Framed messages | Various | AES | Multi-frame bodies |

#### Phase 4: Edge Cases & Negatives

| Category | Description | Expected |
|----------|-------------|----------|
| Empty plaintext | 0 bytes | Success |
| Wrong key | Incorrect decryption key | Error |
| Tampered ciphertext | Modified bytes | Authentication error |
| Commitment mismatch | Invalid commitment key | Error for 0x0478/0x0578 |

### Test Vector Details

**How to fetch**:
```bash
# Clone test vectors repository
git clone https://github.com/awslabs/aws-encryption-sdk-test-vectors.git test/fixtures/test_vectors

# Or download specific ZIP
curl -L -O https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip
unzip python-2.3.0.zip -d test/fixtures/test_vectors
```

**Key material available**:
- AES-128, AES-192, AES-256 symmetric keys (base64 encoded)
- RSA-4096 private/public key pairs (PEM encoded)
- AWS KMS key ARNs (require AWS credentials)

**Recommended starting test vector**:
From the canonical manifests or python-2.3.0.zip:
- Algorithm: 0x0014 (AES-128-GCM, no KDF) or 0x0478 (AES-256-GCM with commitment)
- Keyring: Raw AES (single key)
- Framing: Non-framed (frame size = 0)
- Plaintext: Small (~10 KB)

## Implementation Considerations

### Technical Approach

#### 1. Directory Structure

```
test/
├── support/
│   ├── test_vector_setup.exs     # Setup script (git clone)
│   └── test_vector_harness.ex    # Core harness module
├── test_vectors/
│   ├── decrypt_test.exs          # Decrypt vector tests
│   └── encrypt_test.exs          # Encrypt vector tests
└── fixtures/
    └── test_vectors/             # Cloned repository (gitignored)
        ├── vectors/
        │   └── awses-decrypt/
        │       └── python-2.3.0/
        └── ...
```

#### 2. TestVectorHarness Module Design

```elixir
defmodule AwsEncryptionSdk.TestVectorHarness do
  @moduledoc """
  Harness for loading and executing AWS Encryption SDK test vectors.
  """

  defstruct [:manifest_path, :base_dir, :keys, :tests]

  @doc "Load a test manifest and its referenced keys."
  def load_manifest(path) do
    base_dir = Path.dirname(path)
    manifest = path |> File.read!() |> Jason.decode!()
    keys = load_keys(base_dir, manifest["keys"])
    {:ok, %__MODULE__{manifest_path: path, base_dir: base_dir, keys: keys, tests: manifest["tests"]}}
  end

  @doc "Resolve a file:// URI relative to base directory."
  def resolve_uri(base_dir, "file://" <> relative_path) do
    Path.join(base_dir, relative_path)
  end

  @doc "Load key material from keys manifest."
  def load_keys(base_dir, keys_uri) do
    keys_path = resolve_uri(base_dir, keys_uri)
    keys_manifest = keys_path |> File.read!() |> Jason.decode!()
    keys_manifest["keys"]
  end

  @doc "Build appropriate keyring from master-key spec."
  def build_keyring(master_key_spec, keys) do
    # Implementation depends on keyring availability
  end

  @doc "Execute a single test case."
  def execute_test(test_case, keys, base_dir) do
    ciphertext_path = resolve_uri(base_dir, test_case["ciphertext"])
    ciphertext = File.read!(ciphertext_path)

    case test_case["result"] do
      %{"output" => output} ->
        # Expected success
        expected_path = resolve_uri(base_dir, output["plaintext"])
        expected = File.read!(expected_path)
        # Run decryption and compare

      %{"error" => _} ->
        # Expected failure
        # Run decryption and verify it fails
    end
  end
end
```

#### 3. Test Filtering with ExUnit Tags

```elixir
# In test/test_vectors/decrypt_test.exs

defmodule AwsEncryptionSdk.TestVectors.DecryptTest do
  use ExUnit.Case, async: true

  @moduletag :test_vectors

  # Skip if test vectors not present
  @moduletag skip: not File.exists?("test/fixtures/test_vectors")

  describe "raw AES keyring" do
    @describetag algorithm: :aes
    @describetag keyring: :raw_aes

    test "decrypt with committed algorithm suite", context do
      # Test implementation
    end
  end
end
```

Run filtered tests:
```bash
mix test --only test_vectors
mix test --only keyring:raw_aes
mix test --only algorithm_suite:0x0478
```

#### 4. Graceful Handling of Missing Vectors

```elixir
# In test/support/test_vector_setup.exs

defmodule AwsEncryptionSdk.TestVectorSetup do
  @test_vectors_path "test/fixtures/test_vectors"
  @test_vectors_repo "https://github.com/awslabs/aws-encryption-sdk-test-vectors.git"

  def ensure_test_vectors do
    unless File.exists?(@test_vectors_path) do
      IO.puts("""

      ⚠️  Test vectors not found at #{@test_vectors_path}

      To enable test vector tests, run:

          git clone #{@test_vectors_repo} #{@test_vectors_path}

      Or download specific vectors:

          curl -L -O https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip
          unzip python-2.3.0.zip -d #{@test_vectors_path}

      """)
      :not_available
    else
      :available
    end
  end

  def vectors_available? do
    File.exists?(@test_vectors_path)
  end
end
```

### Potential Challenges

1. **Large Test Vector Files**: The `python-2.3.0.zip` is 48 MB; consider downloading on-demand or caching.

2. **AWS KMS Tests**: Require AWS credentials; must be skipped or mocked in CI without creds.

3. **PEM Key Parsing**: RSA keys in PEM format need careful handling with `:public_key.pem_decode/1`.

4. **Test Execution Time**: Hundreds of test vectors; consider parallel execution and smart filtering.

5. **Incremental Implementation**: Full test vector execution requires keyrings and crypto; plan for partial validation (parsing, structure) before full decryption.

### Open Questions

1. **Test Vector Storage**: Should we commit extracted test vectors or just the ZIP?
   - Recommendation: Clone repo to gitignored directory; CI downloads fresh

2. **Which ZIP to Use**: `python-2.3.0.zip` is most comprehensive but large.
   - Recommendation: Start with canonical manifests from framework repo for minimal footprint, then add python-2.3.0 for full coverage

3. **Parallelism Strategy**: How to balance async tests with shared test vector state?
   - Recommendation: Load manifests once in setup_all, execute tests in parallel

## Workflow Command Updates

### research_issue.md Changes

Add after Step 3 (parallel agents already include test-vector-researcher):

The current `/research_issue` command already spawns a `test-vector-researcher` agent. The command is already well-integrated. Minor enhancements could include:

1. Add explicit mention to summarize test vector counts in the final summary
2. Include specific test vector IDs in the research output (already in template)

### create_plan.md Changes

The current `/create_plan` template already includes:
- Test Vectors section with Validation Strategy
- Test Vector Summary table by phase
- Per-phase test vector specifications

No major changes needed. Already well-integrated.

### implement_plan.md Changes

The current `/implement_plan` command already includes:
- Test vector validation after each phase
- Example test vector execution code
- Explicit "NEVER skip test vector validation" note

No major changes needed. Already well-integrated.

**Conclusion**: The workflow commands already have good test vector integration in their templates. The main work is implementing the actual `TestVectorHarness` module that makes the test vectors usable.

## Implementation Dependencies

### Dependency Graph

```
TestVectorHarness
├── Jason (explicit dependency needed)
├── File I/O (stdlib)
├── Base.decode64/1 (stdlib)
└── :public_key.pem_decode/1 (OTP - for RSA keys)

Test Execution (future)
├── TestVectorHarness
├── Raw AES Keyring (Issue #TBD)
├── Raw RSA Keyring (Issue #TBD)
├── AES-GCM wrapper (Issue #TBD)
└── Message.deserialize/1 (already implemented)
```

### Minimum Viable Harness

The harness can be built and used for **parsing validation** immediately:
1. Parse manifest files
2. Resolve `file://` URIs
3. Load binary files
4. Validate message structure via `Message.deserialize/1`
5. Report parsing success/failure

Full decrypt validation requires keyrings (future issues).

## Recommended Next Steps

1. **Create implementation plan**: `/create_plan thoughts/shared/research/2026-01-25-GH13-test-vector-harness.md`

2. **Phase the implementation**:
   - Phase 1: Add Jason dependency, create `test/support/` structure
   - Phase 2: Implement `TestVectorHarness` core (manifest parsing, URI resolution)
   - Phase 3: Implement `test/support/test_vector_setup.exs`
   - Phase 4: Create `test/test_vectors/decrypt_test.exs` with structure validation
   - Phase 5: Update `.gitignore` and README documentation

3. **Future issues** (after this one):
   - Implement Raw AES Keyring (to enable full test vector execution)
   - Implement AES-GCM wrapper
   - Implement Raw RSA Keyring
   - Implement ECDSA signature verification

## References

- Issue: https://github.com/owner/repo/issues/13
- Test Vector Framework: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- Keys Spec: https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0002-keys.md
- Decrypt Spec: https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md
- Python SDK Test Handlers: https://github.com/aws/aws-encryption-sdk-python/tree/master/test_vector_handlers
