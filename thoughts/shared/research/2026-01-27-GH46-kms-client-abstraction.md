# Research: Implement KMS Client Abstraction Layer

**Issue**: #46 - Implement KMS Client Abstraction Layer
**Date**: 2026-01-27
**Status**: Research complete

## Issue Summary

Create an abstraction layer for AWS KMS client operations to support the AWS KMS keyrings. This enables testability via mocking and flexibility to support different AWS client libraries. The abstraction needs to support three KMS operations: `GenerateDataKey`, `Encrypt`, and `Decrypt`.

## Current Implementation State

### Existing Code

The codebase has established patterns for keyrings and external cryptographic operations:

- `lib/aws_encryption_sdk/keyring/behaviour.ex` - Keyring behaviour with `on_encrypt/1` and `on_decrypt/2` callbacks
- `lib/aws_encryption_sdk/keyring/raw_aes.ex` - Raw AES keyring using `:crypto` module
- `lib/aws_encryption_sdk/keyring/raw_rsa.ex` - Raw RSA keyring using `:public_key` module
- `lib/aws_encryption_sdk/keyring/multi.ex` - Multi-keyring with type-based dispatch
- `lib/aws_encryption_sdk/cmm/default.ex` - Default CMM with keyring dispatch pattern
- `lib/aws_encryption_sdk/crypto/aes_gcm.ex` - Wrapper around `:crypto.crypto_one_time_aead/7`
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex` - EDK struct with `key_provider_id`, `key_provider_info`, `ciphertext`

### Relevant Patterns

**1. Struct-based Configuration**
All keyrings use structs with enforced keys:
```elixir
defstruct [:key_namespace, :key_name, :wrapping_key, :wrapping_algorithm]
```

**2. Constructor Validation Pattern**
All keyrings use `with` pipeline in `new/N`:
```elixir
def new(key_namespace, key_name, wrapping_key, wrapping_algorithm) do
  with :ok <- validate_step_1(...),
       :ok <- validate_step_2(...) do
    {:ok, %__MODULE__{...}}
  end
end
```

**3. Type-based Dispatch Pattern**
CMM and Multi-keyring dispatch via pattern matching:
```elixir
def call_wrap_key(%RawAes{} = keyring, materials), do: RawAes.wrap_key(keyring, materials)
def call_wrap_key(%RawRsa{} = keyring, materials), do: RawRsa.wrap_key(keyring, materials)
```

**4. External Crypto Wrapping**
Crypto operations wrapped in dedicated modules:
- `AesGcm.encrypt/5` wraps `:crypto.crypto_one_time_aead/7`
- RSA uses `:public_key.encrypt_public/3` directly with try/rescue

**5. Error Handling**
- Validation errors return immediately from constructor
- Operational errors wrapped in `{:error, reason}` tuples
- Multi-keyring collects errors: `{:error, {:all_keyrings_failed, [reasons]}}`

### Dependencies

**Current** (`mix.exs`):
- `{:jason, "~> 1.4"}` - JSON parsing only

**No AWS client yet** - need to add `ex_aws_kms` or `aws-elixir`

## Specification Requirements

### Source Documents

- [aws-kms-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md) - Standard KMS keyring
- [aws-kms-mrk-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md) - MRK keyring
- [aws-kms-discovery-keyring.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-discovery-keyring.md) - Discovery keyring

### MUST Requirements

1. **Client Not Null** (aws-kms-keyring.md)
   > The AWS KMS SDK client MUST NOT be null.

   Implementation: Validate client is provided in keyring constructor.

2. **GenerateDataKey Parameters** (aws-kms-keyring.md)
   > - KeyId: MUST be the keyring's KMS key identifier
   > - NumberOfBytes: MUST be the key derivation input length specified by the algorithm suite
   > - EncryptionContext: MUST be the encryption context included in the input encryption materials
   > - GrantTokens: MUST be this keyring's grant tokens

   Implementation: KMS client `generate_data_key/4` must accept all these parameters.

3. **Encrypt Parameters** (aws-kms-keyring.md)
   > - KeyId: MUST be the configured AWS KMS key identifier
   > - PlaintextDataKey: MUST be the plaintext data key in the encryption materials
   > - EncryptionContext: MUST be the encryption context included in the input encryption materials
   > - GrantTokens: MUST be this keyring's grant tokens

   Implementation: KMS client `encrypt/4` must accept all these parameters.

4. **Decrypt Parameters** (aws-kms-keyring.md)
   > - KeyId: MUST be the configured AWS KMS key identifier
   > - CiphertextBlob: MUST be the encrypted data key ciphertext
   > - EncryptionContext: MUST be the encryption context included in the input decryption materials
   > - GrantTokens: MUST be this keyring's grant tokens

   Implementation: KMS client `decrypt/4` must accept all these parameters.

5. **Response Validation - GenerateDataKey** (aws-kms-keyring.md)
   > The response plaintext length MUST match the specification of the algorithm suite's Key Derivation Input Length field.
   > The KeyId returned MUST be a valid AWS KMS key ARN.

   Implementation: Validate response in keyring, not client.

6. **Response Validation - Decrypt** (aws-kms-keyring.md)
   > The returned KeyId MUST equal the configured AWS KMS key identifier.
   > Response Plaintext length MUST equal the key derivation input length specified by the algorithm suite.

   Implementation: Validate response in keyring, not client.

7. **Grant Tokens** (aws-kms-keyring.md)
   > GrantTokens: MUST be this keyring's grant tokens

   Implementation: All three operations must accept and pass grant tokens.

8. **Error Handling - Encrypt** (aws-kms-keyring.md)
   > If the call fails, OnEncrypt MUST fail.

   Implementation: Return `{:error, reason}` on KMS failure.

9. **Error Handling - Decrypt** (aws-kms-keyring.md)
   > Failures are collected; subsequent keys are attempted.
   > If all attempts fail, OnDecrypt MUST yield an error that includes all the collected errors.

   Implementation: Client returns errors; keyring collects and aggregates.

### SHOULD Requirements

1. **Region Validation** (aws-kms-mrk-discovery-keyring.md)
   > The keyring SHOULD fail initialization if the provided region does not match the region of the KMS client.

   Implementation: Optionally validate region matches client configuration.

2. **Descriptive Errors** (keyring-interface.md)
   > Keyrings SHOULD return descriptive error information when operations fail.

   Implementation: Include KMS error codes and messages in error responses.

### MAY Requirements

1. **User Agent String** (branch-key-store.md, GitHub Issue #59)
   > AWS KMS Keyring SHOULD add custom identifier to KMS client user agent string

   Implementation: Optionally append `"aws-encryption-sdk-elixir"` to user agent.

## Test Vectors

### Harness Setup

Test vectors are accessed via the test vector harness:

```elixir
# Check availability
TestVectorSetup.vectors_available?()

# Find and load manifest
{:ok, manifest_path} = TestVectorSetup.find_manifest("**/manifest.json")
{:ok, harness} = TestVectorHarness.load_manifest(manifest_path)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)
```

### Applicable Test Vector Sets

Local test vectors at:
- **Path**: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- **Manifest version**: Supports 2, 3, 4
- **Total KMS references**: 2,007 across manifest and keys files
- **Format**: Decrypt-only (ciphertexts pre-generated by Python SDK 2.2.0)

### KMS Keys in Test Vectors

From `keys.json`:

| Key Name | Type | ARN | Decrypt |
|----------|------|-----|---------|
| `us-west-2-decryptable` | Standard | `arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f` | Yes |
| `us-west-2-encrypt-only` | Standard | `arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad` | No |
| `us-west-2-mrk` | MRK | `arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |
| `us-east-1-mrk` | MRK | `arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7` | Yes |

### Implementation Order

#### Phase 1: Basic KMS Client (This Issue)

Focus on client abstraction, not keyring. Test with mocks:

| Priority | Component | Description |
|----------|-----------|-------------|
| 1 | Behaviour | Define `@callback` for all three operations |
| 2 | Types | Define request/response types |
| 3 | Mock Client | Implement mock for unit testing |
| 4 | ExAws Client | Implement real client using ex_aws_kms |

#### Phase 2: KMS Keyring (Issue #48)

After client abstraction complete, test against real vectors:

| Test ID | Key | Notes |
|---------|-----|-------|
| `686aae13-ec9b-4eab-9dc0-0a1794a2ba34` | us-west-2-decryptable | Simplest case |
| `7bb5cace-2274-4134-957d-0426c9f96637` | us-west-2-mrk | MRK key |
| `af7b820f-b4a9-48a2-8afc-40b747220f69` | us-east-1-mrk | Cross-region MRK |

### Test Vector Constraints

**Important**: KMS test vectors require:
- Internet access
- Valid AWS credentials with `kms:Decrypt` permission
- Cannot run offline

**Testing Strategy**:
1. Unit tests with mock KMS client (no AWS required)
2. Integration tests with real KMS (optional, requires AWS credentials)

### Key Material

KMS keys in test vectors don't have local material:

```elixir
# From test_vector_harness.ex:188-190
def decode_key_material(%{"type" => "aws-kms"}) do
  # AWS KMS keys don't have local material
  {:ok, :aws_kms}
end
```

## Implementation Considerations

### Technical Approach

#### Module Structure

```
lib/aws_encryption_sdk/keyring/
├── kms_client.ex                    # Behaviour definition
└── kms_client/
    ├── ex_aws.ex                    # ExAws implementation
    └── mock.ex                      # Test mock implementation
```

#### KMS Client Behaviour

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsClient do
  @moduledoc """
  Behaviour for AWS KMS client implementations.
  """

  @type key_id :: String.t()
  @type encryption_context :: %{String.t() => String.t()}
  @type grant_tokens :: [String.t()]

  @type generate_data_key_result :: %{
    plaintext: binary(),
    ciphertext: binary(),
    key_id: String.t()
  }

  @type encrypt_result :: %{
    ciphertext: binary(),
    key_id: String.t()
  }

  @type decrypt_result :: %{
    plaintext: binary(),
    key_id: String.t()
  }

  @callback generate_data_key(
    client :: struct(),
    key_id :: key_id(),
    number_of_bytes :: pos_integer(),
    encryption_context :: encryption_context(),
    grant_tokens :: grant_tokens()
  ) :: {:ok, generate_data_key_result()} | {:error, term()}

  @callback encrypt(
    client :: struct(),
    key_id :: key_id(),
    plaintext :: binary(),
    encryption_context :: encryption_context(),
    grant_tokens :: grant_tokens()
  ) :: {:ok, encrypt_result()} | {:error, term()}

  @callback decrypt(
    client :: struct(),
    key_id :: key_id(),
    ciphertext :: binary(),
    encryption_context :: encryption_context(),
    grant_tokens :: grant_tokens()
  ) :: {:ok, decrypt_result()} | {:error, term()}
end
```

#### ExAws Implementation Struct

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsClient.ExAws do
  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  defstruct [:region, :config]

  def new(opts \\ []) do
    region = Keyword.get(opts, :region)
    config = Keyword.get(opts, :config, [])
    {:ok, %__MODULE__{region: region, config: config}}
  end

  @impl true
  def generate_data_key(%__MODULE__{} = client, key_id, number_of_bytes, encryption_context, grant_tokens) do
    request = ExAws.KMS.generate_data_key(key_id, %{
      number_of_bytes: number_of_bytes,
      encryption_context: encryption_context,
      grant_tokens: grant_tokens
    })

    case ExAws.request(request, client.config) do
      {:ok, response} -> {:ok, normalize_generate_response(response)}
      {:error, error} -> {:error, normalize_error(error)}
    end
  end

  # ... encrypt/decrypt implementations
end
```

#### Mock Implementation

```elixir
defmodule AwsEncryptionSdk.Keyring.KmsClient.Mock do
  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  defstruct [:responses, :call_log]

  def new(responses \\ %{}) do
    {:ok, %__MODULE__{responses: responses, call_log: []}}
  end

  @impl true
  def generate_data_key(%__MODULE__{responses: responses} = client, key_id, number_of_bytes, _ec, _gt) do
    case Map.get(responses, {:generate_data_key, key_id}) do
      nil -> {:error, :key_not_found}
      response -> {:ok, response}
    end
  end

  # ... other implementations
end
```

### Potential Challenges

1. **Async vs Sync Calls**
   - ExAws supports async requests
   - Keyring operations are synchronous
   - Need to ensure blocking behavior

2. **Error Normalization**
   - AWS SDK returns various error formats
   - Need consistent error representation
   - Include enough detail for debugging

3. **Credential Configuration**
   - Multiple credential sources (env, file, IAM role)
   - Should leverage ExAws defaults
   - May need to expose configuration options

4. **Region Handling**
   - Client region must match key region (for non-MRK)
   - MRK keyrings need region transformation
   - Region extraction from ARN needed

5. **HTTP Client Selection**
   - ExAws supports hackney, httpc, finch
   - Need to document configuration
   - May affect performance

### Open Questions

1. **Credential Exposure**: Should we expose AWS credential configuration or rely entirely on ExAws defaults?
   - Recommendation: Rely on ExAws defaults, but allow config passthrough

2. **Client Caching**: Should we cache KMS clients per region?
   - Recommendation: No caching in client abstraction; leave to keyring layer

3. **Retry Policy**: Should we implement custom retry logic?
   - Recommendation: Use ExAws defaults initially

4. **Telemetry**: Should KMS operations emit telemetry events?
   - Recommendation: Add telemetry hooks for observability

## Recommended Next Steps

1. **Add Dependencies**: Add `ex_aws`, `ex_aws_kms`, `hackney` to `mix.exs`

2. **Create Implementation Plan**:
   ```
   /create_plan thoughts/shared/research/2026-01-27-GH46-kms-client-abstraction.md
   ```

3. **Implementation Order**:
   - Define behaviour module with types
   - Implement mock client for testing
   - Implement ExAws client
   - Add integration test infrastructure

4. **After This Issue**:
   - Issue #47: KMS Key ARN Utilities
   - Issue #48: AWS KMS Keyring

## References

- Issue: https://github.com/riddler/aws-encryption-sdk-elixir/issues/46
- Spec - KMS Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-keyring.md
- Spec - MRK Keyring: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
- ExAws KMS: https://hexdocs.pm/ex_aws_kms/
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
