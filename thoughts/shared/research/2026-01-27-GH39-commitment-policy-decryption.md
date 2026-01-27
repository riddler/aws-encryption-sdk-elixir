# Research: Add commitment policy enforcement for decryption

**Issue**: #39 - Add commitment policy enforcement for decryption
**Date**: 2026-01-27
**Status**: Research complete

## Issue Summary

Update the Decrypt API to support CMM-based decryption with commitment policy enforcement. The current `Decrypt.decrypt/2` works directly with pre-assembled `DecryptionMaterials`. We need to:
1. Update Decrypt to accept a Client and use its CMM to get materials
2. Enforce commitment policy during decryption
3. Support decrypting messages encrypted with different algorithm suites based on policy

The commitment policy determines which messages can be decrypted:
- `:require_encrypt_require_decrypt` - Only decrypt committed messages (most secure, default)
- `:require_encrypt_allow_decrypt` - Decrypt both committed and non-committed
- `:forbid_encrypt_allow_decrypt` - Decrypt both (legacy compatibility)

## Current Implementation State

### Existing Code

#### Core Decrypt Module
- `lib/aws_encryption_sdk/decrypt.ex` - Main decryption implementation

**Current signature (line 51-68):**
```elixir
@spec decrypt(binary(), DecryptionMaterials.t()) ::
        {:ok, decrypt_result()} | {:error, term()}
def decrypt(ciphertext, %DecryptionMaterials{} = materials)
```

**Current data flow:**
1. `check_base64_encoding/1` - Detects Base64-encoded messages
2. `Message.deserialize/1` - Parses header, body, optional footer
3. `derive_data_key/2` - Derives encryption key from plaintext data key
4. `verify_commitment/3` - Validates key commitment (for committed suites)
5. `verify_header_auth_tag/2` - Authenticates header using AES-GCM
6. `decrypt_body/3` - Decrypts framed or non-framed body
7. `verify_signature/2` - Verifies ECDSA signature (for signed suites)

**Key observation**: The current implementation already handles commitment verification internally but requires materials to be pre-assembled externally.

#### Client Module
- `lib/aws_encryption_sdk/client.ex` - Client configuration with commitment policy

**Client struct (lines 51-63):**
```elixir
@type t :: %__MODULE__{
  cmm: CmmBehaviour.t(),
  commitment_policy: commitment_policy(),
  max_encrypted_data_keys: non_neg_integer() | nil
}
```

**Has encryption support (lines 160-173)** but no decrypt method yet.

#### CMM Behaviour
- `lib/aws_encryption_sdk/cmm/behaviour.ex` - CMM interface

**Decrypt callback (lines 157-158):**
```elixir
@callback get_decryption_materials(cmm :: t(), request :: decrypt_materials_request()) ::
            {:ok, DecryptionMaterials.t()} | {:error, term()}
```

**Policy validation function (lines 259-272):**
```elixir
@spec validate_commitment_policy_for_decrypt(AlgorithmSuite.t(), commitment_policy()) ::
        :ok | {:error, :commitment_policy_requires_committed_suite}
```

#### Default CMM
- `lib/aws_encryption_sdk/cmm/default.ex` - Default CMM implementation

**get_decryption_materials (lines 166-189):** Already implemented with:
1. Policy validation
2. Encryption context validation
3. Signing context consistency check
4. Verification key extraction
5. Keyring unwrap_key dispatch

#### Header Parsing
- `lib/aws_encryption_sdk/format/header.ex` - Header serialization/parsing

**Deserialization (lines 140-145):**
```elixir
@spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
```

Pattern matches on version byte:
- `<<0x02, ...>>` - V2 (committed suites)
- `<<0x01, 0x80, ...>>` - V1 (legacy suites)

Returns `%Header{algorithm_suite: suite, encrypted_data_keys: edks, encryption_context: context, ...}`

#### Algorithm Suite
- `lib/aws_encryption_sdk/algorithm_suite.ex` - Suite definitions

**Commitment check (lines 498-499):**
```elixir
@spec committed?(t()) :: boolean()
def committed?(%__MODULE__{commitment_length: length}), do: length > 0
```

**Committed suites:**
- `0x0578` - AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
- `0x0478` - AES_256_GCM_HKDF_SHA512_COMMIT_KEY

### Relevant Patterns

**CMM dispatch pattern** (from `Client.encrypt/3`):
```elixir
defp get_encryption_materials(%__MODULE__{cmm: cmm}, plaintext, opts) do
  # Build request
  request = %{
    commitment_policy: commitment_policy,
    encryption_context: context,
    # ...
  }

  # Dispatch based on CMM type
  call_get_encryption_materials(cmm, request)
end

defp call_get_encryption_materials(%Default{} = cmm, request) do
  Default.get_encryption_materials(cmm, request)
end
```

**Policy validation pattern** (from `Client.encrypt/3`):
```elixir
with :ok <- CmmBehaviour.validate_commitment_policy_for_encrypt(suite, policy),
     {:ok, materials} <- get_encryption_materials(client, plaintext, opts),
     :ok <- CmmBehaviour.validate_commitment_policy_for_encrypt(materials.algorithm_suite, policy),
     # ...
```

### Dependencies

**What this depends on:**
- `Client` module (exists, has commitment policy)
- `CmmBehaviour.validate_commitment_policy_for_decrypt/2` (exists)
- `Default.get_decryption_materials/2` (exists)
- `Header.deserialize/1` (exists, extracts algorithm suite)
- `Decrypt.decrypt/2` (exists, needs to become internal)

**What depends on this:**
- Main public API `AwsEncryptionSdk.decrypt/2` (needs to be added)

## Specification Requirements

### Source Documents
- [client-apis/decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Decrypt operation spec
- [client-apis/client.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md) - Commitment policy
- [framework/cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - CMM decrypt materials

### MUST Requirements

1. **Decrypt Inputs** (decrypt.md)
   > "The client MUST require the following as inputs to this operation: Encrypted Message"
   > "The client MUST require exactly one of the following types of inputs: Cryptographic Materials Manager (CMM) [or] Keyring"

   Implementation: Accept `encrypted_message` (binary), and a Client with CMM.

2. **Decrypt Outputs** (decrypt.md)
   > The operation MUST provide: decrypted plaintext, encryption context, algorithm suite

   Implementation: Return `{:ok, %{plaintext: binary, encryption_context: map, algorithm_suite: atom, header: Header.t()}}`

3. **Default Commitment Policy** (client.md)
   > "If no commitment policy is provided the default MUST be REQUIRE_ENCRYPT_REQUIRE_DECRYPT."

   Implementation: Already enforced in `Client.new/2`.

4. **Commitment Policy Enforcement** (client.md)
   > `:require_encrypt_require_decrypt` - "decrypt MUST only support algorithm suites that have a Key Commitment value of True"
   > `:require_encrypt_allow_decrypt` - "decrypt MUST support all algorithm suites"
   > `:forbid_encrypt_allow_decrypt` - "decrypt MUST support all algorithm suites"

   Implementation: Validate algorithm suite before calling CMM.

5. **Decrypt Operation Sequence** (decrypt.md)
   > Must execute five steps in strict order:
   > 1. Parse the header
   > 2. Get the decryption materials
   > 3. Verify the header
   > 4. Decrypt the message body
   > 5. Verify the signature (if algorithm suite includes signature algorithm)

   Implementation: Parse header first to get algorithm suite, validate policy, then get materials.

6. **Policy Validation Timing** (decrypt.md)
   > "Before proceeding, validate the algorithm suite ID against the commitment policy."

   Implementation: Validate BEFORE calling CMM.get_decryption_materials.

7. **Security Constraint** (decrypt.md)
   > "This operation MUST NOT release any unauthenticated plaintext or unauthenticated associated data"

   Implementation: Only return after all verification steps succeed.

8. **Encrypted Data Key Limit** (decrypt.md)
   > "Reject messages where encrypted data keys exceed the configured maximum"

   Implementation: Check `length(header.encrypted_data_keys) <= client.max_encrypted_data_keys`.

### SHOULD Requirements

1. **Base64 Detection** (decrypt.md)
   > Implementations "SHOULD detect the first two bytes of the Base64 encoding" and fail with a more specific error message.

   Implementation: Already implemented in `check_base64_encoding/1`.

2. **Signing Context Consistency** (cmm-interface.md)
   > "If the algorithm suite lacks a signing algorithm but the encryption context contains the reserved `aws-crypto-public-key` key, the operation should fail."

   Implementation: Already implemented in `Default.get_decryption_materials/2`.

### MAY Requirements

1. **Max Encrypted Data Keys** (client.md)
   > Client MAY have a configurable maximum for encrypted data keys.

   Implementation: Already in Client struct, needs enforcement during decrypt.

## Test Vectors

### Harness Setup

Test vectors are available at:
- **Location**: `test/fixtures/test_vectors/vectors/awses-decrypt/`
- **Manifest**: `manifest.json` (version 2, generated by Python SDK 2.2.0)
- **Keys**: `keys.json` with symmetric (AES) and asymmetric (RSA) key material

```elixir
# Load manifest
{:ok, harness} = TestVectorHarness.load_manifest(
  "test/fixtures/test_vectors/vectors/awses-decrypt/manifest.json"
)

# List available tests
test_ids = TestVectorHarness.list_test_ids(harness)

# Load specific test
{:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
{:ok, plaintext} = TestVectorHarness.load_expected_plaintext(harness, test_id)
```

### Applicable Test Vector Sets

The project has **8,000+ test vectors** from the official AWS test suite. For commitment policy testing, we need to categorize by algorithm suite:

**Committed Suites (Key Commitment = True):**
- `0x0478`: AES_256_GCM_HKDF_SHA512_COMMIT_KEY
- `0x0578`: AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384

**Non-Committed Suites (Key Commitment = False):**
- `0x0378`: AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
- `0x0178`: AES_256_GCM_IV12_TAG16_HKDF_SHA256
- `0x0078`: AES_256_GCM_IV12_TAG16_NO_KDF (deprecated)
- And others (0x0014, 0x0046, 0x0114, 0x0146, etc.)

### Implementation Order

#### Phase 1: Basic Commitment Policy Tests

| Test Scenario | Algorithm Suite | Policy | Expected |
|--------------|-----------------|--------|----------|
| Committed + strict | 0x0478/0x0578 | require_require | Success |
| Non-committed + strict | 0x0178/0x0378 | require_require | **Fail** |
| Committed + transitional | 0x0478/0x0578 | require_allow | Success |
| Non-committed + transitional | 0x0178/0x0378 | require_allow | Success |
| Committed + legacy | 0x0478/0x0578 | forbid_allow | Success |
| Non-committed + legacy | 0x0178/0x0378 | forbid_allow | Success |

#### Phase 2: Raw AES Keyring Test Vectors

Already integrated vectors (need to categorize by commitment):
- `83928d8e-9f97-4861-8f70-ab1eaa6930ea` (AES-256)
- `917a3a40-3b92-48f7-9cbe-231c9bde6222` (AES-256)
- `4be2393c-2916-4668-ae7a-d26ddb8de593` (AES-128)
- `a9d3c43f-ea48-4af1-9f2b-94114ffc2ff1` (AES-192)

#### Phase 3: Raw RSA Keyring Test Vectors

Available but not yet tested:
- `8a967e4e-aeff-42f2-ba3f-2c6b94b2c59e` (PKCS#1)
- `aba06ffc-a839-4639-967c-a739d8626adc` (OAEP-MGF1 SHA512)
- `7c640f28-9fa1-4ff9-9179-196149f8c346`

#### Phase 4: Edge Cases

- Maximum EDK count enforcement
- Empty encryption context
- Messages with reproduced encryption context

### Test Vector Categorization Script

```elixir
# To categorize test vectors by algorithm suite:
defmodule TestVectorAnalyzer do
  def categorize_by_commitment(harness) do
    harness.tests
    |> Enum.map(fn {test_id, _test} ->
      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      <<version::8, suite_id::16-big, _rest::binary>> = ciphertext
      committed = suite_id in [0x0478, 0x0578]
      {test_id, version, suite_id, committed}
    end)
    |> Enum.group_by(fn {_, _, _, committed} -> committed end)
  end
end
```

## Implementation Considerations

### Technical Approach

**Step 1: Add `Client.decrypt/2`**

```elixir
@spec decrypt(t(), binary(), keyword()) ::
        {:ok, Decrypt.decrypt_result()} | {:error, term()}
def decrypt(%__MODULE__{} = client, ciphertext, opts \\ []) do
  with :ok <- check_base64_encoding(ciphertext),
       {:ok, header, body_and_footer} <- Header.deserialize(ciphertext),
       :ok <- validate_algorithm_suite(client, header.algorithm_suite),
       :ok <- validate_edk_count(client, header),
       {:ok, materials} <- get_decryption_materials(client, header, opts),
       {:ok, result} <- decrypt_with_materials(ciphertext, materials) do
    {:ok, result}
  end
end
```

**Step 2: Implement `validate_algorithm_suite/2`**

```elixir
defp validate_algorithm_suite(%__MODULE__{commitment_policy: policy}, suite) do
  CmmBehaviour.validate_commitment_policy_for_decrypt(suite, policy)
end
```

**Step 3: Implement `get_decryption_materials/3`**

```elixir
defp get_decryption_materials(client, header, opts) do
  reproduced_context = Keyword.get(opts, :encryption_context)

  request = %{
    algorithm_suite: header.algorithm_suite,
    commitment_policy: client.commitment_policy,
    encrypted_data_keys: header.encrypted_data_keys,
    encryption_context: header.encryption_context,
    reproduced_encryption_context: reproduced_context
  }

  call_get_decryption_materials(client.cmm, request)
end
```

**Step 4: Refactor `Decrypt.decrypt/2`**

Keep existing implementation as internal function called after materials are obtained:

```elixir
# Internal function called by Client
@doc false
def decrypt_with_materials(ciphertext, materials) do
  # Existing implementation
end
```

**Step 5: Update Public API**

In `lib/aws_encryption_sdk.ex`:

```elixir
@spec decrypt(Client.t(), binary(), keyword()) ::
        {:ok, decrypt_result()} | {:error, term()}
def decrypt(%Client{} = client, ciphertext, opts \\ []) do
  Client.decrypt(client, ciphertext, opts)
end
```

### Error Handling

New error atoms needed:
- `:commitment_policy_violation` - Algorithm suite doesn't match policy
- `:too_many_encrypted_data_keys` - EDK count exceeds limit

### Potential Challenges

1. **Header Parsing Efficiency**: Currently `Decrypt.decrypt/2` parses the full message. We need to parse header separately first, then continue with body/footer. May need to refactor to avoid parsing twice.

2. **Materials Validation Ordering**: Spec requires validating algorithm suite BEFORE calling CMM, but CMM also validates internally. Need to ensure double-validation is acceptable.

3. **Test Vector Distribution**: Need to identify which existing test vectors use committed vs non-committed suites to properly test all policy scenarios.

### Open Questions

1. **Signature Verification**: The current implementation has a TODO for ECDSA verification (line 239-243 in decrypt.ex). Is this blocking for this issue?

2. **Streaming Support**: The spec mentions streaming considerations. Is this in scope?

3. **Reproduced Encryption Context**: Should `Client.decrypt/3` accept `:encryption_context` option for reproduced context validation?

## Recommended Next Steps

1. **Create implementation plan**: `/create_plan thoughts/shared/research/2026-01-27-GH39-commitment-policy-decryption.md`

2. **Implementation order**:
   - Add `Client.decrypt/2` with policy validation
   - Add `validate_edk_count/2` for max EDK enforcement
   - Add `get_decryption_materials/3` to dispatch to CMM
   - Refactor `Decrypt.decrypt/2` to be callable from Client
   - Update public API `AwsEncryptionSdk.decrypt/2`
   - Add unit tests for each policy mode
   - Add integration tests with test vectors

3. **Test categorization**: Run script to categorize test vectors by commitment status

## References

- Issue: https://github.com/awslabs/aws-encryption-sdk-elixir/issues/39
- Spec (Decrypt): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Spec (Client): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/client.md
- Spec (CMM): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Spec (Algorithm Suites): https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/algorithm-suites.md
- Test Vectors: `test/fixtures/test_vectors/vectors/awses-decrypt/`
