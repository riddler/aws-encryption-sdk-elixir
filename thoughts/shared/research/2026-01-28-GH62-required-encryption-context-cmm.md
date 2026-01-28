# Research: Implement Required Encryption Context CMM

**Issue**: #62 - Implement Required Encryption Context CMM
**Date**: 2026-01-28
**Status**: Research complete

## Issue Summary

Implement the Required Encryption Context CMM that wraps another CMM to enforce that specific encryption context keys are present throughout encryption and decryption operations. This is a security feature that:

- **Validates required keys during encryption** - Ensures configured keys exist in caller's encryption context
- **Validates required keys during decryption** - Ensures configured keys exist in reproduced encryption context
- **Propagates required keys** - Marks required keys in materials for downstream tracking
- **Prevents security gaps** - Stops accidental removal of critical AAD components

## Current Implementation State

### Existing Code

**CMM Behaviour (`lib/aws_encryption_sdk/cmm/behaviour.ex`)**:
- Lines 66-73: Defines `required_encryption_context_keys` in encryption materials request type
- Lines 125: Specifies encryption materials must have required keys as superset of request
- Lines 155: Specifies decryption materials must have all required keys present
- Lines 293-307: `validate_encryption_materials/1` function
- Lines 340-351: `validate_required_context_keys/1` helper (encryption)
- Lines 370-382: `validate_decryption_materials/1` function
- Lines 407-418: `validate_decryption_required_context_keys/1` helper (decryption)
- Line 300: Returns error `:missing_required_encryption_context_key`

**Default CMM (`lib/aws_encryption_sdk/cmm/default.ex`)**:
- Lines 161-214: `get_encryption_materials/2` implementation
- Line 168: Extracts `required_keys` from request
- Line 210: Passes `required_encryption_context_keys` to encryption materials
- Lines 215-262: `get_decryption_materials/2` implementation

**Materials Structs**:
- `lib/aws_encryption_sdk/materials/encryption_materials.ex`:
  - Line 18: `required_encryption_context_keys: [String.t()]` field definition
  - Line 32: Default value `[]`
  - Lines 73 & 104: Keyword.get for `required_encryption_context_keys`

- `lib/aws_encryption_sdk/materials/decryption_materials.ex`:
  - Line 16: `required_encryption_context_keys: [String.t()]` field definition
  - Line 29: Default value `[]`

**Client (`lib/aws_encryption_sdk/client.ex`)**:
- Lines 333-342: `get_encryption_materials/3` private function (builds request map)
- Lines 345-352: `call_cmm_get_encryption_materials/2` dispatcher (pattern matches CMM type)
- Lines 387-398: `get_decryption_materials/3` private function
- Lines 401-408: `call_cmm_get_decryption_materials/2` dispatcher

### Relevant Patterns

**CMM Dispatcher Pattern**: The Client uses struct-based pattern matching to dispatch to the correct CMM module:

```elixir
defp call_cmm_get_encryption_materials(%Default{} = cmm, request) do
  Default.get_encryption_materials(cmm, request)
end

defp call_cmm_get_encryption_materials(cmm, _request) do
  {:error, {:unsupported_cmm_type, cmm.__struct__}}
end
```

A new CMM implementation needs:
1. A struct defining its configuration
2. Implementation of `get_encryption_materials/2` and `get_decryption_materials/2`
3. Pattern match clauses added to Client dispatcher at lines 345-352 and 401-408

**Keyring Dispatch Pattern**: Default CMM uses `call_wrap_key/2` and `call_unwrap_key/3` (lines 88-156) to dispatch to different keyring implementations.

**Validation Flow**: All CMMs call shared validation functions from `CmmBehaviour` module:
- `validate_encryption_materials/1` - includes required keys validation
- `validate_decryption_materials/1` - includes required keys validation
- `validate_encryption_context_for_encrypt/1` - checks reserved key
- `validate_commitment_policy_for_encrypt/2`
- `validate_commitment_policy_for_decrypt/2`

### Dependencies

**What this feature depends on**:
- `AwsEncryptionSdk.Cmm.Behaviour` - Base CMM interface
- `AwsEncryptionSdk.Cmm.Default` - For wrapping keyrings
- `AwsEncryptionSdk.Materials.EncryptionMaterials`
- `AwsEncryptionSdk.Materials.DecryptionMaterials`

**Gap in Current Implementation**: The Client module does NOT populate `required_encryption_context_keys` when building the encryption materials request at lines 334-338. The field is defined in the behaviour type but never set by the Client. The Required Encryption Context CMM will inject this field.

## Specification Requirements

### Source Documents
- [required-encryption-context-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md) - Primary spec
- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - Base CMM interface

### MUST Requirements

#### Initialization

1. **Required Encryption Context Keys Parameter** (required-encryption-context-cmm.md#initialization)
   > The caller MUST provide the following values: Required Encryption Context Keys

   Implementation: Accept `required_encryption_context_keys` parameter (list of strings) in initialization function.

2. **Underlying CMM or Keyring Parameter** (required-encryption-context-cmm.md#initialization)
   > the caller MUST provide one of the following values: Underlying Cryptographic Materials Manager (CMM) or Keyring

   Implementation: Accept either `underlying_cmm` OR `keyring` parameter (at least one required).

3. **Default CMM Creation from Keyring** (required-encryption-context-cmm.md#initialization)
   > If the caller provides a keyring, then the Required Encryption Context CMM MUST set its underlying CMM to a default CMM initialized with the keyring.

   Implementation: Auto-wrap keyring with `Default.new(keyring)`.

#### Get Encryption Materials

4. **Input Validation - Required Keys Present** (required-encryption-context-cmm.md#get-encryption-materials)
   > The encryption context on the encryption materials request MUST contain a value for every key in the configured required encryption context keys or this request MUST fail.

   Implementation: Check all required keys exist in request encryption context before forwarding.

5. **Call Underlying CMM** (required-encryption-context-cmm.md#get-encryption-materials)
   > The Required Encryption Context CMM MUST attempt to obtain encryption materials by making a call to the underlying CMM's Get Encryption Materials.

   Implementation: Forward request to underlying CMM.

6. **Propagate Required Keys to Underlying CMM** (required-encryption-context-cmm.md#get-encryption-materials)
   > All configured required encryption context keys MUST exist in the required encryption context keys of the encryption materials request to the underlying CMM.

   Implementation: Merge configured keys with any existing required keys in request.

7. **Output Validation - Required Keys in Materials** (required-encryption-context-cmm.md#get-encryption-materials)
   > The obtained encryption materials MUST have all configured required encryption context keys in its required encryption context keys.

   Implementation: Verify underlying CMM marked all configured keys as required.

#### Decrypt Materials

8. **Input Validation - Required Keys in Reproduced Context** (required-encryption-context-cmm.md#decrypt-materials)
   > The reproduced encryption context on the decrypt materials request MUST contain a value for every key in the configured required encryption context keys or this request MUST fail.

   Implementation: Check all required keys exist in reproduced context before forwarding.

9. **Call Underlying CMM for Decryption** (required-encryption-context-cmm.md#decrypt-materials)
   > The Required Encryption Context CMM MUST attempt to obtain decryption materials by making a call to the underlying CMM's decrypt materials interface.

   Implementation: Forward request to underlying CMM.

10. **Output Validation - Required Keys in Encryption Context** (required-encryption-context-cmm.md#decrypt-materials)
    > The obtained decryption materials MUST have all configured required encryption context keys in its encryption context.

    **Security Note**: This validation is critical. The spec states:
    > if the underlying Cryptographic Materials Manager (CMM) decides that the encryption context key-value pair SHOULD NOT be included in the encryption context on the decryption materials, then the AEAD Decrypt will not be able to authenticate that key-value pair.

### SHOULD Requirements

1. **Signing Key - Add Public Key to Context** (cmm-interface.md#get-encryption-materials)
   > If the algorithm suite contains a signing algorithm, the CMM SHOULD also add a key-value pair using the reserved key `aws-crypto-public-key` to the encryption context

   Note: Underlying CMM handles this. Wrapping CMM should not modify this.

2. **No Public Key for Non-Signing Suites** (cmm-interface.md#get-encryption-materials)
   > If the algorithm suite does not contain a signing algorithm, the CMM SHOULD NOT add a key-value pair using the reserved key `aws-crypto-public-key`

3. **Decrypt Materials - Append Missing Reproduced Keys** (cmm-interface.md#decrypt-materials)
   > If there are keys in the Encryption Context that don't exist in the Reproduced Encryption Context, these key-value pairs SHOULD be appended to the decryption materials

   Note: Underlying CMM handles merging. Wrapping CMM validates result.

### MAY Requirements

1. **Get Encryption Materials Request - Algorithm Suite ID** (cmm-interface.md)
   > Algorithm Suite ID: The algorithm suite that the caller wants the CMM to return. (MAY be included)

2. **Get Encryption Materials Request - Max Plaintext Length** (cmm-interface.md)
   > Max Plaintext Length: The maximum length of plaintext that will be encrypted using the returned encryption materials. (MAY be included)

3. **Decrypt Materials Request - Reproduced Encryption Context** (cmm-interface.md)
   > Reproduced Encryption Context: The encryption context that the caller has reproduced. (MAY be included)

## Test Vectors

### Harness Setup

No dedicated test vectors exist for the Required Encryption Context CMM in the `aws-encryption-sdk-test-vectors` repository. This is a relatively new feature (v4.x of the SDK) and dedicated vectors haven't been published.

However, existing encryption context handling can be validated with the available `awses-decrypt` vectors.

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

### Applicable Test Vector Sets

**Existing `awses-decrypt` vectors** can validate:
- Basic encryption context serialization and deserialization
- Context matching during decryption
- Reproduced context validation

**Limitations**: These vectors do NOT test:
- Required encryption context keys that are NOT stored in the message
- Validation that required keys are present in reproduced context
- CMM-level enforcement of required keys

### Implementation Order (Unit Tests)

Since dedicated test vectors don't exist, validation relies on unit and integration tests.

#### Phase 1: Basic Validation (Unit Tests)

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| Initialization with CMM | `new(required_keys, cmm)` | Success, stores CMM |
| Initialization with keyring | `new_with_keyring(required_keys, keyring)` | Success, wraps in Default CMM |
| Initialization missing both | No CMM or keyring | `{:error, :must_provide_cmm_or_keyring}` |
| Encrypt: all keys present | Required keys in context | Success |
| Encrypt: missing key | Required key not in context | `{:error, {:missing_required_encryption_context_keys, ["key"]}}` |
| Decrypt: all keys in reproduced | Required keys in reproduced context | Success |
| Decrypt: missing key in reproduced | Required key not in reproduced | `{:error, {:missing_required_encryption_context_keys, ["key"]}}` |
| Output validation: keys propagated | Underlying CMM returns materials | Required keys in materials |
| Output validation: keys stripped | Underlying CMM strips keys | `{:error, :required_keys_not_in_materials}` |

#### Phase 2: Integration Tests

| Test Case | Description | Expected Result |
|-----------|-------------|-----------------|
| Round-trip with required keys | Encrypt and decrypt with all keys | Success, plaintext matches |
| Round-trip missing decrypt key | Encrypt succeeds, decrypt without required key | Decrypt fails |
| Nested CMMs | Required EC CMM wrapping Required EC CMM | Both validation layers work |
| With Multi-keyring | Required EC CMM with multi-keyring | All keyrings work |
| With RawAes keyring | Basic round-trip | Success |
| With AWS KMS keyring | KMS integration | Success |

### Existing Test Patterns

**File**: `test/aws_encryption_sdk/cmm/behaviour_test.exs`
- Lines 194-215: Tests for required encryption context keys validation
- Lines 310-334: Tests for reproduced context validation
- Lines 336-355: Tests for context merging

These patterns should be extended for the Required Encryption Context CMM.

## Implementation Considerations

### Technical Approach

1. **Create Module**: `lib/aws_encryption_sdk/cmm/required_encryption_context.ex`
   - Implement `@behaviour AwsEncryptionSdk.Cmm.Behaviour`
   - Struct with `required_encryption_context_keys` and `underlying_cmm` fields
   - Two constructors: `new/2` (with CMM) and `new_with_keyring/2` (with keyring)

2. **Implementation Flow**:

   **Encryption**:
   ```
   1. Validate input encryption context contains all required keys → FAIL if missing
   2. Add required keys to request.required_encryption_context_keys
   3. Call underlying_cmm.get_encryption_materials(updated_request)
   4. Validate output materials.required_encryption_context_keys contains all required keys
   5. Return materials
   ```

   **Decryption**:
   ```
   1. Validate reproduced encryption context contains all required keys → FAIL if missing
   2. Call underlying_cmm.get_decryption_materials(request) [unchanged]
   3. Validate output materials.encryption_context contains all required keys
   4. Return materials
   ```

3. **Update Client Dispatcher**: Add pattern match clauses at lines 345-352 and 401-408 for `RequiredEncryptionContext` struct.

### Potential Challenges

1. **Empty reproduced context**: If reproduced encryption context is not provided, and required keys are configured, decryption must fail. Handle `nil` reproduced context explicitly.

2. **Nested CMMs**: When Required EC CMM wraps another Required EC CMM, required keys must be cumulative. The inner CMM validates its keys, outer validates its keys.

3. **Error message clarity**: When multiple keys are missing, error should list all missing keys, not just the first one.

4. **Key type validation**: Required keys must be strings. Validate on initialization.

### Open Questions

1. **Should both CMM and keyring be rejected?** Spec says provide "one of" - does providing both fail or prefer CMM?
   - **Answer**: Implementation should reject providing both as ambiguous.

2. **Empty required keys list valid?** Is `[]` a valid configuration?
   - **Answer**: Yes, but effectively makes the CMM a pass-through. Should still be allowed.

3. **Client API integration**: Should `encrypt/3` and `decrypt/3` accept `:required_encryption_context_keys` option directly?
   - **Recommendation**: Defer to a follow-up. The CMM approach is cleaner and follows spec. Client option could be added later as syntactic sugar.

## Recommended Next Steps

1. Create implementation plan: `/create_plan thoughts/shared/research/2026-01-28-GH62-required-encryption-context-cmm.md`

2. Implementation tasks:
   - Create `AwsEncryptionSdk.Cmm.RequiredEncryptionContext` module
   - Implement `new/2` and `new_with_keyring/2` constructors
   - Implement `get_encryption_materials/2` with validation
   - Implement `get_decryption_materials/2` with validation
   - Add Client dispatcher clauses
   - Write unit tests
   - Write integration tests
   - Add documentation

## References

- Issue: https://github.com/owner/repo/issues/62
- Primary Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
- Default CMM Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/default-cmm.md
- Test Vectors Repo: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- AWS Encryption SDK Developer Guide: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
