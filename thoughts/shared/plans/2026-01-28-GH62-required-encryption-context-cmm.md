# Required Encryption Context CMM Implementation Plan

## Overview

Implement the Required Encryption Context CMM, a wrapping CMM that enforces specific encryption context keys are present throughout encryption and decryption operations. This is a security feature that prevents accidental removal of critical AAD components.

**Issue**: #62
**Research**: `thoughts/shared/research/2026-01-28-GH62-required-encryption-context-cmm.md`

## Specification Requirements

### Source Documents
- [required-encryption-context-cmm.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md) - Primary spec
- [cmm-interface.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md) - Base CMM interface

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Accept required_encryption_context_keys list | initialization | MUST |
| Accept underlying CMM or keyring (one required) | initialization | MUST |
| Wrap keyring in Default CMM if keyring provided | initialization | MUST |
| Validate required keys in encryption context | get-encryption-materials | MUST |
| Propagate required keys to underlying CMM request | get-encryption-materials | MUST |
| Validate required keys in returned materials | get-encryption-materials | MUST |
| Validate required keys in reproduced context | decrypt-materials | MUST |
| Validate required keys in returned encryption context | decrypt-materials | MUST |

## Test Vectors

No dedicated test vectors exist for the Required Encryption Context CMM in the `aws-encryption-sdk-test-vectors` repository. This is a v4.x feature. Validation relies on unit and integration tests.

## Current State Analysis

### Key Discoveries:

- **CMM Behaviour** (`lib/aws_encryption_sdk/cmm/behaviour.ex`):
  - Lines 69-75: `encryption_materials_request` type already includes optional `required_encryption_context_keys`
  - Lines 340-351: `validate_required_context_keys/1` validates keys are present in context
  - Lines 407-418: `validate_decryption_required_context_keys/1` for decryption materials

- **Default CMM** (`lib/aws_encryption_sdk/cmm/default.ex`):
  - Line 168: Already extracts `required_keys` from request
  - Line 210: Passes `required_encryption_context_keys` to materials
  - Provides the pattern for CMM dispatch via struct pattern matching

- **Client** (`lib/aws_encryption_sdk/client.ex`):
  - Lines 345-352: `call_cmm_get_encryption_materials/2` dispatcher - needs new clause
  - Lines 401-408: `call_cmm_get_decryption_materials/2` dispatcher - needs new clause
  - Currently only dispatches to `Default` CMM

- **Materials Structs**: Both `EncryptionMaterials` and `DecryptionMaterials` already have `required_encryption_context_keys` field with default `[]`

### Pattern to Follow:

The CMM dispatch pattern uses struct-based pattern matching:

```elixir
defp call_cmm_get_encryption_materials(%Default{} = cmm, request) do
  Default.get_encryption_materials(cmm, request)
end
```

## Desired End State

After implementation:

1. New module `AwsEncryptionSdk.Cmm.RequiredEncryptionContext` exists with:
   - Struct containing `required_encryption_context_keys` and `underlying_cmm`
   - `new/2` constructor accepting required keys and CMM
   - `new_with_keyring/2` constructor accepting required keys and keyring
   - `get_encryption_materials/2` implementing validation and delegation
   - `get_decryption_materials/2` implementing validation and delegation

2. Client dispatches to the new CMM type

3. All tests pass: `mix quality`

### Verification:

```elixir
# In IEx - verify basic round-trip works
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)

cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new_with_keyring(
  ["tenant-id"],
  keyring
)

client = AwsEncryptionSdk.Client.new(cmm)

# Should succeed - required key present
{:ok, result} = AwsEncryptionSdk.Client.encrypt(client, "secret",
  encryption_context: %{"tenant-id" => "acme"}
)

# Should succeed - required key in reproduced context
{:ok, decrypted} = AwsEncryptionSdk.Client.decrypt(client, result.ciphertext,
  encryption_context: %{"tenant-id" => "acme"}
)

# Should fail - missing required key
{:error, _} = AwsEncryptionSdk.Client.encrypt(client, "secret",
  encryption_context: %{"other" => "value"}
)
```

## What We're NOT Doing

- **Client API sugar**: Not adding `:required_encryption_context_keys` option directly to `Client.encrypt/3` or `Client.decrypt/3`. The CMM approach is cleaner and follows the spec.
- **Caching CMM**: That's a separate feature (Milestone 5).
- **Test vectors**: No dedicated vectors exist; relying on unit/integration tests.

## Implementation Approach

Create a wrapping CMM that:
1. Validates required keys exist in input before delegating to underlying CMM
2. Injects required keys into the request's `required_encryption_context_keys` field
3. Delegates to underlying CMM for actual materials generation
4. Validates required keys are preserved in output materials

The CMM follows the existing dispatch pattern and reuses validation functions from `CmmBehaviour`.

---

## Phase 1: Core Module with Struct and Constructors

### Overview

Create the module skeleton with struct definition and two constructors.

### Spec Requirements Addressed

- Initialization: Accept `required_encryption_context_keys` list (MUST)
- Initialization: Accept underlying CMM or keyring (MUST)
- Initialization: Wrap keyring in Default CMM (MUST)

### Changes Required:

#### 1. Create New Module

**File**: `lib/aws_encryption_sdk/cmm/required_encryption_context.ex`

```elixir
defmodule AwsEncryptionSdk.Cmm.RequiredEncryptionContext do
  @moduledoc """
  Required Encryption Context CMM implementation.

  This CMM wraps another CMM and enforces that specific encryption context keys
  are present throughout encryption and decryption operations. It provides:

  - **Encryption validation**: Ensures required keys exist in caller's encryption context
  - **Decryption validation**: Ensures required keys exist in reproduced encryption context
  - **Key propagation**: Marks required keys in materials for downstream tracking
  - **Security enforcement**: Prevents accidental removal of critical AAD components

  ## Example

      # Create with a keyring (auto-wraps in Default CMM)
      {:ok, keyring} = RawAes.new("namespace", "key-name", key_bytes, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)

      # Or wrap an existing CMM
      default_cmm = Default.new(keyring)
      cmm = RequiredEncryptionContext.new(["tenant-id"], default_cmm)

      # Use with Client
      client = Client.new(cmm)

      # Encrypt - will fail if context missing required keys
      {:ok, result} = Client.encrypt(client, plaintext,
        encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
      )

      # Decrypt - must provide required keys in reproduced context
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext,
        encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
      )

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md
  """

  @behaviour AwsEncryptionSdk.Cmm.Behaviour

  alias AwsEncryptionSdk.Cmm.Behaviour, as: CmmBehaviour
  alias AwsEncryptionSdk.Cmm.Default

  @type t :: %__MODULE__{
          required_encryption_context_keys: [String.t()],
          underlying_cmm: CmmBehaviour.t()
        }

  defstruct [:required_encryption_context_keys, :underlying_cmm]

  @doc """
  Creates a new Required Encryption Context CMM wrapping an existing CMM.

  ## Parameters

  - `required_keys` - List of encryption context keys that must be present
  - `underlying_cmm` - The CMM to wrap (e.g., Default CMM)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> default_cmm = AwsEncryptionSdk.Cmm.Default.new(keyring)
      iex> cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new(["tenant-id"], default_cmm)
      iex> cmm.required_encryption_context_keys
      ["tenant-id"]

  """
  @spec new([String.t()], CmmBehaviour.t()) :: t()
  def new(required_keys, underlying_cmm)
      when is_list(required_keys) do
    %__MODULE__{
      required_encryption_context_keys: required_keys,
      underlying_cmm: underlying_cmm
    }
  end

  @doc """
  Creates a new Required Encryption Context CMM from a keyring.

  The keyring is automatically wrapped in a Default CMM.

  ## Parameters

  - `required_keys` - List of encryption context keys that must be present
  - `keyring` - A keyring struct (RawAes, RawRsa, Multi, AwsKms, etc.)

  ## Examples

      iex> key = :crypto.strong_rand_bytes(32)
      iex> {:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
      iex> cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      iex> cmm.required_encryption_context_keys
      ["tenant-id"]

  """
  @spec new_with_keyring([String.t()], Default.keyring()) :: t()
  def new_with_keyring(required_keys, keyring)
      when is_list(required_keys) do
    underlying_cmm = Default.new(keyring)
    new(required_keys, underlying_cmm)
  end

  # Placeholder implementations - will be completed in subsequent phases

  @impl CmmBehaviour
  def get_encryption_materials(_cmm, _request) do
    {:error, :not_implemented}
  end

  @impl CmmBehaviour
  def get_decryption_materials(_cmm, _request) do
    {:error, :not_implemented}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] No warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] Module loads in IEx: `alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext`
- [x] Constructors work: `RequiredEncryptionContext.new(["key"], default_cmm)`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 2: Get Encryption Materials

### Overview

Implement `get_encryption_materials/2` with input validation, required keys propagation, and output validation.

### Spec Requirements Addressed

- Validate required keys in encryption context (MUST)
- Propagate required keys to underlying CMM request (MUST)
- Call underlying CMM's get_encryption_materials (MUST)
- Validate required keys in returned materials (MUST)

### Changes Required:

#### 1. Implement get_encryption_materials/2

**File**: `lib/aws_encryption_sdk/cmm/required_encryption_context.ex`

Replace the placeholder `get_encryption_materials/2` with:

```elixir
@impl CmmBehaviour
def get_encryption_materials(%__MODULE__{} = cmm, request) do
  %{encryption_context: context} = request

  with :ok <- validate_required_keys_in_context(cmm.required_encryption_context_keys, context),
       updated_request = add_required_keys_to_request(cmm, request),
       {:ok, materials} <- call_underlying_cmm_encrypt(cmm.underlying_cmm, updated_request),
       :ok <- validate_required_keys_in_materials(cmm.required_encryption_context_keys, materials) do
    {:ok, materials}
  end
end

# Validates that all required keys exist in the encryption context
defp validate_required_keys_in_context(required_keys, context) do
  missing_keys =
    required_keys
    |> Enum.reject(&Map.has_key?(context, &1))

  if Enum.empty?(missing_keys) do
    :ok
  else
    {:error, {:missing_required_encryption_context_keys, missing_keys}}
  end
end

# Merges configured required keys with any existing required keys in request
defp add_required_keys_to_request(cmm, request) do
  existing_required = Map.get(request, :required_encryption_context_keys, [])

  merged_required =
    (existing_required ++ cmm.required_encryption_context_keys)
    |> Enum.uniq()

  Map.put(request, :required_encryption_context_keys, merged_required)
end

# Dispatches to underlying CMM based on struct type
defp call_underlying_cmm_encrypt(%Default{} = cmm, request) do
  Default.get_encryption_materials(cmm, request)
end

defp call_underlying_cmm_encrypt(%__MODULE__{} = cmm, request) do
  get_encryption_materials(cmm, request)
end

defp call_underlying_cmm_encrypt(cmm, _request) do
  {:error, {:unsupported_cmm_type, cmm.__struct__}}
end

# Validates that returned materials have all required keys marked as required
defp validate_required_keys_in_materials(required_keys, materials) do
  materials_required_keys = materials.required_encryption_context_keys || []
  missing_keys = required_keys -- materials_required_keys

  if Enum.empty?(missing_keys) do
    :ok
  else
    {:error, {:required_keys_not_in_materials, missing_keys}}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] No warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] In IEx, encryption succeeds with required keys present
- [x] In IEx, encryption fails with missing required key

```elixir
# Test in IEx
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new_with_keyring(["tenant"], keyring)

# Direct CMM call - should succeed
request = %{
  encryption_context: %{"tenant" => "acme"},
  commitment_policy: :require_encrypt_require_decrypt
}
{:ok, materials} = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.get_encryption_materials(cmm, request)

# Direct CMM call - should fail
request_missing = %{
  encryption_context: %{"other" => "value"},
  commitment_policy: :require_encrypt_require_decrypt
}
{:error, {:missing_required_encryption_context_keys, ["tenant"]}} =
  AwsEncryptionSdk.Cmm.RequiredEncryptionContext.get_encryption_materials(cmm, request_missing)
```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 3: Get Decryption Materials

### Overview

Implement `get_decryption_materials/2` with reproduced context validation and output validation.

### Spec Requirements Addressed

- Validate required keys in reproduced encryption context (MUST)
- Call underlying CMM's decrypt materials (MUST)
- Validate required keys in returned encryption context (MUST)

### Changes Required:

#### 1. Implement get_decryption_materials/2

**File**: `lib/aws_encryption_sdk/cmm/required_encryption_context.ex`

Replace the placeholder `get_decryption_materials/2` with:

```elixir
@impl CmmBehaviour
def get_decryption_materials(%__MODULE__{} = cmm, request) do
  reproduced_context = Map.get(request, :reproduced_encryption_context) || %{}

  with :ok <- validate_required_keys_in_reproduced_context(cmm.required_encryption_context_keys, reproduced_context),
       {:ok, materials} <- call_underlying_cmm_decrypt(cmm.underlying_cmm, request),
       :ok <- validate_required_keys_in_decryption_materials(cmm.required_encryption_context_keys, materials) do
    {:ok, materials}
  end
end

# Validates that all required keys exist in the reproduced encryption context
defp validate_required_keys_in_reproduced_context(required_keys, reproduced_context) do
  missing_keys =
    required_keys
    |> Enum.reject(&Map.has_key?(reproduced_context, &1))

  if Enum.empty?(missing_keys) do
    :ok
  else
    {:error, {:missing_required_encryption_context_keys, missing_keys}}
  end
end

# Dispatches to underlying CMM based on struct type
defp call_underlying_cmm_decrypt(%Default{} = cmm, request) do
  Default.get_decryption_materials(cmm, request)
end

defp call_underlying_cmm_decrypt(%__MODULE__{} = cmm, request) do
  get_decryption_materials(cmm, request)
end

defp call_underlying_cmm_decrypt(cmm, _request) do
  {:error, {:unsupported_cmm_type, cmm.__struct__}}
end

# Validates that returned materials have all required keys in encryption context
defp validate_required_keys_in_decryption_materials(required_keys, materials) do
  context = materials.encryption_context || %{}
  missing_keys = Enum.reject(required_keys, &Map.has_key?(context, &1))

  if Enum.empty?(missing_keys) do
    :ok
  else
    {:error, {:required_keys_not_in_decryption_context, missing_keys}}
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] No warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] In IEx, decryption fails when reproduced context missing required key

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 4: Client Dispatcher Integration

### Overview

Add pattern match clauses to Client module to dispatch to the new CMM type.

### Changes Required:

#### 1. Add Alias

**File**: `lib/aws_encryption_sdk/client.ex`

Add alias after line 36 (after `alias AwsEncryptionSdk.Cmm.Default`):

```elixir
alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
```

#### 2. Add Encryption Dispatcher Clause

**File**: `lib/aws_encryption_sdk/client.ex`

Add after line 346 (after the Default clause):

```elixir
defp call_cmm_get_encryption_materials(%RequiredEncryptionContext{} = cmm, request) do
  RequiredEncryptionContext.get_encryption_materials(cmm, request)
end
```

#### 3. Add Decryption Dispatcher Clause

**File**: `lib/aws_encryption_sdk/client.ex`

Add after line 402 (after the Default clause):

```elixir
defp call_cmm_get_decryption_materials(%RequiredEncryptionContext{} = cmm, request) do
  RequiredEncryptionContext.get_decryption_materials(cmm, request)
end
```

### Success Criteria:

#### Automated Verification:
- [x] Code compiles: `mix compile`
- [x] No warnings: `mix compile --warnings-as-errors`

#### Manual Verification:
- [x] Full round-trip works via Client API in IEx

```elixir
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = AwsEncryptionSdk.Keyring.RawAes.new("ns", "key", key, :aes_256_gcm)
cmm = AwsEncryptionSdk.Cmm.RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
client = AwsEncryptionSdk.Client.new(cmm)

# Encrypt with required key
{:ok, result} = AwsEncryptionSdk.Client.encrypt(client, "secret data",
  encryption_context: %{"tenant-id" => "acme", "other" => "value"}
)

# Decrypt with required key in reproduced context
{:ok, decrypted} = AwsEncryptionSdk.Client.decrypt(client, result.ciphertext,
  encryption_context: %{"tenant-id" => "acme"}
)

decrypted.plaintext == "secret data"  # Should be true

# Encrypt without required key - should fail
{:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
  AwsEncryptionSdk.Client.encrypt(client, "data",
    encryption_context: %{"other" => "value"}
  )

# Decrypt without required key - should fail
{:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
  AwsEncryptionSdk.Client.decrypt(client, result.ciphertext,
    encryption_context: %{"other" => "value"}
  )
```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to the next phase.

---

## Phase 5: Tests

### Overview

Add comprehensive unit and integration tests for the Required Encryption Context CMM.

### Changes Required:

#### 1. Create Unit Test File

**File**: `test/aws_encryption_sdk/cmm/required_encryption_context_test.exs`

```elixir
defmodule AwsEncryptionSdk.Cmm.RequiredEncryptionContextTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Cmm.{Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Client

  describe "new/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      default_cmm = Default.new(keyring)
      %{default_cmm: default_cmm}
    end

    test "creates CMM with required keys and underlying CMM", %{default_cmm: default_cmm} do
      cmm = RequiredEncryptionContext.new(["tenant-id", "purpose"], default_cmm)

      assert cmm.required_encryption_context_keys == ["tenant-id", "purpose"]
      assert cmm.underlying_cmm == default_cmm
    end

    test "accepts empty required keys list", %{default_cmm: default_cmm} do
      cmm = RequiredEncryptionContext.new([], default_cmm)
      assert cmm.required_encryption_context_keys == []
    end
  end

  describe "new_with_keyring/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      %{keyring: keyring}
    end

    test "creates CMM wrapping keyring in Default CMM", %{keyring: keyring} do
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)

      assert cmm.required_encryption_context_keys == ["tenant-id"]
      assert %Default{} = cmm.underlying_cmm
      assert cmm.underlying_cmm.keyring == keyring
    end
  end

  describe "get_encryption_materials/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      %{cmm: cmm}
    end

    test "succeeds when all required keys present", %{cmm: cmm} do
      request = %{
        encryption_context: %{"tenant-id" => "acme", "other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
      assert "tenant-id" in materials.required_encryption_context_keys
    end

    test "fails when required key missing from context", %{cmm: cmm} do
      request = %{
        encryption_context: %{"other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_encryption_materials(cmm, request)
    end

    test "fails when multiple required keys missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)

      request = %{
        encryption_context: %{"other" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, missing}} =
               RequiredEncryptionContext.get_encryption_materials(cmm, request)

      assert "tenant-id" in missing
      assert "purpose" in missing
    end

    test "merges with existing required keys in request", %{cmm: cmm} do
      request = %{
        encryption_context: %{"tenant-id" => "acme", "existing-required" => "value"},
        commitment_policy: :require_encrypt_require_decrypt,
        required_encryption_context_keys: ["existing-required"]
      }

      assert {:ok, materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
      assert "tenant-id" in materials.required_encryption_context_keys
      assert "existing-required" in materials.required_encryption_context_keys
    end

    test "succeeds with empty required keys (pass-through)" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring([], keyring)

      request = %{
        encryption_context: %{"any" => "value"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, _materials} = RequiredEncryptionContext.get_encryption_materials(cmm, request)
    end
  end

  describe "get_decryption_materials/2" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      client = Client.new(cmm)

      # Create a valid ciphertext to decrypt
      {:ok, result} =
        Client.encrypt(client, "test plaintext",
          encryption_context: %{"tenant-id" => "acme", "other" => "value"}
        )

      %{cmm: cmm, keyring: keyring, ciphertext: result.ciphertext, header: result.header}
    end

    test "succeeds when required keys in reproduced context", %{cmm: cmm, header: header} do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: %{"tenant-id" => "acme"}
      }

      assert {:ok, _materials} = RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when required key missing from reproduced context", %{cmm: cmm, header: header} do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: %{"other" => "value"}
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when reproduced context is nil and required keys configured", %{
      cmm: cmm,
      header: header
    } do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: nil
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end

    test "fails when reproduced context not provided and required keys configured", %{
      cmm: cmm,
      header: header
    } do
      request = %{
        algorithm_suite: header.algorithm_suite,
        commitment_policy: :require_encrypt_require_decrypt,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context
      }

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               RequiredEncryptionContext.get_decryption_materials(cmm, request)
    end
  end

  describe "nested CMMs" do
    test "validates both layers of required keys" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      # Inner CMM requires "inner-key"
      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)

      # Outer CMM requires "outer-key"
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      # Must have both keys
      request = %{
        encryption_context: %{"inner-key" => "value1", "outer-key" => "value2"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:ok, materials} = RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)
      assert "inner-key" in materials.required_encryption_context_keys
      assert "outer-key" in materials.required_encryption_context_keys
    end

    test "fails if outer required key missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      request = %{
        encryption_context: %{"inner-key" => "value1"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      assert {:error, {:missing_required_encryption_context_keys, ["outer-key"]}} =
               RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)
    end

    test "fails if inner required key missing" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)

      inner_cmm = RequiredEncryptionContext.new_with_keyring(["inner-key"], keyring)
      outer_cmm = RequiredEncryptionContext.new(["outer-key"], inner_cmm)

      request = %{
        encryption_context: %{"outer-key" => "value2"},
        commitment_policy: :require_encrypt_require_decrypt
      }

      # Outer validation passes, but inner validation fails
      assert {:error, {:missing_required_encryption_context_keys, ["inner-key"]}} =
               RequiredEncryptionContext.get_encryption_materials(outer_cmm, request)
    end
  end

  describe "Client integration" do
    setup do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id"], keyring)
      client = Client.new(cmm)
      %{client: client}
    end

    test "encrypt succeeds with required keys", %{client: client} do
      {:ok, result} =
        Client.encrypt(client, "secret data",
          encryption_context: %{"tenant-id" => "acme"}
        )

      assert is_binary(result.ciphertext)
    end

    test "encrypt fails without required keys", %{client: client} do
      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.encrypt(client, "secret data",
                 encryption_context: %{"other" => "value"}
               )
    end

    test "decrypt succeeds with required keys in reproduced context", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data",
          encryption_context: %{"tenant-id" => "acme"}
        )

      {:ok, decrypted} =
        Client.decrypt(client, encrypted.ciphertext,
          encryption_context: %{"tenant-id" => "acme"}
        )

      assert decrypted.plaintext == "secret data"
    end

    test "decrypt fails without required keys in reproduced context", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data",
          encryption_context: %{"tenant-id" => "acme"}
        )

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.decrypt(client, encrypted.ciphertext,
                 encryption_context: %{"other" => "value"}
               )
    end

    test "decrypt fails when no reproduced context provided", %{client: client} do
      {:ok, encrypted} =
        Client.encrypt(client, "secret data",
          encryption_context: %{"tenant-id" => "acme"}
        )

      assert {:error, {:missing_required_encryption_context_keys, ["tenant-id"]}} =
               Client.decrypt(client, encrypted.ciphertext)
    end

    test "round-trip with multiple required keys" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test-ns", "test-key", key, :aes_256_gcm)
      cmm = RequiredEncryptionContext.new_with_keyring(["tenant-id", "purpose"], keyring)
      client = Client.new(cmm)

      context = %{"tenant-id" => "acme", "purpose" => "backup", "extra" => "data"}

      {:ok, encrypted} = Client.encrypt(client, "multi-key test", encryption_context: context)

      {:ok, decrypted} =
        Client.decrypt(client, encrypted.ciphertext,
          encryption_context: %{"tenant-id" => "acme", "purpose" => "backup"}
        )

      assert decrypted.plaintext == "multi-key test"
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] All tests pass: `mix test test/aws_encryption_sdk/cmm/required_encryption_context_test.exs`
- [x] Full quality check: `mix quality`

#### Manual Verification:
- [x] Review test output confirms all scenarios covered

**Implementation Note**: After completing this phase and all automated verification passes, the implementation is complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] New module tests pass: `mix test test/aws_encryption_sdk/cmm/required_encryption_context_test.exs`
- [x] Existing CMM tests still pass: `mix test test/aws_encryption_sdk/cmm/`
- [x] Client tests still pass: `mix test test/aws_encryption_sdk/client_test.exs`

### Manual:
- [x] End-to-end verification in IEx (as shown in Phase 4)
- [x] Error messages are clear and helpful

## Testing Strategy

### Unit Tests:
- Constructor validation (new/2, new_with_keyring/2)
- Empty required keys (pass-through behavior)
- Single required key validation
- Multiple required keys validation
- Required keys propagation to underlying CMM
- Nested CMM validation (both layers enforced)

### Integration Tests:
- Client.encrypt with required keys present/missing
- Client.decrypt with reproduced context present/missing
- Full round-trip encryption/decryption
- Multiple required keys round-trip

### Edge Cases:
- Empty required keys list (should work as pass-through)
- Nil reproduced context with required keys (should fail)
- Required key in original context but not in reproduced (should fail)
- Nested Required EC CMMs (both should validate)

## References

- Issue: #62
- Research: `thoughts/shared/research/2026-01-28-GH62-required-encryption-context-cmm.md`
- Primary Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/required-encryption-context-cmm.md
- CMM Interface Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/cmm-interface.md
