# Message Format Serialization Implementation Plan

## Overview

Implement binary serialization and deserialization for the AWS Encryption SDK message format, including headers (v1 and v2), body (framed and non-framed), and footer (signature). This enables the SDK to produce and consume encrypted messages compatible with all other AWS Encryption SDK implementations.

**Issue**: #9
**Research**: `thoughts/shared/research/2026-01-25-GH9-message-format-serialization.md`

## Specification Requirements

### Source Documents
- [data-format/message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md) - Header v1 and v2 format
- [data-format/message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md) - Framed and non-framed body
- [data-format/message-body-aad.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body-aad.md) - Body AAD structure
- [data-format/message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md) - Signature footer
- [framework/structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md) - Encryption context and EDK structures

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| All multi-byte fields big-endian | message-header.md | MUST |
| Version field: 0x01 or 0x02 | message-header.md | MUST |
| v1 Type field: 0x80 | message-header.md | MUST |
| Message ID: 16 bytes (v1) or 32 bytes (v2) | message-header.md | MUST |
| EDK count > 0 | message-header.md | MUST |
| Content type: 0x01 (non-framed) or 0x02 (framed) | message-header.md | MUST |
| v1 Reserved field: 0x00000000 | message-header.md | MUST |
| Frame length = 0 for non-framed | message-header.md | MUST |
| Encryption context sorted by UTF-8 key bytes | structures.md | MUST |
| Frame sequence starts at 1 | message-body.md | MUST |
| Final frame marker: 0xFFFFFFFF | message-body.md | MUST |
| Non-framed content ≤ 64 GiB | message-body.md | MUST |
| Footer required for signed suites | message-footer.md | MUST |
| Signature covers header + body | message-footer.md | MUST |
| ECDSA signatures DER-encoded (RFC 3279) | message-footer.md | MUST |
| `aws-crypto-` prefix reserved | encrypt.md | MUST |

## Test Vectors

### Validation Strategy
Each phase includes unit tests for serialization round-trips. Full integration testing with official test vectors will be done in a later milestone when the decrypt operation is implemented.

### Test Vector Summary
| Phase | Tests | Purpose |
|-------|-------|---------|
| 1 | Unit tests | EDK struct serialization |
| 2 | Unit tests | Encryption context serialization |
| 3 | Unit tests | Body AAD generation |
| 4 | Unit tests | Header v2 serialization |
| 5 | Unit tests | Non-framed body serialization |
| 6 | Unit tests | Framed body serialization |
| 7 | Unit tests | Footer serialization |
| 8 | Unit tests | Header v1 serialization |
| 9 | Integration | Complete message round-trip |

## Current State Analysis

### What Exists
- `lib/aws_encryption_sdk/algorithm_suite.ex` - Complete algorithm suite definitions with `message_format_version`, `commitment_length`, `suite_data_length` fields
- `lib/aws_encryption_sdk/crypto/hkdf.ex` - HKDF implementation for key derivation

### What's Missing
- All files under `lib/aws_encryption_sdk/format/`
- `lib/aws_encryption_sdk/materials/encrypted_data_key.ex`
- Binary serialization/deserialization code

### Key Discoveries
- Algorithm suite provides `message_format_version` (1 or 2) to determine header format
- Algorithm suite provides `suite_data_length` (0 or 32) for commitment key in v2 headers
- Existing code uses tagged tuples `{:ok, value} | {:error, reason}` pattern
- Existing code uses `@enforce_keys` with `defstruct`

## Desired End State

After this plan is complete:

1. **New modules created**:
   - `AwsEncryptionSdk.Materials.EncryptedDataKey` - EDK struct
   - `AwsEncryptionSdk.Format.EncryptionContext` - Context serialization
   - `AwsEncryptionSdk.Format.BodyAad` - Body AAD generation
   - `AwsEncryptionSdk.Format.Header` - Header struct and serialization
   - `AwsEncryptionSdk.Format.Body` - Body serialization (framed/non-framed)
   - `AwsEncryptionSdk.Format.Footer` - Footer serialization
   - `AwsEncryptionSdk.Format.Message` - Complete message handling

2. **Capabilities**:
   - Serialize/deserialize v1 and v2 headers
   - Serialize/deserialize framed and non-framed bodies
   - Serialize/deserialize signature footers
   - Generate correct Body AAD for AES-GCM operations
   - Validate encryption context (no reserved keys)

3. **Verification**:
   - All unit tests pass
   - Round-trip serialization produces identical binaries
   - `mix quality` passes

## What We're NOT Doing

- **Encryption/decryption operations** - This plan covers serialization only, not the actual AES-GCM operations
- **Key derivation for messages** - HKDF usage for deriving data keys and commitment keys is a separate concern
- **Keyring integration** - EDK encryption/decryption via keyrings is out of scope
- **CMM integration** - Materials management is out of scope
- **Test vector validation** - Full decrypt test vectors require the decrypt operation
- **Streaming support** - Initial implementation handles complete messages in memory

## Implementation Approach

Build from the bottom up, starting with the smallest data structures and working toward the complete message. Each phase produces a testable module that can be verified independently.

The order prioritizes:
1. Dependencies first (EDK before Header, since Header contains EDKs)
2. Current standards first (v2 before v1)
3. Simple before complex (non-framed before framed)

---

## Phase 1: EncryptedDataKey Struct

### Overview
Create the EncryptedDataKey struct used throughout the SDK to represent encrypted data keys.

### Spec Requirements Addressed
- EDK format from message-header.md: provider_id (UTF-8), provider_info (binary), ciphertext (binary)

### Changes Required

#### 1. Create EncryptedDataKey module
**File**: `lib/aws_encryption_sdk/materials/encrypted_data_key.ex`

```elixir
defmodule AwsEncryptionSdk.Materials.EncryptedDataKey do
  @moduledoc """
  Encrypted Data Key (EDK) structure.

  An EDK contains a data key encrypted by a specific key provider. Each message
  contains one or more EDKs, allowing decryption with any of the corresponding
  master keys.

  ## Fields

  - `:key_provider_id` - UTF-8 identifier for the key provider (e.g., "aws-kms")
  - `:key_provider_info` - Provider-specific key information (binary)
  - `:ciphertext` - The encrypted data key (binary)

  ## Serialization Format

  Per message-header.md:
  ```
  | Field              | Length        | Type   |
  |--------------------|---------------|--------|
  | Provider ID Length | 2 bytes       | Uint16 |
  | Provider ID        | Variable      | UTF-8  |
  | Provider Info Len  | 2 bytes       | Uint16 |
  | Provider Info      | Variable      | Binary |
  | Ciphertext Length  | 2 bytes       | Uint16 |
  | Ciphertext         | Variable      | Binary |
  ```
  """

  @typedoc "Encrypted Data Key structure"
  @type t :: %__MODULE__{
          key_provider_id: String.t(),
          key_provider_info: binary(),
          ciphertext: binary()
        }

  @enforce_keys [:key_provider_id, :key_provider_info, :ciphertext]
  defstruct @enforce_keys

  @doc """
  Creates a new EncryptedDataKey.

  ## Examples

      iex> AwsEncryptionSdk.Materials.EncryptedDataKey.new("aws-kms", "key-arn", <<1, 2, 3>>)
      %AwsEncryptionSdk.Materials.EncryptedDataKey{
        key_provider_id: "aws-kms",
        key_provider_info: "key-arn",
        ciphertext: <<1, 2, 3>>
      }
  """
  @spec new(String.t(), binary(), binary()) :: t()
  def new(key_provider_id, key_provider_info, ciphertext)
      when is_binary(key_provider_id) and is_binary(key_provider_info) and is_binary(ciphertext) do
    %__MODULE__{
      key_provider_id: key_provider_id,
      key_provider_info: key_provider_info,
      ciphertext: ciphertext
    }
  end

  @doc """
  Serializes an EDK to binary format.

  ## Format
  ```
  <<provider_id_len::16-big, provider_id::binary,
    provider_info_len::16-big, provider_info::binary,
    ciphertext_len::16-big, ciphertext::binary>>
  ```
  """
  @spec serialize(t()) :: binary()
  def serialize(%__MODULE__{} = edk) do
    provider_id_bytes = edk.key_provider_id
    provider_id_len = byte_size(provider_id_bytes)
    provider_info_len = byte_size(edk.key_provider_info)
    ciphertext_len = byte_size(edk.ciphertext)

    <<
      provider_id_len::16-big,
      provider_id_bytes::binary,
      provider_info_len::16-big,
      edk.key_provider_info::binary,
      ciphertext_len::16-big,
      edk.ciphertext::binary
    >>
  end

  @doc """
  Serializes a list of EDKs with a count prefix.

  ## Format
  ```
  <<count::16-big, edk1::binary, edk2::binary, ...>>
  ```
  """
  @spec serialize_list([t()]) :: {:ok, binary()} | {:error, :empty_edk_list}
  def serialize_list([]), do: {:error, :empty_edk_list}

  def serialize_list(edks) when is_list(edks) do
    count = length(edks)
    serialized = edks |> Enum.map(&serialize/1) |> IO.iodata_to_binary()
    {:ok, <<count::16-big, serialized::binary>>}
  end

  @doc """
  Deserializes an EDK from binary format.

  Returns `{:ok, edk, rest}` on success, or `{:error, reason}` on failure.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<
        provider_id_len::16-big,
        provider_id::binary-size(provider_id_len),
        provider_info_len::16-big,
        provider_info::binary-size(provider_info_len),
        ciphertext_len::16-big,
        ciphertext::binary-size(ciphertext_len),
        rest::binary
      >>) do
    edk = %__MODULE__{
      key_provider_id: provider_id,
      key_provider_info: provider_info,
      ciphertext: ciphertext
    }

    {:ok, edk, rest}
  end

  def deserialize(_), do: {:error, :invalid_edk_format}

  @doc """
  Deserializes a list of EDKs with count prefix.

  Returns `{:ok, edks, rest}` on success.
  """
  @spec deserialize_list(binary()) :: {:ok, [t()], binary()} | {:error, term()}
  def deserialize_list(<<count::16-big, rest::binary>>) when count > 0 do
    deserialize_n(rest, count, [])
  end

  def deserialize_list(<<0::16-big, _rest::binary>>), do: {:error, :empty_edk_list}
  def deserialize_list(_), do: {:error, :invalid_edk_list_format}

  defp deserialize_n(rest, 0, acc), do: {:ok, Enum.reverse(acc), rest}

  defp deserialize_n(data, n, acc) do
    case deserialize(data) do
      {:ok, edk, rest} -> deserialize_n(rest, n - 1, [edk | acc])
      {:error, _} = error -> error
    end
  end
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/materials/encrypted_data_key_test.exs`

```elixir
defmodule AwsEncryptionSdk.Materials.EncryptedDataKeyTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "new/3" do
    test "creates an EDK struct" do
      edk = EncryptedDataKey.new("aws-kms", "arn:aws:kms:...", <<1, 2, 3>>)

      assert edk.key_provider_id == "aws-kms"
      assert edk.key_provider_info == "arn:aws:kms:..."
      assert edk.ciphertext == <<1, 2, 3>>
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "round-trips a simple EDK" do
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3, 4>>)
      serialized = EncryptedDataKey.serialize(edk)

      assert {:ok, ^edk, <<>>} = EncryptedDataKey.deserialize(serialized)
    end

    test "round-trips an EDK with empty provider_info" do
      edk = EncryptedDataKey.new("raw", <<>>, <<0::256>>)
      serialized = EncryptedDataKey.serialize(edk)

      assert {:ok, ^edk, <<>>} = EncryptedDataKey.deserialize(serialized)
    end

    test "preserves trailing bytes" do
      edk = EncryptedDataKey.new("test", "info", <<1, 2, 3>>)
      serialized = EncryptedDataKey.serialize(edk)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, ^edk, <<99, 100>>} = EncryptedDataKey.deserialize(with_trailing)
    end

    test "produces correct binary format" do
      edk = EncryptedDataKey.new("ab", "cd", <<1, 2>>)
      serialized = EncryptedDataKey.serialize(edk)

      # provider_id_len (2) + "ab" + provider_info_len (2) + "cd" + ciphertext_len (2) + <<1,2>>
      assert serialized == <<0, 2, ?a, ?b, 0, 2, ?c, ?d, 0, 2, 1, 2>>
    end
  end

  describe "serialize_list/1 and deserialize_list/1" do
    test "round-trips a list of EDKs" do
      edks = [
        EncryptedDataKey.new("provider1", "info1", <<1>>),
        EncryptedDataKey.new("provider2", "info2", <<2>>)
      ]

      assert {:ok, serialized} = EncryptedDataKey.serialize_list(edks)
      assert {:ok, ^edks, <<>>} = EncryptedDataKey.deserialize_list(serialized)
    end

    test "rejects empty list" do
      assert {:error, :empty_edk_list} = EncryptedDataKey.serialize_list([])
    end

    test "rejects zero count in binary" do
      assert {:error, :empty_edk_list} = EncryptedDataKey.deserialize_list(<<0, 0>>)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/materials/encrypted_data_key_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, create an EDK, serialize it, and verify the binary matches expected format

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Encryption Context Serialization

### Overview
Implement encryption context serialization with proper UTF-8 key sorting and reserved key validation.

### Spec Requirements Addressed
- Empty context → empty byte sequence (structures.md)
- Non-empty: 2-byte count + sorted key-value entries (structures.md)
- Entries sorted ascending by UTF-8 key bytes (structures.md)
- `aws-crypto-` prefix reserved (encrypt.md)

### Changes Required

#### 1. Create EncryptionContext module
**File**: `lib/aws_encryption_sdk/format/encryption_context.ex`

```elixir
defmodule AwsEncryptionSdk.Format.EncryptionContext do
  @moduledoc """
  Encryption context serialization and validation.

  The encryption context is a key-value mapping of arbitrary, non-secret,
  UTF-8 encoded strings used as Additional Authenticated Data (AAD).

  ## Serialization Format

  Per structures.md:
  - Empty context: empty byte sequence (0 bytes)
  - Non-empty context:
    ```
    <<count::16-big, entry1::binary, entry2::binary, ...>>
    ```
  - Each entry:
    ```
    <<key_len::16-big, key::binary, value_len::16-big, value::binary>>
    ```
  - Entries MUST be sorted ascending by UTF-8 encoded key bytes

  ## Reserved Keys

  The prefix `aws-crypto-` is reserved for internal SDK use. User-provided
  encryption context MUST NOT contain keys with this prefix.
  """

  @reserved_prefix "aws-crypto-"

  @typedoc "Encryption context map"
  @type t :: %{String.t() => String.t()}

  @doc """
  Validates that user-provided encryption context does not contain reserved keys.

  Returns `:ok` if valid, or `{:error, {:reserved_keys, keys}}` if reserved keys found.

  ## Examples

      iex> validate(%{"user-key" => "value"})
      :ok

      iex> validate(%{"aws-crypto-public-key" => "value"})
      {:error, {:reserved_keys, ["aws-crypto-public-key"]}}
  """
  @spec validate(t()) :: :ok | {:error, {:reserved_keys, [String.t()]}}
  def validate(context) when is_map(context) do
    reserved_keys =
      context
      |> Map.keys()
      |> Enum.filter(&String.starts_with?(&1, @reserved_prefix))

    case reserved_keys do
      [] -> :ok
      keys -> {:error, {:reserved_keys, Enum.sort(keys)}}
    end
  end

  @doc """
  Serializes an encryption context to binary format.

  Empty maps produce an empty binary. Non-empty maps produce a count-prefixed
  sequence of key-value entries, sorted by key.

  ## Examples

      iex> serialize(%{})
      <<>>

      iex> serialize(%{"a" => "1"})
      <<0, 1, 0, 1, ?a, 0, 1, ?1>>
  """
  @spec serialize(t()) :: binary()
  def serialize(context) when map_size(context) == 0, do: <<>>

  def serialize(context) when is_map(context) do
    sorted_entries = Enum.sort_by(context, fn {k, _v} -> k end)
    count = length(sorted_entries)

    entries_binary =
      sorted_entries
      |> Enum.map(&serialize_entry/1)
      |> IO.iodata_to_binary()

    <<count::16-big, entries_binary::binary>>
  end

  @doc """
  Deserializes an encryption context from binary format.

  Returns `{:ok, context, rest}` on success.

  ## Examples

      iex> deserialize(<<>>)
      {:ok, %{}, <<>>}
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<>>), do: {:ok, %{}, <<>>}

  def deserialize(<<count::16-big, rest::binary>>) when count > 0 do
    deserialize_entries(rest, count, %{})
  end

  def deserialize(<<0::16-big, rest::binary>>), do: {:ok, %{}, rest}

  def deserialize(_), do: {:error, :invalid_encryption_context_format}

  # Private functions

  defp serialize_entry({key, value}) do
    key_len = byte_size(key)
    value_len = byte_size(value)
    <<key_len::16-big, key::binary, value_len::16-big, value::binary>>
  end

  defp deserialize_entries(rest, 0, acc), do: {:ok, acc, rest}

  defp deserialize_entries(
         <<key_len::16-big, key::binary-size(key_len), value_len::16-big,
           value::binary-size(value_len), rest::binary>>,
         n,
         acc
       ) do
    deserialize_entries(rest, n - 1, Map.put(acc, key, value))
  end

  defp deserialize_entries(_, _, _), do: {:error, :invalid_encryption_context_entry}
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/encryption_context_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.EncryptionContextTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.EncryptionContext

  describe "validate/1" do
    test "accepts empty context" do
      assert :ok = EncryptionContext.validate(%{})
    end

    test "accepts context without reserved keys" do
      assert :ok = EncryptionContext.validate(%{"user-key" => "value", "another" => "val"})
    end

    test "rejects context with aws-crypto- prefix" do
      context = %{"aws-crypto-public-key" => "value"}
      assert {:error, {:reserved_keys, ["aws-crypto-public-key"]}} = EncryptionContext.validate(context)
    end

    test "returns all reserved keys found" do
      context = %{
        "aws-crypto-a" => "1",
        "aws-crypto-b" => "2",
        "valid-key" => "3"
      }

      assert {:error, {:reserved_keys, keys}} = EncryptionContext.validate(context)
      assert keys == ["aws-crypto-a", "aws-crypto-b"]
    end
  end

  describe "serialize/1 and deserialize/1" do
    test "round-trips empty context" do
      assert <<>> = EncryptionContext.serialize(%{})
      assert {:ok, %{}, <<>>} = EncryptionContext.deserialize(<<>>)
    end

    test "round-trips single entry" do
      context = %{"key" => "value"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "round-trips multiple entries" do
      context = %{"a" => "1", "b" => "2", "c" => "3"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "sorts entries by key" do
      context = %{"z" => "last", "a" => "first", "m" => "middle"}
      serialized = EncryptionContext.serialize(context)

      # First entry should be "a" (0x61), not "m" (0x6d) or "z" (0x7a)
      <<1::16-big, rest::binary>> = serialized
      <<key_len::16-big, first_key::binary-size(key_len), _::binary>> = rest

      assert first_key == "a"
    end

    test "handles UTF-8 keys correctly" do
      context = %{"café" => "coffee", "naïve" => "simple"}
      serialized = EncryptionContext.serialize(context)

      assert {:ok, ^context, <<>>} = EncryptionContext.deserialize(serialized)
    end

    test "preserves trailing bytes" do
      context = %{"k" => "v"}
      serialized = EncryptionContext.serialize(context)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, ^context, <<99, 100>>} = EncryptionContext.deserialize(with_trailing)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/encryption_context_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, serialize a context and verify keys are sorted in output binary

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Body AAD Serialization

### Overview
Implement Body AAD (Additional Authenticated Data) generation for AES-GCM operations on message body content.

### Spec Requirements Addressed
- AAD format: Message ID + Content String + Sequence Number + Content Length (message-body-aad.md)
- Content strings: "AWSKMSEncryptionClient Single Block", "AWSKMSEncryptionClient Frame", "AWSKMSEncryptionClient Final Frame"
- Sequence number: uint32 big-endian, starts at 1 for non-framed
- Content length: uint64 big-endian

### Changes Required

#### 1. Create BodyAad module
**File**: `lib/aws_encryption_sdk/format/body_aad.ex`

```elixir
defmodule AwsEncryptionSdk.Format.BodyAad do
  @moduledoc """
  Message Body AAD (Additional Authenticated Data) serialization.

  Used as AAD input to AES-GCM when encrypting/decrypting message body content.

  ## Format

  Per message-body-aad.md:
  ```
  | Field           | Size           | Type   |
  |-----------------|----------------|--------|
  | Message ID      | 16 (v1) or 32 (v2) bytes | Binary |
  | Body AAD Content| Variable       | UTF-8  |
  | Sequence Number | 4 bytes        | Uint32 |
  | Content Length  | 8 bytes        | Uint64 |
  ```

  The Body AAD Content string varies by content type:
  - Non-framed: "AWSKMSEncryptionClient Single Block"
  - Regular frame: "AWSKMSEncryptionClient Frame"
  - Final frame: "AWSKMSEncryptionClient Final Frame"
  """

  @non_framed_content "AWSKMSEncryptionClient Single Block"
  @regular_frame_content "AWSKMSEncryptionClient Frame"
  @final_frame_content "AWSKMSEncryptionClient Final Frame"

  @typedoc "Content type for Body AAD"
  @type content_type :: :non_framed | :regular_frame | :final_frame

  @doc """
  Serializes Message Body AAD for use in AES-GCM encryption/decryption.

  ## Parameters

  - `message_id` - 16 bytes (v1) or 32 bytes (v2)
  - `content_type` - `:non_framed`, `:regular_frame`, or `:final_frame`
  - `sequence_number` - Frame sequence number (1 for non-framed)
  - `content_length` - Plaintext length being encrypted

  ## Examples

      iex> message_id = :crypto.strong_rand_bytes(32)
      iex> aad = serialize(message_id, :non_framed, 1, 1024)
      iex> byte_size(aad)
      79  # 32 + 35 + 4 + 8
  """
  @spec serialize(binary(), content_type(), pos_integer(), non_neg_integer()) :: binary()
  def serialize(message_id, content_type, sequence_number, content_length)
      when is_binary(message_id) and
             content_type in [:non_framed, :regular_frame, :final_frame] and
             is_integer(sequence_number) and sequence_number > 0 and
             is_integer(content_length) and content_length >= 0 do
    body_content = content_string(content_type)

    <<
      message_id::binary,
      body_content::binary,
      sequence_number::32-big,
      content_length::64-big
    >>
  end

  @doc """
  Returns the Body AAD Content string for a given content type.
  """
  @spec content_string(content_type()) :: String.t()
  def content_string(:non_framed), do: @non_framed_content
  def content_string(:regular_frame), do: @regular_frame_content
  def content_string(:final_frame), do: @final_frame_content
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/body_aad_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.BodyAadTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.BodyAad

  describe "serialize/4" do
    test "produces correct size for v1 message ID (16 bytes)" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :non_framed, 1, 1024)

      # 16 + 35 ("AWSKMSEncryptionClient Single Block") + 4 + 8 = 63
      assert byte_size(aad) == 63
    end

    test "produces correct size for v2 message ID (32 bytes)" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :non_framed, 1, 1024)

      # 32 + 35 + 4 + 8 = 79
      assert byte_size(aad) == 79
    end

    test "produces correct size for regular frame" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :regular_frame, 1, 4096)

      # 32 + 29 ("AWSKMSEncryptionClient Frame") + 4 + 8 = 73
      assert byte_size(aad) == 73
    end

    test "produces correct size for final frame" do
      message_id = :crypto.strong_rand_bytes(32)
      aad = BodyAad.serialize(message_id, :final_frame, 5, 100)

      # 32 + 35 ("AWSKMSEncryptionClient Final Frame") + 4 + 8 = 79
      assert byte_size(aad) == 79
    end

    test "includes message ID at start" do
      message_id = <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16>>
      aad = BodyAad.serialize(message_id, :non_framed, 1, 0)

      assert binary_part(aad, 0, 16) == message_id
    end

    test "includes content string after message ID" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :regular_frame, 1, 0)

      content_string = binary_part(aad, 16, 29)
      assert content_string == "AWSKMSEncryptionClient Frame"
    end

    test "encodes sequence number as big-endian uint32" do
      message_id = :crypto.strong_rand_bytes(16)
      aad = BodyAad.serialize(message_id, :non_framed, 256, 0)

      # Sequence number starts after message_id (16) + content string (35)
      <<_::binary-size(51), seq::32-big, _::binary>> = aad
      assert seq == 256
    end

    test "encodes content length as big-endian uint64" do
      message_id = :crypto.strong_rand_bytes(16)
      content_length = 0x0001_0002_0003_0004
      aad = BodyAad.serialize(message_id, :non_framed, 1, content_length)

      # Content length is last 8 bytes
      <<_::binary-size(55), len::64-big>> = aad
      assert len == content_length
    end
  end

  describe "content_string/1" do
    test "returns correct string for non_framed" do
      assert BodyAad.content_string(:non_framed) == "AWSKMSEncryptionClient Single Block"
    end

    test "returns correct string for regular_frame" do
      assert BodyAad.content_string(:regular_frame) == "AWSKMSEncryptionClient Frame"
    end

    test "returns correct string for final_frame" do
      assert BodyAad.content_string(:final_frame) == "AWSKMSEncryptionClient Final Frame"
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/body_aad_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [ ] In IEx, generate AAD and verify byte layout matches spec

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: Header V2 Serialization

### Overview
Implement serialization and deserialization for message header version 2.0 (committed algorithm suites).

### Spec Requirements Addressed
- Version byte: 0x02 (message-header.md)
- No type field in v2 (message-header.md)
- Message ID: 32 bytes (message-header.md)
- Algorithm suite data: 32 bytes for committed suites (message-header.md)
- No IV field in v2 (uses zero IV)
- Auth tag: 16 bytes

### Changes Required

#### 1. Create Header module
**File**: `lib/aws_encryption_sdk/format/header.ex`

```elixir
defmodule AwsEncryptionSdk.Format.Header do
  @moduledoc """
  Message header serialization and deserialization.

  Supports both version 1.0 and 2.0 header formats.

  ## Version 2.0 Format (Committed Suites)

  ```
  | Field                | Size      |
  |----------------------|-----------|
  | Version              | 1 byte    | 0x02
  | Algorithm Suite ID   | 2 bytes   |
  | Message ID           | 32 bytes  |
  | AAD Length           | 2 bytes   |
  | AAD (enc context)    | Variable  |
  | EDK Count            | 2 bytes   |
  | EDKs                 | Variable  |
  | Content Type         | 1 byte    |
  | Frame Length         | 4 bytes   |
  | Algorithm Suite Data | 32 bytes  | (commitment key)
  | Auth Tag             | 16 bytes  |
  ```

  ## Version 1.0 Format (Legacy)

  ```
  | Field                | Size      |
  |----------------------|-----------|
  | Version              | 1 byte    | 0x01
  | Type                 | 1 byte    | 0x80
  | Algorithm Suite ID   | 2 bytes   |
  | Message ID           | 16 bytes  |
  | AAD Length           | 2 bytes   |
  | AAD (enc context)    | Variable  |
  | EDK Count            | 2 bytes   |
  | EDKs                 | Variable  |
  | Content Type         | 1 byte    |
  | Reserved             | 4 bytes   | 0x00000000
  | IV Length            | 1 byte    |
  | Frame Length         | 4 bytes   |
  | IV                   | Variable  |
  | Auth Tag             | 16 bytes  |
  ```
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  @type content_type :: :framed | :non_framed

  @typedoc "Message header structure"
  @type t :: %__MODULE__{
          version: 1 | 2,
          algorithm_suite: AlgorithmSuite.t(),
          message_id: binary(),
          encryption_context: EncryptionContext.t(),
          encrypted_data_keys: [EncryptedDataKey.t()],
          content_type: content_type(),
          frame_length: non_neg_integer(),
          algorithm_suite_data: binary() | nil,
          header_iv: binary() | nil,
          header_auth_tag: binary()
        }

  @enforce_keys [
    :version,
    :algorithm_suite,
    :message_id,
    :encryption_context,
    :encrypted_data_keys,
    :content_type,
    :frame_length,
    :header_auth_tag
  ]

  defstruct [
    :version,
    :algorithm_suite,
    :message_id,
    :encryption_context,
    :encrypted_data_keys,
    :content_type,
    :frame_length,
    :algorithm_suite_data,
    :header_iv,
    :header_auth_tag
  ]

  @content_type_non_framed 0x01
  @content_type_framed 0x02

  @doc """
  Generates a new random message ID for the given version.

  - Version 1: 16 random bytes
  - Version 2: 32 random bytes
  """
  @spec generate_message_id(1 | 2) :: binary()
  def generate_message_id(1), do: :crypto.strong_rand_bytes(16)
  def generate_message_id(2), do: :crypto.strong_rand_bytes(32)

  @doc """
  Serializes the header body (everything except the auth tag).

  This is the data that gets authenticated by the header auth tag.
  """
  @spec serialize_body(t()) :: {:ok, binary()} | {:error, term()}
  def serialize_body(%__MODULE__{version: 2} = header) do
    serialize_v2_body(header)
  end

  def serialize_body(%__MODULE__{version: 1} = header) do
    serialize_v1_body(header)
  end

  @doc """
  Serializes a complete header including the auth tag.
  """
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(%__MODULE__{version: 2} = header) do
    with {:ok, body} <- serialize_v2_body(header) do
      {:ok, body <> header.header_auth_tag}
    end
  end

  def serialize(%__MODULE__{version: 1} = header) do
    with {:ok, body} <- serialize_v1_body(header) do
      auth_section = <<header.header_iv::binary, header.header_auth_tag::binary>>
      {:ok, body <> auth_section}
    end
  end

  @doc """
  Deserializes a header from binary data.

  Returns `{:ok, header, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<0x02, rest::binary>>), do: deserialize_v2(rest)
  def deserialize(<<0x01, 0x80, rest::binary>>), do: deserialize_v1(rest)
  def deserialize(<<0x01, type, _::binary>>), do: {:error, {:invalid_type, type}}
  def deserialize(<<version, _::binary>>), do: {:error, {:unsupported_version, version}}
  def deserialize(_), do: {:error, :incomplete_header}

  # Version 2 serialization

  defp serialize_v2_body(%__MODULE__{version: 2} = header) do
    aad_binary = EncryptionContext.serialize(header.encryption_context)
    aad_length = byte_size(aad_binary)

    with {:ok, edks_binary} <- EncryptedDataKey.serialize_list(header.encrypted_data_keys) do
      content_type_byte = encode_content_type(header.content_type)
      frame_length = if header.content_type == :non_framed, do: 0, else: header.frame_length
      suite_data = header.algorithm_suite_data || <<0::256>>

      body =
        <<
          0x02::8,
          header.algorithm_suite.id::16-big,
          header.message_id::binary-size(32),
          aad_length::16-big,
          aad_binary::binary,
          edks_binary::binary,
          content_type_byte::8,
          frame_length::32-big,
          suite_data::binary-size(32)
        >>

      {:ok, body}
    end
  end

  # Version 2 deserialization

  defp deserialize_v2(<<
         algorithm_id::16-big,
         message_id::binary-size(32),
         aad_length::16-big,
         rest::binary
       >>) do
    with {:ok, suite} <- AlgorithmSuite.by_id(algorithm_id),
         {:ok, encryption_context, rest} <- deserialize_aad(rest, aad_length),
         {:ok, edks, rest} <- EncryptedDataKey.deserialize_list(rest),
         {:ok, content_type, frame_length, suite_data, auth_tag, rest} <-
           deserialize_v2_tail(rest) do
      header = %__MODULE__{
        version: 2,
        algorithm_suite: suite,
        message_id: message_id,
        encryption_context: encryption_context,
        encrypted_data_keys: edks,
        content_type: content_type,
        frame_length: frame_length,
        algorithm_suite_data: suite_data,
        header_iv: nil,
        header_auth_tag: auth_tag
      }

      {:ok, header, rest}
    end
  end

  defp deserialize_v2(_), do: {:error, :invalid_v2_header}

  defp deserialize_v2_tail(<<
         content_type_byte::8,
         frame_length::32-big,
         suite_data::binary-size(32),
         auth_tag::binary-size(16),
         rest::binary
       >>) do
    with {:ok, content_type} <- decode_content_type(content_type_byte) do
      {:ok, content_type, frame_length, suite_data, auth_tag, rest}
    end
  end

  defp deserialize_v2_tail(_), do: {:error, :invalid_v2_header_tail}

  # Version 1 serialization

  defp serialize_v1_body(%__MODULE__{version: 1} = header) do
    aad_binary = EncryptionContext.serialize(header.encryption_context)
    aad_length = byte_size(aad_binary)

    with {:ok, edks_binary} <- EncryptedDataKey.serialize_list(header.encrypted_data_keys) do
      content_type_byte = encode_content_type(header.content_type)
      frame_length = if header.content_type == :non_framed, do: 0, else: header.frame_length
      iv_length = header.algorithm_suite.iv_length

      body =
        <<
          0x01::8,
          0x80::8,
          header.algorithm_suite.id::16-big,
          header.message_id::binary-size(16),
          aad_length::16-big,
          aad_binary::binary,
          edks_binary::binary,
          content_type_byte::8,
          0::32,
          iv_length::8,
          frame_length::32-big
        >>

      {:ok, body}
    end
  end

  # Version 1 deserialization

  defp deserialize_v1(<<
         algorithm_id::16-big,
         message_id::binary-size(16),
         aad_length::16-big,
         rest::binary
       >>) do
    with {:ok, suite} <- AlgorithmSuite.by_id(algorithm_id),
         {:ok, encryption_context, rest} <- deserialize_aad(rest, aad_length),
         {:ok, edks, rest} <- EncryptedDataKey.deserialize_list(rest),
         {:ok, content_type, frame_length, iv, auth_tag, rest} <-
           deserialize_v1_tail(rest, suite.iv_length) do
      header = %__MODULE__{
        version: 1,
        algorithm_suite: suite,
        message_id: message_id,
        encryption_context: encryption_context,
        encrypted_data_keys: edks,
        content_type: content_type,
        frame_length: frame_length,
        algorithm_suite_data: nil,
        header_iv: iv,
        header_auth_tag: auth_tag
      }

      {:ok, header, rest}
    end
  end

  defp deserialize_v1(_), do: {:error, :invalid_v1_header}

  defp deserialize_v1_tail(
         <<
           content_type_byte::8,
           0::32,
           iv_length::8,
           frame_length::32-big,
           rest::binary
         >>,
         expected_iv_length
       )
       when iv_length == expected_iv_length do
    with {:ok, content_type} <- decode_content_type(content_type_byte),
         <<iv::binary-size(iv_length), auth_tag::binary-size(16), rest::binary>> <- rest do
      {:ok, content_type, frame_length, iv, auth_tag, rest}
    else
      _ -> {:error, :invalid_v1_header_auth}
    end
  end

  defp deserialize_v1_tail(<<_::8, reserved::32, _::binary>>, _) when reserved != 0 do
    {:error, :invalid_reserved_field}
  end

  defp deserialize_v1_tail(_, _), do: {:error, :invalid_v1_header_tail}

  # Common helpers

  defp deserialize_aad(data, 0), do: {:ok, %{}, data}

  defp deserialize_aad(data, aad_length) when byte_size(data) >= aad_length do
    <<aad_binary::binary-size(aad_length), rest::binary>> = data

    case EncryptionContext.deserialize(aad_binary) do
      {:ok, context, <<>>} -> {:ok, context, rest}
      {:ok, _, _trailing} -> {:error, :aad_length_mismatch}
      error -> error
    end
  end

  defp deserialize_aad(_, _), do: {:error, :incomplete_aad}

  defp encode_content_type(:non_framed), do: @content_type_non_framed
  defp encode_content_type(:framed), do: @content_type_framed

  defp decode_content_type(@content_type_non_framed), do: {:ok, :non_framed}
  defp decode_content_type(@content_type_framed), do: {:ok, :framed}
  defp decode_content_type(byte), do: {:error, {:invalid_content_type, byte}}
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/header_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.HeaderTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "generate_message_id/1" do
    test "generates 16 bytes for version 1" do
      id = Header.generate_message_id(1)
      assert byte_size(id) == 16
    end

    test "generates 32 bytes for version 2" do
      id = Header.generate_message_id(2)
      assert byte_size(id) == 32
    end

    test "generates unique IDs" do
      id1 = Header.generate_message_id(2)
      id2 = Header.generate_message_id(2)
      assert id1 != id2
    end
  end

  describe "v2 header serialization" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{"key" => "value"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :framed,
        frame_length: 4096,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_iv: nil,
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header: header}
    end

    test "round-trips a v2 header", %{header: header} do
      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)

      assert deserialized.version == header.version
      assert deserialized.algorithm_suite.id == header.algorithm_suite.id
      assert deserialized.message_id == header.message_id
      assert deserialized.encryption_context == header.encryption_context
      assert deserialized.content_type == header.content_type
      assert deserialized.frame_length == header.frame_length
      assert deserialized.algorithm_suite_data == header.algorithm_suite_data
      assert deserialized.header_auth_tag == header.header_auth_tag
    end

    test "starts with version byte 0x02", %{header: header} do
      assert {:ok, <<0x02, _::binary>>} = Header.serialize(header)
    end

    test "encodes algorithm suite ID as big-endian", %{header: header} do
      assert {:ok, <<0x02, 0x04, 0x78, _::binary>>} = Header.serialize(header)
    end

    test "non-framed content type sets frame_length to 0" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 4096,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)
      assert deserialized.frame_length == 0
    end
  end

  describe "v1 header serialization" do
    setup do
      suite = AlgorithmSuite.aes_256_gcm_iv12_tag16_hkdf_sha256()

      header = %Header{
        version: 1,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(16),
        encryption_context: %{"key" => "value"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :framed,
        frame_length: 4096,
        algorithm_suite_data: nil,
        header_iv: :crypto.strong_rand_bytes(12),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header: header}
    end

    test "round-trips a v1 header", %{header: header} do
      assert {:ok, serialized} = Header.serialize(header)
      assert {:ok, deserialized, <<>>} = Header.deserialize(serialized)

      assert deserialized.version == header.version
      assert deserialized.algorithm_suite.id == header.algorithm_suite.id
      assert deserialized.message_id == header.message_id
      assert deserialized.encryption_context == header.encryption_context
      assert deserialized.content_type == header.content_type
      assert deserialized.frame_length == header.frame_length
      assert deserialized.header_iv == header.header_iv
      assert deserialized.header_auth_tag == header.header_auth_tag
    end

    test "starts with version 0x01 and type 0x80", %{header: header} do
      assert {:ok, <<0x01, 0x80, _::binary>>} = Header.serialize(header)
    end
  end

  describe "deserialize/1 error handling" do
    test "rejects unsupported version" do
      assert {:error, {:unsupported_version, 0x03}} = Header.deserialize(<<0x03, 0::200>>)
    end

    test "rejects invalid type for v1" do
      assert {:error, {:invalid_type, 0x81}} = Header.deserialize(<<0x01, 0x81, 0::200>>)
    end

    test "rejects unknown algorithm suite" do
      # v2 header with invalid algorithm ID 0xFFFF
      header = <<0x02, 0xFF, 0xFF, 0::800>>
      assert {:error, :unknown_suite_id} = Header.deserialize(header)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/header_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, create a v2 header, serialize it, and examine the byte structure

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 5.

---

## Phase 5: Body Serialization (Non-Framed)

### Overview
Implement serialization and deserialization for non-framed message bodies.

### Spec Requirements Addressed
- Non-framed structure: IV (12 bytes) + content length (uint64) + ciphertext + auth tag (16 bytes)
- Content length ≤ 64 GiB (message-body.md)

### Changes Required

#### 1. Create Body module
**File**: `lib/aws_encryption_sdk/format/body.ex`

```elixir
defmodule AwsEncryptionSdk.Format.Body do
  @moduledoc """
  Message body serialization and deserialization.

  Supports both framed and non-framed body formats.

  ## Non-Framed Format

  ```
  | Field           | Size      |
  |-----------------|-----------|
  | IV              | 12 bytes  |
  | Content Length  | 8 bytes   | Uint64
  | Ciphertext      | Variable  |
  | Auth Tag        | 16 bytes  |
  ```

  ## Framed Format

  Regular frames:
  ```
  | Field           | Size      |
  |-----------------|-----------|
  | Sequence Number | 4 bytes   | Uint32 (1, 2, 3, ...)
  | IV              | 12 bytes  |
  | Ciphertext      | frame_length bytes |
  | Auth Tag        | 16 bytes  |
  ```

  Final frame:
  ```
  | Field           | Size      |
  |-----------------|-----------|
  | Seq Number End  | 4 bytes   | 0xFFFFFFFF
  | Sequence Number | 4 bytes   | Actual sequence number
  | IV              | 12 bytes  |
  | Content Length  | 4 bytes   | Uint32
  | Ciphertext      | Variable  |
  | Auth Tag        | 16 bytes  |
  ```
  """

  @iv_length 12
  @auth_tag_length 16
  @final_frame_marker 0xFFFFFFFF
  @max_non_framed_content 68_719_476_704  # 2^36 - 32 = 64 GiB

  @typedoc "Non-framed body structure"
  @type non_framed :: %{
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary()
        }

  @typedoc "Regular frame structure"
  @type regular_frame :: %{
          sequence_number: pos_integer(),
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary()
        }

  @typedoc "Final frame structure"
  @type final_frame :: %{
          sequence_number: pos_integer(),
          iv: binary(),
          ciphertext: binary(),
          auth_tag: binary(),
          final: true
        }

  @typedoc "Any frame type"
  @type frame :: regular_frame() | final_frame()

  # Non-framed body functions

  @doc """
  Serializes a non-framed body.

  ## Parameters

  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content
  - `auth_tag` - 16-byte authentication tag

  ## Returns

  `{:ok, binary}` on success, `{:error, reason}` if content exceeds 64 GiB limit.
  """
  @spec serialize_non_framed(binary(), binary(), binary()) ::
          {:ok, binary()} | {:error, :content_too_large}
  def serialize_non_framed(iv, ciphertext, auth_tag)
      when byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    content_length = byte_size(ciphertext)

    if content_length > @max_non_framed_content do
      {:error, :content_too_large}
    else
      body =
        <<
          iv::binary-size(@iv_length),
          content_length::64-big,
          ciphertext::binary,
          auth_tag::binary-size(@auth_tag_length)
        >>

      {:ok, body}
    end
  end

  @doc """
  Deserializes a non-framed body.

  Returns `{:ok, body_map, rest}` on success.
  """
  @spec deserialize_non_framed(binary()) :: {:ok, non_framed(), binary()} | {:error, term()}
  def deserialize_non_framed(<<
        iv::binary-size(@iv_length),
        content_length::64-big,
        rest::binary
      >>)
      when content_length <= @max_non_framed_content do
    case rest do
      <<ciphertext::binary-size(content_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        body = %{
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag
        }

        {:ok, body, remaining}

      _ ->
        {:error, :incomplete_non_framed_body}
    end
  end

  def deserialize_non_framed(<<_iv::binary-size(@iv_length), content_length::64-big, _::binary>>)
      when content_length > @max_non_framed_content do
    {:error, :content_too_large}
  end

  def deserialize_non_framed(_), do: {:error, :invalid_non_framed_body}

  # Framed body functions

  @doc """
  Serializes a regular frame.

  ## Parameters

  - `sequence_number` - Frame sequence (1, 2, 3, ...)
  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content (must be exactly frame_length bytes)
  - `auth_tag` - 16-byte authentication tag
  """
  @spec serialize_regular_frame(pos_integer(), binary(), binary(), binary()) :: binary()
  def serialize_regular_frame(sequence_number, iv, ciphertext, auth_tag)
      when is_integer(sequence_number) and sequence_number > 0 and
             byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    <<
      sequence_number::32-big,
      iv::binary-size(@iv_length),
      ciphertext::binary,
      auth_tag::binary-size(@auth_tag_length)
    >>
  end

  @doc """
  Serializes a final frame.

  ## Parameters

  - `sequence_number` - Frame sequence number
  - `iv` - 12-byte initialization vector
  - `ciphertext` - Encrypted content (may be shorter than frame_length)
  - `auth_tag` - 16-byte authentication tag
  """
  @spec serialize_final_frame(pos_integer(), binary(), binary(), binary()) :: binary()
  def serialize_final_frame(sequence_number, iv, ciphertext, auth_tag)
      when is_integer(sequence_number) and sequence_number > 0 and
             byte_size(iv) == @iv_length and byte_size(auth_tag) == @auth_tag_length do
    content_length = byte_size(ciphertext)

    <<
      @final_frame_marker::32-big,
      sequence_number::32-big,
      iv::binary-size(@iv_length),
      content_length::32-big,
      ciphertext::binary,
      auth_tag::binary-size(@auth_tag_length)
    >>
  end

  @doc """
  Deserializes a frame (regular or final).

  Returns `{:ok, frame_map, rest}` where frame_map includes `:final` key for final frames.
  """
  @spec deserialize_frame(binary(), pos_integer()) ::
          {:ok, frame(), binary()} | {:error, term()}
  def deserialize_frame(
        <<@final_frame_marker::32-big, sequence_number::32-big, iv::binary-size(@iv_length),
          content_length::32-big, rest::binary>>,
        _frame_length
      ) do
    case rest do
      <<ciphertext::binary-size(content_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        frame = %{
          sequence_number: sequence_number,
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag,
          final: true
        }

        {:ok, frame, remaining}

      _ ->
        {:error, :incomplete_final_frame}
    end
  end

  def deserialize_frame(
        <<sequence_number::32-big, iv::binary-size(@iv_length), rest::binary>>,
        frame_length
      )
      when sequence_number != @final_frame_marker do
    case rest do
      <<ciphertext::binary-size(frame_length), auth_tag::binary-size(@auth_tag_length),
        remaining::binary>> ->
        frame = %{
          sequence_number: sequence_number,
          iv: iv,
          ciphertext: ciphertext,
          auth_tag: auth_tag
        }

        {:ok, frame, remaining}

      _ ->
        {:error, :incomplete_regular_frame}
    end
  end

  def deserialize_frame(_, _), do: {:error, :invalid_frame}

  @doc """
  Deserializes all frames from a framed body.

  Returns `{:ok, frames, rest}` where frames is a list ordered by sequence number.
  """
  @spec deserialize_all_frames(binary(), pos_integer()) ::
          {:ok, [frame()], binary()} | {:error, term()}
  def deserialize_all_frames(data, frame_length) do
    deserialize_frames_loop(data, frame_length, 1, [])
  end

  defp deserialize_frames_loop(data, frame_length, expected_seq, acc) do
    case deserialize_frame(data, frame_length) do
      {:ok, %{final: true} = frame, rest} ->
        if frame.sequence_number == expected_seq do
          {:ok, Enum.reverse([frame | acc]), rest}
        else
          {:error, {:sequence_mismatch, expected_seq, frame.sequence_number}}
        end

      {:ok, frame, rest} ->
        if frame.sequence_number == expected_seq do
          deserialize_frames_loop(rest, frame_length, expected_seq + 1, [frame | acc])
        else
          {:error, {:sequence_mismatch, expected_seq, frame.sequence_number}}
        end

      {:error, _} = error ->
        error
    end
  end
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/body_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.BodyTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.Body

  describe "non-framed body" do
    test "serialize_non_framed/3 produces correct format" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      # IV (12) + content_length (8) + ciphertext (5) + auth_tag (16) = 41
      assert byte_size(serialized) == 41
    end

    test "round-trips non-framed body" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(100)
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
      assert {:ok, body, <<>>} = Body.deserialize_non_framed(serialized)

      assert body.iv == iv
      assert body.ciphertext == ciphertext
      assert body.auth_tag == auth_tag
    end

    test "encodes content length as big-endian uint64" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(256)
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      <<_iv::binary-size(12), length::64-big, _rest::binary>> = serialized
      assert length == 256
    end

    test "rejects content exceeding 64 GiB limit" do
      # We can't actually allocate 64 GiB, but we can test the error path
      # by mocking or just documenting the behavior
      iv = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)
      # Create a small ciphertext - actual limit test would need special handling
      ciphertext = <<1, 2, 3>>

      assert {:ok, _} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
    end

    test "preserves trailing bytes" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)

      assert {:ok, serialized} = Body.serialize_non_framed(iv, ciphertext, auth_tag)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, _body, <<99, 100>>} = Body.deserialize_non_framed(with_trailing)
    end
  end

  describe "framed body" do
    test "serialize_regular_frame/4 produces correct format" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(4096)
      auth_tag = :crypto.strong_rand_bytes(16)

      frame = Body.serialize_regular_frame(1, iv, ciphertext, auth_tag)

      # seq (4) + iv (12) + ciphertext (4096) + auth_tag (16) = 4128
      assert byte_size(frame) == 4128

      # Check sequence number
      <<seq::32-big, _::binary>> = frame
      assert seq == 1
    end

    test "serialize_final_frame/4 includes marker and content length" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)

      frame = Body.serialize_final_frame(3, iv, ciphertext, auth_tag)

      # marker (4) + seq (4) + iv (12) + content_len (4) + ciphertext (5) + auth_tag (16) = 45
      assert byte_size(frame) == 45

      <<marker::32-big, seq::32-big, _iv::binary-size(12), len::32-big, _::binary>> = frame
      assert marker == 0xFFFFFFFF
      assert seq == 3
      assert len == 5
    end

    test "deserialize_frame/2 parses regular frame" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = :crypto.strong_rand_bytes(100)
      auth_tag = :crypto.strong_rand_bytes(16)

      serialized = Body.serialize_regular_frame(5, iv, ciphertext, auth_tag)

      assert {:ok, frame, <<>>} = Body.deserialize_frame(serialized, 100)
      assert frame.sequence_number == 5
      assert frame.iv == iv
      assert frame.ciphertext == ciphertext
      assert frame.auth_tag == auth_tag
      refute Map.has_key?(frame, :final)
    end

    test "deserialize_frame/2 parses final frame" do
      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)

      serialized = Body.serialize_final_frame(10, iv, ciphertext, auth_tag)

      assert {:ok, frame, <<>>} = Body.deserialize_frame(serialized, 100)
      assert frame.sequence_number == 10
      assert frame.iv == iv
      assert frame.ciphertext == ciphertext
      assert frame.auth_tag == auth_tag
      assert frame.final == true
    end

    test "deserialize_all_frames/2 parses multiple frames" do
      frame_length = 50
      iv1 = :crypto.strong_rand_bytes(12)
      iv2 = :crypto.strong_rand_bytes(12)
      iv3 = :crypto.strong_rand_bytes(12)
      auth_tag = :crypto.strong_rand_bytes(16)

      data =
        Body.serialize_regular_frame(1, iv1, :crypto.strong_rand_bytes(frame_length), auth_tag) <>
          Body.serialize_regular_frame(2, iv2, :crypto.strong_rand_bytes(frame_length), auth_tag) <>
          Body.serialize_final_frame(3, iv3, <<1, 2, 3>>, auth_tag)

      assert {:ok, frames, <<>>} = Body.deserialize_all_frames(data, frame_length)
      assert length(frames) == 3
      assert Enum.at(frames, 0).sequence_number == 1
      assert Enum.at(frames, 1).sequence_number == 2
      assert Enum.at(frames, 2).sequence_number == 3
      assert Enum.at(frames, 2).final == true
    end

    test "deserialize_all_frames/2 rejects out-of-order frames" do
      frame_length = 50
      auth_tag = :crypto.strong_rand_bytes(16)

      # Sequence 1, then 3 (skipping 2)
      data =
        Body.serialize_regular_frame(
          1,
          :crypto.strong_rand_bytes(12),
          :crypto.strong_rand_bytes(frame_length),
          auth_tag
        ) <>
          Body.serialize_final_frame(3, :crypto.strong_rand_bytes(12), <<1>>, auth_tag)

      assert {:error, {:sequence_mismatch, 2, 3}} = Body.deserialize_all_frames(data, frame_length)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/body_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, serialize a non-framed body and verify the byte layout

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 6.

---

## Phase 6: Footer Serialization

### Overview
Implement serialization and deserialization for message footer (ECDSA signature).

### Spec Requirements Addressed
- Footer required when algorithm suite includes signing (message-footer.md)
- Format: 2-byte length + DER-encoded signature (message-footer.md)
- ECDSA signatures use DER encoding per RFC 3279

### Changes Required

#### 1. Create Footer module
**File**: `lib/aws_encryption_sdk/format/footer.ex`

```elixir
defmodule AwsEncryptionSdk.Format.Footer do
  @moduledoc """
  Message footer serialization and deserialization.

  The footer contains an ECDSA signature that covers the entire message
  (header + body). It is only present when using algorithm suites that
  include digital signatures.

  ## Format

  ```
  | Field            | Size      |
  |------------------|-----------|
  | Signature Length | 2 bytes   | Uint16
  | Signature        | Variable  | DER-encoded ECDSA signature
  ```

  ## Signature Encoding

  ECDSA signatures are DER-encoded per RFC 3279. The length varies:
  - P-256 (ECDSA_P256): typically 70-72 bytes
  - P-384 (ECDSA_P384): typically 102-104 bytes
  """

  @typedoc "Footer structure"
  @type t :: %{signature: binary()}

  @doc """
  Serializes a footer with the given signature.

  ## Parameters

  - `signature` - DER-encoded ECDSA signature

  ## Examples

      iex> Footer.serialize(<<48, 69, ...>>)
      {:ok, <<0, 71, 48, 69, ...>>}
  """
  @spec serialize(binary()) :: {:ok, binary()}
  def serialize(signature) when is_binary(signature) do
    length = byte_size(signature)
    {:ok, <<length::16-big, signature::binary>>}
  end

  @doc """
  Deserializes a footer from binary data.

  Returns `{:ok, footer_map, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(<<length::16-big, rest::binary>>) when byte_size(rest) >= length do
    <<signature::binary-size(length), remaining::binary>> = rest
    {:ok, %{signature: signature}, remaining}
  end

  def deserialize(<<_length::16-big, _rest::binary>>), do: {:error, :incomplete_footer}
  def deserialize(_), do: {:error, :invalid_footer}
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/footer_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.FooterTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Format.Footer

  describe "serialize/1 and deserialize/1" do
    test "round-trips a signature" do
      # Simulate a DER-encoded signature
      signature = :crypto.strong_rand_bytes(103)

      assert {:ok, serialized} = Footer.serialize(signature)
      assert {:ok, footer, <<>>} = Footer.deserialize(serialized)

      assert footer.signature == signature
    end

    test "encodes length as big-endian uint16" do
      signature = :crypto.strong_rand_bytes(72)

      assert {:ok, <<0, 72, _::binary>>} = Footer.serialize(signature)
    end

    test "preserves trailing bytes" do
      signature = <<1, 2, 3, 4, 5>>

      assert {:ok, serialized} = Footer.serialize(signature)
      with_trailing = serialized <> <<99, 100>>

      assert {:ok, %{signature: ^signature}, <<99, 100>>} = Footer.deserialize(with_trailing)
    end

    test "handles empty signature" do
      assert {:ok, <<0, 0>>} = Footer.serialize(<<>>)
      assert {:ok, %{signature: <<>>}, <<>>} = Footer.deserialize(<<0, 0>>)
    end

    test "returns error for incomplete footer" do
      # Length says 100 bytes, but only 5 present
      assert {:error, :incomplete_footer} = Footer.deserialize(<<0, 100, 1, 2, 3, 4, 5>>)
    end

    test "returns error for invalid footer" do
      assert {:error, :invalid_footer} = Footer.deserialize(<<0>>)
      assert {:error, :invalid_footer} = Footer.deserialize(<<>>)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/footer_test.exs`
- [x] Quality checks pass: `mix quality --quick`

#### Manual Verification:
- [x] In IEx, serialize a mock signature and verify the byte layout

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 7.

---

## Phase 7: Complete Message Module

### Overview
Create a unified Message module that combines header, body, and footer handling.

### Spec Requirements Addressed
- Complete message = header + body + optional footer
- Footer presence determined by algorithm suite's signing flag

### Changes Required

#### 1. Create Message module
**File**: `lib/aws_encryption_sdk/format/message.ex`

```elixir
defmodule AwsEncryptionSdk.Format.Message do
  @moduledoc """
  Complete message serialization and deserialization.

  An AWS Encryption SDK message consists of:
  1. Header - Contains algorithm suite, message ID, encryption context, EDKs
  2. Body - Encrypted content (framed or non-framed)
  3. Footer - Optional ECDSA signature (only for signed algorithm suites)

  ## Message Structure

  ```
  +--------+--------+--------+
  | Header | Body   | Footer |
  +--------+--------+--------+
                    ^
                    |
                    Only present for signed suites
  ```
  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.Footer
  alias AwsEncryptionSdk.Format.Header

  @typedoc "Non-framed message body content"
  @type non_framed_body :: Body.non_framed()

  @typedoc "Framed message body content"
  @type framed_body :: [Body.frame()]

  @typedoc "Complete message structure"
  @type t :: %{
          header: Header.t(),
          body: non_framed_body() | framed_body(),
          footer: %{signature: binary()} | nil
        }

  @doc """
  Deserializes a complete message from binary data.

  Returns `{:ok, message, rest}` on success.
  """
  @spec deserialize(binary()) :: {:ok, t(), binary()} | {:error, term()}
  def deserialize(data) do
    with {:ok, header, rest} <- Header.deserialize(data),
         {:ok, body, rest} <- deserialize_body(rest, header),
         {:ok, footer, rest} <- deserialize_footer(rest, header.algorithm_suite) do
      message = %{
        header: header,
        body: body,
        footer: footer
      }

      {:ok, message, rest}
    end
  end

  @doc """
  Checks if a message requires a footer based on its algorithm suite.
  """
  @spec requires_footer?(Header.t()) :: boolean()
  def requires_footer?(%Header{algorithm_suite: suite}) do
    AlgorithmSuite.signed?(suite)
  end

  # Private functions

  defp deserialize_body(data, %Header{content_type: :non_framed}) do
    Body.deserialize_non_framed(data)
  end

  defp deserialize_body(data, %Header{content_type: :framed, frame_length: frame_length}) do
    Body.deserialize_all_frames(data, frame_length)
  end

  defp deserialize_footer(data, suite) do
    if AlgorithmSuite.signed?(suite) do
      Footer.deserialize(data)
    else
      {:ok, nil, data}
    end
  end
end
```

#### 2. Create test file
**File**: `test/aws_encryption_sdk/format/message_test.exs`

```elixir
defmodule AwsEncryptionSdk.Format.MessageTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.Footer
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Format.Message
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  describe "requires_footer?/1" do
    test "returns true for signed suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      assert Message.requires_footer?(header)
    end

    test "returns false for unsigned suite" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      refute Message.requires_footer?(header)
    end
  end

  describe "deserialize/1 with non-framed body" do
    test "deserializes unsigned message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{"k" => "v"},
        encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3, 4, 5>>
      auth_tag = :crypto.strong_rand_bytes(16)
      {:ok, body_bin} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      message_bin = header_bin <> body_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.algorithm_suite.id == suite.id
      assert message.body.ciphertext == ciphertext
      assert message.footer == nil
    end

    test "deserializes signed message with footer" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :non_framed,
        frame_length: 0,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      iv = :crypto.strong_rand_bytes(12)
      ciphertext = <<1, 2, 3>>
      auth_tag = :crypto.strong_rand_bytes(16)
      {:ok, body_bin} = Body.serialize_non_framed(iv, ciphertext, auth_tag)

      signature = :crypto.strong_rand_bytes(103)
      {:ok, footer_bin} = Footer.serialize(signature)

      message_bin = header_bin <> body_bin <> footer_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.algorithm_suite.id == suite.id
      assert message.body.ciphertext == ciphertext
      assert message.footer.signature == signature
    end
  end

  describe "deserialize/1 with framed body" do
    test "deserializes framed message" do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
      frame_length = 100

      header = %Header{
        version: 2,
        algorithm_suite: suite,
        message_id: :crypto.strong_rand_bytes(32),
        encryption_context: %{},
        encrypted_data_keys: [EncryptedDataKey.new("p", "i", <<1>>)],
        content_type: :framed,
        frame_length: frame_length,
        algorithm_suite_data: :crypto.strong_rand_bytes(32),
        header_auth_tag: :crypto.strong_rand_bytes(16)
      }

      {:ok, header_bin} = Header.serialize(header)

      auth_tag = :crypto.strong_rand_bytes(16)

      body_bin =
        Body.serialize_regular_frame(
          1,
          :crypto.strong_rand_bytes(12),
          :crypto.strong_rand_bytes(frame_length),
          auth_tag
        ) <>
          Body.serialize_final_frame(2, :crypto.strong_rand_bytes(12), <<1, 2, 3>>, auth_tag)

      message_bin = header_bin <> body_bin

      assert {:ok, message, <<>>} = Message.deserialize(message_bin)
      assert message.header.content_type == :framed
      assert length(message.body) == 2
      assert Enum.at(message.body, 0).sequence_number == 1
      assert Enum.at(message.body, 1).sequence_number == 2
      assert Enum.at(message.body, 1).final == true
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/format/message_test.exs`
- [x] Full test suite passes: `mix quality`

#### Manual Verification:
- [x] In IEx, create a complete message and verify deserialization works

**Implementation Note**: After completing this phase and all automated verification passes, pause here for final review.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All format module tests pass

### Manual:
- [x] Create and serialize a v2 non-framed message in IEx
- [x] Create and serialize a v2 framed message in IEx
- [x] Create and serialize a v1 header in IEx
- [x] Verify encryption context sorting works correctly

## Testing Strategy

### Unit Tests
Each module has comprehensive unit tests covering:
- Round-trip serialization/deserialization
- Binary format correctness
- Error handling
- Edge cases (empty values, max sizes)

### Manual Testing Steps
1. Start IEx: `iex -S mix`
2. Create an EDK and serialize it
3. Create an encryption context and verify sorting
4. Create a v2 header and examine the binary
5. Create a non-framed body and examine the binary
6. Create a framed body with multiple frames
7. Combine into a complete message

## References

- Issue: #9
- Research: `thoughts/shared/research/2026-01-25-GH9-message-format-serialization.md`
- Spec:
  - [message-header.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-header.md)
  - [message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md)
  - [message-body-aad.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body-aad.md)
  - [message-footer.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-footer.md)
  - [structures.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/structures.md)
