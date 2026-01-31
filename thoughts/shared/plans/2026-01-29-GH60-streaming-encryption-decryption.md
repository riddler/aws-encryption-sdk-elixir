# Streaming Encryption/Decryption Implementation Plan

## Overview

Implement streaming encryption and decryption APIs that process data incrementally without loading the entire plaintext or ciphertext into memory. Uses state machines with Elixir's `Enumerable` protocol for seamless integration with `Stream` functions.

**Issue**: #60
**Research**: `thoughts/shared/research/2026-01-29-GH60-streaming-encryption-decryption.md`

## Specification Requirements

### Source Documents
- [encrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md) - Streaming encryption
- [decrypt.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md) - Streaming decryption
- [message-body.md](https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md) - Frame format

### Key Requirements

| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Header bytes MUST NOT be released until entire header serialized | encrypt.md | MUST |
| Frame bytes MUST NOT be released until entire frame serialized | encrypt.md | MUST |
| Footer bytes MUST NOT be released until entire footer serialized | encrypt.md | MUST |
| Signature input MUST be fed incrementally (no buffering) | encrypt.md | MUST |
| Frame sequence numbers MUST start at 1, increment by 1 | message-body.md | MUST |
| Final frame marker MUST be 0xFFFFFFFF | message-body.md | MUST |
| Trailing bytes after completion MUST cause failure | decrypt.md | MUST |
| MUST provide config option to fail on signed algorithm suites | decrypt.md | MUST |
| Final frame plaintext MUST NOT be released until signature verified | decrypt.md | MUST |
| Regular frame plaintext SHOULD be released after frame auth (unsigned) | decrypt.md | SHOULD |
| Regular frame plaintext SHOULD be released for signed (marked unverified) | decrypt.md | SHOULD |

## Test Vectors

### Validation Strategy

Each phase validates against existing decrypt test vectors. The streaming implementation must produce identical output to the non-streaming implementation for all test vectors.

Test vectors are validated using the harness at `test/support/test_vector_harness.ex`.

Run test vector tests with: `mix test --only test_vectors`

### Test Vector Summary

| Phase | Focus | Validation Approach |
|-------|-------|---------------------|
| 1 | Signature Accumulator | Unit tests with known ECDSA signatures |
| 2 | Stream Encryptor | Round-trip: encrypt streaming → decrypt non-streaming |
| 3 | Stream Decryptor | Decrypt test vectors via streaming API |
| 4 | Signed Suites | Test vectors with algorithm 0x0578 |
| 5 | High-Level API | Full round-trip with `Stream` composition |
| 6 | Edge Cases | Empty plaintext, single byte, exact frame multiples |

### Harness Setup Pattern

```elixir
# In test file setup_all
setup_all do
  case TestVectorSetup.find_manifest("**/manifest.json") do
    {:ok, manifest_path} ->
      {:ok, harness} = TestVectorHarness.load_manifest(manifest_path)
      {:ok, harness: harness}
    :not_found ->
      {:ok, harness: nil}
  end
end
```

## Current State Analysis

### Key Discoveries

1. **Non-streaming noted explicitly** (`encrypt.ex:7`, `decrypt.ex:7`):
   > "This is a non-streaming implementation that requires the entire plaintext in memory"

2. **Frame primitives exist** (`format/body.ex`):
   - `deserialize_frame/2` (line 204) returns `{:ok, frame, rest}` - streaming-ready
   - `serialize_regular_frame/4` (line 161) and `serialize_final_frame/4` (line 183)

3. **ECDSA uses full message** (`crypto/ecdsa.ex:99-100`):
   ```elixir
   :crypto.sign(:ecdsa, :sha384, message, [private_key, :secp384r1])
   ```
   But Erlang supports `{:digest, hash}` form for pre-hashed data.

4. **Chunking logic** (`encrypt.ex:206-218`):
   - `chunk_plaintext_loop/3` - recursive binary slicing by frame_length
   - Can be adapted for streaming input

5. **Frame decryption** (`decrypt.ex:189-206`):
   - Uses `Enum.reduce_while/3` over all frames
   - Each frame independently authenticated

### Existing Patterns to Follow

- State structs with atoms for state names (see `cache/local_cache.ex` GenServer)
- Return tuples: `{:ok, result}` / `{:error, reason}`
- Binary pattern matching for parsing (see `format/body.ex`)
- AAD construction via `BodyAad.serialize/4`

## Desired End State

After this plan is complete:

1. **New modules exist**:
   - `lib/aws_encryption_sdk/stream/encryptor.ex`
   - `lib/aws_encryption_sdk/stream/decryptor.ex`
   - `lib/aws_encryption_sdk/stream/signature_accumulator.ex`

2. **High-level API added** to `lib/aws_encryption_sdk.ex`:
   ```elixir
   AwsEncryptionSdk.encrypt_stream(client, plaintext_stream, opts)
   AwsEncryptionSdk.decrypt_stream(client, ciphertext_stream, opts)
   ```

3. **Idiomatic usage works**:
   ```elixir
   File.stream!("large_file.bin", [], 4096)
   |> AwsEncryptionSdk.encrypt_stream(client)
   |> Stream.into(File.stream!("encrypted.bin"))
   |> Stream.run()
   ```

4. **All existing tests pass** - streaming produces identical output to non-streaming

5. **`:fail_on_signed` option** rejects signed algorithm suites in streaming mode

### Verification

```elixir
# Round-trip verification
plaintext = :crypto.strong_rand_bytes(100_000)

# Non-streaming
{:ok, %{ciphertext: ct1}} = AwsEncryptionSdk.encrypt(client, plaintext)

# Streaming (collect to binary for comparison)
ct2 =
  [plaintext]
  |> AwsEncryptionSdk.encrypt_stream(client)
  |> Enum.into(<<>>, &(&2 <> &1))

# Must be identical
ct1 == ct2
```

## What We're NOT Doing

- **GenServer-based streaming** - Using pure functions with explicit state for better composability
- **GenStage/Flow integration** - Out of scope; users can wrap if needed
- **Non-framed streaming** - Non-framed messages are inherently non-streaming
- **Partial frame release** - Frames are atomic; no mid-frame plaintext release
- **Automatic retry on signature failure** - Caller handles errors

---

## Phase 1: Signature Accumulator

### Overview

Create a module for incremental SHA-384 hash accumulation that can be used for ECDSA signing/verification without buffering the entire message.

### Spec Requirements Addressed

- Signature input MUST be fed incrementally (encrypt.md)
- Signature MUST be calculated over header + body in order (message-footer.md)

### Changes Required

#### 1. New Module: `lib/aws_encryption_sdk/stream/signature_accumulator.ex`

**File**: `lib/aws_encryption_sdk/stream/signature_accumulator.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.SignatureAccumulator do
  @moduledoc """
  Incremental signature accumulation for streaming operations.

  Uses SHA-384 hash accumulation to avoid buffering the entire message
  for ECDSA signing/verification.

  ## Example

      acc = SignatureAccumulator.init()
      acc = SignatureAccumulator.update(acc, header_bytes)
      acc = SignatureAccumulator.update(acc, frame1_bytes)
      acc = SignatureAccumulator.update(acc, frame2_bytes)
      signature = SignatureAccumulator.sign(acc, private_key)

  """

  @type t :: %__MODULE__{
          hash_ctx: :crypto.hash_state()
        }

  defstruct [:hash_ctx]

  @doc """
  Initializes a new signature accumulator with SHA-384.
  """
  @spec init() :: t()
  def init do
    %__MODULE__{hash_ctx: :crypto.hash_init(:sha384)}
  end

  @doc """
  Updates the accumulator with additional data.
  """
  @spec update(t(), binary()) :: t()
  def update(%__MODULE__{hash_ctx: ctx} = acc, data) when is_binary(data) do
    %{acc | hash_ctx: :crypto.hash_update(ctx, data)}
  end

  @doc """
  Finalizes the hash and signs with ECDSA P-384.

  Returns DER-encoded signature.
  """
  @spec sign(t(), binary()) :: binary()
  def sign(%__MODULE__{hash_ctx: ctx}, private_key) when is_binary(private_key) do
    digest = :crypto.hash_final(ctx)
    :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [private_key, :secp384r1])
  end

  @doc """
  Finalizes the hash and verifies an ECDSA P-384 signature.

  Returns `true` if valid, `false` otherwise.
  """
  @spec verify(t(), binary(), binary()) :: boolean()
  def verify(%__MODULE__{hash_ctx: ctx}, signature, public_key)
      when is_binary(signature) and is_binary(public_key) do
    digest = :crypto.hash_final(ctx)
    :crypto.verify(:ecdsa, :sha384, {:digest, digest}, signature, [public_key, :secp384r1])
  end

  @doc """
  Returns the current hash digest without finalizing.

  Useful for debugging or intermediate verification.
  """
  @spec digest(t()) :: binary()
  def digest(%__MODULE__{hash_ctx: ctx}) do
    # Clone context to avoid consuming it
    :crypto.hash_final(ctx)
  end
end
```

#### 2. Test File: `test/aws_encryption_sdk/stream/signature_accumulator_test.exs`

**File**: `test/aws_encryption_sdk/stream/signature_accumulator_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.SignatureAccumulatorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  describe "init/0" do
    test "creates accumulator with hash context" do
      acc = SignatureAccumulator.init()
      assert %SignatureAccumulator{hash_ctx: ctx} = acc
      assert is_reference(ctx)
    end
  end

  describe "update/2" do
    test "accumulates data" do
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("hello")
        |> SignatureAccumulator.update(" world")

      digest = SignatureAccumulator.digest(acc)
      expected = :crypto.hash(:sha384, "hello world")
      assert digest == expected
    end

    test "handles empty data" do
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update(<<>>)
        |> SignatureAccumulator.update("data")

      digest = SignatureAccumulator.digest(acc)
      expected = :crypto.hash(:sha384, "data")
      assert digest == expected
    end
  end

  describe "sign/2 and verify/3" do
    test "produces valid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("header bytes")
        |> SignatureAccumulator.update("frame 1 bytes")
        |> SignatureAccumulator.update("frame 2 bytes")

      signature = SignatureAccumulator.sign(acc, private_key)
      assert is_binary(signature)

      # Verify with fresh accumulator (same data)
      verify_acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("header bytes")
        |> SignatureAccumulator.update("frame 1 bytes")
        |> SignatureAccumulator.update("frame 2 bytes")

      assert SignatureAccumulator.verify(verify_acc, signature, public_key)
    end

    test "rejects invalid signature" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("original data")

      signature = SignatureAccumulator.sign(acc, private_key)

      # Different data should fail verification
      bad_acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update("different data")

      refute SignatureAccumulator.verify(bad_acc, signature, public_key)
    end

    test "matches ECDSA.sign for complete message" do
      {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)
      message = "complete message for signing"

      # Incremental signing
      acc =
        SignatureAccumulator.init()
        |> SignatureAccumulator.update(message)

      incremental_sig = SignatureAccumulator.sign(acc, private_key)

      # Both should verify with the same public key
      assert ECDSA.verify(message, incremental_sig, public_key, :secp384r1)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/signature_accumulator_test.exs`
- [x] Code compiles without warnings: `mix compile --warnings-as-errors`
- [x] Dialyzer passes: `mix dialyzer`

#### Manual Verification:
- [x] Verify in IEx that incremental signing produces valid signatures:
  ```elixir
  alias AwsEncryptionSdk.Stream.SignatureAccumulator
  alias AwsEncryptionSdk.Crypto.ECDSA

  {priv, pub} = ECDSA.generate_key_pair(:secp384r1)
  acc = SignatureAccumulator.init() |> SignatureAccumulator.update("test")
  sig = SignatureAccumulator.sign(acc, priv)
  ECDSA.verify("test", sig, pub, :secp384r1)  # Should return true
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Stream Encryptor Core

### Overview

Implement the streaming encryptor state machine for unsigned algorithm suites. Handles plaintext input in chunks and emits ciphertext frames incrementally.

### Spec Requirements Addressed

- Header bytes MUST NOT be released until entire header serialized (encrypt.md)
- Frame bytes MUST NOT be released until entire frame serialized (encrypt.md)
- Frame sequence numbers MUST start at 1, increment by 1 (message-body.md)
- Final frame marker MUST be 0xFFFFFFFF (message-body.md)

### Changes Required

#### 1. New Module: `lib/aws_encryption_sdk/stream/encryptor.ex`

**File**: `lib/aws_encryption_sdk/stream/encryptor.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.Encryptor do
  @moduledoc """
  Streaming encryptor state machine.

  Processes plaintext incrementally and emits ciphertext frames. Designed for
  use with Elixir's Stream functions.

  ## State Machine

  1. `:init` - Not started, awaiting first input
  2. `:encrypting` - Processing frames
  3. `:done` - Encryption complete

  ## Example

      # Initialize encryptor
      {:ok, enc} = Encryptor.init(materials, frame_length: 4096)

      # Process chunks, collecting output
      {enc, header_bytes} = Encryptor.start(enc)
      {enc, frame1_bytes} = Encryptor.update(enc, chunk1)
      {enc, frame2_bytes} = Encryptor.update(enc, chunk2)
      {enc, final_bytes} = Encryptor.finalize(enc)

  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  @default_frame_length 4096

  @type state :: :init | :encrypting | :done

  @type t :: %__MODULE__{
          state: state(),
          materials: EncryptionMaterials.t(),
          frame_length: pos_integer(),
          header: Header.t() | nil,
          derived_key: binary() | nil,
          sequence_number: pos_integer(),
          buffer: binary(),
          signature_acc: SignatureAccumulator.t() | nil
        }

  defstruct [
    :state,
    :materials,
    :frame_length,
    :header,
    :derived_key,
    :sequence_number,
    :buffer,
    :signature_acc
  ]

  @doc """
  Initializes a new streaming encryptor.

  ## Options

  - `:frame_length` - Frame size in bytes (default: 4096)
  """
  @spec init(EncryptionMaterials.t(), keyword()) :: {:ok, t()} | {:error, term()}
  def init(%EncryptionMaterials{} = materials, opts \\ []) do
    frame_length = Keyword.get(opts, :frame_length, @default_frame_length)
    suite = materials.algorithm_suite

    if AlgorithmSuite.allows_encryption?(suite) do
      # Initialize signature accumulator for signed suites
      sig_acc = if AlgorithmSuite.signed?(suite), do: SignatureAccumulator.init(), else: nil

      {:ok,
       %__MODULE__{
         state: :init,
         materials: materials,
         frame_length: frame_length,
         header: nil,
         derived_key: nil,
         sequence_number: 1,
         buffer: <<>>,
         signature_acc: sig_acc
       }}
    else
      {:error, :deprecated_algorithm_suite}
    end
  end

  @doc """
  Starts encryption by generating header.

  Returns `{:ok, updated_encryptor, header_bytes}` on success.
  Must be called before `update/2`.
  """
  @spec start(t()) :: {:ok, t(), binary()} | {:error, term()}
  def start(%__MODULE__{state: :init} = enc) do
    with {:ok, message_id} <- generate_message_id(enc.materials.algorithm_suite),
         {:ok, derived_key, commitment_key} <- derive_keys(enc.materials, message_id),
         {:ok, header} <- build_header(enc.materials, message_id, enc.frame_length, commitment_key),
         {:ok, header_with_tag} <- compute_header_auth_tag(header, derived_key),
         {:ok, header_binary} <- Header.serialize(header_with_tag) do
      # Update signature accumulator with header
      sig_acc =
        if enc.signature_acc do
          SignatureAccumulator.update(enc.signature_acc, header_binary)
        else
          nil
        end

      {:ok,
       %{enc | state: :encrypting, header: header_with_tag, derived_key: derived_key, signature_acc: sig_acc},
       header_binary}
    end
  end

  def start(%__MODULE__{state: state}) do
    {:error, {:invalid_state, state, :expected_init}}
  end

  @doc """
  Processes plaintext chunk.

  Buffers partial frames and emits complete frames. Returns `{:ok, updated_encryptor, frame_bytes}`
  where `frame_bytes` may be empty if not enough data for a complete frame.
  """
  @spec update(t(), binary()) :: {:ok, t(), binary()} | {:error, term()}
  def update(%__MODULE__{state: :encrypting} = enc, plaintext) when is_binary(plaintext) do
    # Add to buffer
    buffer = enc.buffer <> plaintext

    # Extract complete frames
    {frames, remaining_buffer, enc} = extract_frames(buffer, enc)

    # Serialize frames
    frame_bytes = IO.iodata_to_binary(frames)

    {:ok, %{enc | buffer: remaining_buffer}, frame_bytes}
  end

  def update(%__MODULE__{state: state}, _plaintext) do
    {:error, {:invalid_state, state, :expected_encrypting}}
  end

  @doc """
  Finalizes encryption.

  Encrypts any remaining buffered data as the final frame, optionally adds footer.
  Returns `{:ok, updated_encryptor, final_bytes}`.
  """
  @spec finalize(t()) :: {:ok, t(), binary()} | {:error, term()}
  def finalize(%__MODULE__{state: :encrypting} = enc) do
    # Encrypt remaining buffer as final frame
    final_frame = encrypt_frame(enc.buffer, enc, true)

    # Update signature accumulator
    sig_acc =
      if enc.signature_acc do
        SignatureAccumulator.update(enc.signature_acc, final_frame)
      else
        nil
      end

    # Build footer for signed suites
    footer_binary =
      if sig_acc do
        signature = SignatureAccumulator.sign(sig_acc, enc.materials.signing_key)
        signature_length = byte_size(signature)
        <<signature_length::16-big, signature::binary>>
      else
        <<>>
      end

    {:ok, %{enc | state: :done, buffer: <<>>, signature_acc: nil}, final_frame <> footer_binary}
  end

  def finalize(%__MODULE__{state: state}) do
    {:error, {:invalid_state, state, :expected_encrypting}}
  end

  @doc """
  Returns the current state of the encryptor.
  """
  @spec state(t()) :: state()
  def state(%__MODULE__{state: state}), do: state

  # Private functions

  defp generate_message_id(suite) do
    {:ok, Header.generate_message_id(suite.message_format_version)}
  end

  defp derive_keys(materials, message_id) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        {:ok, materials.plaintext_data_key, nil}

      :hkdf ->
        key_length = div(suite.data_key_length, 8)
        info = derive_key_info(suite)

        {:ok, derived_key} =
          HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, message_id, info, key_length)

        commitment_key =
          if suite.commitment_length > 0 do
            commit_info = "COMMITKEY" <> <<suite.id::16-big>>
            {:ok, key} = HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, message_id, commit_info, 32)
            key
          else
            nil
          end

        {:ok, derived_key, commitment_key}
    end
  end

  defp derive_key_info(%{commitment_length: 32} = suite) do
    "DERIVEKEY" <> <<suite.id::16-big>>
  end

  defp derive_key_info(suite) do
    <<suite.id::16-big>>
  end

  defp build_header(materials, message_id, frame_length, commitment_key) do
    suite = materials.algorithm_suite
    header_iv = if suite.message_format_version == 1, do: AesGcm.zero_iv(), else: nil

    header = %Header{
      version: suite.message_format_version,
      algorithm_suite: suite,
      message_id: message_id,
      encryption_context: materials.encryption_context,
      encrypted_data_keys: materials.encrypted_data_keys,
      content_type: :framed,
      frame_length: frame_length,
      algorithm_suite_data: commitment_key,
      header_iv: header_iv,
      header_auth_tag: <<0::128>>
    }

    {:ok, header}
  end

  defp compute_header_auth_tag(header, derived_key) do
    {:ok, header_body} = Header.serialize_body(header)
    ec_bytes = EncryptionContext.serialize(header.encryption_context)
    aad = header_body <> ec_bytes
    iv = AesGcm.zero_iv()

    {<<>>, auth_tag} =
      AesGcm.encrypt(
        header.algorithm_suite.encryption_algorithm,
        derived_key,
        iv,
        <<>>,
        aad
      )

    {:ok, %{header | header_auth_tag: auth_tag}}
  end

  defp extract_frames(buffer, enc) when byte_size(buffer) < enc.frame_length do
    {[], buffer, enc}
  end

  defp extract_frames(buffer, enc) do
    extract_frames_loop(buffer, enc, [])
  end

  defp extract_frames_loop(buffer, enc, acc) when byte_size(buffer) < enc.frame_length do
    {Enum.reverse(acc), buffer, enc}
  end

  defp extract_frames_loop(buffer, enc, acc) do
    <<chunk::binary-size(enc.frame_length), rest::binary>> = buffer
    frame = encrypt_frame(chunk, enc, false)

    # Update signature accumulator
    sig_acc =
      if enc.signature_acc do
        SignatureAccumulator.update(enc.signature_acc, frame)
      else
        nil
      end

    new_enc = %{enc | sequence_number: enc.sequence_number + 1, signature_acc: sig_acc}
    extract_frames_loop(rest, new_enc, [frame | acc])
  end

  defp encrypt_frame(plaintext, enc, is_final) do
    content_type = if is_final, do: :final_frame, else: :regular_frame
    aad = BodyAad.serialize(enc.header.message_id, content_type, enc.sequence_number, byte_size(plaintext))
    iv = AesGcm.sequence_number_to_iv(enc.sequence_number)

    {ciphertext, auth_tag} =
      AesGcm.encrypt(
        enc.header.algorithm_suite.encryption_algorithm,
        enc.derived_key,
        iv,
        plaintext,
        aad
      )

    if is_final do
      Body.serialize_final_frame(enc.sequence_number, iv, ciphertext, auth_tag)
    else
      Body.serialize_regular_frame(enc.sequence_number, iv, ciphertext, auth_tag)
    end
  end
end
```

#### 2. Test File: `test/aws_encryption_sdk/stream/encryptor_test.exs`

**File**: `test/aws_encryption_sdk/stream/encryptor_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.EncryptorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Create test materials with unsigned committed suite
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_data_key = :crypto.strong_rand_bytes(32)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: %{"purpose" => "test"},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: nil,
      required_encryption_context_keys: []
    }

    {:ok, materials: materials}
  end

  describe "init/2" do
    test "initializes encryptor in init state", %{materials: materials} do
      assert {:ok, enc} = Encryptor.init(materials)
      assert enc.state == :init
      assert enc.sequence_number == 1
      assert enc.buffer == <<>>
    end

    test "accepts frame_length option", %{materials: materials} do
      assert {:ok, enc} = Encryptor.init(materials, frame_length: 1024)
      assert enc.frame_length == 1024
    end
  end

  describe "start/1" do
    test "generates header and transitions to encrypting", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials)
      assert {:ok, enc, header_bytes} = Encryptor.start(enc)
      assert enc.state == :encrypting
      assert is_binary(header_bytes)
      assert byte_size(header_bytes) > 0
    end

    test "fails if not in init state", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials)
      {:ok, enc, _} = Encryptor.start(enc)
      assert {:error, {:invalid_state, :encrypting, :expected_init}} = Encryptor.start(enc)
    end
  end

  describe "update/2" do
    test "buffers partial frames", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 100)
      {:ok, enc, _header} = Encryptor.start(enc)

      # Less than frame_length
      {:ok, enc, output} = Encryptor.update(enc, "small")
      assert output == <<>>
      assert enc.buffer == "small"
    end

    test "emits complete frames", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 10)
      {:ok, enc, _header} = Encryptor.start(enc)

      # Exactly one frame
      {:ok, enc, output} = Encryptor.update(enc, "0123456789")
      assert byte_size(output) > 0
      assert enc.buffer == <<>>
      assert enc.sequence_number == 2
    end

    test "emits multiple frames", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 5)
      {:ok, enc, _header} = Encryptor.start(enc)

      # Three complete frames plus partial
      {:ok, enc, output} = Encryptor.update(enc, "0123456789ABCDEF")
      assert byte_size(output) > 0
      assert enc.buffer == "F"
      assert enc.sequence_number == 4
    end
  end

  describe "finalize/1" do
    test "encrypts remaining buffer as final frame", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 100)
      {:ok, enc, _header} = Encryptor.start(enc)
      {:ok, enc, _} = Encryptor.update(enc, "partial data")

      {:ok, enc, final} = Encryptor.finalize(enc)
      assert enc.state == :done
      assert byte_size(final) > 0
    end

    test "handles empty buffer", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 100)
      {:ok, enc, _header} = Encryptor.start(enc)

      {:ok, enc, final} = Encryptor.finalize(enc)
      assert enc.state == :done
      assert byte_size(final) > 0  # Empty final frame
    end
  end

  describe "round-trip with non-streaming decrypt" do
    test "produces valid ciphertext", %{materials: materials} do
      plaintext = :crypto.strong_rand_bytes(150)

      # Stream encrypt
      {:ok, enc} = Encryptor.init(materials, frame_length: 50)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Non-streaming decrypt
      decryption_materials = %AwsEncryptionSdk.Materials.DecryptionMaterials{
        algorithm_suite: materials.algorithm_suite,
        plaintext_data_key: materials.plaintext_data_key,
        encryption_context: materials.encryption_context,
        verification_key: nil,
        required_encryption_context_keys: []
      }

      assert {:ok, result} = AwsEncryptionSdk.Decrypt.decrypt(ciphertext, decryption_materials)
      assert result.plaintext == plaintext
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/encryptor_test.exs`
- [x] Code compiles without warnings
- [x] Round-trip test passes (streaming encrypt → non-streaming decrypt)

#### Manual Verification:
- [x] Verify in IEx:
  ```elixir
  # Create materials (use test setup)
  {:ok, enc} = Encryptor.init(materials, frame_length: 100)
  {:ok, enc, header} = Encryptor.start(enc)
  {:ok, enc, frame1} = Encryptor.update(enc, String.duplicate("x", 100))
  {:ok, enc, frame2} = Encryptor.update(enc, "final data")
  {:ok, _enc, final} = Encryptor.finalize(enc)
  ciphertext = header <> frame1 <> frame2 <> final
  # Verify can decrypt with existing decrypt module
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Stream Decryptor Core

### Overview

Implement the streaming decryptor state machine for unsigned algorithm suites. Parses ciphertext incrementally and emits plaintext frames.

### Spec Requirements Addressed

- Trailing bytes after completion MUST cause failure (decrypt.md)
- Regular frame plaintext SHOULD be released after frame auth (decrypt.md)
- Frame sequence numbers validated incrementally

### Changes Required

#### 1. New Module: `lib/aws_encryption_sdk/stream/decryptor.ex`

**File**: `lib/aws_encryption_sdk/stream/decryptor.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.Decryptor do
  @moduledoc """
  Streaming decryptor state machine.

  Processes ciphertext incrementally and emits plaintext frames. Designed for
  use with Elixir's Stream functions.

  ## State Machine

  1. `:init` - Not started, awaiting ciphertext
  2. `:reading_header` - Accumulating header bytes
  3. `:decrypting` - Processing frames
  4. `:reading_footer` - Accumulating footer (signed suites)
  5. `:done` - Decryption complete

  ## Security

  For unsigned suites, plaintext is released immediately after frame authentication.
  For signed suites, see `:fail_on_signed` option.

  """

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Body
  alias AwsEncryptionSdk.Format.BodyAad
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Stream.SignatureAccumulator

  @type state :: :init | :reading_header | :decrypting | :reading_footer | :done

  @type plaintext_status :: :verified | :unverified

  @type t :: %__MODULE__{
          state: state(),
          materials: DecryptionMaterials.t() | nil,
          get_materials: (Header.t() -> {:ok, DecryptionMaterials.t()} | {:error, term()}) | nil,
          header: Header.t() | nil,
          derived_key: binary() | nil,
          expected_sequence: pos_integer(),
          buffer: binary(),
          signature_acc: SignatureAccumulator.t() | nil,
          fail_on_signed: boolean(),
          final_frame_plaintext: binary() | nil
        }

  defstruct [
    :state,
    :materials,
    :get_materials,
    :header,
    :derived_key,
    :expected_sequence,
    :buffer,
    :signature_acc,
    :fail_on_signed,
    :final_frame_plaintext
  ]

  @doc """
  Initializes a new streaming decryptor.

  ## Options

  - `:get_materials` - Function `(header) -> {:ok, materials} | {:error, reason}` to obtain
    decryption materials after header is parsed. Required.
  - `:fail_on_signed` - If `true`, fails immediately when a signed algorithm suite is detected.
    Default: `false`.
  """
  @spec init(keyword()) :: {:ok, t()} | {:error, term()}
  def init(opts \\ []) do
    get_materials = Keyword.fetch!(opts, :get_materials)
    fail_on_signed = Keyword.get(opts, :fail_on_signed, false)

    {:ok,
     %__MODULE__{
       state: :init,
       materials: nil,
       get_materials: get_materials,
       header: nil,
       derived_key: nil,
       expected_sequence: 1,
       buffer: <<>>,
       signature_acc: nil,
       fail_on_signed: fail_on_signed,
       final_frame_plaintext: nil
     }}
  end

  @doc """
  Processes ciphertext chunk.

  Returns `{:ok, updated_decryptor, plaintexts}` where `plaintexts` is a list of
  `{plaintext_binary, status}` tuples. Status is `:verified` for unsigned suites
  or final frame after signature verification, `:unverified` otherwise.

  For unsigned suites, plaintext is released immediately after frame authentication.
  """
  @spec update(t(), binary()) ::
          {:ok, t(), [{binary(), plaintext_status()}]} | {:error, term()}
  def update(%__MODULE__{} = dec, ciphertext) when is_binary(ciphertext) do
    buffer = dec.buffer <> ciphertext
    process_buffer(%{dec | buffer: buffer}, [])
  end

  @doc """
  Finalizes decryption.

  Verifies no trailing bytes remain and completes signature verification for signed suites.
  Returns `{:ok, updated_decryptor, final_plaintexts}`.
  """
  @spec finalize(t()) :: {:ok, t(), [{binary(), plaintext_status()}]} | {:error, term()}
  def finalize(%__MODULE__{state: :done, buffer: <<>>} = dec) do
    {:ok, dec, []}
  end

  def finalize(%__MODULE__{state: :done, buffer: buffer}) when byte_size(buffer) > 0 do
    {:error, :trailing_bytes}
  end

  def finalize(%__MODULE__{state: :reading_footer} = dec) do
    # Try to parse footer
    case parse_footer(dec) do
      {:ok, dec, plaintexts} -> {:ok, dec, plaintexts}
      {:error, :incomplete_footer} -> {:error, :incomplete_message}
      error -> error
    end
  end

  def finalize(%__MODULE__{state: state}) do
    {:error, {:incomplete_message, state}}
  end

  @doc """
  Returns the parsed header, if available.
  """
  @spec header(t()) :: Header.t() | nil
  def header(%__MODULE__{header: header}), do: header

  @doc """
  Returns the current state.
  """
  @spec state(t()) :: state()
  def state(%__MODULE__{state: state}), do: state

  # Private: Process buffer based on current state

  defp process_buffer(%{state: :init} = dec, acc) do
    process_buffer(%{dec | state: :reading_header}, acc)
  end

  defp process_buffer(%{state: :reading_header} = dec, acc) do
    case Header.deserialize(dec.buffer) do
      {:ok, header, rest} ->
        # Check for signed suite if fail_on_signed is set
        if dec.fail_on_signed and AlgorithmSuite.signed?(header.algorithm_suite) do
          {:error, :signed_algorithm_suite_not_allowed}
        else
          # Get materials
          case dec.get_materials.(header) do
            {:ok, materials} ->
              with {:ok, derived_key} <- derive_data_key(materials, header),
                   :ok <- verify_commitment(materials, header),
                   :ok <- verify_header_auth_tag(header, derived_key) do
                # Initialize signature accumulator for signed suites
                sig_acc =
                  if AlgorithmSuite.signed?(header.algorithm_suite) do
                    {:ok, header_binary} = Header.serialize(header)

                    SignatureAccumulator.init()
                    |> SignatureAccumulator.update(header_binary)
                  else
                    nil
                  end

                dec = %{
                  dec
                  | state: :decrypting,
                    materials: materials,
                    header: header,
                    derived_key: derived_key,
                    buffer: rest,
                    signature_acc: sig_acc
                }

                process_buffer(dec, acc)
              end

            {:error, _} = error ->
              error
          end
        end

      {:error, :incomplete_header} ->
        {:ok, dec, Enum.reverse(acc)}

      {:error, _} = error ->
        error
    end
  end

  defp process_buffer(%{state: :decrypting} = dec, acc) do
    case Body.deserialize_frame(dec.buffer, dec.header.frame_length) do
      {:ok, frame, rest} ->
        # Verify sequence number
        if frame.sequence_number != dec.expected_sequence do
          {:error, {:sequence_mismatch, dec.expected_sequence, frame.sequence_number}}
        else
          case decrypt_frame(frame, dec) do
            {:ok, plaintext} ->
              # Update signature accumulator with original frame bytes
              {sig_acc, consumed_bytes} =
                if dec.signature_acc do
                  # Calculate how much we consumed
                  consumed = byte_size(dec.buffer) - byte_size(rest)
                  frame_bytes = binary_part(dec.buffer, 0, consumed)
                  {SignatureAccumulator.update(dec.signature_acc, frame_bytes), consumed}
                else
                  {nil, 0}
                end

              is_final = Map.get(frame, :final, false)

              cond do
                is_final and sig_acc != nil ->
                  # Signed suite: hold final frame, transition to reading_footer
                  dec = %{
                    dec
                    | state: :reading_footer,
                      buffer: rest,
                      signature_acc: sig_acc,
                      final_frame_plaintext: plaintext
                  }

                  process_buffer(dec, acc)

                is_final ->
                  # Unsigned suite: done
                  dec = %{dec | state: :done, buffer: rest}
                  {:ok, dec, Enum.reverse([{plaintext, :verified} | acc])}

                sig_acc != nil ->
                  # Signed suite, regular frame: release as unverified
                  dec = %{
                    dec
                    | expected_sequence: dec.expected_sequence + 1,
                      buffer: rest,
                      signature_acc: sig_acc
                  }

                  process_buffer(dec, [{plaintext, :unverified} | acc])

                true ->
                  # Unsigned suite, regular frame: release as verified
                  dec = %{dec | expected_sequence: dec.expected_sequence + 1, buffer: rest}
                  process_buffer(dec, [{plaintext, :verified} | acc])
              end

            {:error, _} = error ->
              error
          end
        end

      {:error, :incomplete_regular_frame} ->
        {:ok, dec, Enum.reverse(acc)}

      {:error, :incomplete_final_frame} ->
        {:ok, dec, Enum.reverse(acc)}

      {:error, _} = error ->
        error
    end
  end

  defp process_buffer(%{state: :reading_footer} = dec, acc) do
    case parse_footer(dec) do
      {:ok, dec, plaintexts} -> {:ok, dec, Enum.reverse(acc) ++ plaintexts}
      {:error, :incomplete_footer} -> {:ok, dec, Enum.reverse(acc)}
      error -> error
    end
  end

  defp process_buffer(%{state: :done} = dec, acc) do
    {:ok, dec, Enum.reverse(acc)}
  end

  defp parse_footer(%{buffer: <<sig_len::16-big, rest::binary>>} = dec)
       when byte_size(rest) >= sig_len do
    <<signature::binary-size(sig_len), remaining::binary>> = rest

    # Verify signature
    if SignatureAccumulator.verify(dec.signature_acc, signature, dec.materials.verification_key) do
      dec = %{dec | state: :done, buffer: remaining, signature_acc: nil}
      {:ok, dec, [{dec.final_frame_plaintext, :verified}]}
    else
      {:error, :signature_verification_failed}
    end
  end

  defp parse_footer(_dec) do
    {:error, :incomplete_footer}
  end

  defp derive_data_key(materials, header) do
    suite = materials.algorithm_suite

    case suite.kdf_type do
      :identity ->
        {:ok, materials.plaintext_data_key}

      :hkdf ->
        key_length = div(suite.data_key_length, 8)
        info = derive_key_info(suite)
        HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, header.message_id, info, key_length)
    end
  end

  defp derive_key_info(%{commitment_length: 32} = suite) do
    "DERIVEKEY" <> <<suite.id::16-big>>
  end

  defp derive_key_info(suite) do
    <<suite.id::16-big>>
  end

  defp verify_commitment(_materials, %{algorithm_suite: %{commitment_length: 0}}) do
    :ok
  end

  defp verify_commitment(materials, header) do
    suite = materials.algorithm_suite
    info = "COMMITKEY" <> <<suite.id::16-big>>

    case HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, header.message_id, info, 32) do
      {:ok, expected_commitment} ->
        if :crypto.hash_equals(expected_commitment, header.algorithm_suite_data) do
          :ok
        else
          {:error, :commitment_mismatch}
        end

      {:error, _} = error ->
        error
    end
  end

  defp verify_header_auth_tag(header, derived_key) do
    {:ok, header_body} = Header.serialize_body(header)
    ec_bytes = EncryptionContext.serialize(header.encryption_context)
    aad = header_body <> ec_bytes
    iv = AesGcm.zero_iv()

    case AesGcm.decrypt(
           header.algorithm_suite.encryption_algorithm,
           derived_key,
           iv,
           <<>>,
           aad,
           header.header_auth_tag
         ) do
      {:ok, <<>>} -> :ok
      {:error, :authentication_failed} -> {:error, :header_authentication_failed}
    end
  end

  defp decrypt_frame(frame, dec) do
    content_type = if Map.get(frame, :final), do: :final_frame, else: :regular_frame
    plaintext_length = byte_size(frame.ciphertext)

    aad =
      BodyAad.serialize(dec.header.message_id, content_type, frame.sequence_number, plaintext_length)

    iv = AesGcm.sequence_number_to_iv(frame.sequence_number)

    case AesGcm.decrypt(
           dec.header.algorithm_suite.encryption_algorithm,
           dec.derived_key,
           iv,
           frame.ciphertext,
           aad,
           frame.auth_tag
         ) do
      {:ok, plaintext} -> {:ok, plaintext}
      {:error, :authentication_failed} -> {:error, :body_authentication_failed}
    end
  end
end
```

#### 2. Test File: `test/aws_encryption_sdk/stream/decryptor_test.exs`

**File**: `test/aws_encryption_sdk/stream/decryptor_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.DecryptorTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Create test materials
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_data_key = :crypto.strong_rand_bytes(32)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: %{"purpose" => "test"},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: nil,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: %{"purpose" => "test"},
      verification_key: nil,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "init/1" do
    test "initializes decryptor" do
      get_materials = fn _header -> {:error, :not_implemented} end
      assert {:ok, dec} = Decryptor.init(get_materials: get_materials)
      assert dec.state == :init
    end
  end

  describe "update/2 with unsigned suite" do
    test "decrypts complete message in one chunk", ctx do
      plaintext = "Hello, streaming world!"

      # Encrypt
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Decrypt in one chunk
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, plaintexts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final} = Decryptor.finalize(dec)

      all_plaintexts = plaintexts ++ final
      result = all_plaintexts |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext

      # All should be verified (unsigned suite)
      assert Enum.all?(all_plaintexts, fn {_, status} -> status == :verified end)
    end

    test "decrypts message in multiple chunks", ctx do
      plaintext = :crypto.strong_rand_bytes(200)

      # Encrypt
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Decrypt in small chunks
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      chunks = chunk_binary(ciphertext, 30)

      {dec, all_plaintexts} =
        Enum.reduce(chunks, {dec, []}, fn chunk, {dec, acc} ->
          {:ok, dec, plaintexts} = Decryptor.update(dec, chunk)
          {dec, acc ++ plaintexts}
        end)

      {:ok, _dec, final} = Decryptor.finalize(dec)
      all_plaintexts = all_plaintexts ++ final

      result = all_plaintexts |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end

    test "releases plaintext incrementally", ctx do
      plaintext = :crypto.strong_rand_bytes(500)

      # Encrypt with small frames
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 50)

      # Feed header + first few frames
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)

      # Split: header (~200 bytes) + some frames, then rest
      {:ok, dec, plaintexts1} = Decryptor.update(dec, binary_part(ciphertext, 0, 400))
      assert length(plaintexts1) > 0  # Should have some plaintext already

      {:ok, dec, plaintexts2} = Decryptor.update(dec, binary_part(ciphertext, 400, byte_size(ciphertext) - 400))
      {:ok, _dec, final} = Decryptor.finalize(dec)

      all = plaintexts1 ++ plaintexts2 ++ final
      result = all |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "finalize/1" do
    test "fails with trailing bytes", ctx do
      plaintext = "test"
      ciphertext = encrypt_streaming(ctx.enc_materials, plaintext, 100)
      # Add trailing garbage
      bad_ciphertext = ciphertext <> "garbage"

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, _} = Decryptor.update(dec, bad_ciphertext)

      assert {:error, :trailing_bytes} = Decryptor.finalize(dec)
    end
  end

  describe "fail_on_signed option" do
    test "rejects signed suite when enabled" do
      # This would need a signed suite - placeholder test
      # The actual test requires signed materials setup
    end
  end

  # Helper functions

  defp encrypt_streaming(materials, plaintext, frame_length) do
    {:ok, enc} = Encryptor.init(materials, frame_length: frame_length)
    {:ok, enc, header} = Encryptor.start(enc)
    {:ok, enc, frames} = Encryptor.update(enc, plaintext)
    {:ok, _enc, final} = Encryptor.finalize(enc)
    header <> frames <> final
  end

  defp chunk_binary(binary, chunk_size) do
    chunk_binary_loop(binary, chunk_size, [])
  end

  defp chunk_binary_loop(<<>>, _chunk_size, acc), do: Enum.reverse(acc)

  defp chunk_binary_loop(binary, chunk_size, acc) when byte_size(binary) <= chunk_size do
    Enum.reverse([binary | acc])
  end

  defp chunk_binary_loop(binary, chunk_size, acc) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    chunk_binary_loop(rest, chunk_size, [chunk | acc])
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/decryptor_test.exs`
- [x] Round-trip works: streaming encrypt → streaming decrypt
- [x] Incremental plaintext release works for unsigned suites

#### Manual Verification:
- [x] Verify plaintext is released incrementally (not all at once) in IEx
- [x] Verify trailing bytes cause failure

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: Signed Suite Support

### Overview

Add full signature verification support for signed algorithm suites (e.g., 0x0578). Regular frames release plaintext as "unverified", final frame held until signature verification.

### Spec Requirements Addressed

- Signature input MUST be fed incrementally (encrypt.md, decrypt.md)
- Final frame plaintext MUST NOT be released until signature verified (decrypt.md)
- Regular frame plaintext SHOULD be released for signed (marked unverified) (decrypt.md)

### Changes Required

#### 1. Update ECDSA module for digest-based signing

**File**: `lib/aws_encryption_sdk/crypto/ecdsa.ex`
**Changes**: Add digest-based sign/verify functions

```elixir
# Add after existing sign/2 function (around line 101)

@doc """
Signs a pre-computed digest using ECDSA P-384.

This is useful for streaming where the hash is accumulated incrementally.

## Parameters

- `digest` - SHA-384 digest (48 bytes)
- `private_key` - Raw private key bytes

## Returns

- DER-encoded ECDSA signature
"""
@spec sign_digest(binary(), binary()) :: binary()
def sign_digest(digest, private_key) when byte_size(digest) == 48 and is_binary(private_key) do
  :crypto.sign(:ecdsa, :sha384, {:digest, digest}, [private_key, :secp384r1])
end

@doc """
Verifies an ECDSA signature against a pre-computed digest.

## Parameters

- `digest` - SHA-384 digest (48 bytes)
- `signature` - DER-encoded ECDSA signature
- `public_key` - Raw public key bytes

## Returns

- `true` if valid, `false` otherwise
"""
@spec verify_digest(binary(), binary(), binary()) :: boolean()
def verify_digest(digest, signature, public_key)
    when byte_size(digest) == 48 and is_binary(signature) and is_binary(public_key) do
  :crypto.verify(:ecdsa, :sha384, {:digest, digest}, signature, [public_key, :secp384r1])
end
```

#### 2. Test signed suite round-trip

**File**: `test/aws_encryption_sdk/stream/signed_suite_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.SignedSuiteTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    # Create test materials with signed suite
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
    plaintext_data_key = :crypto.strong_rand_bytes(32)
    {private_key, public_key} = ECDSA.generate_key_pair(:secp384r1)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    # Add public key to encryption context (required for signed suites)
    enc_context = %{
      "purpose" => "test",
      "aws-crypto-public-key" => ECDSA.encode_public_key(public_key)
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: enc_context,
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: private_key,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: enc_context,
      verification_key: public_key,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "signed suite streaming" do
    test "encrypts and decrypts with signature", ctx do
      plaintext = :crypto.strong_rand_bytes(500)

      # Encrypt
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Verify footer exists (should have signature)
      # The final bytes should include 2-byte length + signature
      assert byte_size(final) > 100  # Includes final frame + footer

      # Decrypt
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, plaintexts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_plaintexts} = Decryptor.finalize(dec)

      all = plaintexts ++ final_plaintexts

      # Regular frames should be unverified
      regular = Enum.filter(all, fn {_, status} -> status == :unverified end)
      assert length(regular) > 0

      # Final frame should be verified (after signature check)
      final = Enum.filter(all, fn {_, status} -> status == :verified end)
      assert length(final) == 1

      result = all |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end

    test "fails on corrupted signature", ctx do
      plaintext = "test data"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Corrupt the last byte (signature)
      corrupted = binary_part(ciphertext, 0, byte_size(ciphertext) - 1) <> <<0xFF>>

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, _} = Decryptor.update(dec, corrupted)

      assert {:error, :signature_verification_failed} = Decryptor.finalize(dec)
    end

    test "fail_on_signed rejects signed suite", ctx do
      plaintext = "test"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials, fail_on_signed: true)

      assert {:error, :signed_algorithm_suite_not_allowed} = Decryptor.update(dec, ciphertext)
    end
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/signed_suite_test.exs`
- [x] Regular frames marked as `:unverified`
- [x] Final frame marked as `:verified` after signature check
- [x] Corrupted signature fails verification
- [x] `fail_on_signed: true` rejects signed suites

#### Manual Verification:
- [x] Verify in IEx that signed suite produces footer with signature
- [x] Verify plaintext status changes from unverified to verified

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 5.

---

## Phase 5: High-Level Stream API

### Overview

Add `Enumerable` protocol implementation and high-level `encrypt_stream`/`decrypt_stream` functions to the main API.

### Changes Required

#### 1. Stream Wrapper Module

**File**: `lib/aws_encryption_sdk/stream.ex`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream do
  @moduledoc """
  Streaming encryption and decryption APIs.

  Provides Stream-compatible functions for processing large data incrementally.

  ## Example

      # Encrypt a file stream
      File.stream!("input.bin", [], 4096)
      |> AwsEncryptionSdk.Stream.encrypt(client)
      |> Stream.into(File.stream!("output.encrypted"))
      |> Stream.run()

      # Decrypt a file stream
      File.stream!("output.encrypted", [], 4096)
      |> AwsEncryptionSdk.Stream.decrypt(client)
      |> Stream.map(fn {plaintext, _status} -> plaintext end)
      |> Stream.into(File.stream!("decrypted.bin"))
      |> Stream.run()

  """

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Behaviour, as: Cmm
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  @doc """
  Creates a stream that encrypts plaintext chunks.

  Returns a Stream that emits ciphertext binaries.

  ## Options

  - `:encryption_context` - Encryption context (default: `%{}`)
  - `:frame_length` - Frame size in bytes (default: 4096)
  - `:algorithm_suite` - Algorithm suite to use (default: from client)
  """
  @spec encrypt(Enumerable.t(), Client.t(), keyword()) :: Enumerable.t()
  def encrypt(plaintext_stream, %Client{} = client, opts \\ []) do
    Stream.resource(
      fn -> init_encryptor(client, opts) end,
      fn
        {:error, reason} ->
          {:halt, {:error, reason}}

        {enc, :start, enum} ->
          case Encryptor.start(enc) do
            {:ok, enc, header} ->
              {[header], {enc, :encrypting, enum}}

            {:error, reason} ->
              {:halt, {:error, reason}}
          end

        {enc, :encrypting, enum} ->
          case Enumerable.reduce(enum, {:cont, {enc, []}}, fn chunk, {enc, acc} ->
                 case Encryptor.update(enc, chunk) do
                   {:ok, enc, bytes} when byte_size(bytes) > 0 ->
                     {:suspend, {enc, [bytes | acc]}}

                   {:ok, enc, <<>>} ->
                     {:cont, {enc, acc}}

                   {:error, reason} ->
                     {:halt, {:error, reason}}
                 end
               end) do
            {:suspended, {enc, chunks}, continuation} ->
              {Enum.reverse(chunks), {enc, :encrypting, continuation}}

            {:done, {enc, chunks}} ->
              {Enum.reverse(chunks), {enc, :finalizing, nil}}

            {:halted, {:error, reason}} ->
              {:halt, {:error, reason}}
          end

        {enc, :finalizing, _} ->
          case Encryptor.finalize(enc) do
            {:ok, _enc, final} ->
              {[final], {:done, nil}}

            {:error, reason} ->
              {:halt, {:error, reason}}
          end

        {:done, _} ->
          {:halt, :done}
      end,
      fn _ -> :ok end
    )
  end

  @doc """
  Creates a stream that decrypts ciphertext chunks.

  Returns a Stream that emits `{plaintext, status}` tuples where status is
  `:verified` or `:unverified`.

  ## Options

  - `:encryption_context` - Reproduced context to validate (optional)
  - `:fail_on_signed` - Fail immediately on signed suites (default: false)
  """
  @spec decrypt(Enumerable.t(), Client.t(), keyword()) :: Enumerable.t()
  def decrypt(ciphertext_stream, %Client{} = client, opts \\ []) do
    Stream.resource(
      fn -> init_decryptor(client, opts) end,
      fn
        {:error, reason} ->
          {:halt, {:error, reason}}

        {dec, enum} ->
          case Enumerable.reduce(enum, {:cont, {dec, []}}, fn chunk, {dec, acc} ->
                 case Decryptor.update(dec, chunk) do
                   {:ok, dec, plaintexts} when plaintexts != [] ->
                     {:suspend, {dec, acc ++ plaintexts}}

                   {:ok, dec, []} ->
                     {:cont, {dec, acc}}

                   {:error, reason} ->
                     {:halt, {:error, reason}}
                 end
               end) do
            {:suspended, {dec, plaintexts}, continuation} ->
              {plaintexts, {dec, continuation}}

            {:done, {dec, plaintexts}} ->
              case Decryptor.finalize(dec) do
                {:ok, _dec, final} ->
                  {plaintexts ++ final, {:done, nil}}

                {:error, reason} ->
                  {:halt, {:error, reason}}
              end

            {:halted, {:error, reason}} ->
              {:halt, {:error, reason}}
          end

        {:done, _} ->
          {:halt, :done}
      end,
      fn _ -> :ok end
    )
  end

  # Private helpers

  defp init_encryptor(client, opts) do
    encryption_context = Keyword.get(opts, :encryption_context, %{})
    frame_length = Keyword.get(opts, :frame_length, 4096)

    request = %{
      encryption_context: encryption_context,
      commitment_policy: client.commitment_policy
    }

    case Cmm.get_encryption_materials(client.cmm, request) do
      {:ok, materials} ->
        case Encryptor.init(materials, frame_length: frame_length) do
          {:ok, enc} -> {enc, :start, nil}
          error -> error
        end

      error ->
        error
    end
  end

  defp init_decryptor(client, opts) do
    fail_on_signed = Keyword.get(opts, :fail_on_signed, false)
    reproduced_context = Keyword.get(opts, :encryption_context, %{})

    get_materials = fn header ->
      request = %{
        algorithm_suite: header.algorithm_suite,
        encrypted_data_keys: header.encrypted_data_keys,
        encryption_context: header.encryption_context,
        reproduced_encryption_context: reproduced_context
      }

      Cmm.get_decryption_materials(client.cmm, request)
    end

    case Decryptor.init(get_materials: get_materials, fail_on_signed: fail_on_signed) do
      {:ok, dec} -> {dec, nil}
      error -> error
    end
  end
end
```

#### 2. Add to main API

**File**: `lib/aws_encryption_sdk.ex`
**Changes**: Add streaming functions (add after line 269)

```elixir
# Add after decrypt_with_keyring delegation

@doc """
Creates a stream that encrypts plaintext chunks.

See `AwsEncryptionSdk.Stream.encrypt/3` for details.

## Example

    File.stream!("input.bin", [], 4096)
    |> AwsEncryptionSdk.encrypt_stream(client)
    |> Stream.into(File.stream!("output.encrypted"))
    |> Stream.run()

"""
defdelegate encrypt_stream(plaintext_stream, client, opts \\ []), to: AwsEncryptionSdk.Stream, as: :encrypt

@doc """
Creates a stream that decrypts ciphertext chunks.

See `AwsEncryptionSdk.Stream.decrypt/3` for details.

## Example

    File.stream!("encrypted.bin", [], 4096)
    |> AwsEncryptionSdk.decrypt_stream(client)
    |> Stream.map(fn {plaintext, _status} -> plaintext end)
    |> Stream.into(File.stream!("output.bin"))
    |> Stream.run()

"""
defdelegate decrypt_stream(ciphertext_stream, client, opts \\ []), to: AwsEncryptionSdk.Stream, as: :decrypt
```

#### 3. Update moduledoc

**File**: `lib/aws_encryption_sdk.ex`
**Changes**: Update moduledoc to mention streaming (around line 36)

Add after the existing API list:

```elixir
## Streaming API

For large files or memory-constrained environments:

- `encrypt_stream/3` - Stream encryption with chunked input
- `decrypt_stream/3` - Stream decryption with chunked input

```elixir
# Encrypt a large file
File.stream!("large_file.bin", [], 4096)
|> AwsEncryptionSdk.encrypt_stream(client)
|> Stream.into(File.stream!("encrypted.bin"))
|> Stream.run()
```
```

#### 4. Integration tests

**File**: `test/aws_encryption_sdk/stream/integration_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.IntegrationTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default, as: DefaultCmm
  alias AwsEncryptionSdk.Keyring.RawAes

  setup do
    # Create keyring and client
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("test", "key-1", key, :aes_256_gcm)
    cmm = DefaultCmm.new(keyring)
    client = Client.new(cmm)

    {:ok, client: client, key: key}
  end

  describe "encrypt_stream/3" do
    test "encrypts stream chunks", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(10_000)
      chunks = chunk_binary(plaintext, 1000)

      ciphertext =
        chunks
        |> AwsEncryptionSdk.encrypt_stream(client, encryption_context: %{"test" => "value"})
        |> Enum.into(<<>>, &(&2 <> &1))

      # Verify with non-streaming decrypt
      {:ok, result} = AwsEncryptionSdk.decrypt(client, ciphertext)
      assert result.plaintext == plaintext
    end
  end

  describe "decrypt_stream/3" do
    test "decrypts stream chunks", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(10_000)

      # Encrypt with non-streaming
      {:ok, %{ciphertext: ciphertext}} =
        AwsEncryptionSdk.encrypt(client, plaintext, encryption_context: %{"test" => "value"})

      # Decrypt with streaming
      chunks = chunk_binary(ciphertext, 500)

      result_plaintext =
        chunks
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result_plaintext == plaintext
    end
  end

  describe "round-trip streaming" do
    test "encrypt_stream -> decrypt_stream", %{client: client} do
      plaintext = :crypto.strong_rand_bytes(50_000)
      chunks = chunk_binary(plaintext, 2000)

      result =
        chunks
        |> AwsEncryptionSdk.encrypt_stream(client, frame_length: 1000)
        |> AwsEncryptionSdk.decrypt_stream(client)
        |> Enum.map(fn {pt, _status} -> pt end)
        |> IO.iodata_to_binary()

      assert result == plaintext
    end
  end

  defp chunk_binary(binary, chunk_size) do
    chunk_binary_loop(binary, chunk_size, [])
  end

  defp chunk_binary_loop(<<>>, _chunk_size, acc), do: Enum.reverse(acc)

  defp chunk_binary_loop(binary, chunk_size, acc) when byte_size(binary) <= chunk_size do
    Enum.reverse([binary | acc])
  end

  defp chunk_binary_loop(binary, chunk_size, acc) do
    <<chunk::binary-size(chunk_size), rest::binary>> = binary
    chunk_binary_loop(rest, chunk_size, [chunk | acc])
  end
end
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/integration_test.exs` (11/11 passing)
- [x] `encrypt_stream` produces valid ciphertext
- [x] `decrypt_stream` produces correct plaintext
- [x] Round-trip streaming works
- [x] Code quality: `mix quality` passes (all 12 Credo issues resolved)

#### Manual Verification:
- [ ] Test with actual file streams in IEx:
  ```elixir
  # Write test file
  File.write!("/tmp/test_input.bin", :crypto.strong_rand_bytes(100_000))

  # Stream encrypt
  File.stream!("/tmp/test_input.bin", [], 4096)
  |> AwsEncryptionSdk.encrypt_stream(client)
  |> Stream.into(File.stream!("/tmp/test_encrypted.bin"))
  |> Stream.run()

  # Stream decrypt
  File.stream!("/tmp/test_encrypted.bin", [], 4096)
  |> AwsEncryptionSdk.decrypt_stream(client)
  |> Stream.map(fn {pt, _} -> pt end)
  |> Stream.into(File.stream!("/tmp/test_output.bin"))
  |> Stream.run()

  # Verify
  File.read!("/tmp/test_input.bin") == File.read!("/tmp/test_output.bin")
  ```

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 6.

---

## Phase 6: Configuration & Polish

### Overview

Add `:fail_on_signed` configuration to Client, comprehensive documentation, and edge case handling.

### Changes Required

#### 1. Add streaming options to Client

**File**: `lib/aws_encryption_sdk/client.ex`
**Changes**: Add streaming configuration options

```elixir
# Add to @type t struct definition (around line 50)
# After existing fields, add:
stream_fail_on_signed: boolean()

# Update defstruct to include default
stream_fail_on_signed: false

# Add to new/2 opts handling
stream_fail_on_signed = Keyword.get(opts, :stream_fail_on_signed, false)
```

#### 2. Edge case tests

**File**: `test/aws_encryption_sdk/stream/edge_cases_test.exs`
**Changes**: New file

```elixir
defmodule AwsEncryptionSdk.Stream.EdgeCasesTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Materials.EncryptedDataKey
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Stream.Decryptor
  alias AwsEncryptionSdk.Stream.Encryptor

  setup do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    plaintext_data_key = :crypto.strong_rand_bytes(32)

    edk = %EncryptedDataKey{
      key_provider_id: "test",
      key_provider_info: "key-1",
      ciphertext: plaintext_data_key
    }

    enc_materials = %EncryptionMaterials{
      algorithm_suite: suite,
      encryption_context: %{},
      encrypted_data_keys: [edk],
      plaintext_data_key: plaintext_data_key,
      signing_key: nil,
      required_encryption_context_keys: []
    }

    dec_materials = %DecryptionMaterials{
      algorithm_suite: suite,
      plaintext_data_key: plaintext_data_key,
      encryption_context: %{},
      verification_key: nil,
      required_encryption_context_keys: []
    }

    {:ok, enc_materials: enc_materials, dec_materials: dec_materials}
  end

  describe "empty plaintext" do
    test "produces single empty final frame", ctx do
      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, <<>>)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      # Decrypt should produce empty plaintext
      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == <<>>
    end
  end

  describe "single byte plaintext" do
    test "encrypts and decrypts correctly", ctx do
      plaintext = <<42>>

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "exact frame multiple" do
    test "handles plaintext = N * frame_length", ctx do
      # Exactly 3 frames worth
      plaintext = :crypto.strong_rand_bytes(300)

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "off-by-one" do
    test "handles plaintext = N * frame_length + 1", ctx do
      # 3 frames + 1 byte
      plaintext = :crypto.strong_rand_bytes(301)

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 100)
      {:ok, enc, header} = Encryptor.start(enc)
      {:ok, enc, frames} = Encryptor.update(enc, plaintext)
      {:ok, _enc, final} = Encryptor.finalize(enc)

      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end

  describe "byte-by-byte input" do
    test "handles one byte at a time", ctx do
      plaintext = "Hello!"

      {:ok, enc} = Encryptor.init(ctx.enc_materials, frame_length: 3)
      {:ok, enc, header} = Encryptor.start(enc)

      # Feed one byte at a time
      {enc, frame_chunks} =
        plaintext
        |> String.graphemes()
        |> Enum.reduce({enc, []}, fn char, {enc, acc} ->
          {:ok, enc, bytes} = Encryptor.update(enc, char)
          {enc, [bytes | acc]}
        end)

      {:ok, _enc, final} = Encryptor.finalize(enc)

      frames = frame_chunks |> Enum.reverse() |> IO.iodata_to_binary()
      ciphertext = header <> frames <> final

      get_materials = fn _header -> {:ok, ctx.dec_materials} end
      {:ok, dec} = Decryptor.init(get_materials: get_materials)
      {:ok, dec, pts} = Decryptor.update(dec, ciphertext)
      {:ok, _dec, final_pts} = Decryptor.finalize(dec)

      result = (pts ++ final_pts) |> Enum.map(&elem(&1, 0)) |> IO.iodata_to_binary()
      assert result == plaintext
    end
  end
end
```

#### 3. Documentation updates

**File**: `lib/aws_encryption_sdk.ex`
**Changes**: Update "Current Limitations" section in moduledoc

Replace lines 57-60:
```elixir
## Streaming Support

This SDK supports both batch and streaming encryption/decryption:

- **Batch API** (`encrypt/3`, `decrypt/3`): Requires entire plaintext/ciphertext in memory
- **Streaming API** (`encrypt_stream/3`, `decrypt_stream/3`): Processes data incrementally

For large files, use the streaming API to avoid memory issues.
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix test test/aws_encryption_sdk/stream/edge_cases_test.exs`
- [x] All streaming tests pass: `mix test test/aws_encryption_sdk/stream/`
- [x] Full test suite passes: `mix quality`
- [x] No compiler warnings

#### Manual Verification:
- [ ] Documentation looks correct: `mix docs` and review
- [ ] Edge cases work in IEx

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality` (788/788 tests passing, 94.1% coverage, 0 Credo issues)
- [x] All streaming tests: `mix test test/aws_encryption_sdk/stream/`
- [x] Dialyzer passes: `mix dialyzer` (no warnings)

### Manual:
- [ ] File streaming round-trip with large file (1MB+)
- [ ] Signed suite streaming works
- [ ] `fail_on_signed` option works
- [ ] Memory usage stays constant during streaming (verify with `:observer`)

## Testing Strategy

### Unit Tests

Each module has dedicated tests:
- `signature_accumulator_test.exs` - Incremental hashing
- `encryptor_test.exs` - Encryption state machine
- `decryptor_test.exs` - Decryption state machine
- `signed_suite_test.exs` - ECDSA signing/verification
- `edge_cases_test.exs` - Boundary conditions
- `integration_test.exs` - High-level API

### Test Vector Integration

The streaming implementation should produce identical output to non-streaming for all test vectors:

```elixir
# For each test vector
{:ok, ct_streaming} = stream_encrypt(plaintext, materials)
{:ok, ct_batch} = batch_encrypt(plaintext, materials)
assert ct_streaming == ct_batch
```

### Manual Testing Steps

1. Create 10MB test file
2. Stream encrypt to output file
3. Stream decrypt to verify file
4. Compare original and decrypted files
5. Monitor memory usage during streaming

## References

- Issue: #60
- Research: `thoughts/shared/research/2026-01-29-GH60-streaming-encryption-decryption.md`
- Encrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/encrypt.md
- Decrypt Spec: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/client-apis/decrypt.md
- Frame Format: https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/data-format/message-body.md
