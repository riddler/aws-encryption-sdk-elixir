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
      {:ok, enc, _header} = Encryptor.start(enc)
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
      {:ok, enc, _frames} = Encryptor.update(enc, "partial data")

      {:ok, enc, final} = Encryptor.finalize(enc)
      assert enc.state == :done
      assert byte_size(final) > 0
    end

    test "handles empty buffer", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 100)
      {:ok, enc, _header} = Encryptor.start(enc)

      {:ok, enc, final} = Encryptor.finalize(enc)
      assert enc.state == :done
      # Empty final frame
      assert byte_size(final) > 0
    end
  end

  describe "frame limit" do
    # The specification allows at most 2^32 - 1 frames in one message. These
    # tests set the encryptor's sequence number near the limit instead of
    # encrypting that many frames; the number is the next frame to write.
    #
    # Sabotage: in update/2, checking `sequence_number + 2` before a regular
    # frame turns the 2^32 - 2 test red; checking `sequence_number` alone,
    # with the frame serializer's and the IV's guards lifted, turns both
    # refusal tests of update/2 red. In finalize/1, checking
    # `sequence_number + 1` turns the 2^32 - 1 tests red; dropping the
    # check, with those guards lifted, turns the 2^32 test red. With the
    # guards in place, a dropped or shifted refusal raises
    # FunctionClauseError instead of writing a truncated frame.
    @max_frames 4_294_967_295

    setup %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 1)
      {:ok, enc, _header} = Encryptor.start(enc)
      {:ok, enc: enc}
    end

    test "writes regular frame 2^32 - 2 and final frame 2^32 - 1", %{enc: enc} do
      enc = %{enc | sequence_number: @max_frames - 1}

      assert {:ok, enc, <<0xFFFFFFFE::32-big, _frame::binary>>} = Encryptor.update(enc, "a")
      assert enc.sequence_number == @max_frames

      assert {:ok, enc, <<0xFFFFFFFF::32-big, 0xFFFFFFFF::32-big, _final::binary>>} =
               Encryptor.finalize(enc)

      assert enc.state == :done
    end

    test "refuses a regular frame numbered 2^32 - 1", %{enc: enc} do
      enc = %{enc | sequence_number: @max_frames}

      assert {:error, :max_frames_exceeded} = Encryptor.update(enc, "a")
    end

    test "emits no frame of a chunk that crosses the limit", %{enc: enc} do
      enc = %{enc | sequence_number: @max_frames - 1}

      # The first byte would be frame 2^32 - 2, the second frame 2^32 - 1.
      assert {:error, :max_frames_exceeded} = Encryptor.update(enc, "ab")

      # The caller's encryptor is unchanged and still writes the last frames.
      assert {:ok, enc, <<0xFFFFFFFE::32-big, _frame::binary>>} = Encryptor.update(enc, "a")

      assert {:ok, _enc, <<0xFFFFFFFF::32-big, 0xFFFFFFFF::32-big, _rest::binary>>} =
               Encryptor.finalize(enc)
    end

    test "writes a buffered final frame numbered 2^32 - 1", %{materials: materials} do
      {:ok, enc} = Encryptor.init(materials, frame_length: 2)
      {:ok, enc, _header} = Encryptor.start(enc)
      enc = %{enc | sequence_number: @max_frames}

      assert {:ok, enc, <<>>} = Encryptor.update(enc, "a")

      assert {:ok, _enc, <<0xFFFFFFFF::32-big, 0xFFFFFFFF::32-big, _final::binary>>} =
               Encryptor.finalize(enc)
    end

    test "refuses a final frame numbered 2^32", %{enc: enc} do
      enc = %{enc | sequence_number: @max_frames + 1}

      assert {:error, :max_frames_exceeded} = Encryptor.finalize(enc)
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
