defmodule AwsEncryptionSdk.SigningSuitesTest do
  @moduledoc """
  Every signed algorithm suite signs on its own curve with its own hash:
  0x0214 on P-256 with SHA-256; 0x0346, 0x0378 and 0x0578 on P-384 with
  SHA-384.

  Each suite is written one-shot and streaming, and each message is read
  one-shot and streaming. The verification key in the header and the
  footer's signature are also checked directly against the curve and hash
  the suite specifies, independently of the SDK's own signing code.

  Each test that guards a mutation names it in a "Sabotage" comment.
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Crypto.ECDSA
  alias AwsEncryptionSdk.Decrypt
  alias AwsEncryptionSdk.Format.{Header, Message}
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.EncryptionMaterials
  alias AwsEncryptionSdk.Stream
  alias AwsEncryptionSdk.Stream.{Decryptor, Encryptor}

  @public_key "aws-crypto-public-key"
  @context %{"purpose" => "signing suites test"}

  # {suite id, curve, hash, compressed key size, commitment policy}
  @suites [
    {0x0214, :secp256r1, :sha256, 33, :forbid_encrypt_allow_decrypt},
    {0x0346, :secp384r1, :sha384, 49, :forbid_encrypt_allow_decrypt},
    {0x0378, :secp384r1, :sha384, 49, :forbid_encrypt_allow_decrypt},
    {0x0578, :secp384r1, :sha384, 49, :require_encrypt_require_decrypt}
  ]

  setup do
    key = :crypto.strong_rand_bytes(32)
    {:ok, keyring} = RawAes.new("signing-ns", "signing-key", key, :aes_256_gcm)
    # Several frames and a partial final frame
    plaintext = :crypto.strong_rand_bytes(250)
    {:ok, keyring: keyring, plaintext: plaintext}
  end

  defp client(keyring, policy), do: Client.new(Default.new(keyring), commitment_policy: policy)

  defp write(:one_shot, keyring, suite, policy, plaintext) do
    {:ok, %{ciphertext: ciphertext}} =
      Client.encrypt(client(keyring, policy), plaintext,
        encryption_context: @context,
        algorithm_suite: suite,
        frame_length: 64
      )

    ciphertext
  end

  defp write(:streaming, keyring, suite, policy, plaintext) do
    {:ok, materials} =
      Default.get_encryption_materials(Default.new(keyring), %{
        encryption_context: @context,
        commitment_policy: policy,
        algorithm_suite: suite
      })

    {:ok, enc} = Encryptor.init(materials, frame_length: 64)
    {:ok, enc, header} = Encryptor.start(enc)
    {:ok, enc, frames} = Encryptor.update(enc, plaintext)
    {:ok, _enc, final} = Encryptor.finalize(enc)
    header <> frames <> final
  end

  defp read(:one_shot, keyring, policy, ciphertext) do
    case Client.decrypt(client(keyring, policy), ciphertext) do
      {:ok, %{plaintext: plaintext}} -> {:ok, plaintext}
      {:error, reason} -> {:error, reason}
    end
  end

  # Stream.decrypt raises on a failed decrypt; the raise becomes an error
  # tuple here so that a failed read fails the test's assertion.
  defp read(:streaming, keyring, policy, ciphertext) do
    plaintext =
      [ciphertext]
      |> Stream.decrypt(client(keyring, policy))
      |> Enum.map_join(fn {plaintext, _status} -> plaintext end)

    {:ok, plaintext}
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp header_key(ciphertext) do
    {:ok, message, <<>>} = Message.deserialize(ciphertext)
    {:ok, key} = Base.decode64(Map.fetch!(message.header.encryption_context, @public_key))
    {message, key}
  end

  defp signed_bytes(ciphertext, signature) do
    binary_part(ciphertext, 0, byte_size(ciphertext) - 2 - byte_size(signature))
  end

  for {id, curve, hash, key_size, policy} <- @suites,
      writer <- [:one_shot, :streaming] do
    @id id
    @curve curve
    @hash hash
    @key_size key_size
    @policy policy
    @writer writer

    describe "suite 0x#{String.pad_leading(Integer.to_string(id, 16), 4, "0")} written #{writer}" do
      # Sabotage: in ECDSA.curve_for_suite/1, map :ecdsa_p256 to :secp384r1
      # -> the 0x0214 header key is 49 bytes; mapping :ecdsa_p384 to
      # :secp256r1 turns the P-384 suites red the same way.
      test "the header carries a compressed key on the suite's curve", ctx do
        suite = AlgorithmSuite.by_id(@id) |> elem(1)
        ciphertext = write(@writer, ctx.keyring, suite, @policy, ctx.plaintext)
        {message, key} = header_key(ciphertext)

        assert message.header.algorithm_suite.id == @id
        assert byte_size(key) == @key_size
        assert :binary.first(key) in [0x02, 0x03]
      end

      # Sabotage: in ECDSA.hash_for_curve/1, answer :sha384 for :secp256r1
      # -> the 0x0214 footer does not verify with SHA-256 here, though the
      # SDK's own round trip would still pass.
      test "the footer verifies with the suite's hash on the suite's curve", ctx do
        suite = AlgorithmSuite.by_id(@id) |> elem(1)
        ciphertext = write(@writer, ctx.keyring, suite, @policy, ctx.plaintext)
        {message, key} = header_key(ciphertext)
        signature = message.footer.signature
        point = ECDSA.normalize_public_key(key, @curve)

        # :crypto raises on a key that is not a point on the curve
        verified =
          try do
            :crypto.verify(:ecdsa, @hash, signed_bytes(ciphertext, signature), signature, [
              point,
              @curve
            ])
          rescue
            _error -> false
          end

        assert verified
      end

      for reader <- [:one_shot, :streaming] do
        @reader reader

        # Sabotage: in Cmm.Default, generate every signing key on :secp384r1
        # -> 0x0214 read one-shot fails :signature_verification_failed.
        # Sabotage: in SignatureAccumulator.init/1, ignore the suite and use
        # P-384 -> 0x0214 read streaming fails.
        test "decrypts #{reader}", ctx do
          suite = AlgorithmSuite.by_id(@id) |> elem(1)
          ciphertext = write(@writer, ctx.keyring, suite, @policy, ctx.plaintext)

          assert {:ok, ctx.plaintext} == read(@reader, ctx.keyring, @policy, ciphertext)
        end
      end
    end
  end

  describe "a verification key not on the suite's curve" do
    # A 0x0214 message whose verification key is a P-384 point, as versions
    # before this fix wrote the key on 0x0214.
    setup ctx do
      suite = AlgorithmSuite.aes_128_gcm_iv12_tag16_hkdf_sha256_ecdsa_p256()

      ciphertext =
        write(:streaming, ctx.keyring, suite, :forbid_encrypt_allow_decrypt, ctx.plaintext)

      {:ok, header, _rest} = Header.deserialize(ciphertext)

      {:ok, materials} =
        Default.get_decryption_materials(Default.new(ctx.keyring), %{
          algorithm_suite: suite,
          commitment_policy: :forbid_encrypt_allow_decrypt,
          encrypted_data_keys: header.encrypted_data_keys,
          encryption_context: header.encryption_context
        })

      {_private_key, p384_public_key} = ECDSA.generate_key_pair(:secp384r1)
      p384_compressed = Base.decode64!(ECDSA.encode_public_key(p384_public_key))

      {:ok, ciphertext: ciphertext, wrong_curve: %{materials | verification_key: p384_compressed}}
    end

    # Sabotage: remove the rescue in SignatureAccumulator.verify/3 -> the
    # streaming decrypt raises ErlangError instead of returning the error.
    test "the streaming decrypt returns an error instead of raising", ctx do
      {:ok, dec} = Decryptor.init(get_materials: fn _header -> {:ok, ctx.wrong_curve} end)

      result =
        try do
          case Decryptor.update(dec, ctx.ciphertext) do
            {:ok, dec, _plaintexts} -> Decryptor.finalize(dec)
            error -> error
          end
        rescue
          error -> {:raised, error}
        end

      assert result == {:error, :signature_verification_failed}
    end

    test "the one-shot decrypt gives the same answer", ctx do
      assert {:error, :signature_verification_failed} =
               Decrypt.decrypt(ctx.ciphertext, ctx.wrong_curve)
    end
  end

  describe "a caller-supplied signing key" do
    # Materials as a caller assembles them, outside a CMM: a key pair
    # generated on `curve`, its public key in the context, and the data key
    # from the keyring.
    defp caller_materials(keyring, suite, curve) do
      {private_key, public_key} = ECDSA.generate_key_pair(curve)
      context = Map.put(@context, @public_key, ECDSA.encode_public_key(public_key))

      {:ok, materials} =
        RawAes.wrap_key(
          keyring,
          EncryptionMaterials.new_for_encrypt(suite, context, signing_key: private_key)
        )

      materials
    end

    # {suite id, the suite's curve, the other curve, commitment policy}
    @mismatches [
      {0x0214, :secp256r1, :secp384r1, :forbid_encrypt_allow_decrypt},
      {0x0346, :secp384r1, :secp256r1, :forbid_encrypt_allow_decrypt},
      {0x0378, :secp384r1, :secp256r1, :forbid_encrypt_allow_decrypt},
      {0x0578, :secp384r1, :secp256r1, :require_encrypt_require_decrypt}
    ]

    for {id, curve, other, policy} <- @mismatches do
      @id id
      @curve curve
      @other other
      @policy policy
      @hex "0x" <> String.pad_leading(Integer.to_string(id, 16), 4, "0")
      @message ~r/^the signing key is not a #{curve} private key, the curve algorithm suite #{@hex} signs on: it is \d+ bytes, the size of a #{other} private key$/

      # Sabotage: in Encrypt.encrypt/3, drop the ECDSA.check_signing_key!/2
      # step -> 0x0214 raises ErlangError from :crypto and the P-384 suites
      # answer {:ok, _}: a P-256 key signs on P-384 without complaint.
      test "#{@hex}: a #{other} key raises ArgumentError one-shot", ctx do
        suite = AlgorithmSuite.by_id(@id) |> elem(1)
        materials = caller_materials(ctx.keyring, suite, @other)

        assert_raise ArgumentError, @message, fn ->
          AwsEncryptionSdk.encrypt(materials, ctx.plaintext, frame_length: 64)
        end
      end

      # Sabotage: in Stream.Encryptor.init/2, drop the
      # ECDSA.check_signing_key!/2 step -> init answers {:ok, _}.
      test "#{@hex}: a #{other} key raises ArgumentError streaming, before any byte", ctx do
        suite = AlgorithmSuite.by_id(@id) |> elem(1)
        materials = caller_materials(ctx.keyring, suite, @other)

        assert_raise ArgumentError, @message, fn ->
          Encryptor.init(materials, frame_length: 64)
        end
      end

      test "#{@hex}: a #{curve} key signs, and the message decrypts", ctx do
        suite = AlgorithmSuite.by_id(@id) |> elem(1)
        materials = caller_materials(ctx.keyring, suite, @curve)

        {:ok, %{ciphertext: one_shot}} =
          AwsEncryptionSdk.encrypt(materials, ctx.plaintext, frame_length: 64)

        {:ok, enc} = Encryptor.init(materials, frame_length: 64)
        {:ok, enc, header} = Encryptor.start(enc)
        {:ok, enc, frames} = Encryptor.update(enc, ctx.plaintext)
        {:ok, _enc, final} = Encryptor.finalize(enc)

        for ciphertext <- [one_shot, header <> frames <> final],
            reader <- [:one_shot, :streaming] do
          assert {:ok, ctx.plaintext} == read(reader, ctx.keyring, @policy, ciphertext)
        end
      end
    end
  end
end
