defmodule AwsEncryptionSdk.RequiredContextStorageTest do
  @moduledoc """
  Where required encryption context keys travel, and that every message
  written before 1.1.0 still decrypts.

  A message written with required encryption context keys stores none of
  them in its header; they are authenticated as the tail of the
  header-authentication AAD and bound into the encrypted data keys. Messages
  written by 1.0.x stored them as well, and the committed fixtures under
  `test/fixtures/pre_1_1_messages/` (see its README) pin that they still
  decrypt. The fixtures under `test/fixtures/conforming_messages/` were
  written by another SDK that follows the specification.

  Each test that guards a mutation names it in a "Sabotage" comment.
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Cache.LocalCache
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.{Caching, Default, RequiredEncryptionContext}
  alias AwsEncryptionSdk.Decrypt
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Stream

  @pre_fix_dir Path.expand("../fixtures/pre_1_1_messages", __DIR__)
  @conforming_dir Path.expand("../fixtures/conforming_messages", __DIR__)

  # The fixtures' test key is derived from a public label (see the READMEs);
  # it protects nothing.
  @fixture_key :crypto.hash(:sha256, "aws-encryption-sdk-elixir pre-1.1 fixture test key")
  @fixture_plaintext "fixture plaintext"
  @required ["required-a", "required-b"]
  @context %{"required-a" => "value-a", "required-b" => "value-b", "stored-a" => "value-s"}
  @public_key "aws-crypto-public-key"

  setup do
    {:ok, keyring} = RawAes.new("fixture-ns", "fixture-wrapping-key", @fixture_key, :aes_256_gcm)
    {:ok, keyring: keyring}
  end

  defp fixture(dir, name), do: File.read!(Path.join(dir, name))

  defp required_client(keyring),
    do: Client.new(RequiredEncryptionContext.new_with_keyring(@required, keyring))

  defp default_client(keyring), do: Client.new(Default.new(keyring))

  defp stored_context(ciphertext) do
    {:ok, header, _rest} = Header.deserialize(ciphertext)
    header.encryption_context
  end

  defp stream_decrypt(ciphertext, client, context) do
    [ciphertext]
    |> Stream.decrypt(client, encryption_context: context)
    |> Enum.map_join(fn {plaintext, _status} -> plaintext end)
  end

  defp suites do
    [
      {"0478", AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()},
      {"0578", AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()}
    ]
  end

  defp encrypt(client, suite, context \\ @context) do
    {:ok, result} =
      Client.encrypt(client, @fixture_plaintext,
        encryption_context: context,
        algorithm_suite: suite
      )

    result.ciphertext
  end

  defp stream_encrypt(client, suite) do
    [@fixture_plaintext]
    |> Stream.encrypt(client, encryption_context: @context, algorithm_suite: suite)
    |> Enum.join()
  end

  describe "the header a message with required keys stores" do
    # Sabotage: build_header/4 storing materials.encryption_context (the
    # whole map, as 1.0.x did) turns this test red.
    test "holds none of the required keys, buffered and streaming", %{keyring: keyring} do
      client = required_client(keyring)

      for {_name, suite} <- suites(),
          ciphertext <- [encrypt(client, suite), stream_encrypt(client, suite)] do
        stored = stored_context(ciphertext)

        refute Map.has_key?(stored, "required-a")
        refute Map.has_key?(stored, "required-b")
        assert stored["stored-a"] == "value-s"

        assert Map.keys(stored) -- [@public_key] == ["stored-a"]
      end
    end

    # Sabotage: compute_header_auth_tag/4 dropping the serialized required
    # pairs from the AAD turns this test red.
    test "authenticates them as the tail of the header-authentication AAD", %{keyring: keyring} do
      for {_name, suite} <- suites() do
        ciphertext = encrypt(required_client(keyring), suite)
        {:ok, header, _rest} = Header.deserialize(ciphertext)

        verification_key =
          case Map.fetch(header.encryption_context, @public_key) do
            {:ok, encoded} -> Base.decode64!(encoded)
            :error -> nil
          end

        materials =
          DecryptionMaterials.new_for_decrypt(
            suite,
            Map.merge(header.encryption_context, @context),
            verification_key: verification_key
          )

        {:ok, unwrapped} = RawAes.unwrap_key(keyring, materials, header.encrypted_data_keys)

        assert {:error, :header_authentication_failed} =
                 Decrypt.decrypt(ciphertext, %{unwrapped | required_encryption_context_keys: []})

        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Decrypt.decrypt(ciphertext, %{
                   unwrapped
                   | required_encryption_context_keys: @required
                 })
      end
    end

    test "round-trips through the required-context CMM, buffered and streaming", %{
      keyring: keyring
    } do
      client = required_client(keyring)

      for {_name, suite} <- suites() do
        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Client.decrypt(client, encrypt(client, suite), encryption_context: @context)

        assert stream_decrypt(stream_encrypt(client, suite), client, @context) ==
                 @fixture_plaintext
      end
    end
  end

  describe "a message written before 1.1.0 (committed fixture)" do
    test "stores the required keys in its header (the form being pinned)" do
      for {name, _suite} <- suites() do
        stored = stored_context(fixture(@pre_fix_dir, "required-context-#{name}.bin"))

        assert Map.take(stored, Map.keys(@context)) == @context
      end
    end

    # Sabotage: RequiredEncryptionContext.get_decryption_materials/2 setting
    # the required set to the underlying CMM's set alone (dropping the union
    # with its configured keys) turns this test red.
    test "decrypts through the required-context CMM, buffered and streaming", %{keyring: keyring} do
      client = required_client(keyring)

      for {name, _suite} <- suites() do
        ciphertext = fixture(@pre_fix_dir, "required-context-#{name}.bin")

        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Client.decrypt(client, ciphertext, encryption_context: @context)

        assert stream_decrypt(ciphertext, client, @context) == @fixture_plaintext
      end
    end

    test "decrypts with only the required keys reproduced", %{keyring: keyring} do
      ciphertext = fixture(@pre_fix_dir, "required-context-0478.bin")
      reproduced = Map.take(@context, @required)

      assert {:ok, %{plaintext: @fixture_plaintext}} =
               Client.decrypt(required_client(keyring), ciphertext,
                 encryption_context: reproduced
               )
    end

    test "refuses a reproduced value that differs from the stored one, before any unwrap",
         %{keyring: keyring} do
      ciphertext = fixture(@pre_fix_dir, "required-context-0478.bin")
      wrong = Map.put(@context, "required-a", "other-value")

      assert {:error, {:encryption_context_mismatch, "required-a"}} =
               Client.decrypt(required_client(keyring), ciphertext, encryption_context: wrong)

      assert {:error, {:encryption_context_mismatch, "required-a"}} =
               Client.decrypt(default_client(keyring), ciphertext, encryption_context: wrong)
    end

    # Sabotage: removing the stored-context retry in
    # Cmm.Default.get_decryption_materials/2 turns this test red.
    test "still decrypts when the caller passes a key the message never carried",
         %{keyring: keyring} do
      for {name, _suite} <- suites() do
        ciphertext = fixture(@pre_fix_dir, "required-context-#{name}.bin")
        extra = Map.put(@context, "never-carried", "advisory")

        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Client.decrypt(required_client(keyring), ciphertext, encryption_context: extra)

        assert stream_decrypt(ciphertext, required_client(keyring), extra) == @fixture_plaintext
      end
    end

    test "a signed message stores the uncompressed verification key and still decrypts",
         %{keyring: keyring} do
      ciphertext = fixture(@pre_fix_dir, "signed-0578.bin")
      stored = stored_context(ciphertext)

      assert <<0x04, _coordinates::binary-size(96)>> = Base.decode64!(stored[@public_key])

      assert {:ok, %{plaintext: @fixture_plaintext}} =
               Client.decrypt(default_client(keyring), ciphertext,
                 encryption_context: %{"stored-a" => "value-s"}
               )

      assert stream_decrypt(ciphertext, default_client(keyring), %{}) == @fixture_plaintext
    end
  end

  describe "a message in the specification's form (required keys not stored)" do
    # Sabotage: Cmm.Default.get_decryption_materials/2 unwrapping under the
    # stored context only (never appending the reproduced pairs first)
    # turns this test red.
    test "written by another SDK, decrypts with or without the required-context CMM",
         %{keyring: keyring} do
      for {name, _suite} <- suites() do
        ciphertext = fixture(@conforming_dir, "required-context-#{name}.bin")
        stored = stored_context(ciphertext)

        refute Map.has_key?(stored, "required-a")
        refute Map.has_key?(stored, "required-b")

        for client <- [required_client(keyring), default_client(keyring)] do
          assert {:ok, %{plaintext: @fixture_plaintext}} =
                   Client.decrypt(client, ciphertext, encryption_context: @context)

          assert stream_decrypt(ciphertext, client, @context) == @fixture_plaintext
        end
      end
    end

    test "written by this SDK, a plain default-CMM reader that reproduces the keys decrypts",
         %{keyring: keyring} do
      for {_name, suite} <- suites() do
        ciphertext = encrypt(required_client(keyring), suite)

        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Client.decrypt(default_client(keyring), ciphertext, encryption_context: @context)
      end
    end

    test "a wrong value for a required key fails the unwrap", %{keyring: keyring} do
      ciphertext =
        encrypt(required_client(keyring), AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key())

      wrong = Map.put(@context, "required-a", "other-value")

      for client <- [required_client(keyring), default_client(keyring)] do
        assert {:error, _reason} = Client.decrypt(client, ciphertext, encryption_context: wrong)
      end
    end

    test "a reader that does not reproduce a required key cannot decrypt", %{keyring: keyring} do
      ciphertext =
        encrypt(required_client(keyring), AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key())

      partial = Map.delete(@context, "required-b")

      assert {:error, {:missing_required_encryption_context_keys, ["required-b"]}} =
               Client.decrypt(required_client(keyring), ciphertext, encryption_context: partial)

      assert {:error, _reason} =
               Client.decrypt(default_client(keyring), ciphertext, encryption_context: partial)
    end
  end

  describe "a warm decryption cache" do
    setup %{keyring: keyring} do
      {:ok, cache} = LocalCache.start_link([])
      partition_id = :crypto.strong_rand_bytes(16)

      # A second Caching CMM on the same cache and partition whose keyring
      # holds another key: it can only succeed by a cache hit.
      {:ok, other_keyring} =
        RawAes.new(
          "fixture-ns",
          "fixture-wrapping-key",
          :crypto.strong_rand_bytes(32),
          :aes_256_gcm
        )

      cached = fn kr ->
        Client.new(Caching.new(Default.new(kr), cache, max_age: 300, partition_id: partition_id))
      end

      ciphertext =
        encrypt(required_client(keyring), AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key())

      {:ok, warm: cached.(keyring), hit_only: cached.(other_keyring), ciphertext: ciphertext}
    end

    # Sabotage: serving a decryption cache hit without check_bound_context/2
    # turns this test red (the wrong value gets plaintext).
    test "refuses a second read claiming a different value for a key the header does not store",
         ctx do
      assert {:ok, %{plaintext: @fixture_plaintext}} =
               Client.decrypt(ctx.warm, ctx.ciphertext, encryption_context: @context)

      wrong = Map.put(@context, "required-a", "other-value")

      assert {:error, {:encryption_context_mismatch, "required-a"}} =
               Client.decrypt(ctx.hit_only, ctx.ciphertext, encryption_context: wrong)
    end

    test "refuses a second read that omits a bound key the header does not store", ctx do
      assert {:ok, _first_read} =
               Client.decrypt(ctx.warm, ctx.ciphertext, encryption_context: @context)

      assert {:error, {:missing_required_encryption_context_keys, ["required-a"]}} =
               Client.decrypt(ctx.hit_only, ctx.ciphertext,
                 encryption_context: Map.delete(@context, "required-a")
               )
    end

    test "refuses a second read that disagrees with a stored key", ctx do
      assert {:ok, _first_read} =
               Client.decrypt(ctx.warm, ctx.ciphertext, encryption_context: @context)

      assert {:error, {:encryption_context_mismatch, "stored-a"}} =
               Client.decrypt(ctx.hit_only, ctx.ciphertext,
                 encryption_context: Map.put(@context, "stored-a", "other-value")
               )
    end

    test "serves a second read with the right values from the cache", ctx do
      assert {:ok, _first_read} =
               Client.decrypt(ctx.warm, ctx.ciphertext, encryption_context: @context)

      assert {:ok, %{plaintext: @fixture_plaintext}} =
               Client.decrypt(ctx.hit_only, ctx.ciphertext, encryption_context: @context)

      # A reproduced key the entry did not bind is not compared, as on a cold read.
      assert {:ok, %{plaintext: @fixture_plaintext}} =
               Client.decrypt(ctx.hit_only, ctx.ciphertext,
                 encryption_context: Map.put(@context, "never-carried", "advisory")
               )
    end
  end

  describe "the verification key a signed message stores" do
    # Sabotage: encode_public_key/1 writing the uncompressed point turns
    # this test red.
    test "is the SEC 1 compressed point, and the message decrypts", %{keyring: keyring} do
      suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()

      for client <- [default_client(keyring), required_client(keyring)],
          ciphertext <- [encrypt(client, suite), stream_encrypt(client, suite)] do
        assert <<prefix, _x::binary-size(48)>> =
                 Base.decode64!(stored_context(ciphertext)[@public_key])

        assert prefix in [0x02, 0x03]

        assert {:ok, %{plaintext: @fixture_plaintext}} =
                 Client.decrypt(client, ciphertext, encryption_context: @context)
      end
    end
  end
end
