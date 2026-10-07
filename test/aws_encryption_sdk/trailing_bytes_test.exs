defmodule AwsEncryptionSdk.TrailingBytesTest do
  @moduledoc """
  A message followed by trailing bytes is refused by every public decrypt
  entry point.

  Sabotage: `Decrypt.deserialize_whole_message/1` accepting
  `{:ok, message, rest}` with a non-empty `rest` (ignoring the trailing
  bytes) turns the buffered tests red; the streaming test pins
  `Stream.Decryptor.finalize/1`.
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Keyring.RawAes
  alias AwsEncryptionSdk.Materials.DecryptionMaterials
  alias AwsEncryptionSdk.Stream

  @plaintext "trailing bytes plaintext"
  @context %{"purpose" => "trailing-bytes-test"}

  setup do
    {:ok, keyring} = RawAes.new("ns", "key", :crypto.strong_rand_bytes(32), :aes_256_gcm)
    {:ok, keyring: keyring, client: Client.new(Default.new(keyring))}
  end

  defp suites do
    [
      AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
      AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key_ecdsa_p384()
    ]
  end

  defp encrypt(client, suite) do
    {:ok, %{ciphertext: ciphertext}} =
      Client.encrypt(client, @plaintext, encryption_context: @context, algorithm_suite: suite)

    ciphertext
  end

  test "the message alone decrypts (the control)", %{client: client} do
    for suite <- suites() do
      assert {:ok, %{plaintext: @plaintext}} = Client.decrypt(client, encrypt(client, suite))
    end
  end

  test "Client.decrypt/3 and AwsEncryptionSdk.decrypt/3 refuse one appended byte",
       %{client: client} do
    for suite <- suites() do
      with_trailing = encrypt(client, suite) <> <<0>>

      assert {:error, :trailing_bytes} = Client.decrypt(client, with_trailing)
      assert {:error, :trailing_bytes} = AwsEncryptionSdk.decrypt(client, with_trailing)
    end
  end

  test "decrypt_with_keyring/3 refuses one appended byte", %{client: client, keyring: keyring} do
    for suite <- suites() do
      with_trailing = encrypt(client, suite) <> <<0>>

      assert {:error, :trailing_bytes} = Client.decrypt_with_keyring(keyring, with_trailing)

      assert {:error, :trailing_bytes} =
               AwsEncryptionSdk.decrypt_with_keyring(keyring, with_trailing)
    end
  end

  test "decrypt with materials refuses one appended byte", %{client: client, keyring: keyring} do
    suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
    ciphertext = encrypt(client, suite)
    {:ok, header, _rest} = Header.deserialize(ciphertext)

    {:ok, materials} =
      RawAes.unwrap_key(
        keyring,
        DecryptionMaterials.new_for_decrypt(suite, header.encryption_context),
        header.encrypted_data_keys
      )

    assert {:ok, %{plaintext: @plaintext}} = AwsEncryptionSdk.decrypt(ciphertext, materials)

    assert {:error, :trailing_bytes} = AwsEncryptionSdk.decrypt(ciphertext <> <<0>>, materials)

    assert {:error, :trailing_bytes} =
             AwsEncryptionSdk.decrypt_with_materials(ciphertext <> <<0>>, materials)
  end

  test "Stream.decrypt/3 raises on one appended byte", %{client: client} do
    for suite <- suites() do
      with_trailing = encrypt(client, suite) <> <<0>>

      assert_raise RuntimeError, ~r/trailing_bytes/, fn ->
        [with_trailing] |> Stream.decrypt(client) |> Enum.to_list()
      end
    end
  end
end
