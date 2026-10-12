defmodule AwsEncryptionSdk.Crypto.HeaderAuthTest do
  @moduledoc """
  The header-authentication arities that read the required pairs from the
  header's stored encryption context are deprecated, not removed, and still
  give the answers they always gave.

  Sabotage: removing a `@deprecated` attribute from one of the four heads
  fails the deprecation test; changing a deprecated head to pass a different
  required-keys list fails the equivalence test.
  """

  use ExUnit.Case, async: true

  # The deprecated arities are called through apply/3 on purpose: a direct
  # call would print the deprecation warning at compile time.
  # credo:disable-for-this-file Credo.Check.Refactor.Apply

  alias AwsEncryptionSdk.AlgorithmSuite
  alias AwsEncryptionSdk.Crypto.HeaderAuth
  alias AwsEncryptionSdk.Format.Header
  alias AwsEncryptionSdk.Materials.EncryptedDataKey

  @context %{"alpha" => "one", "beta" => "two"}
  @derived_key :binary.copy(<<7>>, 32)

  defp header do
    %Header{
      version: 2,
      algorithm_suite: AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key(),
      message_id: :binary.copy(<<1>>, 32),
      encryption_context: @context,
      encrypted_data_keys: [EncryptedDataKey.new("provider", "info", <<1, 2, 3>>)],
      content_type: :framed,
      frame_length: 4096,
      algorithm_suite_data: :binary.copy(<<2>>, 32),
      header_iv: nil,
      header_auth_tag: <<0::128>>
    }
  end

  defp deprecations do
    {:docs_v1, _anno, _lang, _fmt, _moduledoc, _meta, docs} = Code.fetch_docs(HeaderAuth)

    for {{:function, name, arity}, _anno, _sig, _doc, meta} <- docs,
        name in [:compute_header_auth_tag, :verify_header_auth_tag],
        into: %{} do
      {{name, arity}, Map.get(meta, :deprecated)}
    end
  end

  test "the /2 and /3 arities are deprecated and the /4 arity is not" do
    deprecations = deprecations()

    for name <- [:compute_header_auth_tag, :verify_header_auth_tag], arity <- [2, 3] do
      message = deprecations[{name, arity}]
      assert is_binary(message)
      assert message =~ "#{name}/4"
    end

    assert deprecations[{:compute_header_auth_tag, 4}] == nil
    assert deprecations[{:verify_header_auth_tag, 4}] == nil
  end

  test "the deprecated arities are still exported" do
    {:module, HeaderAuth} = Code.ensure_loaded(HeaderAuth)

    for {name, arity} <- [
          compute_header_auth_tag: 2,
          compute_header_auth_tag: 3,
          verify_header_auth_tag: 2,
          verify_header_auth_tag: 3
        ] do
      assert function_exported?(HeaderAuth, name, arity)
    end
  end

  test "the deprecated arities answer as the /4 arity does with the header context" do
    {:ok, tagged_2} = apply(HeaderAuth, :compute_header_auth_tag, [header(), @derived_key])

    {:ok, tagged_4_empty} =
      HeaderAuth.compute_header_auth_tag(header(), @derived_key, @context, [])

    assert tagged_2.header_auth_tag == tagged_4_empty.header_auth_tag

    keys = ["alpha"]
    {:ok, tagged_3} = apply(HeaderAuth, :compute_header_auth_tag, [header(), @derived_key, keys])
    {:ok, tagged_4} = HeaderAuth.compute_header_auth_tag(header(), @derived_key, @context, keys)
    assert tagged_3.header_auth_tag == tagged_4.header_auth_tag
    refute tagged_3.header_auth_tag == tagged_2.header_auth_tag

    assert :ok == apply(HeaderAuth, :verify_header_auth_tag, [tagged_2, @derived_key])
    assert :ok == apply(HeaderAuth, :verify_header_auth_tag, [tagged_3, @derived_key, keys])

    assert {:error, :header_authentication_failed} ==
             apply(HeaderAuth, :verify_header_auth_tag, [tagged_3, @derived_key, []])
  end
end
