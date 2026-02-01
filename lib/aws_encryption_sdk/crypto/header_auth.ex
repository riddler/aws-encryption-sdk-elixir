defmodule AwsEncryptionSdk.Crypto.HeaderAuth do
  @moduledoc """
  Header authentication operations shared between encryption and decryption.

  Handles header construction and authentication tag computation/verification
  for both streaming and non-streaming operations.
  """

  alias AwsEncryptionSdk.Crypto.AesGcm
  alias AwsEncryptionSdk.Format.EncryptionContext
  alias AwsEncryptionSdk.Format.Header

  @doc """
  Builds a header struct (without auth tag) from encryption materials.

  Returns a header with a placeholder auth tag that must be computed separately.
  """
  @spec build_header(
          AwsEncryptionSdk.Materials.EncryptionMaterials.t(),
          binary(),
          pos_integer(),
          binary() | nil
        ) :: {:ok, Header.t()}
  def build_header(materials, message_id, frame_length, commitment_key) do
    suite = materials.algorithm_suite

    # For v1 headers, we need header_iv (12 bytes of zeros)
    # For v2 headers, header_iv is not used (nil)
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
      # Placeholder, will be computed
      header_auth_tag: <<0::128>>
    }

    {:ok, header}
  end

  @doc """
  Computes the header authentication tag.

  Returns a new header with the computed authentication tag.

  ## Parameters

  - `header` - The message header
  - `derived_key` - The derived data encryption key
  - `full_encryption_context` - The complete encryption context (stored + required keys)
  - `required_ec_keys` - List of required encryption context keys (defaults to empty list)

  Per the spec, the AAD is: header_body || required_encryption_context_bytes
  where required_encryption_context_bytes is the serialization of only the
  encryption context keys in the required_ec_keys list from the full EC.
  """
  @spec compute_header_auth_tag(
          Header.t(),
          binary(),
          map() | [String.t()],
          [String.t()] | nil
        ) ::
          {:ok, Header.t()}
  def compute_header_auth_tag(
        header,
        derived_key,
        full_ec_or_required_keys \\ [],
        required_ec_keys_opt \\ nil
      ) do
    # Handle both old (3-param) and new (4-param) signatures for backwards compatibility
    {full_encryption_context, required_ec_keys} =
      case {full_ec_or_required_keys, required_ec_keys_opt} do
        {full_ec, req_keys} when is_map(full_ec) and is_list(req_keys) ->
          # New signature: (header, derived_key, full_ec, required_keys)
          {full_ec, req_keys}

        {req_keys, nil} when is_list(req_keys) ->
          # Old signature: (header, derived_key, required_keys)
          # Use header EC as fallback
          {header.encryption_context, req_keys}

        {[], nil} ->
          # Default: no required keys
          {header.encryption_context, []}
      end

    # AAD = header body + serialized required encryption context
    {:ok, header_body} = Header.serialize_body(header)

    # Only serialize EC keys that are in the required list from full EC
    required_ec = Map.take(full_encryption_context, required_ec_keys)
    ec_bytes = EncryptionContext.serialize(required_ec)
    aad = header_body <> ec_bytes

    # IV is all zeros
    iv = AesGcm.zero_iv()

    # Encrypt empty plaintext to get auth tag
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

  @doc """
  Verifies the header authentication tag.

  Returns `:ok` if verification succeeds, `{:error, reason}` otherwise.

  ## Parameters

  - `header` - The message header
  - `derived_key` - The derived data encryption key
  - `full_encryption_context` - The complete encryption context (stored + required keys)
  - `required_ec_keys` - List of required encryption context keys (defaults to empty list)

  Per the spec, the AAD is: header_body || required_encryption_context_bytes
  where required_encryption_context_bytes is the serialization of only the
  encryption context keys in the required_ec_keys list from the full EC.
  """
  @spec verify_header_auth_tag(Header.t(), binary(), map() | [String.t()], [String.t()] | nil) ::
          :ok | {:error, term()}
  def verify_header_auth_tag(
        header,
        derived_key,
        full_ec_or_required_keys \\ [],
        required_ec_keys_opt \\ nil
      ) do
    # Handle both old (3-param) and new (4-param) signatures for backwards compatibility
    {full_encryption_context, required_ec_keys} =
      case {full_ec_or_required_keys, required_ec_keys_opt} do
        {full_ec, req_keys} when is_map(full_ec) and is_list(req_keys) ->
          # New signature: (header, derived_key, full_ec, required_keys)
          {full_ec, req_keys}

        {req_keys, nil} when is_list(req_keys) ->
          # Old signature: (header, derived_key, required_keys)
          # Use header EC as fallback
          {header.encryption_context, req_keys}

        {[], nil} ->
          # Default: no required keys
          {header.encryption_context, []}
      end

    # Compute AAD: header body + serialized required encryption context
    {:ok, header_body} = Header.serialize_body(header)

    # Only serialize EC keys that are in the required list from full EC
    # (Required keys are not in header, they're provided during decrypt)
    required_ec = Map.take(full_encryption_context, required_ec_keys)
    ec_bytes = EncryptionContext.serialize(required_ec)
    aad = header_body <> ec_bytes

    # IV is all zeros for header
    iv = AesGcm.zero_iv()

    # Decrypt empty ciphertext to verify tag
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
end
