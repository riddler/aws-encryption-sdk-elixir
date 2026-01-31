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
  """
  @spec compute_header_auth_tag(Header.t(), binary()) :: {:ok, Header.t()}
  def compute_header_auth_tag(header, derived_key) do
    # AAD = header body + serialized encryption context
    {:ok, header_body} = Header.serialize_body(header)
    ec_bytes = EncryptionContext.serialize(header.encryption_context)
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
  """
  @spec verify_header_auth_tag(Header.t(), binary()) :: :ok | {:error, term()}
  def verify_header_auth_tag(header, derived_key) do
    # Compute AAD: header body + serialized encryption context
    {:ok, header_body} = Header.serialize_body(header)
    ec_bytes = EncryptionContext.serialize(header.encryption_context)
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
