defmodule AwsEncryptionSdk.Crypto.Commitment do
  @moduledoc """
  Key commitment verification operations.

  Verifies that the commitment key stored in the message header matches
  the commitment key derived from the plaintext data key. This prevents
  key commitment attacks on committed algorithm suites.
  """

  alias AwsEncryptionSdk.Crypto.HKDF
  alias AwsEncryptionSdk.Format.Header

  @doc """
  Verifies key commitment for committed algorithm suites.

  For non-committed suites (commitment_length = 0), returns `:ok` immediately.
  For committed suites, derives the commitment key and compares it to the
  stored value in the header.

  Returns `:ok` if verification succeeds, `{:error, :commitment_mismatch}` otherwise.
  """
  @spec verify_commitment(
          AwsEncryptionSdk.Materials.DecryptionMaterials.t(),
          Header.t()
        ) :: :ok | {:error, term()}
  def verify_commitment(
        _materials,
        %Header{algorithm_suite: %{commitment_length: 0}}
      ) do
    # Non-committed suite, skip verification
    :ok
  end

  def verify_commitment(materials, header) do
    suite = materials.algorithm_suite

    # Derive commitment key
    info = "COMMITKEY" <> <<suite.id::16-big>>

    case HKDF.derive(suite.kdf_hash, materials.plaintext_data_key, header.message_id, info, 32) do
      {:ok, expected_commitment} ->
        if :crypto.hash_equals(expected_commitment, header.algorithm_suite_data) do
          :ok
        else
          {:error, :commitment_mismatch}
        end

      {:error, _reason} = error ->
        error
    end
  end
end
