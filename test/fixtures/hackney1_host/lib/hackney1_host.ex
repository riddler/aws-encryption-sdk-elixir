defmodule Hackney1Host do
  @moduledoc """
  Calls the SDK's ExAws KMS client so that compiling this host proves the
  client module was compiled into the SDK on the hackney 1.x stack.
  """

  alias AwsEncryptionSdk.Keyring.KmsClient.ExAws, as: KmsExAws

  @doc "Builds a KMS client for the given region."
  @spec kms_client(String.t()) :: {:ok, KmsExAws.t()}
  def kms_client(region) do
    KmsExAws.new(region: region)
  end
end
