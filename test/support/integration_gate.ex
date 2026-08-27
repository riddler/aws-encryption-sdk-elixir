defmodule AwsEncryptionSdk.TestSupport.IntegrationGate do
  @moduledoc """
  Decides whether the `:integration` tests should run.

  Those tests make real AWS KMS calls, so they need both a test key
  (`KMS_KEY_ARN`) and credentials AWS actually accepts. When either is
  missing the tests cannot say anything about this library, so they are
  excluded rather than failed.

  Only "AWS does not recognize this key" is treated as unconfigured.
  `SignatureDoesNotMatch` and `AccessDeniedException` still fail the suite:
  those can point at a real regression in how requests are signed or scoped,
  and silently skipping them would hide it.
  """

  # AWS returns these when the access key itself is unknown to it, which
  # means the key was never valid, or has since been rotated or deleted.
  @unknown_credential_errors ["UnrecognizedClientException", "InvalidClientTokenId"]

  @doc """
  Returns `:run` when integration tests should execute, or
  `{:exclude, reason}` when they should be skipped.
  """
  @spec check() :: :run | {:exclude, String.t()}
  def check do
    case System.get_env("KMS_KEY_ARN") do
      nil -> {:exclude, "KMS_KEY_ARN is not set"}
      "" -> {:exclude, "KMS_KEY_ARN is empty"}
      key_arn -> check_credentials(key_arn)
    end
  end

  # The ExAws client only exists when the optional AWS deps are installed;
  # without them there is nothing to make a KMS call with, so integration
  # tests are unconfigurable by definition.
  if Code.ensure_loaded?(AwsEncryptionSdk.Keyring.KmsClient.ExAws) do
    alias AwsEncryptionSdk.Keyring.KmsClient.ExAws, as: KmsExAws

    defp check_credentials(key_arn) do
      region = System.get_env("AWS_REGION", "us-east-1")
      {:ok, client} = KmsExAws.new(region: region)

      # Cheapest call that still proves the credentials are accepted
      case KmsExAws.generate_data_key(client, key_arn, 32, %{}, []) do
        {:ok, _result} ->
          :run

        {:error, error} ->
          if unknown_credential_error?(error) do
            {:exclude, "AWS rejected the configured credentials: #{describe(error)}"}
          else
            # Any other failure is left for the tests themselves to report,
            # since it may be a genuine problem with this library
            :run
          end
      end
    rescue
      # A transport or configuration failure this early means the environment
      # cannot reach KMS at all; let the tests run and report it themselves
      _error -> :run
    catch
      :exit, _reason -> {:exclude, "AWS credentials could not be resolved"}
    end
  else
    defp check_credentials(_key_arn) do
      {:exclude, "the optional AWS KMS deps (ex_aws et al.) are not installed"}
    end
  end

  @doc """
  Prints why the integration tests are being skipped.
  """
  @spec print_skip_notice(String.t()) :: :ok
  def print_skip_notice(reason) do
    # credo:disable-for-next-line Credo.Check.Refactor.IoPuts
    IO.puts("""

    Note: skipping AWS KMS integration tests - #{reason}.
    Set KMS_KEY_ARN with working AWS credentials to run them.
    """)
  end

  defp unknown_credential_error?({:connection_error, {code, _message}}),
    do: code in @unknown_credential_errors

  defp unknown_credential_error?(_other), do: false

  defp describe({:connection_error, {code, message}}), do: "#{code} - #{message}"
  defp describe(other), do: inspect(other)
end
