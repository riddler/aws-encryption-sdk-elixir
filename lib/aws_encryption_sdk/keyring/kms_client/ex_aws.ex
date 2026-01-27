defmodule AwsEncryptionSdk.Keyring.KmsClient.ExAws do
  @moduledoc """
  AWS KMS client implementation using ExAws.

  Provides production-ready KMS operations using the ExAws library.
  Credentials and region are resolved using ExAws's default credential chain.

  ## Configuration

  Configuration can be passed via the `:config` option or through application config:

      # Option 1: Pass config directly
      {:ok, client} = ExAws.new(
        region: "us-east-1",
        config: [
          access_key_id: "...",
          secret_access_key: "..."
        ]
      )

      # Option 2: Use application config (config/config.exs)
      config :ex_aws,
        access_key_id: [{:system, "AWS_ACCESS_KEY_ID"}, :instance_role],
        secret_access_key: [{:system, "AWS_SECRET_ACCESS_KEY"}, :instance_role],
        region: "us-east-1"

  ## Example

      {:ok, client} = ExAws.new(region: "us-east-1")

      {:ok, result} = ExAws.generate_data_key(
        client,
        "arn:aws:kms:us-east-1:123456789012:key/abc123",
        32,
        %{"purpose" => "encryption"},
        []
      )

      IO.inspect(result.plaintext)  # The unencrypted data key
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  alias AwsEncryptionSdk.Keyring.KmsClient

  defstruct [:region, :config]

  @type t :: %__MODULE__{
          region: String.t() | nil,
          config: keyword()
        }

  @doc """
  Creates a new ExAws KMS client.

  ## Options

  - `:region` - AWS region (optional, defaults to ExAws config)
  - `:config` - ExAws configuration options (optional)

  ## Example

      {:ok, client} = ExAws.new(region: "us-east-1")
  """
  @spec new(keyword()) :: {:ok, t()}
  def new(opts \\ []) do
    region = Keyword.get(opts, :region)
    config = Keyword.get(opts, :config, [])

    {:ok, %__MODULE__{region: region, config: config}}
  end

  # NOTE: This code is tested via integration tests (test/aws_encryption_sdk/keyring/kms_client/ex_aws_integration_test.exs)
  # Run with: source .env && mix test --only integration
  # Coverage is excluded here to allow local development without AWS credentials.
  # CI should run integration tests for full coverage.
  # coveralls-ignore-start

  @impl KmsClient
  def generate_data_key(
        %__MODULE__{} = client,
        key_id,
        number_of_bytes,
        encryption_context,
        grant_tokens
      ) do
    opts =
      build_opts(encryption_context, grant_tokens)
      |> Keyword.put(:number_of_bytes, number_of_bytes)

    key_id
    |> ExAws.KMS.generate_data_key(opts)
    |> execute_request(client)
    |> normalize_generate_data_key_response()
  end

  @impl KmsClient
  def encrypt(%__MODULE__{} = client, key_id, plaintext, encryption_context, grant_tokens) do
    opts = build_opts(encryption_context, grant_tokens)

    # AWS KMS API expects base64-encoded plaintext in JSON
    plaintext_b64 = Base.encode64(plaintext)

    key_id
    |> ExAws.KMS.encrypt(plaintext_b64, opts)
    |> execute_request(client)
    |> normalize_encrypt_response()
  end

  @impl KmsClient
  def decrypt(%__MODULE__{} = client, key_id, ciphertext, encryption_context, grant_tokens) do
    opts =
      build_opts(encryption_context, grant_tokens)
      |> Keyword.put(:key_id, key_id)

    # AWS KMS API expects base64-encoded ciphertext in JSON
    ciphertext_b64 = Base.encode64(ciphertext)

    ciphertext_b64
    |> ExAws.KMS.decrypt(opts)
    |> execute_request(client)
    |> normalize_decrypt_response()
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp build_opts(encryption_context, grant_tokens) do
    opts = []

    opts =
      if map_size(encryption_context) > 0 do
        Keyword.put(opts, :encryption_context, encryption_context)
      else
        opts
      end

    case grant_tokens do
      [] -> opts
      _tokens -> Keyword.put(opts, :grant_tokens, grant_tokens)
    end
  end

  defp execute_request(request, %__MODULE__{config: config, region: region}) do
    # Merge region into config if specified
    config =
      if region do
        Keyword.put(config, :region, region)
      else
        config
      end

    ExAws.request(request, config)
  end

  defp normalize_generate_data_key_response({:ok, response}) do
    {:ok,
     %{
       plaintext: Base.decode64!(response["Plaintext"]),
       ciphertext: Base.decode64!(response["CiphertextBlob"]),
       key_id: response["KeyId"]
     }}
  end

  defp normalize_generate_data_key_response({:error, error}) do
    {:error, normalize_error(error)}
  end

  defp normalize_encrypt_response({:ok, response}) do
    {:ok,
     %{
       ciphertext: Base.decode64!(response["CiphertextBlob"]),
       key_id: response["KeyId"]
     }}
  end

  defp normalize_encrypt_response({:error, error}) do
    {:error, normalize_error(error)}
  end

  defp normalize_decrypt_response({:ok, response}) do
    {:ok,
     %{
       plaintext: Base.decode64!(response["Plaintext"]),
       key_id: response["KeyId"]
     }}
  end

  defp normalize_decrypt_response({:error, error}) do
    {:error, normalize_error(error)}
  end

  @spec normalize_error(term()) :: KmsClient.kms_error()
  defp normalize_error({:http_error, status_code, %{body: body}}) do
    parse_aws_error_body(body, status_code)
  end

  defp normalize_error({:http_error, status_code, body}) when is_binary(body) do
    parse_aws_error_body(body, status_code)
  end

  defp normalize_error(%{reason: reason}) do
    {:connection_error, reason}
  end

  defp normalize_error(other) do
    {:connection_error, other}
  end

  # Parse AWS error JSON and extract type and message
  defp parse_aws_error_body(body, status_code) do
    case Jason.decode(body) do
      {:ok, %{"__type" => type, "message" => message}} ->
        {:kms_error, extract_error_type(type), message}

      {:ok, %{"__type" => type, "Message" => message}} ->
        {:kms_error, extract_error_type(type), message}

      {:ok, %{"__type" => type}} ->
        # Error type without message - use type name as message
        {:kms_error, extract_error_type(type), type}

      _other ->
        {:http_error, status_code, body}
    end
  end

  # Extract error type from AWS error format like "com.amazonaws.kms#AccessDeniedException"
  defp extract_error_type(type) when is_binary(type) do
    type
    |> String.split("#")
    |> List.last()
    |> String.replace("Exception", "")
    |> Macro.underscore()
    |> String.to_atom()
  end

  # coveralls-ignore-stop
end
