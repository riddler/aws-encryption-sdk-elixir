defmodule AwsEncryptionSdk.Keyring.KmsClient.Mock do
  @moduledoc """
  Mock KMS client for testing.

  Provides a configurable mock that returns pre-defined responses for KMS operations.
  Useful for unit testing keyrings without requiring AWS credentials.

  ## Example

      # Set up mock with expected responses
      {:ok, mock} = Mock.new(%{
        {:generate_data_key, "arn:aws:kms:us-east-1:123:key/abc"} => %{
          plaintext: <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>,
          ciphertext: <<...encrypted...>>,
          key_id: "arn:aws:kms:us-east-1:123:key/abc"
        },
        {:decrypt, "arn:aws:kms:us-east-1:123:key/abc"} => %{
          plaintext: <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
                       17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32>>,
          key_id: "arn:aws:kms:us-east-1:123:key/abc"
        }
      })

      # Use in tests
      {:ok, result} = Mock.generate_data_key(mock, "arn:aws:kms:us-east-1:123:key/abc", 32, %{}, [])
  """

  @behaviour AwsEncryptionSdk.Keyring.KmsClient

  alias AwsEncryptionSdk.Keyring.KmsClient

  defstruct [:responses]

  @type response_key ::
          {:generate_data_key, KmsClient.key_id()}
          | {:encrypt, KmsClient.key_id()}
          | {:decrypt, KmsClient.key_id()}

  @type responses :: %{
          optional(response_key()) =>
            KmsClient.generate_data_key_result()
            | KmsClient.encrypt_result()
            | KmsClient.decrypt_result()
            | {:error, KmsClient.kms_error()}
        }

  @type t :: %__MODULE__{
          responses: responses()
        }

  @doc """
  Creates a new mock client with pre-configured responses.

  ## Parameters

  - `responses` - Map of `{operation, key_id}` to response values

  ## Example

      Mock.new(%{
        {:generate_data_key, "key-arn"} => %{plaintext: <<...>>, ciphertext: <<...>>, key_id: "key-arn"},
        {:decrypt, "key-arn"} => %{plaintext: <<...>>, key_id: "key-arn"},
        {:encrypt, "key-arn"} => {:error, {:kms_error, :access_denied, "Access denied"}}
      })
  """
  @spec new(responses()) :: {:ok, t()}
  def new(responses \\ %{}) when is_map(responses) do
    {:ok, %__MODULE__{responses: responses}}
  end

  @impl KmsClient
  def generate_data_key(
        %__MODULE__{responses: responses},
        key_id,
        _number_of_bytes,
        _encryption_context,
        _grant_tokens
      ) do
    lookup_response(responses, :generate_data_key, key_id)
  end

  @impl KmsClient
  def encrypt(
        %__MODULE__{responses: responses},
        key_id,
        _plaintext,
        _encryption_context,
        _grant_tokens
      ) do
    lookup_response(responses, :encrypt, key_id)
  end

  @impl KmsClient
  def decrypt(
        %__MODULE__{responses: responses},
        key_id,
        _ciphertext,
        _encryption_context,
        _grant_tokens
      ) do
    lookup_response(responses, :decrypt, key_id)
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp lookup_response(responses, operation, key_id) do
    case Map.get(responses, {operation, key_id}) do
      nil ->
        {:error,
         {:kms_error, :key_not_found,
          "No mock response configured for #{operation} with key #{key_id}"}}

      {:error, _error} = error ->
        error

      response when is_map(response) ->
        {:ok, response}
    end
  end
end
