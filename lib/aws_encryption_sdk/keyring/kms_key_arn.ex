defmodule AwsEncryptionSdk.Keyring.KmsKeyArn do
  @moduledoc """
  AWS KMS Key ARN parsing, validation, and MRK matching utilities.

  Implements the AWS Encryption SDK specification for KMS key identifiers:
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-key-arn.md
  - https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md

  ## ARN Format

  AWS KMS ARNs follow the format:
  `arn:partition:kms:region:account:resource-type/resource-id`

  Example: `arn:aws:kms:us-west-2:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab`

  ## Multi-Region Keys (MRK)

  Multi-Region keys have resource IDs that start with `mrk-`. They can be used
  interchangeably across regions for decrypt operations.
  """

  @type t :: %__MODULE__{
          partition: String.t(),
          service: String.t(),
          region: String.t(),
          account: String.t(),
          resource_type: String.t(),
          resource_id: String.t()
        }

  @enforce_keys [:partition, :service, :region, :account, :resource_type, :resource_id]
  defstruct @enforce_keys

  @valid_resource_types ["alias", "key"]

  @doc """
  Parses an AWS KMS ARN string into a structured format.

  ## Parameters

  - `arn_string` - A string containing an AWS KMS ARN

  ## Returns

  - `{:ok, t()}` on successful parsing
  - `{:error, reason}` on validation failure

  ## Errors

  - `{:error, :invalid_prefix}` - ARN does not start with "arn"
  - `{:error, :empty_partition}` - Partition component is empty
  - `{:error, :empty_service}` - Service component is empty
  - `{:error, :invalid_service}` - Service is not "kms"
  - `{:error, :empty_region}` - Region component is empty
  - `{:error, :empty_account}` - Account component is empty
  - `{:error, :invalid_resource_section}` - Resource section missing "/" separator
  - `{:error, :empty_resource_type}` - Resource type is empty
  - `{:error, :invalid_resource_type}` - Resource type not "alias" or "key"
  - `{:error, :empty_resource_id}` - Resource ID is empty

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123456789012:key/1234abcd")
      {:ok, %AwsEncryptionSdk.Keyring.KmsKeyArn{
        partition: "aws",
        service: "kms",
        region: "us-west-2",
        account: "123456789012",
        resource_type: "key",
        resource_id: "1234abcd"
      }}

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.parse("invalid")
      {:error, :invalid_prefix}

  """
  @spec parse(String.t()) :: {:ok, t()} | {:error, term()}
  def parse(arn_string) when is_binary(arn_string) do
    parts = String.split(arn_string, ":", parts: 6)

    with :ok <- validate_part_count(parts),
         [prefix, partition, service, region, account, resource] = parts,
         :ok <- validate_prefix(prefix),
         :ok <- validate_partition(partition),
         :ok <- validate_service(service),
         :ok <- validate_region(region),
         :ok <- validate_account(account),
         {:ok, {resource_type, resource_id}} <- parse_resource(resource) do
      {:ok,
       %__MODULE__{
         partition: partition,
         service: service,
         region: region,
         account: account,
         resource_type: resource_type,
         resource_id: resource_id
       }}
    end
  end

  @doc """
  Checks if a string looks like an ARN (starts with "arn:").

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.arn?("arn:aws:kms:us-west-2:123:key/abc")
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.arn?("mrk-123")
      false

  """
  @spec arn?(String.t()) :: boolean()
  def arn?(identifier) when is_binary(identifier) do
    String.starts_with?(identifier, "arn:")
  end

  @doc """
  Determines if a key identifier represents a Multi-Region Key (MRK).

  Accepts either a parsed `KmsKeyArn` struct or a string identifier.

  ## Parameters

  - `arn_or_identifier` - A `KmsKeyArn` struct or string key identifier

  ## Returns

  - `true` if the identifier represents an MRK
  - `false` otherwise

  ## Rules

  For ARN structs:
  - Resource type "alias" always returns false
  - Resource type "key" with ID starting with "mrk-" returns true
  - Otherwise returns false

  For string identifiers:
  - Strings starting with "arn:" are parsed and checked as ARNs
  - Strings starting with "alias/" return false
  - Strings starting with "mrk-" return true
  - All other strings return false

  ## Examples

      iex> {:ok, arn} = AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/mrk-abc")
      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?(arn)
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?("mrk-abc123")
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk?("alias/my-key")
      false

  """
  @spec mrk?(t() | String.t()) :: boolean()
  def mrk?(%__MODULE__{resource_type: "alias"}), do: false

  def mrk?(%__MODULE__{resource_type: "key", resource_id: resource_id}) do
    String.starts_with?(resource_id, "mrk-")
  end

  def mrk?(%__MODULE__{}), do: false

  def mrk?(identifier) when is_binary(identifier) do
    cond do
      arn?(identifier) ->
        case parse(identifier) do
          {:ok, arn} -> mrk?(arn)
          {:error, _reason} -> false
        end

      String.starts_with?(identifier, "alias/") ->
        false

      String.starts_with?(identifier, "mrk-") ->
        true

      true ->
        false
    end
  end

  @doc """
  Determines if two key identifiers match for decrypt purposes.

  This implements the AWS KMS MRK Match for Decrypt algorithm. Two identifiers
  match if:
  1. They are identical strings, OR
  2. Both are Multi-Region keys with the same partition, service, account,
     resource type, and resource ID (region may differ)

  ## Parameters

  - `identifier_a` - First AWS KMS key identifier (ARN or raw ID)
  - `identifier_b` - Second AWS KMS key identifier (ARN or raw ID)

  ## Returns

  - `true` if the identifiers match for decrypt purposes
  - `false` otherwise

  ## Examples

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk_match?(
      ...>   "arn:aws:kms:us-west-2:123:key/mrk-abc",
      ...>   "arn:aws:kms:us-east-1:123:key/mrk-abc"
      ...> )
      true

      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.mrk_match?(
      ...>   "arn:aws:kms:us-west-2:123:key/mrk-abc",
      ...>   "arn:aws:kms:us-west-2:123:key/normal-key"
      ...> )
      false

  """
  @spec mrk_match?(String.t(), String.t()) :: boolean()
  def mrk_match?(identifier_a, identifier_b)
      when is_binary(identifier_a) and is_binary(identifier_b) do
    # Rule 1: Identical identifiers always match
    if identifier_a == identifier_b do
      true
    else
      # Rule 2: Both must be MRKs to match across regions
      mrk_match_different_identifiers(identifier_a, identifier_b)
    end
  end

  @doc """
  Reconstructs an ARN string from a parsed `KmsKeyArn` struct.

  ## Examples

      iex> {:ok, arn} = AwsEncryptionSdk.Keyring.KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/abc")
      iex> AwsEncryptionSdk.Keyring.KmsKeyArn.to_string(arn)
      "arn:aws:kms:us-west-2:123:key/abc"

  """
  @spec to_string(t()) :: String.t()
  def to_string(%__MODULE__{} = arn) do
    "arn:#{arn.partition}:#{arn.service}:#{arn.region}:#{arn.account}:#{arn.resource_type}/#{arn.resource_id}"
  end

  defimpl String.Chars do
    alias AwsEncryptionSdk.Keyring.KmsKeyArn

    def to_string(arn) do
      KmsKeyArn.to_string(arn)
    end
  end

  defp mrk_match_different_identifiers(identifier_a, identifier_b) do
    # If either is not MRK, they can't match (since they're already not identical)
    if not mrk?(identifier_a) or not mrk?(identifier_b) do
      false
    else
      # Both are MRKs - compare all parts except region
      compare_mrk_components(identifier_a, identifier_b)
    end
  end

  defp compare_mrk_components(identifier_a, identifier_b) do
    # For raw MRK identifiers (mrk-xxx), compare directly
    if not arn?(identifier_a) and not arn?(identifier_b) do
      identifier_a == identifier_b
    else
      # At least one is an ARN - need to parse and compare components
      with {:ok, arn_a} <- parse_if_arn(identifier_a),
           {:ok, arn_b} <- parse_if_arn(identifier_b) do
        compare_arn_components_except_region(arn_a, arn_b)
      else
        _error -> false
      end
    end
  end

  defp parse_if_arn(identifier) do
    if arn?(identifier) do
      parse(identifier)
    else
      # Raw identifier - can't compare components
      {:error, :not_an_arn}
    end
  end

  defp compare_arn_components_except_region(
         %__MODULE__{
           partition: partition,
           service: service,
           account: account,
           resource_type: resource_type,
           resource_id: resource_id
         },
         %__MODULE__{
           partition: partition,
           service: service,
           account: account,
           resource_type: resource_type,
           resource_id: resource_id
         }
       ) do
    true
  end

  defp compare_arn_components_except_region(%__MODULE__{}, %__MODULE__{}), do: false

  # Private validation functions

  defp validate_part_count(parts) when length(parts) == 6, do: :ok
  defp validate_part_count(_parts), do: {:error, :invalid_arn_format}

  defp validate_prefix("arn"), do: :ok
  defp validate_prefix(_prefix), do: {:error, :invalid_prefix}

  defp validate_partition(""), do: {:error, :empty_partition}
  defp validate_partition(_partition), do: :ok

  defp validate_service(""), do: {:error, :empty_service}
  defp validate_service("kms"), do: :ok
  defp validate_service(_service), do: {:error, :invalid_service}

  defp validate_region(""), do: {:error, :empty_region}
  defp validate_region(_region), do: :ok

  defp validate_account(""), do: {:error, :empty_account}
  defp validate_account(_account), do: :ok

  defp parse_resource(resource) do
    case String.split(resource, "/", parts: 2) do
      [_type_only] ->
        {:error, :invalid_resource_section}

      [type, ""] ->
        if type == "", do: {:error, :invalid_resource_section}, else: {:error, :empty_resource_id}

      ["", _id] ->
        {:error, :empty_resource_type}

      [type, id] ->
        if type in @valid_resource_types do
          {:ok, {type, id}}
        else
          {:error, :invalid_resource_type}
        end
    end
  end
end
