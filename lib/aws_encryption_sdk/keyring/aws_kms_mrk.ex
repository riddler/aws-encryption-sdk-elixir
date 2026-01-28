defmodule AwsEncryptionSdk.Keyring.AwsKmsMrk do
  @moduledoc """
  AWS KMS Multi-Region Key (MRK) Keyring implementation.

  Enables cross-region encryption and decryption using KMS Multi-Region Keys.
  MRKs are KMS keys that are replicated across AWS regions with the same key
  material but different regional ARNs.

  ## Use Cases

  - **Disaster recovery**: Encrypt in primary region, decrypt in DR region
  - **Global applications**: Access data from any region with MRK replica
  - **Data locality**: Keep encrypted data close to users while maintaining access

  ## Multi-Region Keys (MRKs)

  MRKs have special key IDs starting with `mrk-`:

  | Key Type | Key ID Format | Cross-Region |
  |----------|---------------|--------------|
  | Single-region | `12345678-...` | No |
  | Multi-region | `mrk-12345678-...` | Yes |

  ## MRK Matching

  This keyring uses MRK matching to determine if it can decrypt an EDK:

  | Configured Key | EDK Key | Match? |
  |----------------|---------|--------|
  | `mrk-abc` in us-west-2 | `mrk-abc` in us-east-1 | Yes |
  | `mrk-abc` in us-west-2 | `mrk-xyz` in us-west-2 | No |
  | `12345` in us-west-2 | `12345` in us-east-1 | No |

  ## Operations

  ### Encryption (wrap_key)

  Identical to standard `AwsKms` keyring - MRK awareness only affects decryption.

  ### Decryption (unwrap_key)

  Uses MRK matching to allow decryption with any regional replica:
  1. Filters EDKs by provider ID "aws-kms"
  2. Uses MRK matching to find compatible EDKs
  3. Calls KMS Decrypt with the configured key ARN
  4. Returns decrypted plaintext data key

  ## IAM Permissions Required

  Same as standard KMS keyring, but grant on all regional replicas:

  ```json
  {
    "Effect": "Allow",
    "Action": [
      "kms:GenerateDataKey",
      "kms:Encrypt",
      "kms:Decrypt"
    ],
    "Resource": [
      "arn:aws:kms:us-west-2:123456789012:key/mrk-*",
      "arn:aws:kms:us-east-1:123456789012:key/mrk-*"
    ]
  }
  ```

  ## Examples

  ### Basic MRK Usage

  ```elixir
  alias AwsEncryptionSdk.Keyring.AwsKmsMrk
  alias AwsEncryptionSdk.Keyring.KmsClient.ExAws
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Client

  # Create keyring with MRK in us-west-2
  {:ok, kms_client} = ExAws.new(region: "us-west-2")
  {:ok, keyring} = AwsKmsMrk.new(
    "arn:aws:kms:us-west-2:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
    kms_client
  )

  # Encrypt in us-west-2
  cmm = Default.new(keyring)
  client = Client.new(cmm)
  {:ok, ciphertext} = Client.encrypt(client, "sensitive data")
  ```

  ### Cross-Region Decryption

  ```elixir
  # Original encryption in us-west-2 (above)

  # Decrypt in us-east-1 using the regional replica
  {:ok, east_client} = ExAws.new(region: "us-east-1")
  {:ok, east_keyring} = AwsKmsMrk.new(
    "arn:aws:kms:us-east-1:123456789012:key/mrk-12345678-1234-1234-1234-123456789012",
    east_client
  )

  # This works because MRK matching recognizes same key in different region
  {:ok, {plaintext, _}} = Client.decrypt(Client.new(Default.new(east_keyring)), ciphertext)
  ```

  ### Multi-Keyring for Multi-Region

  ```elixir
  alias AwsEncryptionSdk.Keyring.Multi

  # Use Multi.new_mrk_aware/4 for easy multi-region setup
  {:ok, multi} = Multi.new_mrk_aware(
    "arn:aws:kms:us-west-2:123:key/mrk-abc",
    west_client,
    [
      {"us-east-1", east_client},
      {"eu-west-1", eu_client}
    ]
  )

  # Encrypts with us-west-2, can decrypt in any region
  ```

  ## Spec Reference

  https://github.com/awslabs/aws-encryption-sdk-specification/blob/master/framework/aws-kms/aws-kms-mrk-keyring.md
  """

  @behaviour AwsEncryptionSdk.Keyring.Behaviour

  alias AwsEncryptionSdk.Keyring.AwsKms
  alias AwsEncryptionSdk.Materials.{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials}

  @type t :: %__MODULE__{
          kms_key_id: String.t(),
          kms_client: struct(),
          grant_tokens: [String.t()]
        }

  @enforce_keys [:kms_key_id, :kms_client]
  defstruct [:kms_key_id, :kms_client, grant_tokens: []]

  @doc """
  Creates a new AWS KMS MRK Keyring.

  ## Parameters

  - `kms_key_id` - AWS KMS key identifier (ARN, alias ARN, alias name, or key ID).
    Should be an MRK identifier (mrk-*) to enable cross-region functionality.
  - `kms_client` - KMS client struct implementing KmsClient behaviour
  - `opts` - Optional keyword list:
    - `:grant_tokens` - List of grant tokens for KMS API calls

  ## Returns

  - `{:ok, keyring}` on success
  - `{:error, reason}` on validation failure

  ## Errors

  Same as AwsKms.new/3 - validates key_id and client

  ## Examples

      {:ok, client} = KmsClient.Mock.new(%{})
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client
      )

      # With grant tokens
      {:ok, keyring} = AwsKmsMrk.new(
        "arn:aws:kms:us-west-2:123:key/mrk-abc",
        client,
        grant_tokens: ["token1"]
      )

  """
  @spec new(String.t(), struct(), keyword()) :: {:ok, t()} | {:error, term()}
  def new(kms_key_id, kms_client, opts \\ []) do
    # Delegate validation to AwsKms
    with {:ok, aws_kms} <- AwsKms.new(kms_key_id, kms_client, opts) do
      {:ok, from_aws_kms(aws_kms)}
    end
  end

  @doc """
  Wraps a data key using AWS KMS.

  Delegates to AwsKms.wrap_key/2. Behavior is identical - MRK awareness
  only affects decryption.

  ## Returns

  - `{:ok, materials}` - Data key generated/encrypted and EDK added
  - `{:error, reason}` - KMS operation failed or validation error

  """
  @spec wrap_key(t(), EncryptionMaterials.t()) ::
          {:ok, EncryptionMaterials.t()} | {:error, term()}
  def wrap_key(%__MODULE__{} = keyring, %EncryptionMaterials{} = materials) do
    keyring
    |> to_aws_kms()
    |> AwsKms.wrap_key(materials)
  end

  @doc """
  Unwraps a data key using AWS KMS with MRK matching.

  Delegates to AwsKms.unwrap_key/3, which uses MRK matching to filter EDKs.
  This enables cross-region decryption with MRK replicas.

  ## Returns

  - `{:ok, materials}` - Data key successfully decrypted
  - `{:error, :plaintext_data_key_already_set}` - Materials already have key
  - `{:error, {:unable_to_decrypt_any_data_key, errors}}` - All decryption attempts failed

  """
  @spec unwrap_key(t(), DecryptionMaterials.t(), [EncryptedDataKey.t()]) ::
          {:ok, DecryptionMaterials.t()} | {:error, term()}
  def unwrap_key(%__MODULE__{} = keyring, %DecryptionMaterials{} = materials, edks) do
    keyring
    |> to_aws_kms()
    |> AwsKms.unwrap_key(materials, edks)
  end

  # Convert AwsKmsMrk struct to AwsKms struct
  defp to_aws_kms(%__MODULE__{} = keyring) do
    %AwsKms{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Convert AwsKms struct to AwsKmsMrk struct
  defp from_aws_kms(%AwsKms{} = keyring) do
    %__MODULE__{
      kms_key_id: keyring.kms_key_id,
      kms_client: keyring.kms_client,
      grant_tokens: keyring.grant_tokens
    }
  end

  # Behaviour callbacks - direct users to wrap_key/unwrap_key
  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_encrypt(_materials) do
    {:error, {:must_use_wrap_key, "Call AwsKmsMrk.wrap_key(keyring, materials) instead"}}
  end

  @impl AwsEncryptionSdk.Keyring.Behaviour
  def on_decrypt(_materials, _encrypted_data_keys) do
    {:error,
     {:must_use_unwrap_key, "Call AwsKmsMrk.unwrap_key(keyring, materials, edks) instead"}}
  end
end
