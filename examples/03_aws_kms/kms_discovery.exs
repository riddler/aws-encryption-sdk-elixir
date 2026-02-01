# KMS Discovery Keyring Example
#
# Demonstrates decrypt-only discovery keyring that can decrypt data
# encrypted with any KMS key the caller has access to.
#
# Prerequisites:
#   - AWS credentials configured
#   - KMS key with GenerateDataKey permission (for encryption)
#   - kms:Decrypt permission on keys in discovery filter
#
# Usage:
#   export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."
#   export AWS_ACCOUNT_ID="123456789012"
#   mix run examples/kms_discovery.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.{AwsKms, AwsKmsDiscovery}
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
kms_key_arn = System.get_env("KMS_KEY_ARN") ||
  raise "Set KMS_KEY_ARN environment variable"

account_id = System.get_env("AWS_ACCOUNT_ID") ||
  case Regex.run(~r/arn:aws:kms:[^:]+:(\d+):/, kms_key_arn) do
    [_, account] -> account
    _ -> raise "Could not determine account - set AWS_ACCOUNT_ID"
  end

region = System.get_env("AWS_REGION") ||
  case Regex.run(~r/arn:aws:kms:([^:]+):/, kms_key_arn) do
    [_, region] -> region
    _ -> raise "Could not determine region - set AWS_REGION"
  end

IO.puts("Encryption key: #{kms_key_arn}")
IO.puts("Discovery filter account: #{account_id}")

# ============================================================
# Step 1: Encrypt with known KMS key
# ============================================================

{:ok, kms_client} = ExAws.new(region: region)
{:ok, encrypt_keyring} = AwsKms.new(kms_key_arn, kms_client)

encrypt_client = Client.new(Default.new(encrypt_keyring))

plaintext = "Secret message for discovery example"

IO.puts("\nEncrypting with known key...")
{:ok, result} = Client.encrypt(encrypt_client, plaintext,
  encryption_context: %{"example" => "discovery"}
)
IO.puts("Encrypted! Size: #{byte_size(result.ciphertext)} bytes")

# ============================================================
# Step 2: Decrypt with discovery keyring
# ============================================================

# Create discovery keyring with filter (recommended for security)
{:ok, discovery_keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{
    partition: "aws",
    accounts: [account_id]
  }
)

decrypt_client = Client.new(Default.new(discovery_keyring))

IO.puts("\nDecrypting with discovery keyring...")
IO.puts("(Discovery keyring doesn't know which key was used)")

{:ok, decrypt_result} = Client.decrypt(decrypt_client, result.ciphertext)
IO.puts("Decrypted: #{decrypt_result.plaintext}")

IO.puts("\n✓ Discovery decryption successful!")
IO.puts("The discovery keyring found the correct key automatically.")
