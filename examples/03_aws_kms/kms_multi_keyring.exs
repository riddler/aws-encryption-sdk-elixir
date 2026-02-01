# Multi-Keyring with KMS Example
#
# Demonstrates encrypting with multiple KMS keys for redundancy.
# Data can be decrypted with ANY of the keys.
#
# Prerequisites:
#   - AWS credentials configured
#   - Two KMS keys with appropriate permissions
#
# Usage:
#   export KMS_KEY_ARN_1="arn:aws:kms:us-west-2:123:key/primary"
#   export KMS_KEY_ARN_2="arn:aws:kms:us-west-2:123:key/backup"
#   mix run examples/kms_multi_keyring.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.{AwsKms, Multi}
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
key_arn_1 = System.get_env("KMS_KEY_ARN_1") ||
  raise "Set KMS_KEY_ARN_1 environment variable"

key_arn_2 = System.get_env("KMS_KEY_ARN_2") ||
  raise "Set KMS_KEY_ARN_2 environment variable"

# Extract region from first key
region = case Regex.run(~r/arn:aws:kms:([^:]+):/, key_arn_1) do
  [_, region] -> region
  _ -> System.get_env("AWS_REGION") || raise "Could not determine region"
end

IO.puts("Primary key: #{key_arn_1}")
IO.puts("Backup key: #{key_arn_2}")
IO.puts("Region: #{region}")

# Create clients
{:ok, kms_client} = ExAws.new(region: region)

# Create keyrings
{:ok, primary_keyring} = AwsKms.new(key_arn_1, kms_client)
{:ok, backup_keyring} = AwsKms.new(key_arn_2, kms_client)

# Create multi-keyring
# - Primary is the generator (creates the data key)
# - Backup is a child (wraps the same data key)
{:ok, multi_keyring} = Multi.new(
  generator: primary_keyring,
  children: [backup_keyring]
)

IO.puts("\nMulti-keyring created with 2 keys")

# ============================================================
# Encrypt with multi-keyring
# ============================================================

encrypt_client = Client.new(Default.new(multi_keyring))

plaintext = "Critical data protected by multiple keys"

IO.puts("\nEncrypting with multi-keyring...")
{:ok, result} = Client.encrypt(encrypt_client, plaintext)
IO.puts("Encrypted! Data key wrapped by both keys.")

# ============================================================
# Decrypt with primary key only
# ============================================================

IO.puts("\nDecrypting with primary key only...")
primary_client = Client.new(Default.new(primary_keyring))
{:ok, decrypt_result} = Client.decrypt(primary_client, result.ciphertext)
IO.puts("✓ Decrypted with primary: #{decrypt_result.plaintext}")

# ============================================================
# Decrypt with backup key only
# ============================================================

IO.puts("\nDecrypting with backup key only...")
backup_client = Client.new(Default.new(backup_keyring))
{:ok, decrypt_result} = Client.decrypt(backup_client, result.ciphertext)
IO.puts("✓ Decrypted with backup: #{decrypt_result.plaintext}")

IO.puts("\n✓ Multi-keyring example complete!")
IO.puts("Data can be decrypted with either key for redundancy.")
