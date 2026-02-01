# Cross-Region MRK Decryption Example
#
# Demonstrates encrypting with an MRK in one region and decrypting
# with the replica in another region.
#
# Prerequisites:
#   - AWS credentials configured
#   - Multi-Region Key (mrk-*) replicated across regions
#
# Usage:
#   export MRK_KEY_ARN="arn:aws:kms:us-west-2:123:key/mrk-..."
#   export REPLICA_REGION="us-east-1"
#   mix run examples/kms_cross_region.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.AwsKmsMrk
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Configuration
mrk_key_arn = System.get_env("MRK_KEY_ARN") ||
  raise "Set MRK_KEY_ARN environment variable (must be mrk-* key)"

replica_region = System.get_env("REPLICA_REGION") || "us-east-1"

# Validate it's an MRK
unless String.contains?(mrk_key_arn, "/mrk-") do
  raise "Key must be a Multi-Region Key (key ID starting with mrk-)"
end

# Extract primary region and construct replica ARN
primary_region = case Regex.run(~r/arn:aws:kms:([^:]+):/, mrk_key_arn) do
  [_, region] -> region
  _ -> raise "Invalid key ARN format"
end

replica_key_arn = String.replace(mrk_key_arn, primary_region, replica_region)

IO.puts("Primary key (#{primary_region}): #{mrk_key_arn}")
IO.puts("Replica key (#{replica_region}): #{replica_key_arn}")

# ============================================================
# Step 1: Encrypt in primary region
# ============================================================

{:ok, primary_client} = ExAws.new(region: primary_region)
{:ok, primary_keyring} = AwsKmsMrk.new(mrk_key_arn, primary_client)

encrypt_client = Client.new(Default.new(primary_keyring))

plaintext = "Data encrypted in #{primary_region}, to be decrypted in #{replica_region}"

IO.puts("\nEncrypting in #{primary_region}...")
{:ok, result} = Client.encrypt(encrypt_client, plaintext,
  encryption_context: %{"source_region" => primary_region}
)
IO.puts("Encrypted! Size: #{byte_size(result.ciphertext)} bytes")

# ============================================================
# Step 2: Decrypt in replica region
# ============================================================

IO.puts("\nDecrypting in #{replica_region} using MRK replica...")

{:ok, replica_client} = ExAws.new(region: replica_region)
{:ok, replica_keyring} = AwsKmsMrk.new(replica_key_arn, replica_client)

decrypt_client = Client.new(Default.new(replica_keyring))

{:ok, decrypt_result} = Client.decrypt(decrypt_client, result.ciphertext)

IO.puts("Decrypted: #{decrypt_result.plaintext}")
IO.puts("Context shows source: #{decrypt_result.encryption_context["source_region"]}")

IO.puts("\n✓ Cross-region decryption successful!")
IO.puts("Data encrypted in #{primary_region} was decrypted in #{replica_region}")
