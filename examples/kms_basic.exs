# Basic KMS Encryption Example
#
# Prerequisites:
#   - AWS credentials configured
#   - KMS key with GenerateDataKey and Decrypt permissions
#
# Usage:
#   export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."
#   export AWS_REGION="us-west-2"  # optional, defaults to key's region
#   mix run examples/kms_basic.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Get configuration from environment
kms_key_arn = System.get_env("KMS_KEY_ARN") ||
  raise "Set KMS_KEY_ARN environment variable"

region = System.get_env("AWS_REGION") ||
  # Extract region from ARN
  case Regex.run(~r/arn:aws:kms:([^:]+):/, kms_key_arn) do
    [_, region] -> region
    _ -> raise "Could not determine region - set AWS_REGION"
  end

IO.puts("Using KMS key: #{kms_key_arn}")
IO.puts("Region: #{region}")

# Create KMS client and keyring
{:ok, kms_client} = ExAws.new(region: region)
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)

# Create CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# Original data
plaintext = "Hello, AWS Encryption SDK!"
encryption_context = %{
  "purpose" => "example",
  "environment" => "development"
}

IO.puts("\nOriginal: #{plaintext}")
IO.puts("Encryption context: #{inspect(encryption_context)}")

# Encrypt
IO.puts("\nEncrypting...")
{:ok, ciphertext} = Client.encrypt(client, plaintext,
  encryption_context: encryption_context
)
IO.puts("Encrypted! Ciphertext size: #{byte_size(ciphertext)} bytes")

# Decrypt
IO.puts("\nDecrypting...")
{:ok, {decrypted, returned_context}} = Client.decrypt(client, ciphertext)

IO.puts("Decrypted: #{decrypted}")
IO.puts("Returned context: #{inspect(returned_context)}")

# Verify
if decrypted == plaintext do
  IO.puts("\n✓ Success! Round-trip encryption/decryption verified.")
else
  IO.puts("\n✗ Error: Decrypted data doesn't match original!")
  System.halt(1)
end
