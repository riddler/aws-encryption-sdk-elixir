# Getting Started

Welcome to the AWS Encryption SDK for Elixir! This guide walks you through
encrypting and decrypting data in minutes.

## Installation

See the [README](readme.html#installation) for installation instructions.

## Your First Encryption

Let's encrypt a secret message using a local AES key. This is the simplest
path - no AWS account required.

```elixir
alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

# 1. Generate a 256-bit AES key
key = :crypto.strong_rand_bytes(32)

# 2. Create a keyring to manage the key
{:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)

# 3. Create a CMM and client
cmm = Default.new(keyring)
client = Client.new(cmm)

# 4. Encrypt your data
plaintext = "Hello, World!"
{:ok, result} = Client.encrypt(client, plaintext)

# 5. Decrypt it back
{:ok, decrypted} = Client.decrypt(client, result.ciphertext)
decrypted.plaintext
# => "Hello, World!"
```

## Understanding Encryption Context

Encryption context provides additional authenticated data (AAD) that is
cryptographically bound to the ciphertext. It's not secret, but it must
match during decryption.

```elixir
# Encrypt with context
context = %{"tenant" => "acme-corp", "purpose" => "user-data"}

{:ok, result} = Client.encrypt(client, "secret data",
  encryption_context: context
)

# Context is stored in the message header (unencrypted but authenticated)
result.encryption_context
# => %{"tenant" => "acme-corp", "purpose" => "user-data"}

# Decrypt - context is returned for verification
{:ok, decrypted} = Client.decrypt(client, result.ciphertext)
decrypted.encryption_context
# => %{"tenant" => "acme-corp", "purpose" => "user-data"}
```

**Best Practice**: Always include meaningful encryption context. It helps
with auditing and prevents ciphertext from being used in unintended contexts.

## Using AWS KMS

For production use, AWS KMS provides secure key management:

```elixir
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

# Create KMS client (uses default AWS credentials)
{:ok, kms_client} = ExAws.new(region: "us-west-2")

# Create keyring with your KMS key
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/12345678-1234-1234-1234-123456789012",
  kms_client
)

# Use the same Client API
cmm = Default.new(keyring)
client = Client.new(cmm)

{:ok, result} = Client.encrypt(client, "secret",
  encryption_context: %{"env" => "production"}
)
```

See `examples/kms_basic.exs` for a complete runnable example.

## Error Handling

The SDK returns tagged tuples for all operations:

```elixir
case Client.encrypt(client, plaintext, encryption_context: context) do
  {:ok, result} ->
    # Success - result.ciphertext contains the encrypted message
    store_encrypted(result.ciphertext)

  {:error, :commitment_policy_requires_committed_suite} ->
    # Algorithm suite doesn't match commitment policy
    Logger.error("Algorithm suite mismatch")

  {:error, reason} ->
    # Other errors
    Logger.error("Encryption failed: #{inspect(reason)}")
end
```

Common errors:
- `:commitment_policy_requires_committed_suite` - Algorithm suite doesn't support key commitment
- `:reserved_encryption_context_key` - Using reserved `aws-crypto-*` keys
- `:max_encrypted_data_keys_exceeded` - Too many encrypted data keys

## Next Steps

- **[Choosing Components](choosing-components.html)** - Select the right keyring and CMM for your use case
- **[Security Best Practices](security-best-practices.html)** - Production deployment guidance
- **[API Reference](AwsEncryptionSdk.html)** - Complete module documentation
