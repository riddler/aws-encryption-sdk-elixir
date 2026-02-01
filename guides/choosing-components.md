# Choosing Components

This guide helps you select the right keyring and Cryptographic Materials
Manager (CMM) for your use case.

## Understanding the Architecture

The AWS Encryption SDK uses two key abstractions:

```text
┌─────────────────────────────────────────────────────────────┐
│                         Client                              │
│            (commitment policy, max EDKs)                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│              Cryptographic Materials Manager (CMM)          │
│          (key caching, required context enforcement)        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                         Keyring                             │
│       (wraps/unwraps data keys using master keys)           │
└─────────────────────────────────────────────────────────────┘
```

**Keyring**: Wraps and unwraps data encryption keys using your master keys.
Choose based on where your keys are stored.

**CMM**: Manages cryptographic materials. The Default CMM is sufficient for
most use cases. Use specialized CMMs for caching or context enforcement.

## Keyring Selection

### Decision Tree

```text
Where are your master keys stored?
│
├─► AWS KMS
│   │
│   ├─► Do you know the key ARN at decrypt time?
│   │   │
│   │   ├─► YES ──► AwsKms Keyring
│   │   │           (Best for most use cases)
│   │   │
│   │   └─► NO ───► AwsKmsDiscovery Keyring
│   │               (Decrypts any KMS-encrypted message)
│   │
│   └─► Do you need multi-region disaster recovery?
│       │
│       ├─► YES ──► AwsKmsMrk or AwsKmsMrkDiscovery Keyring
│       │           (Works with KMS multi-region keys)
│       │
│       └─► NO ───► Standard AwsKms Keyring
│
├─► Local/HSM keys
│   │
│   ├─► Symmetric key (AES)?
│   │   └─► RawAes Keyring
│   │       (256-bit keys recommended)
│   │
│   └─► Asymmetric key (RSA)?
│       └─► RawRsa Keyring
│           (Useful for encrypt-only or decrypt-only scenarios)
│
└─► Multiple keys for redundancy?
    └─► Multi Keyring
        (Combines multiple keyrings)
```

### Keyring Comparison

| Keyring | Use Case | Key Location | Notes |
|---------|----------|--------------|-------|
| `AwsKms` | Production with AWS | AWS KMS | Recommended for most cases |
| `AwsKmsDiscovery` | Decrypt unknown sources | AWS KMS | Use discovery filter! |
| `AwsKmsMrk` | Multi-region DR | AWS KMS | For MRK keys only |
| `AwsKmsMrkDiscovery` | Multi-region discovery | AWS KMS | Combine with filter |
| `RawAes` | Local/testing | Your app | You manage key storage |
| `RawRsa` | Asymmetric workflows | Your app | Encrypt-only or decrypt-only |
| `Multi` | Redundancy | Multiple | Combines other keyrings |

### Keyring Examples

#### AWS KMS (Recommended for Production)

```elixir
alias AwsEncryptionSdk.Keyring.AwsKms
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws

{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(
  "arn:aws:kms:us-west-2:123456789012:key/...",
  kms_client
)
```

#### Raw AES (Local Development/Testing)

```elixir
alias AwsEncryptionSdk.Keyring.RawAes

key = :crypto.strong_rand_bytes(32)  # 256-bit key
{:ok, keyring} = RawAes.new("my-namespace", "my-key", key, :aes_256_gcm)
```

#### Multi-Keyring (Redundancy)

```elixir
alias AwsEncryptionSdk.Keyring.Multi

# Primary KMS key + backup KMS key
{:ok, primary} = AwsKms.new(primary_arn, kms_client)
{:ok, backup} = AwsKms.new(backup_arn, kms_client)

{:ok, keyring} = Multi.new(generator: primary, children: [backup])
```

## CMM Selection

### Decision Tree

```text
Do you need special materials handling?
│
├─► No special needs
│   └─► Default CMM
│       (Wraps any keyring, handles materials lifecycle)
│
├─► High-volume encryption (>1000 ops/sec)?
│   └─► Caching CMM
│       (Reduces KMS calls, improves performance)
│
└─► Enforce required encryption context keys?
    └─► RequiredEncryptionContext CMM
        (Fails if required keys missing)
```

### CMM Comparison

| CMM | Use Case | Notes |
|-----|----------|-------|
| `Default` | Standard operations | Use for most cases |
| `Caching` | High-volume workloads | Set max_age, max_messages limits |
| `RequiredEncryptionContext` | Compliance/security | Enforces context key presence |

### CMM Examples

#### Default CMM (Most Common)

```elixir
alias AwsEncryptionSdk.Cmm.Default

cmm = Default.new(keyring)
client = Client.new(cmm)
```

#### Caching CMM (High Volume)

Note: Caching CMM currently works with the streaming API.

```elixir
alias AwsEncryptionSdk.Cmm.Caching
alias AwsEncryptionSdk.Cache.LocalCache
alias AwsEncryptionSdk.Stream

# Start the cache process
{:ok, cache} = LocalCache.start_link([])

# Wrap the keyring with caching
cmm = Caching.new_with_keyring(keyring, cache,
  max_age: 300,        # 5 minutes
  max_messages: 1000   # Re-key after 1000 messages
)

client = Client.new(cmm)

# Use with streaming API
ciphertext =
  [plaintext]
  |> Stream.encrypt(client)
  |> Enum.to_list()
  |> IO.iodata_to_binary()
```

#### Required Encryption Context CMM

```elixir
alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext

# Require tenant_id in all encryption operations
cmm = RequiredEncryptionContext.new_with_keyring(["tenant_id"], keyring)

client = Client.new(cmm)

# This succeeds
{:ok, _} = Client.encrypt(client, "data",
  encryption_context: %{"tenant_id" => "acme"}
)

# This fails - missing required key
{:error, _} = Client.encrypt(client, "data",
  encryption_context: %{"other" => "value"}
)
```

## Common Configurations

### Development/Testing
```elixir
key = :crypto.strong_rand_bytes(32)
{:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
cmm = Default.new(keyring)
client = Client.new(cmm)
```

### Production with AWS KMS
```elixir
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
cmm = Default.new(keyring)
client = Client.new(cmm)
```

### High-Volume Production
```elixir
{:ok, kms_client} = ExAws.new(region: "us-west-2")
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
{:ok, cache} = LocalCache.start_link([])
cmm = Caching.new_with_keyring(keyring, cache, max_age: 300)
client = Client.new(cmm)

# Use with Stream API for caching
ciphertext =
  [plaintext]
  |> Stream.encrypt(client)
  |> Enum.to_list()
  |> IO.iodata_to_binary()
```

### Multi-Tenant with Required Context
```elixir
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)
cmm = RequiredEncryptionContext.new_with_keyring(["tenant_id"], keyring)
client = Client.new(cmm)
```
