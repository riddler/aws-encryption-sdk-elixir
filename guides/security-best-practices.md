# Security Best Practices

This guide covers security best practices for using the AWS Encryption SDK
for Elixir in production environments.

## 1. Use Key Commitment (Default)

Key commitment ensures ciphertext can only decrypt to one plaintext. This
prevents sophisticated attacks where malicious ciphertext decrypts to
different values with different keys.

**The SDK defaults to the strictest policy: `require_encrypt_require_decrypt`**

```elixir
# Default - strictest policy (recommended)
client = Client.new(cmm)

# Explicit - same as default
client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
```

### Commitment Policies

| Policy | Encrypt | Decrypt | Use Case |
|--------|---------|---------|----------|
| `:require_encrypt_require_decrypt` | Committed only | Committed only | New applications (default) |
| `:require_encrypt_allow_decrypt` | Committed only | Both | Migration from legacy |
| `:forbid_encrypt_allow_decrypt` | Non-committed only | Both | Legacy compatibility |

### Migration Path

If migrating from non-committed messages:

1. **Phase 1**: Deploy with `:require_encrypt_allow_decrypt`
   - New encryptions use commitment
   - Can still decrypt legacy messages

2. **Phase 2**: After all messages re-encrypted, switch to `:require_encrypt_require_decrypt`

```elixir
# Phase 1: Transitional
client = Client.new(cmm, commitment_policy: :require_encrypt_allow_decrypt)

# Phase 2: After migration complete
client = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
```

## 2. Always Use Encryption Context

Encryption context provides authenticated data that is cryptographically
bound to the ciphertext but stored unencrypted in the message header.

**Benefits:**
- Prevents ciphertext substitution attacks
- Provides audit trail
- Enables access control decisions

```elixir
# Good - meaningful context
context = %{
  "tenant_id" => "acme-corp",
  "data_type" => "user-pii",
  "purpose" => "storage"
}

{:ok, result} = Client.encrypt(client, data, encryption_context: context)
```

### Context Best Practices

| Do | Don't |
|----|-------|
| Include tenant/user identifiers | Store secrets in context |
| Add data classification | Use context as the only access control |
| Include purpose/operation | Include frequently-changing values |
| Use consistent key names | Use `aws-crypto-*` prefix (reserved) |

### Verifying Context on Decrypt

```elixir
{:ok, result} = Client.decrypt(client, ciphertext)

# Always verify the context matches expectations
case result.encryption_context do
  %{"tenant_id" => ^expected_tenant} ->
    {:ok, result.plaintext}
  _ ->
    {:error, :context_mismatch}
end
```

## 3. Protect Your Wrapping Keys

### For AWS KMS Keys

- Use IAM policies to restrict key access
- Enable CloudTrail logging for key usage
- Use key policies to define administrators vs. users
- Consider using grants for temporary access

### For Raw Keys

- Generate keys using cryptographically secure random:
  ```elixir
  key = :crypto.strong_rand_bytes(32)  # 256-bit
  ```

- Store keys securely (HSM, secrets manager, encrypted config)
- Rotate keys periodically
- Never log or expose keys

## 4. Specify Wrapping Keys Explicitly

Avoid using discovery keyrings for encryption. Always specify the exact
key(s) to use:

```elixir
# Good - explicit key
{:ok, keyring} = AwsKms.new(kms_key_arn, kms_client)

# Avoid for encryption - discovery doesn't specify a key
{:ok, discovery} = AwsKmsDiscovery.new(kms_client)  # Can only decrypt!
```

### When Using Discovery for Decryption

Always use discovery filters to limit which keys can decrypt:

```elixir
# Good - filtered discovery
{:ok, keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{
    partition: "aws",
    accounts: ["123456789012", "987654321098"]
  }
)

# Dangerous - accepts any AWS account's keys
{:ok, keyring} = AwsKmsDiscovery.new(kms_client)  # No filter!
```

## 5. Limit Encrypted Data Keys

Set a maximum number of encrypted data keys (EDKs) to prevent denial-of-service:

```elixir
# Limit to 5 EDKs (most messages have 1-3)
client = Client.new(cmm, max_encrypted_data_keys: 5)
```

This protects against:
- Maliciously crafted messages with thousands of EDKs
- Resource exhaustion during decryption
- Misconfigured keyrings generating too many EDKs

## 6. Use Digital Signatures (Default)

The default algorithm suite includes ECDSA signatures that verify the
message hasn't been tampered with and was created by an authorized party.

```elixir
# Default suite includes signing (recommended)
{:ok, result} = Client.encrypt(client, data)

# Only disable if you have a specific reason
# (e.g., performance-critical, already authenticated channel)
suite = AlgorithmSuite.aes_256_gcm_hkdf_sha512_commit_key()
{:ok, result} = Client.encrypt(client, data, algorithm_suite: suite)
```

## 7. Handle Errors Securely

Never expose internal error details to end users:

```elixir
case Client.decrypt(client, ciphertext) do
  {:ok, result} ->
    {:ok, result.plaintext}

  {:error, reason} ->
    # Log detailed error for debugging
    Logger.error("Decryption failed: #{inspect(reason)}")

    # Return generic error to user
    {:error, :decryption_failed}
end
```

## 8. Production Deployment Checklist

### Before Going Live

- [ ] **Commitment policy**: Using `:require_encrypt_require_decrypt`
- [ ] **Encryption context**: All operations include meaningful context
- [ ] **Key management**: Using AWS KMS or secure HSM
- [ ] **Discovery filters**: All discovery keyrings have account filters
- [ ] **EDK limits**: `max_encrypted_data_keys` set appropriately
- [ ] **Error handling**: Internal errors not exposed to users
- [ ] **Logging**: Encrypt/decrypt operations logged (without plaintext)
- [ ] **Key rotation**: Plan for periodic key rotation

### Monitoring

- Monitor KMS API calls via CloudTrail
- Alert on decryption failures (may indicate attack)
- Track encryption context patterns for anomalies

### Testing

- Test with production-like keys before deployment
- Verify round-trip encryption/decryption
- Test error handling paths
- Verify context validation logic

## Common Security Pitfalls

### 1. Missing Encryption Context
```elixir
# Bad - no context
{:ok, result} = Client.encrypt(client, data)

# Good - meaningful context
{:ok, result} = Client.encrypt(client, data,
  encryption_context: %{"purpose" => "user-data"}
)
```

### 2. Unfiltered Discovery Keyring
```elixir
# Bad - accepts any account
{:ok, keyring} = AwsKmsDiscovery.new(kms_client)

# Good - restricted to your accounts
{:ok, keyring} = AwsKmsDiscovery.new(kms_client,
  discovery_filter: %{partition: "aws", accounts: ["123456789012"]}
)
```

### 3. Storing Raw Keys Insecurely
```elixir
# Bad - key in code/config
key = <<1, 2, 3, ...>>

# Good - key from secure source
key = fetch_key_from_secrets_manager()
```

### 4. Ignoring Returned Context
```elixir
# Bad - ignoring context
{:ok, result} = Client.decrypt(client, ciphertext)
use_data(result.plaintext)

# Good - verify context
{:ok, result} = Client.decrypt(client, ciphertext)
if valid_context?(result.encryption_context) do
  use_data(result.plaintext)
end
```

## Further Reading

- [AWS Encryption SDK Best Practices](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/best-practices.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [OWASP Cryptographic Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
