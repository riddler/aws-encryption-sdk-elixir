# Add Non-AWS Encryption Examples Implementation Plan

## Overview

Add three example files demonstrating encryption/decryption using Raw AES and Raw RSA keyrings, enabling users to use the SDK without AWS credentials. Examples will include environment variable key loading and error handling patterns.

**Issue**: #74

## Current State Analysis

### Existing Examples
All 4 current examples in `examples/` require AWS KMS:
- `kms_basic.exs` - Basic KMS encryption/decryption
- `kms_discovery.exs` - Discovery keyring pattern
- `kms_multi_keyring.exs` - Multi-keyring with KMS
- `kms_cross_region.exs` - Cross-region MRK decryption

### Key Patterns from Existing Examples
- Header: Title, description, prerequisites, usage instructions
- Aliases at top of file
- Configuration/validation section
- Step sections with banner comments for multi-step flows
- Output with `IO.puts` and ✓/✗ indicators
- Verification at end with `System.halt(1)` on failure

### Available APIs
- `RawAes.new(namespace, key_name, wrapping_key, algorithm)` - AES keyring
- `RawRsa.new(namespace, key_name, padding_scheme, public_key: pub, private_key: priv)` - RSA keyring
- `RawRsa.load_public_key_pem/1` and `RawRsa.load_private_key_pem/1` - PEM loading
- `Multi.new(generator: keyring, children: [keyrings])` - Multi-keyring
- `Client.new(Default.new(keyring))` - Standard client setup

## Desired End State

Three new runnable examples that:
1. Work without any AWS credentials or network access
2. Demonstrate key generation, environment variable loading, and error handling
3. Follow existing example conventions for consistency
4. Include security warnings about production key management

### Verification
```bash
# All examples run successfully
mix run examples/raw_aes_basic.exs
mix run examples/raw_rsa.exs
mix run examples/multi_keyring_local.exs

# RSA example with PEM keys from environment variables
export RSA_PRIVATE_KEY_PEM="$(cat private.pem)"
export RSA_PUBLIC_KEY_PEM="$(cat public.pem)"
mix run examples/raw_rsa.exs
```

## What We're NOT Doing

- Streaming encryption examples (separate feature)
- Caching CMM examples (separate feature)
- AWS KMS integration in these examples
- Production key management solutions
- Key generation utilities or separate scripts

---

## Phase 1: Raw AES Basic Example

### Overview
Create `examples/raw_aes_basic.exs` demonstrating AES-256-GCM encryption with in-memory key generation, encryption context usage, and error handling.

### Changes Required

#### 1. Create `examples/raw_aes_basic.exs`

```elixir
# Raw AES Keyring Example
#
# Demonstrates client-side encryption using a locally-managed AES key.
# No AWS credentials required.
#
# SECURITY WARNING: This example generates keys in memory for demonstration.
# In production, use a secure key management system and never hardcode keys.
#
# Usage:
#   mix run examples/raw_aes_basic.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawAes

IO.puts("Raw AES Keyring Example")
IO.puts("=======================\n")

# ============================================================
# Step 1: Generate a 256-bit AES key
# ============================================================

IO.puts("Generating 256-bit AES key...")

# In production, retrieve this from a secure key store
wrapping_key = :crypto.strong_rand_bytes(32)

IO.puts("✓ Generated #{bit_size(wrapping_key)}-bit key")

# ============================================================
# Step 2: Create Raw AES keyring
# ============================================================

IO.puts("\nCreating Raw AES keyring...")

# key_namespace: Identifies your key provider (cannot start with "aws-kms")
# key_name: Unique identifier for this specific key
# wrapping_key: The 32-byte AES key
# algorithm: :aes_256_gcm (also supports :aes_128_gcm, :aes_192_gcm)

case RawAes.new("my-application", "local-key-2024", wrapping_key, :aes_256_gcm) do
  {:ok, keyring} ->
    IO.puts("✓ Keyring created")

    # Create client
    cmm = Default.new(keyring)
    client = Client.new(cmm)

    # ============================================================
    # Step 3: Encrypt data with encryption context
    # ============================================================

    plaintext = "Sensitive data to encrypt"

    # Encryption context provides authenticated metadata
    # It's stored unencrypted but authenticated - tampering causes decryption to fail
    encryption_context = %{
      "purpose" => "example",
      "user_id" => "user-123",
      "timestamp" => DateTime.utc_now() |> DateTime.to_iso8601()
    }

    IO.puts("\nOriginal plaintext: #{plaintext}")
    IO.puts("Encryption context: #{inspect(encryption_context)}")

    IO.puts("\nEncrypting...")

    case Client.encrypt(client, plaintext, encryption_context: encryption_context) do
      {:ok, ciphertext} ->
        IO.puts("✓ Encrypted! Ciphertext size: #{byte_size(ciphertext)} bytes")

        # ============================================================
        # Step 4: Decrypt and verify
        # ============================================================

        IO.puts("\nDecrypting...")

        case Client.decrypt(client, ciphertext) do
          {:ok, {decrypted, returned_context}} ->
            IO.puts("✓ Decrypted: #{decrypted}")
            IO.puts("Returned context: #{inspect(returned_context)}")

            # Verify the data matches
            if decrypted == plaintext do
              IO.puts("\n✓ Success! Round-trip encryption/decryption verified.")
            else
              IO.puts("\n✗ Error: Decrypted data doesn't match original!")
              System.halt(1)
            end

          {:error, reason} ->
            IO.puts("\n✗ Decryption failed: #{inspect(reason)}")
            System.halt(1)
        end

      {:error, reason} ->
        IO.puts("\n✗ Encryption failed: #{inspect(reason)}")
        System.halt(1)
    end

  {:error, reason} ->
    IO.puts("✗ Failed to create keyring: #{inspect(reason)}")
    System.halt(1)
end

# ============================================================
# Bonus: Demonstrate key size variations
# ============================================================

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Key Size Variations")
IO.puts(String.duplicate("=", 60))

key_configs = [
  {16, :aes_128_gcm, "AES-128-GCM"},
  {24, :aes_192_gcm, "AES-192-GCM"},
  {32, :aes_256_gcm, "AES-256-GCM"}
]

for {key_size, algorithm, name} <- key_configs do
  key = :crypto.strong_rand_bytes(key_size)

  case RawAes.new("demo", "key", key, algorithm) do
    {:ok, keyring} ->
      cmm = Default.new(keyring)
      client = Client.new(cmm)
      {:ok, ct} = Client.encrypt(client, "test")
      {:ok, {pt, _}} = Client.decrypt(client, ct)

      if pt == "test" do
        IO.puts("✓ #{name}: #{key_size * 8}-bit key works")
      end

    {:error, reason} ->
      IO.puts("✗ #{name}: #{inspect(reason)}")
  end
end

IO.puts("\n✓ Raw AES example complete!")
```

### Success Criteria

#### Automated Verification:
- [x] Example runs without errors: `mix run examples/raw_aes_basic.exs`
- [x] Tests pass: `mix quality --quick`

#### Manual Verification:
- [x] Output shows all steps completing with ✓ indicators
- [x] All three key sizes (128, 192, 256) work correctly
- [x] Error handling paths work when tested manually

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Raw RSA Example

### Overview
Create `examples/raw_rsa.exs` demonstrating RSA encryption with all 5 padding schemes, both in-memory key generation and environment variable PEM loading.

### Changes Required

#### 1. Create `examples/raw_rsa.exs`

```elixir
# Raw RSA Keyring Example
#
# Demonstrates asymmetric encryption using locally-managed RSA keys.
# Shows all 5 padding schemes and environment variable key loading.
# No AWS credentials required.
#
# SECURITY WARNING: This example generates keys in memory for demonstration.
# In production, use proper key management and protect private keys.
#
# Usage:
#   # With generated keys:
#   mix run examples/raw_rsa.exs
#
#   # With PEM keys from environment variables:
#   export RSA_PRIVATE_KEY_PEM="$(cat private.pem)"
#   export RSA_PUBLIC_KEY_PEM="$(cat public.pem)"
#   mix run examples/raw_rsa.exs
#
# To generate test PEM files:
#   openssl genrsa -out private.pem 4096
#   openssl rsa -in private.pem -pubout -out public.pem

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.RawRsa

IO.puts("Raw RSA Keyring Example")
IO.puts("=======================\n")

# ============================================================
# Step 1: Load or generate RSA key pair
# ============================================================

# Check for PEM keys in environment variables
private_pem = System.get_env("RSA_PRIVATE_KEY_PEM")
public_pem = System.get_env("RSA_PUBLIC_KEY_PEM")

{private_key, public_key} =
  cond do
    # Both environment variables set - load from PEM
    private_pem != nil and public_pem != nil ->
      IO.puts("Loading keys from environment variables...")

      # Load private key
      private_key =
        case RawRsa.load_private_key_pem(private_pem) do
          {:ok, key} ->
            IO.puts("✓ Private key loaded from RSA_PRIVATE_KEY_PEM")
            key

          {:error, reason} ->
            IO.puts("✗ Failed to parse RSA_PRIVATE_KEY_PEM: #{inspect(reason)}")
            System.halt(1)
        end

      # Load public key
      public_key =
        case RawRsa.load_public_key_pem(public_pem) do
          {:ok, key} ->
            IO.puts("✓ Public key loaded from RSA_PUBLIC_KEY_PEM")
            key

          {:error, reason} ->
            IO.puts("✗ Failed to parse RSA_PUBLIC_KEY_PEM: #{inspect(reason)}")
            System.halt(1)
        end

      {private_key, public_key}

    # Only one variable set - error
    private_pem != nil or public_pem != nil ->
      IO.puts("✗ Both RSA_PRIVATE_KEY_PEM and RSA_PUBLIC_KEY_PEM must be set")
      IO.puts("  RSA_PRIVATE_KEY_PEM: #{if private_pem, do: "set", else: "missing"}")
      IO.puts("  RSA_PUBLIC_KEY_PEM: #{if public_pem, do: "set", else: "missing"}")
      System.halt(1)

    # No environment variables - generate keys
    true ->
      IO.puts("Generating 4096-bit RSA key pair...")
      IO.puts("(This may take a moment)")
      IO.puts("Tip: Set RSA_PRIVATE_KEY_PEM and RSA_PUBLIC_KEY_PEM to use existing keys")

      # Generate RSA private key
      private_key = :public_key.generate_key({:rsa, 4096, 65_537})

      # Extract public key from private key
      {:RSAPrivateKey, _version, modulus, public_exp, _private_exp,
       _prime1, _prime2, _exp1, _exp2, _coef, _other} = private_key

      public_key = {:RSAPublicKey, modulus, public_exp}

      IO.puts("✓ Key pair generated")

      {private_key, public_key}
  end

# ============================================================
# Step 2: Demonstrate all padding schemes
# ============================================================

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Testing All Padding Schemes")
IO.puts(String.duplicate("=", 60))

# All 5 supported padding schemes
padding_schemes = [
  {:pkcs1_v1_5, "PKCS#1 v1.5"},
  {{:oaep, :sha1}, "OAEP-SHA1"},
  {{:oaep, :sha256}, "OAEP-SHA256"},
  {{:oaep, :sha384}, "OAEP-SHA384"},
  {{:oaep, :sha512}, "OAEP-SHA512"}
]

plaintext = "Secret message for RSA encryption"

for {padding, name} <- padding_schemes do
  IO.puts("\nTesting #{name}...")

  case RawRsa.new("my-app", "rsa-key-2024", padding,
         public_key: public_key,
         private_key: private_key
       ) do
    {:ok, keyring} ->
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      case Client.encrypt(client, plaintext) do
        {:ok, ciphertext} ->
          case Client.decrypt(client, ciphertext) do
            {:ok, {decrypted, _context}} ->
              if decrypted == plaintext do
                IO.puts("  ✓ #{name}: Encrypt/decrypt successful")
              else
                IO.puts("  ✗ #{name}: Data mismatch!")
                System.halt(1)
              end

            {:error, reason} ->
              IO.puts("  ✗ #{name}: Decrypt failed - #{inspect(reason)}")
              System.halt(1)
          end

        {:error, reason} ->
          IO.puts("  ✗ #{name}: Encrypt failed - #{inspect(reason)}")
          System.halt(1)
      end

    {:error, reason} ->
      IO.puts("  ✗ #{name}: Keyring creation failed - #{inspect(reason)}")
      System.halt(1)
  end
end

# ============================================================
# Step 3: Demonstrate encrypt-only and decrypt-only keyrings
# ============================================================

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Asymmetric Key Usage Patterns")
IO.puts(String.duplicate("=", 60))

# Encrypt-only keyring (public key only)
IO.puts("\nCreating encrypt-only keyring (public key only)...")

case RawRsa.new("sender", "recipient-key", {:oaep, :sha256}, public_key: public_key) do
  {:ok, encrypt_keyring} ->
    IO.puts("✓ Encrypt-only keyring created")

    encrypt_client = Client.new(Default.new(encrypt_keyring))

    case Client.encrypt(encrypt_client, "Message from sender") do
      {:ok, ciphertext} ->
        IO.puts("✓ Encrypted with public key only")

        # Decrypt-only keyring (private key only)
        IO.puts("\nCreating decrypt-only keyring (private key only)...")

        case RawRsa.new("sender", "recipient-key", {:oaep, :sha256}, private_key: private_key) do
          {:ok, decrypt_keyring} ->
            IO.puts("✓ Decrypt-only keyring created")

            decrypt_client = Client.new(Default.new(decrypt_keyring))

            case Client.decrypt(decrypt_client, ciphertext) do
              {:ok, {decrypted, _}} ->
                IO.puts("✓ Decrypted with private key: #{decrypted}")

              {:error, reason} ->
                IO.puts("✗ Decryption failed: #{inspect(reason)}")
                System.halt(1)
            end

          {:error, reason} ->
            IO.puts("✗ Failed to create decrypt keyring: #{inspect(reason)}")
            System.halt(1)
        end

      {:error, reason} ->
        IO.puts("✗ Encryption failed: #{inspect(reason)}")
        System.halt(1)
    end

  {:error, reason} ->
    IO.puts("✗ Failed to create encrypt keyring: #{inspect(reason)}")
    System.halt(1)
end

# ============================================================
# Step 4: Demonstrate error handling
# ============================================================

IO.puts("\n" <> String.duplicate("=", 60))
IO.puts("Error Handling Examples")
IO.puts(String.duplicate("=", 60))

# Attempt to decrypt with wrong key
IO.puts("\nAttempting to decrypt with wrong key...")

wrong_private_key = :public_key.generate_key({:rsa, 2048, 65_537})

case RawRsa.new("wrong", "key", {:oaep, :sha256}, private_key: wrong_private_key) do
  {:ok, wrong_keyring} ->
    # Encrypt with correct key first
    {:ok, correct_keyring} = RawRsa.new("test", "key", {:oaep, :sha256},
      public_key: public_key,
      private_key: private_key
    )
    {:ok, ciphertext} = Client.encrypt(Client.new(Default.new(correct_keyring)), "test")

    # Try to decrypt with wrong key
    wrong_client = Client.new(Default.new(wrong_keyring))

    case Client.decrypt(wrong_client, ciphertext) do
      {:ok, _} ->
        IO.puts("✗ Unexpected success - this should have failed!")
        System.halt(1)

      {:error, _reason} ->
        IO.puts("✓ Correctly failed: Wrong key cannot decrypt")
    end

  {:error, reason} ->
    IO.puts("✗ Keyring creation failed: #{inspect(reason)}")
end

# Attempt with invalid padding scheme
IO.puts("\nAttempting invalid padding scheme...")

case RawRsa.new("test", "key", :invalid_padding, public_key: public_key) do
  {:ok, _} ->
    IO.puts("✗ Should have rejected invalid padding!")
    System.halt(1)

  {:error, :invalid_padding_scheme} ->
    IO.puts("✓ Correctly rejected invalid padding scheme")

  {:error, reason} ->
    IO.puts("✓ Rejected with: #{inspect(reason)}")
end

# Attempt without any keys
IO.puts("\nAttempting keyring without any keys...")

case RawRsa.new("test", "key", {:oaep, :sha256}, []) do
  {:ok, _} ->
    IO.puts("✗ Should have required at least one key!")
    System.halt(1)

  {:error, :no_keys_provided} ->
    IO.puts("✓ Correctly required at least one key")

  {:error, reason} ->
    IO.puts("✓ Rejected with: #{inspect(reason)}")
end

IO.puts("\n✓ Raw RSA example complete!")
IO.puts("\nNote: RSA keyrings wrap the data key, not the plaintext directly.")
IO.puts("The actual data is encrypted with AES-GCM using the wrapped data key.")
```

### Success Criteria

#### Automated Verification:
- [x] Example runs without errors: `mix run examples/raw_rsa.exs`
- [x] Tests pass: `mix quality --quick`

#### Manual Verification:
- [x] All 5 padding schemes work correctly
- [x] Environment variable key loading works with OpenSSL-generated PEM files
- [x] Encrypt-only and decrypt-only keyring patterns work
- [x] Error handling correctly rejects invalid inputs
- [x] Partial environment variable config (only one set) produces helpful error

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Multi-Keyring Local Example

### Overview
Create `examples/multi_keyring_local.exs` demonstrating the generator + children pattern with Raw AES keyrings for key redundancy and rotation scenarios.

### Changes Required

#### 1. Create `examples/multi_keyring_local.exs`

```elixir
# Multi-Keyring Local Example
#
# Demonstrates combining multiple Raw keyrings for:
# - Key redundancy (encrypt once, decrypt with any key)
# - Key rotation preparation
# - Defense in depth
#
# No AWS credentials required.
#
# SECURITY WARNING: Keys are generated in memory for demonstration.
# In production, manage keys securely and implement proper rotation.
#
# Usage:
#   mix run examples/multi_keyring_local.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Keyring.{Multi, RawAes}

IO.puts("Multi-Keyring Local Example")
IO.puts("===========================\n")

# ============================================================
# Step 1: Create multiple Raw AES keyrings
# ============================================================

IO.puts("Creating keyrings for redundancy scenario...")

# Primary key - the generator that creates and wraps data keys
primary_key = :crypto.strong_rand_bytes(32)

case RawAes.new("my-app", "primary-2024", primary_key, :aes_256_gcm) do
  {:ok, primary_keyring} ->
    IO.puts("✓ Primary keyring created")

    # Backup key - wraps the same data key for redundancy
    backup_key = :crypto.strong_rand_bytes(32)

    case RawAes.new("my-app", "backup-2024", backup_key, :aes_256_gcm) do
      {:ok, backup_keyring} ->
        IO.puts("✓ Backup keyring created")

        # ============================================================
        # Step 2: Create multi-keyring
        # ============================================================

        IO.puts("\nCreating multi-keyring...")
        IO.puts("  Generator: primary-2024 (creates the data key)")
        IO.puts("  Child: backup-2024 (wraps the same data key)")

        case Multi.new(generator: primary_keyring, children: [backup_keyring]) do
          {:ok, multi_keyring} ->
            IO.puts("✓ Multi-keyring created")

            # ============================================================
            # Step 3: Encrypt with multi-keyring
            # ============================================================

            IO.puts("\n" <> String.duplicate("=", 60))
            IO.puts("Encrypting with Multi-Keyring")
            IO.puts(String.duplicate("=", 60))

            encrypt_client = Client.new(Default.new(multi_keyring))

            plaintext = "Critical data protected by multiple keys"
            encryption_context = %{"purpose" => "multi-keyring-demo"}

            IO.puts("\nPlaintext: #{plaintext}")
            IO.puts("Encrypting...")

            case Client.encrypt(encrypt_client, plaintext, encryption_context: encryption_context) do
              {:ok, ciphertext} ->
                IO.puts("✓ Encrypted! Ciphertext: #{byte_size(ciphertext)} bytes")
                IO.puts("  Data key wrapped by BOTH keyrings")

                # ============================================================
                # Step 4: Decrypt with primary key only
                # ============================================================

                IO.puts("\n" <> String.duplicate("=", 60))
                IO.puts("Decrypt with Primary Key Only")
                IO.puts(String.duplicate("=", 60))

                primary_client = Client.new(Default.new(primary_keyring))

                case Client.decrypt(primary_client, ciphertext) do
                  {:ok, {decrypted, _context}} ->
                    IO.puts("✓ Decrypted with primary: #{decrypted}")

                  {:error, reason} ->
                    IO.puts("✗ Primary decryption failed: #{inspect(reason)}")
                    System.halt(1)
                end

                # ============================================================
                # Step 5: Decrypt with backup key only
                # ============================================================

                IO.puts("\n" <> String.duplicate("=", 60))
                IO.puts("Decrypt with Backup Key Only")
                IO.puts(String.duplicate("=", 60))

                backup_client = Client.new(Default.new(backup_keyring))

                case Client.decrypt(backup_client, ciphertext) do
                  {:ok, {decrypted, _context}} ->
                    IO.puts("✓ Decrypted with backup: #{decrypted}")

                  {:error, reason} ->
                    IO.puts("✗ Backup decryption failed: #{inspect(reason)}")
                    System.halt(1)
                end

                # ============================================================
                # Step 6: Key rotation scenario
                # ============================================================

                IO.puts("\n" <> String.duplicate("=", 60))
                IO.puts("Key Rotation Scenario")
                IO.puts(String.duplicate("=", 60))

                IO.puts("\nSimulating key rotation: primary-2024 -> primary-2025")

                # New key for rotation
                new_primary_key = :crypto.strong_rand_bytes(32)

                case RawAes.new("my-app", "primary-2025", new_primary_key, :aes_256_gcm) do
                  {:ok, new_primary_keyring} ->
                    IO.puts("✓ New primary keyring (2025) created")

                    # During rotation: new key as generator, old keys as children
                    case Multi.new(
                           generator: new_primary_keyring,
                           children: [primary_keyring, backup_keyring]
                         ) do
                      {:ok, rotation_keyring} ->
                        IO.puts("✓ Rotation multi-keyring created")
                        IO.puts("  Generator: primary-2025 (new)")
                        IO.puts("  Children: primary-2024, backup-2024 (old)")

                        rotation_client = Client.new(Default.new(rotation_keyring))

                        # Can decrypt old data
                        IO.puts("\nDecrypting old data with rotation keyring...")

                        case Client.decrypt(rotation_client, ciphertext) do
                          {:ok, {decrypted, _}} ->
                            IO.puts("✓ Old data decrypted: #{decrypted}")

                          {:error, reason} ->
                            IO.puts("✗ Failed: #{inspect(reason)}")
                            System.halt(1)
                        end

                        # New encryptions use new key
                        IO.puts("\nEncrypting new data with rotation keyring...")

                        case Client.encrypt(rotation_client, "New data after rotation") do
                          {:ok, new_ciphertext} ->
                            IO.puts("✓ New data encrypted with 2025 key")
                            IO.puts("  Ciphertext: #{byte_size(new_ciphertext)} bytes")

                            # Verify new primary can decrypt
                            new_client = Client.new(Default.new(new_primary_keyring))

                            case Client.decrypt(new_client, new_ciphertext) do
                              {:ok, {decrypted, _}} ->
                                IO.puts("✓ Verified: new primary decrypts new data")
                                IO.puts("  Decrypted: #{decrypted}")

                              {:error, reason} ->
                                IO.puts("✗ New primary failed: #{inspect(reason)}")
                                System.halt(1)
                            end

                          {:error, reason} ->
                            IO.puts("✗ New encryption failed: #{inspect(reason)}")
                            System.halt(1)
                        end

                      {:error, reason} ->
                        IO.puts("✗ Rotation keyring failed: #{inspect(reason)}")
                        System.halt(1)
                    end

                  {:error, reason} ->
                    IO.puts("✗ New keyring failed: #{inspect(reason)}")
                    System.halt(1)
                end

                # ============================================================
                # Step 7: Error handling - wrong key
                # ============================================================

                IO.puts("\n" <> String.duplicate("=", 60))
                IO.puts("Error Handling")
                IO.puts(String.duplicate("=", 60))

                wrong_key = :crypto.strong_rand_bytes(32)

                case RawAes.new("my-app", "wrong-key", wrong_key, :aes_256_gcm) do
                  {:ok, wrong_keyring} ->
                    wrong_client = Client.new(Default.new(wrong_keyring))

                    IO.puts("\nAttempting decrypt with unrelated key...")

                    case Client.decrypt(wrong_client, ciphertext) do
                      {:ok, _} ->
                        IO.puts("✗ Should have failed!")
                        System.halt(1)

                      {:error, _reason} ->
                        IO.puts("✓ Correctly failed: unrelated key cannot decrypt")
                    end

                  {:error, reason} ->
                    IO.puts("✗ Wrong keyring failed: #{inspect(reason)}")
                end

                IO.puts("\n✓ Multi-keyring example complete!")
                IO.puts("\nKey Takeaways:")
                IO.puts("  • Generator creates and wraps the data key")
                IO.puts("  • Children wrap the same data key for redundancy")
                IO.puts("  • Any single keyring can decrypt the message")
                IO.puts("  • Use this pattern for key rotation and disaster recovery")

              {:error, reason} ->
                IO.puts("✗ Encryption failed: #{inspect(reason)}")
                System.halt(1)
            end

          {:error, reason} ->
            IO.puts("✗ Multi-keyring creation failed: #{inspect(reason)}")
            System.halt(1)
        end

      {:error, reason} ->
        IO.puts("✗ Backup keyring failed: #{inspect(reason)}")
        System.halt(1)
    end

  {:error, reason} ->
    IO.puts("✗ Primary keyring failed: #{inspect(reason)}")
    System.halt(1)
end
```

### Success Criteria

#### Automated Verification:
- [x] Example runs without errors: `mix run examples/multi_keyring_local.exs`
- [x] Tests pass: `mix quality --quick`

#### Manual Verification:
- [x] Generator + children pattern demonstrated
- [x] Decrypt works with primary key only
- [x] Decrypt works with backup key only
- [x] Key rotation scenario works correctly
- [x] Error handling rejects wrong keys

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: Update README

### Overview
Update `examples/README.md` to document the new examples and provide a clear distinction between AWS and non-AWS examples.

### Changes Required

#### 1. Update `examples/README.md`

Replace the content with:

```markdown
# AWS Encryption SDK Examples

Example scripts demonstrating various encryption scenarios.

## Quick Start (No AWS Required)

These examples work without AWS credentials:

```bash
# Basic AES encryption
mix run examples/raw_aes_basic.exs

# RSA encryption with all padding schemes (generates keys)
mix run examples/raw_rsa.exs

# RSA with existing PEM keys
export RSA_PRIVATE_KEY_PEM="$(cat private.pem)"
export RSA_PUBLIC_KEY_PEM="$(cat public.pem)"
mix run examples/raw_rsa.exs

# Multi-keyring for redundancy
mix run examples/multi_keyring_local.exs
```

## AWS KMS Examples

These examples require AWS credentials and KMS keys:

### Prerequisites

1. AWS credentials configured (environment variables, instance profile, or ~/.aws/credentials)
2. KMS key(s) with appropriate permissions
3. Dependencies installed: `mix deps.get`

### Running KMS Examples

```bash
# Set your KMS key ARN
export KMS_KEY_ARN="arn:aws:kms:us-west-2:123456789012:key/..."

# Run an example
mix run examples/kms_basic.exs
```

## Examples

### Local Key Examples (No AWS Required)

| File | Description |
|------|-------------|
| `raw_aes_basic.exs` | AES-GCM encryption with local key, all key sizes |
| `raw_rsa.exs` | RSA encryption, all padding schemes, env var PEM support |
| `multi_keyring_local.exs` | Multi-keyring for redundancy and key rotation |

### AWS KMS Examples

| File | Description |
|------|-------------|
| `kms_basic.exs` | Basic encryption/decryption with KMS keyring |
| `kms_discovery.exs` | Discovery keyring for flexible decryption |
| `kms_multi_keyring.exs` | Multi-keyring with KMS generator |
| `kms_cross_region.exs` | Cross-region decryption with MRK keyrings |

## Environment Variables

### RSA Example

| Variable | Description |
|----------|-------------|
| `RSA_PRIVATE_KEY_PEM` | PEM-encoded RSA private key (optional) |
| `RSA_PUBLIC_KEY_PEM` | PEM-encoded RSA public key (optional) |

If both are set, the example uses these keys. If neither is set, keys are generated.

## Security Notes

- **Never hardcode keys** in production code
- **Protect private keys** with appropriate file permissions
- **Use a key management system** for production deployments
- The local key examples are for development and testing
```

### Success Criteria

#### Automated Verification:
- [x] Tests pass: `mix quality --quick`

#### Manual Verification:
- [x] README clearly distinguishes AWS vs non-AWS examples
- [x] Quick start section is accurate and works
- [x] All example files are listed in tables

**Implementation Note**: After completing this phase, proceed to Final Verification.

---

## Final Verification

After all phases complete:

### Automated:
- [x] Full test suite: `mix quality`
- [x] All examples run: `mix run examples/raw_aes_basic.exs && mix run examples/raw_rsa.exs && mix run examples/multi_keyring_local.exs`

### Manual:
- [x] RSA example with PEM keys via environment variables:
  ```bash
  openssl genrsa -out /tmp/private.pem 4096
  openssl rsa -in /tmp/private.pem -pubout -out /tmp/public.pem
  export RSA_PRIVATE_KEY_PEM="$(cat /tmp/private.pem)"
  export RSA_PUBLIC_KEY_PEM="$(cat /tmp/public.pem)"
  mix run examples/raw_rsa.exs
  ```
- [x] Review output messages for clarity
- [x] Verify security warnings are visible

## References

- Issue: #74
- Raw AES Keyring: `lib/aws_encryption_sdk/keyring/raw_aes.ex`
- Raw RSA Keyring: `lib/aws_encryption_sdk/keyring/raw_rsa.ex`
- Multi Keyring: `lib/aws_encryption_sdk/keyring/multi.ex`
- Existing examples: `examples/*.exs`
