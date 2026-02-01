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
        {:ok, result} ->
          case Client.decrypt(client, result.ciphertext) do
            {:ok, decrypt_result} ->
              if decrypt_result.plaintext == plaintext do
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
      {:ok, result} ->
        IO.puts("✓ Encrypted with public key only")

        # Decrypt-only keyring (private key only)
        IO.puts("\nCreating decrypt-only keyring (private key only)...")

        case RawRsa.new("sender", "recipient-key", {:oaep, :sha256}, private_key: private_key) do
          {:ok, decrypt_keyring} ->
            IO.puts("✓ Decrypt-only keyring created")

            decrypt_client = Client.new(Default.new(decrypt_keyring))

            case Client.decrypt(decrypt_client, result.ciphertext) do
              {:ok, decrypt_result} ->
                IO.puts("✓ Decrypted with private key: #{decrypt_result.plaintext}")

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
    {:ok, result} = Client.encrypt(Client.new(Default.new(correct_keyring)), "test")

    # Try to decrypt with wrong key
    wrong_client = Client.new(Default.new(wrong_keyring))

    case Client.decrypt(wrong_client, result.ciphertext) do
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
