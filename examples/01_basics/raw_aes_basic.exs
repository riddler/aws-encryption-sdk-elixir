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
      {:ok, result} ->
        IO.puts("✓ Encrypted! Ciphertext size: #{byte_size(result.ciphertext)} bytes")

        # ============================================================
        # Step 4: Decrypt and verify
        # ============================================================

        IO.puts("\nDecrypting...")

        case Client.decrypt(client, result.ciphertext) do
          {:ok, decrypt_result} ->
            IO.puts("✓ Decrypted: #{decrypt_result.plaintext}")
            IO.puts("Returned context: #{inspect(decrypt_result.encryption_context)}")

            # Verify the data matches
            if decrypt_result.plaintext == plaintext do
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
      {:ok, result} = Client.encrypt(client, "test")
      {:ok, decrypt_result} = Client.decrypt(client, result.ciphertext)

      if decrypt_result.plaintext == "test" do
        IO.puts("✓ #{name}: #{key_size * 8}-bit key works")
      end

    {:error, reason} ->
      IO.puts("✗ #{name}: #{inspect(reason)}")
  end
end

IO.puts("\n✓ Raw AES example complete!")
