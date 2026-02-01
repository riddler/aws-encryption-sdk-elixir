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
              {:ok, result} ->
                IO.puts("✓ Encrypted! Ciphertext: #{byte_size(result.ciphertext)} bytes")
                IO.puts("  Data key wrapped by BOTH keyrings")

                # ============================================================
                # Step 4: Decrypt with primary key only
                # ============================================================

                IO.puts("\n" <> String.duplicate("=", 60))
                IO.puts("Decrypt with Primary Key Only")
                IO.puts(String.duplicate("=", 60))

                primary_client = Client.new(Default.new(primary_keyring))

                case Client.decrypt(primary_client, result.ciphertext) do
                  {:ok, decrypt_result} ->
                    IO.puts("✓ Decrypted with primary: #{decrypt_result.plaintext}")

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

                case Client.decrypt(backup_client, result.ciphertext) do
                  {:ok, decrypt_result} ->
                    IO.puts("✓ Decrypted with backup: #{decrypt_result.plaintext}")

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

                        case Client.decrypt(rotation_client, result.ciphertext) do
                          {:ok, decrypt_result} ->
                            IO.puts("✓ Old data decrypted: #{decrypt_result.plaintext}")

                          {:error, reason} ->
                            IO.puts("✗ Failed: #{inspect(reason)}")
                            System.halt(1)
                        end

                        # New encryptions use new key
                        IO.puts("\nEncrypting new data with rotation keyring...")

                        case Client.encrypt(rotation_client, "New data after rotation") do
                          {:ok, new_result} ->
                            IO.puts("✓ New data encrypted with 2025 key")
                            IO.puts("  Ciphertext: #{byte_size(new_result.ciphertext)} bytes")

                            # Verify new primary can decrypt
                            new_client = Client.new(Default.new(new_primary_keyring))

                            case Client.decrypt(new_client, new_result.ciphertext) do
                              {:ok, decrypt_result} ->
                                IO.puts("✓ Verified: new primary decrypts new data")
                                IO.puts("  Decrypted: #{decrypt_result.plaintext}")

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

                    case Client.decrypt(wrong_client, result.ciphertext) do
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
