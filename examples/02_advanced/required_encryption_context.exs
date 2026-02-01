#!/usr/bin/env elixir
# Required Encryption Context CMM Example
#
# Demonstrates enforcing mandatory encryption context keys using the
# Required Encryption Context CMM. This is useful for compliance and
# security policies that require certain metadata on all encrypted data.
#
# Run with: mix run examples/required_encryption_context.exs

alias AwsEncryptionSdk.Client
alias AwsEncryptionSdk.Cmm.Default
alias AwsEncryptionSdk.Cmm.RequiredEncryptionContext
alias AwsEncryptionSdk.Keyring.RawAes

defmodule RequiredContextDemo do
  def run do
    IO.puts(String.duplicate("=", 60))
    IO.puts("Required Encryption Context CMM Example")
    IO.puts(String.duplicate("=", 60))
    IO.puts("")

    # Step 1: Set up keyring
    IO.puts("Step 1: Setting up Raw AES keyring...")
    {:ok, keyring} = setup_keyring()
    IO.puts("  ✓ Keyring created")
    IO.puts("")

    # Step 2: Create Required Encryption Context CMM
    IO.puts("Step 2: Creating Required Encryption Context CMM...")
    IO.puts("  Required keys: [\"tenant_id\", \"environment\"]")
    cmm = RequiredEncryptionContext.new_with_keyring(
      ["tenant_id", "environment"],
      keyring
    )
    client = Client.new(cmm)
    IO.puts("  ✓ CMM configured to require 'tenant_id' and 'environment'")
    IO.puts("")

    # Step 3: Successful encryption with all required keys
    IO.puts("Step 3: Encrypting with all required keys (should succeed)...")
    encryption_context = %{
      "tenant_id" => "acme-corp",
      "environment" => "production",
      "optional_key" => "some-value"
    }

    case Client.encrypt(client, "sensitive data", encryption_context: encryption_context) do
      {:ok, result} ->
        IO.puts("  ✓ Encryption succeeded!")
        IO.puts("  Context: #{inspect(encryption_context)}")
        IO.puts("  Ciphertext length: #{byte_size(result.ciphertext)} bytes")

        # Store for later decryption tests
        Process.put(:encrypted_result, result)
        Process.put(:encryption_context, encryption_context)

      {:error, reason} ->
        IO.puts("  ✗ Unexpected error: #{inspect(reason)}")
        System.halt(1)
    end
    IO.puts("")

    # Step 4: Failed encryption - missing required key
    IO.puts("Step 4: Encrypting without 'environment' key (should fail)...")
    incomplete_context = %{
      "tenant_id" => "acme-corp"
      # Missing "environment"
    }

    case Client.encrypt(client, "sensitive data", encryption_context: incomplete_context) do
      {:ok, _result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 5: Failed encryption - no context at all
    IO.puts("Step 5: Encrypting without any context (should fail)...")

    case Client.encrypt(client, "sensitive data") do
      {:ok, _result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 6: Successful decryption with reproduced context
    IO.puts("Step 6: Decrypting with reproduced context (should succeed)...")
    result = Process.get(:encrypted_result)
    encryption_context = Process.get(:encryption_context)

    case Client.decrypt(client, result.ciphertext, encryption_context: encryption_context) do
      {:ok, decrypt_result} ->
        IO.puts("  ✓ Decryption succeeded!")
        IO.puts("  Plaintext: #{inspect(decrypt_result.plaintext)}")

      {:error, reason} ->
        IO.puts("  ✗ Unexpected error: #{inspect(reason)}")
        System.halt(1)
    end
    IO.puts("")

    # Step 7: Failed decryption - missing reproduced context
    IO.puts("Step 7: Decrypting without reproduced context (should fail)...")

    case Client.decrypt(client, result.ciphertext) do
      {:ok, _decrypt_result} ->
        IO.puts("  ✗ Should have failed but succeeded!")
        System.halt(1)

      {:error, {:missing_required_encryption_context_keys, missing}} ->
        IO.puts("  ✓ Correctly rejected! Missing keys: #{inspect(missing)}")
    end
    IO.puts("")

    # Step 8: Compare with non-enforcing client
    IO.puts("Step 8: Comparison with standard CMM (no enforcement)...")
    standard_cmm = Default.new(keyring)
    standard_client = Client.new(standard_cmm)

    case Client.encrypt(standard_client, "data", encryption_context: %{}) do
      {:ok, _result} ->
        IO.puts("  Standard CMM: Allows empty encryption context")

      {:error, _reason} ->
        IO.puts("  Standard CMM: Rejected (unexpected)")
    end

    IO.puts("  Required EC CMM: Enforces mandatory keys")
    IO.puts("  ✓ Use Required EC CMM for compliance requirements")
    IO.puts("")

    # Step 9: Use cases
    IO.puts("Step 9: Common use cases for Required Encryption Context CMM...")
    IO.puts("  • Multi-tenant systems: Require 'tenant_id' on all data")
    IO.puts("  • Compliance: Require 'data_classification' or 'retention_policy'")
    IO.puts("  • Auditing: Require 'created_by' or 'request_id'")
    IO.puts("  • Environment separation: Require 'environment' (prod/staging/dev)")
    IO.puts("")

    IO.puts(String.duplicate("=", 60))
    IO.puts("Required Encryption Context demonstration completed!")
    IO.puts(String.duplicate("=", 60))
  end

  defp setup_keyring do
    wrapping_key = :crypto.strong_rand_bytes(32)
    RawAes.new("example", "required-context-demo-key", wrapping_key, :aes_256_gcm)
  end
end

RequiredContextDemo.run()
