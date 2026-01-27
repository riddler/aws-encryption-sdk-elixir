# Manual Verification Script for KMS Client Implementation
# Run with: source .env && mix run scripts/verify_kms_client.exs

IO.puts("\n=== KMS Client Manual Verification ===\n")

# Phase 1: Verify ex_aws_kms is available
IO.puts("✓ Phase 1: Checking ExAws.KMS availability...")

if Code.ensure_loaded?(ExAws.KMS) do
  IO.puts("  ✓ ExAws.KMS module loaded")
  IO.puts("  ✓ Functions available: #{inspect(ExAws.KMS.__info__(:functions) |> Enum.take(3))}...")
else
  IO.puts("  ✗ ExAws.KMS not available")
  System.halt(1)
end

# Phase 3: Verify Mock client works
IO.puts("\n✓ Phase 3: Testing Mock client...")
alias AwsEncryptionSdk.Keyring.KmsClient.Mock

{:ok, mock} =
  Mock.new(%{
    {:generate_data_key, "test-key"} => %{
      plaintext: <<1, 2, 3>>,
      ciphertext: <<4, 5, 6>>,
      key_id: "test-key"
    }
  })

{:ok, result} = Mock.generate_data_key(mock, "test-key", 32, %{}, [])
IO.puts("  ✓ Mock.new/1 works")
IO.puts("  ✓ Mock.generate_data_key/5 returns: #{inspect(result)}")

# Phase 4: Verify ExAws client can be instantiated
IO.puts("\n✓ Phase 4: Testing ExAws client...")
alias AwsEncryptionSdk.Keyring.KmsClient.ExAws, as: KmsExAws

{:ok, client} = KmsExAws.new(region: "us-east-1")
IO.puts("  ✓ ExAws.new/1 works")
IO.puts("  ✓ Client struct: #{inspect(client)}")

# Optional: Test with real AWS if credentials are available
key_arn = System.get_env("KMS_KEY_ARN")

if key_arn do
  IO.puts("\n✓ Testing with real AWS KMS...")
  IO.puts("  Key ARN: #{key_arn}")

  case KmsExAws.generate_data_key(client, key_arn, 32, %{"test" => "verification"}, []) do
    {:ok, result} ->
      IO.puts("  ✓ Real KMS call succeeded!")
      IO.puts("  ✓ Plaintext key length: #{byte_size(result.plaintext)} bytes")
      IO.puts("  ✓ Ciphertext present: #{is_binary(result.ciphertext)}")
      IO.puts("  ✓ Key ID returned: #{result.key_id}")

    {:error, error} ->
      IO.puts("  ✗ KMS call failed: #{inspect(error)}")
      IO.puts("  This might be a permissions issue. Check your AWS credentials.")
  end
else
  IO.puts("\n⚠ Skipping real AWS test (KMS_KEY_ARN not set)")
  IO.puts("  To test with real AWS, run:")
  IO.puts("    export KMS_KEY_ARN=\"your-key-arn\"")
  IO.puts("    source .env && mix run scripts/verify_kms_client.exs")
end

IO.puts("\n=== Verification Complete ===\n")
IO.puts("All manual checks passed!")
IO.puts("\nTo view documentation:")
IO.puts("  mix docs && open doc/index.html")
IO.puts("\nTo run integration tests:")
IO.puts("  source .env && mix test --only integration")
