defmodule AwsEncryptionSdk.Keyring.KmsClient.ExAwsIntegrationTest do
  use ExUnit.Case, async: false

  alias AwsEncryptionSdk.Keyring.KmsClient.ExAws, as: KmsExAws

  @moduletag :integration
  @moduletag :requires_aws

  # These tests require AWS credentials to be set:
  # - AWS_ACCESS_KEY_ID
  # - AWS_SECRET_ACCESS_KEY
  # - AWS_REGION (defaults to us-east-1)
  # - KMS_KEY_ARN (a test KMS key you have access to)
  #
  # Run with: source .env && mix test --only integration
  #
  # Note: These tests will make real AWS API calls and may incur small costs.

  setup_all do
    # Skip all tests if KMS_KEY_ARN is not set
    case System.get_env("KMS_KEY_ARN") do
      nil ->
        {:ok, skip: true}

      key_arn ->
        {:ok, key_arn: key_arn, region: System.get_env("AWS_REGION", "us-east-1")}
    end
  end

  describe "generate_data_key/5 integration" do
    test "generates data key with real KMS", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      {:ok, result} = KmsExAws.generate_data_key(client, key_arn, 32, %{}, [])

      assert byte_size(result.plaintext) == 32
      assert is_binary(result.ciphertext)
      assert result.key_id =~ ~r/^arn:aws:kms:/
    end

    test "generates data key with encryption context", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      encryption_context = %{
        "purpose" => "test",
        "environment" => "integration"
      }

      {:ok, result} =
        KmsExAws.generate_data_key(client, key_arn, 32, encryption_context, [])

      assert byte_size(result.plaintext) == 32
      assert is_binary(result.ciphertext)
      assert result.key_id =~ ~r/^arn:aws:kms:/
    end

    test "returns error for invalid key", %{region: region} do
      invalid_key =
        "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"

      {:ok, client} = KmsExAws.new(region: region)

      assert {:error, error} = KmsExAws.generate_data_key(client, invalid_key, 32, %{}, [])

      # Error should be one of our normalized error types
      assert match?({:kms_error, _type, _message}, error) or
               match?({:http_error, _code, _body}, error) or
               match?({:connection_error, _reason}, error)

      # Should contain descriptive information
      assert is_tuple(error)
      assert tuple_size(error) >= 2
    end
  end

  describe "encrypt/5 integration" do
    test "encrypts data with KMS key", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      plaintext = :crypto.strong_rand_bytes(32)

      {:ok, result} = KmsExAws.encrypt(client, key_arn, plaintext, %{}, [])

      assert is_binary(result.ciphertext)
      assert byte_size(result.ciphertext) > 0
      assert result.key_id =~ ~r/^arn:aws:kms:/
    end

    test "encrypts data with encryption context", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      plaintext = :crypto.strong_rand_bytes(32)

      encryption_context = %{
        "purpose" => "test",
        "operation" => "encrypt"
      }

      {:ok, result} = KmsExAws.encrypt(client, key_arn, plaintext, encryption_context, [])

      assert is_binary(result.ciphertext)
      assert result.key_id =~ ~r/^arn:aws:kms:/
    end
  end

  describe "decrypt/5 integration" do
    test "decrypts KMS-encrypted data", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      plaintext = :crypto.strong_rand_bytes(32)

      # First encrypt
      {:ok, encrypt_result} = KmsExAws.encrypt(client, key_arn, plaintext, %{}, [])

      # Then decrypt
      {:ok, decrypt_result} =
        KmsExAws.decrypt(client, key_arn, encrypt_result.ciphertext, %{}, [])

      assert decrypt_result.plaintext == plaintext
      assert decrypt_result.key_id =~ ~r/^arn:aws:kms:/
    end

    test "decrypts data with encryption context", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      plaintext = :crypto.strong_rand_bytes(32)

      encryption_context = %{
        "purpose" => "test",
        "operation" => "roundtrip"
      }

      # Encrypt with context
      {:ok, encrypt_result} =
        KmsExAws.encrypt(client, key_arn, plaintext, encryption_context, [])

      # Decrypt with same context
      {:ok, decrypt_result} =
        KmsExAws.decrypt(client, key_arn, encrypt_result.ciphertext, encryption_context, [])

      assert decrypt_result.plaintext == plaintext
      assert decrypt_result.key_id =~ ~r/^arn:aws:kms:/
    end

    test "fails to decrypt with wrong encryption context", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      plaintext = :crypto.strong_rand_bytes(32)

      encryption_context = %{"purpose" => "test"}
      wrong_context = %{"purpose" => "wrong"}

      # Encrypt with context
      {:ok, encrypt_result} =
        KmsExAws.encrypt(client, key_arn, plaintext, encryption_context, [])

      # Try to decrypt with wrong context
      assert {:error, error} =
               KmsExAws.decrypt(client, key_arn, encrypt_result.ciphertext, wrong_context, [])

      assert match?({:kms_error, _type, _message}, error)
    end
  end

  describe "generate_data_key/5 roundtrip integration" do
    test "can decrypt generated data key ciphertext", %{key_arn: key_arn, region: region} do
      {:ok, client} = KmsExAws.new(region: region)

      encryption_context = %{"purpose" => "test-roundtrip"}

      # Generate data key
      {:ok, generate_result} =
        KmsExAws.generate_data_key(client, key_arn, 32, encryption_context, [])

      # Decrypt the ciphertext to verify we get the same plaintext
      {:ok, decrypt_result} =
        KmsExAws.decrypt(
          client,
          key_arn,
          generate_result.ciphertext,
          encryption_context,
          []
        )

      assert decrypt_result.plaintext == generate_result.plaintext
      assert byte_size(decrypt_result.plaintext) == 32
    end
  end
end
