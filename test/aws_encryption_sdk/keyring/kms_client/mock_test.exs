defmodule AwsEncryptionSdk.Keyring.KmsClient.MockTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.KmsClient.Mock

  @test_key_id "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  @test_plaintext :crypto.strong_rand_bytes(32)
  @test_ciphertext :crypto.strong_rand_bytes(64)

  describe "new/1" do
    test "creates mock with empty responses" do
      assert {:ok, %Mock{responses: %{}}} = Mock.new()
    end

    test "creates mock with configured responses" do
      responses = %{
        {:generate_data_key, @test_key_id} => %{
          plaintext: @test_plaintext,
          ciphertext: @test_ciphertext,
          key_id: @test_key_id
        }
      }

      assert {:ok, %Mock{responses: ^responses}} = Mock.new(responses)
    end
  end

  describe "generate_data_key/5" do
    test "returns configured response" do
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @test_key_id} => %{
            plaintext: @test_plaintext,
            ciphertext: @test_ciphertext,
            key_id: @test_key_id
          }
        })

      assert {:ok, result} = Mock.generate_data_key(mock, @test_key_id, 32, %{}, [])
      assert result.plaintext == @test_plaintext
      assert result.ciphertext == @test_ciphertext
      assert result.key_id == @test_key_id
    end

    test "returns error for unconfigured key" do
      {:ok, mock} = Mock.new()

      assert {:error, {:kms_error, :key_not_found, message}} =
               Mock.generate_data_key(mock, @test_key_id, 32, %{}, [])

      assert message =~ "generate_data_key"
      assert message =~ @test_key_id
    end

    test "returns configured error response" do
      {:ok, mock} =
        Mock.new(%{
          {:generate_data_key, @test_key_id} =>
            {:error, {:kms_error, :access_denied, "Access denied"}}
        })

      assert {:error, {:kms_error, :access_denied, "Access denied"}} =
               Mock.generate_data_key(mock, @test_key_id, 32, %{}, [])
    end
  end

  describe "encrypt/5" do
    test "returns configured response" do
      {:ok, mock} =
        Mock.new(%{
          {:encrypt, @test_key_id} => %{
            ciphertext: @test_ciphertext,
            key_id: @test_key_id
          }
        })

      assert {:ok, result} = Mock.encrypt(mock, @test_key_id, @test_plaintext, %{}, [])
      assert result.ciphertext == @test_ciphertext
      assert result.key_id == @test_key_id
    end

    test "returns error for unconfigured key" do
      {:ok, mock} = Mock.new()

      assert {:error, {:kms_error, :key_not_found, _message}} =
               Mock.encrypt(mock, @test_key_id, @test_plaintext, %{}, [])
    end
  end

  describe "decrypt/5" do
    test "returns configured response" do
      {:ok, mock} =
        Mock.new(%{
          {:decrypt, @test_key_id} => %{
            plaintext: @test_plaintext,
            key_id: @test_key_id
          }
        })

      assert {:ok, result} = Mock.decrypt(mock, @test_key_id, @test_ciphertext, %{}, [])
      assert result.plaintext == @test_plaintext
      assert result.key_id == @test_key_id
    end

    test "returns error for unconfigured key" do
      {:ok, mock} = Mock.new()

      assert {:error, {:kms_error, :key_not_found, _message}} =
               Mock.decrypt(mock, @test_key_id, @test_ciphertext, %{}, [])
    end
  end
end
