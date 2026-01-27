defmodule AwsEncryptionSdk.Keyring.KmsClientTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.KmsClient

  describe "behaviour" do
    test "Mock implements all callbacks" do
      behaviours = KmsClient.Mock.__info__(:attributes)[:behaviour]
      assert KmsClient in behaviours
    end

    test "ExAws implements all callbacks" do
      behaviours = KmsClient.ExAws.__info__(:attributes)[:behaviour]
      assert KmsClient in behaviours
    end
  end

  describe "types" do
    test "generate_data_key_result has required keys" do
      result = %{plaintext: <<1, 2, 3>>, ciphertext: <<4, 5, 6>>, key_id: "arn:..."}
      assert Map.has_key?(result, :plaintext)
      assert Map.has_key?(result, :ciphertext)
      assert Map.has_key?(result, :key_id)
    end

    test "encrypt_result has required keys" do
      result = %{ciphertext: <<4, 5, 6>>, key_id: "arn:..."}
      assert Map.has_key?(result, :ciphertext)
      assert Map.has_key?(result, :key_id)
    end

    test "decrypt_result has required keys" do
      result = %{plaintext: <<1, 2, 3>>, key_id: "arn:..."}
      assert Map.has_key?(result, :plaintext)
      assert Map.has_key?(result, :key_id)
    end
  end
end
