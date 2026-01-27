defmodule AwsEncryptionSdk.Keyring.KmsClient.ExAwsTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.KmsClient.ExAws, as: KmsExAws

  describe "new/1" do
    test "creates client with defaults" do
      assert {:ok, %KmsExAws{region: nil, config: []}} = KmsExAws.new()
    end

    test "creates client with region" do
      assert {:ok, %KmsExAws{region: "us-west-2", config: []}} =
               KmsExAws.new(region: "us-west-2")
    end

    test "creates client with config" do
      config = [access_key_id: "test", secret_access_key: "test"]

      assert {:ok, %KmsExAws{region: nil, config: ^config}} =
               KmsExAws.new(config: config)
    end

    test "creates client with region and config" do
      config = [access_key_id: "test", secret_access_key: "test"]

      assert {:ok, %KmsExAws{region: "eu-west-1", config: ^config}} =
               KmsExAws.new(region: "eu-west-1", config: config)
    end
  end

  # Note: Integration tests for actual KMS calls require AWS credentials
  # and should be run separately with appropriate setup.
  #
  # Example integration test (requires AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
  #
  # @tag :integration
  # @tag :requires_aws
  # describe "generate_data_key/5 integration" do
  #   test "generates data key with real KMS" do
  #     {:ok, client} = KmsExAws.new(region: "us-east-1")
  #     key_id = System.get_env("KMS_TEST_KEY_ARN")
  #
  #     {:ok, result} = KmsExAws.generate_data_key(client, key_id, 32, %{}, [])
  #
  #     assert byte_size(result.plaintext) == 32
  #     assert is_binary(result.ciphertext)
  #     assert result.key_id == key_id
  #   end
  # end
end
