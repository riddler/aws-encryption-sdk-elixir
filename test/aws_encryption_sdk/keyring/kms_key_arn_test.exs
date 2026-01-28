defmodule AwsEncryptionSdk.Keyring.KmsKeyArnTest do
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Keyring.KmsKeyArn

  describe "parse/1" do
    test "parses valid standard key ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.partition == "aws"
      assert parsed.service == "kms"
      assert parsed.region == "us-west-2"
      assert parsed.account == "658956600833"
      assert parsed.resource_type == "key"
      assert parsed.resource_id == "b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
    end

    test "parses valid MRK ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.resource_type == "key"
      assert parsed.resource_id == "mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
    end

    test "parses valid alias ARN" do
      arn = "arn:aws:kms:us-west-2:658956600833:alias/my-alias"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.resource_type == "alias"
      assert parsed.resource_id == "my-alias"
    end

    test "parses ARN with non-standard partition" do
      arn = "arn:aws-cn:kms:cn-north-1:658956600833:key/1234abcd"

      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert parsed.partition == "aws-cn"
    end

    # Invalid prefix tests
    test "rejects ARN not starting with arn" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse("aws:kms:us-west-2:658956600833:key:mrk-123")
    end

    test "rejects ARN with empty prefix" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse(":aws:kms:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with wrong prefix" do
      assert {:error, :invalid_prefix} =
               KmsKeyArn.parse("arn-not:aws:kms:us-west-2:658956600833:key/mrk-123")
    end

    # Empty component tests
    test "rejects ARN with empty partition" do
      assert {:error, :empty_partition} =
               KmsKeyArn.parse("arn::kms:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with empty service" do
      assert {:error, :empty_service} =
               KmsKeyArn.parse("arn:aws::us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with invalid service" do
      assert {:error, :invalid_service} =
               KmsKeyArn.parse("arn:aws:kms-not:us-west-2:658956600833:key/mrk-123")
    end

    test "rejects ARN with empty region" do
      assert {:error, :empty_region} =
               KmsKeyArn.parse("arn:aws:kms::658956600833:key/mrk-123")
    end

    test "rejects ARN with empty account" do
      assert {:error, :empty_account} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2::key/mrk-123")
    end

    # Resource section tests
    test "rejects ARN with missing resource separator" do
      assert {:error, :invalid_resource_section} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:mrk-123")
    end

    test "rejects ARN with empty resource type" do
      assert {:error, :empty_resource_type} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:/mrk-123")
    end

    test "rejects ARN with invalid resource type" do
      assert {:error, :invalid_resource_type} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key-not/mrk-123")
    end

    test "rejects ARN with missing resource id" do
      assert {:error, :invalid_resource_section} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key")
    end

    test "rejects ARN with empty resource id" do
      assert {:error, :empty_resource_id} =
               KmsKeyArn.parse("arn:aws:kms:us-west-2:658956600833:key/")
    end
  end

  describe "mrk?/1 with struct" do
    test "returns true for key with mrk- prefix" do
      {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/mrk-abc123")
      assert KmsKeyArn.mrk?(arn) == true
    end

    test "returns false for key without mrk- prefix" do
      {:ok, arn} =
        KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f")

      assert KmsKeyArn.mrk?(arn) == false
    end

    test "returns false for alias even with mrk- in name" do
      {:ok, arn} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:alias/mrk-lookalike")
      assert KmsKeyArn.mrk?(arn) == false
    end
  end

  describe "mrk?/1 with string identifier" do
    test "returns true for MRK ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:key/mrk-abc") == true
    end

    test "returns false for non-MRK ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:key/normal-key") == false
    end

    test "returns false for alias ARN string" do
      assert KmsKeyArn.mrk?("arn:aws:kms:us-west-2:123:alias/mrk-lookalike") == false
    end

    test "returns true for raw mrk- identifier" do
      assert KmsKeyArn.mrk?("mrk-80bd8ecdcd4342aebd84b7dc9da498a7") == true
    end

    test "returns false for alias/ identifier" do
      assert KmsKeyArn.mrk?("alias/my-alias") == false
    end

    test "returns false for regular key id" do
      assert KmsKeyArn.mrk?("b3537ef1-d8dc-4780-9f5a-55776cbb2f7f") == false
    end

    test "returns false for invalid ARN" do
      assert KmsKeyArn.mrk?("arn:invalid:format") == false
    end
  end

  describe "arn?/1" do
    test "returns true for ARN strings" do
      assert KmsKeyArn.arn?("arn:aws:kms:us-west-2:123:key/abc") == true
    end

    test "returns false for non-ARN strings" do
      assert KmsKeyArn.arn?("mrk-123") == false
      assert KmsKeyArn.arn?("alias/my-key") == false
      assert KmsKeyArn.arn?("key-id") == false
    end
  end

  describe "mrk_match?/2" do
    test "returns true for identical ARNs" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn, arn) == true
    end

    test "returns true for identical non-MRK ARNs" do
      arn = "arn:aws:kms:us-west-2:123:key/normal-key"
      assert KmsKeyArn.mrk_match?(arn, arn) == true
    end

    test "returns true for same MRK in different regions" do
      arn_west = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_east = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_west, arn_east) == true
    end

    test "returns false when first is MRK but second is not" do
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_normal = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn_mrk, arn_normal) == false
    end

    test "returns false when second is MRK but first is not" do
      arn_normal = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_normal, arn_mrk) == false
    end

    test "returns false for different non-MRK keys" do
      arn1 = "arn:aws:kms:us-west-2:658956600833:key/key-1"
      arn2 = "arn:aws:kms:us-west-2:658956600833:key/key-2"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns true for identical raw MRK identifiers" do
      mrk_id = "mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(mrk_id, mrk_id) == true
    end

    test "returns false for different raw MRK identifiers" do
      assert KmsKeyArn.mrk_match?("mrk-abc", "mrk-def") == false
    end

    test "returns false for MRKs with different accounts" do
      arn1 = "arn:aws:kms:us-west-2:111111111111:key/mrk-abc"
      arn2 = "arn:aws:kms:us-west-2:222222222222:key/mrk-abc"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns false for MRKs with different partitions" do
      arn1 = "arn:aws:kms:us-west-2:123:key/mrk-abc"
      arn2 = "arn:aws-cn:kms:cn-north-1:123:key/mrk-abc"
      assert KmsKeyArn.mrk_match?(arn1, arn2) == false
    end

    test "returns false for aliases even with matching mrk- in name" do
      alias1 = "arn:aws:kms:us-west-2:123:alias/mrk-lookalike"
      alias2 = "arn:aws:kms:us-east-1:123:alias/mrk-lookalike"
      assert KmsKeyArn.mrk_match?(alias1, alias2) == false
    end

    test "returns false for MRK ARN vs non-MRK raw identifier" do
      arn = "arn:aws:kms:us-west-2:123:key/mrk-abc"
      raw = "key-123"
      assert KmsKeyArn.mrk_match?(arn, raw) == false
    end
  end

  describe "to_string/1" do
    test "reconstructs ARN from parsed struct" do
      original = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      {:ok, parsed} = KmsKeyArn.parse(original)
      assert KmsKeyArn.to_string(parsed) == original
    end

    test "works with String.Chars protocol" do
      {:ok, parsed} = KmsKeyArn.parse("arn:aws:kms:us-west-2:123:key/abc")
      assert "#{parsed}" == "arn:aws:kms:us-west-2:123:key/abc"
    end
  end

  describe "keys.json test vector validation" do
    # Valid ARNs from keys.json
    @valid_arns [
      {"us-west-2-decryptable",
       "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f", false},
      {"us-west-2-encrypt-only",
       "arn:aws:kms:us-west-2:658956600833:key/590fd781-ddde-4036-abec-3e1ab5a5d2ad", false},
      {"us-west-2-mrk",
       "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7", true},
      {"us-east-1-mrk",
       "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7", true}
    ]

    for {name, arn, is_mrk} <- @valid_arns do
      test "parses valid ARN: #{name}" do
        assert {:ok, parsed} = KmsKeyArn.parse(unquote(arn))
        assert KmsKeyArn.mrk?(parsed) == unquote(is_mrk)
        assert KmsKeyArn.to_string(parsed) == unquote(arn)
      end
    end

    # Invalid ARNs from keys.json that should fail parsing
    @invalid_arns [
      "aws:kms:us-west-2:658956600833:key:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      ":aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn-not:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn::kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws::us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms-not:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms::658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2::key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:key-not/mrk-80bd8ecdcd4342aebd84b7dc9da498a7",
      "arn:aws:kms:us-west-2:658956600833:key",
      "arn:aws:kms:us-west-2:658956600833:key/"
    ]

    for arn <- @invalid_arns do
      test "rejects invalid ARN: #{arn}" do
        assert {:error, _reason} = KmsKeyArn.parse(unquote(arn))
      end
    end

    # These are valid ARNs but NOT MRKs (aliases never are)
    test "parses alias but identifies as non-MRK even with mrk- prefix" do
      arn = "arn:aws:kms:us-west-2:658956600833:alias/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      assert KmsKeyArn.mrk?(parsed) == false
    end

    # Note: "mrk-80bd8ecdcd4342aebd84b7dc9da498a7-not" starts with "mrk-" so per spec it IS an MRK
    test "parses key with mrk- prefix and suffix as MRK" do
      arn = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7-not"
      assert {:ok, parsed} = KmsKeyArn.parse(arn)
      # Per spec: resource type "key" with ID starting with "mrk-" is MRK
      assert KmsKeyArn.mrk?(parsed) == true
    end

    # MRK matching tests from keys.json
    test "us-west-2-mrk and us-east-1-mrk match" do
      arn_west = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_east = "arn:aws:kms:us-east-1:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      assert KmsKeyArn.mrk_match?(arn_west, arn_east) == true
    end

    test "MRK does not match non-MRK key" do
      arn_mrk = "arn:aws:kms:us-west-2:658956600833:key/mrk-80bd8ecdcd4342aebd84b7dc9da498a7"
      arn_key = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f"
      assert KmsKeyArn.mrk_match?(arn_mrk, arn_key) == false
    end
  end
end
