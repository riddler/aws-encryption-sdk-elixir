defmodule GuidesTest do
  @moduledoc """
  Tests to validate code examples from user guides.

  These tests extract code blocks from the markdown guides and execute them where possible,
  ensuring that code snippets work correctly. Since many guide examples build on each other
  sequentially, we focus on testing complete standalone examples and validating extraction.
  """
  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.Client
  alias AwsEncryptionSdk.Cmm.Default
  alias AwsEncryptionSdk.Keyring.{Multi, RawAes}
  alias AwsEncryptionSdk.TestSupport.GuideCodeExtractor

  @guides_dir Path.join([__DIR__, "..", "guides"])

  describe "Getting Started Guide" do
    setup do
      file_path = Path.join(@guides_dir, "getting-started.md")
      blocks = GuideCodeExtractor.extract_code_blocks(file_path)
      {:ok, blocks: blocks}
    end

    test "extracts code blocks from guide", %{blocks: blocks} do
      assert blocks != []
      assert length(blocks) >= 2

      # Verify blocks have expected structure
      for block <- blocks do
        assert is_binary(block.code)
        assert is_integer(block.line)
        assert is_boolean(block.testable)
      end
    end

    test "first encryption example from guide executes correctly", %{blocks: blocks} do
      # Find the complete first encryption example
      block =
        blocks
        |> Enum.find(fn b ->
          String.contains?(b.code, "Hello, World!") &&
            String.contains?(b.code, "RawAes.new") &&
            String.contains?(b.code, "Client.encrypt") &&
            String.contains?(b.code, "Client.decrypt")
        end)

      assert block, "Could not find first encryption example"

      # This is a complete example that should execute
      code = GuideCodeExtractor.clean_code_for_execution(block.code)
      code = code <> "\ndecrypted.plaintext"

      {result, _binding} = Code.eval_string(code)
      assert result == "Hello, World!"
    end
  end

  describe "Choosing Components Guide" do
    setup do
      file_path = Path.join(@guides_dir, "choosing-components.md")
      blocks = GuideCodeExtractor.extract_code_blocks(file_path)
      {:ok, blocks: blocks}
    end

    test "extracts code blocks from guide", %{blocks: blocks} do
      assert blocks != []
      assert length(blocks) >= 5
    end

    test "validates configuration examples exist", %{blocks: blocks} do
      # Find configuration examples
      config_blocks =
        blocks
        |> Enum.filter(fn b -> b.section == "Common Configurations" && b.testable end)

      assert config_blocks != [], "Should have common configuration examples"

      # Verify they have expected content (patterns from the guide)
      for block <- config_blocks do
        assert String.contains?(block.code, "Client.new")
      end
    end
  end

  describe "Security Best Practices Guide" do
    setup do
      file_path = Path.join(@guides_dir, "security-best-practices.md")
      blocks = GuideCodeExtractor.extract_code_blocks(file_path)
      {:ok, blocks: blocks}
    end

    test "extracts code blocks from guide", %{blocks: blocks} do
      assert blocks != []
      assert length(blocks) >= 5
    end

    test "validates commitment policy examples exist", %{blocks: blocks} do
      # Find commitment policy examples
      policy_blocks =
        blocks
        |> Enum.filter(fn b ->
          String.contains?(b.code, "commitment_policy:")
        end)

      assert policy_blocks != [], "Should have commitment policy examples"

      # Verify they show the key patterns from the guide
      for block <- policy_blocks do
        assert String.contains?(block.code, "Client.new")
      end
    end
  end

  describe "Code extraction and cleaning" do
    test "clean_code_for_execution removes output comments" do
      code_with_output = """
      result = some_function()
      # => :ok
      result
      """

      cleaned = GuideCodeExtractor.clean_code_for_execution(code_with_output)

      refute String.contains?(cleaned, "# =>")
      assert String.contains?(cleaned, "result = some_function()")
      assert String.contains?(cleaned, "result")
    end

    test "clean_code_for_execution preserves regular comments" do
      code_with_comments = """
      # This is a regular comment
      result = some_function()
      # Another comment
      result
      """

      cleaned = GuideCodeExtractor.clean_code_for_execution(code_with_comments)

      assert String.contains?(cleaned, "# This is a regular comment")
      assert String.contains?(cleaned, "# Another comment")
    end
  end

  describe "Manual validation of key examples" do
    # These tests manually validate that key patterns from the guides actually work
    # They're based on the guide content but written to be independently executable

    test "getting started: first encryption pattern works" do
      # Based on "Your First Encryption" section
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("my-app", "my-key", key, :aes_256_gcm)
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      plaintext = "Hello, World!"
      {:ok, result} = Client.encrypt(client, plaintext)
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)

      assert decrypted.plaintext == "Hello, World!"
    end

    test "choosing components: multi-keyring pattern works" do
      # Based on Multi-keyring example
      key1 = :crypto.strong_rand_bytes(32)
      key2 = :crypto.strong_rand_bytes(32)
      {:ok, primary} = RawAes.new("ns", "primary", key1, :aes_256_gcm)
      {:ok, backup} = RawAes.new("ns", "backup", key2, :aes_256_gcm)

      {:ok, keyring} = Multi.new(generator: primary, children: [backup])
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      {:ok, result} = Client.encrypt(client, "test")
      {:ok, decrypted} = Client.decrypt(client, result.ciphertext)

      assert decrypted.plaintext == "test"
      assert is_struct(keyring, Multi)
    end

    test "security: commitment policy pattern works" do
      # Based on commitment policy examples
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)

      # Default - strictest policy
      client = Client.new(cmm)
      assert client.commitment_policy == :require_encrypt_require_decrypt

      # Explicit policy
      client2 = Client.new(cmm, commitment_policy: :require_encrypt_require_decrypt)
      assert client2.commitment_policy == :require_encrypt_require_decrypt
    end

    test "security: max encrypted data keys pattern works" do
      # Based on EDK limit example
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)

      client = Client.new(cmm, max_encrypted_data_keys: 5)
      assert client.max_encrypted_data_keys == 5
    end

    test "security: encryption context best practices pattern works" do
      # Based on context verification example
      key = :crypto.strong_rand_bytes(32)
      {:ok, keyring} = RawAes.new("test", "key", key, :aes_256_gcm)
      cmm = Default.new(keyring)
      client = Client.new(cmm)

      context = %{
        "tenant_id" => "acme-corp",
        "data_type" => "user-pii",
        "purpose" => "storage"
      }

      {:ok, encrypt_result} = Client.encrypt(client, "data", encryption_context: context)
      {:ok, decrypted} = Client.decrypt(client, encrypt_result.ciphertext)

      # Verify context as shown in guide
      expected_tenant = "acme-corp"

      result =
        case decrypted.encryption_context do
          %{"tenant_id" => ^expected_tenant} -> {:ok, decrypted.plaintext}
          _other -> {:error, :context_mismatch}
        end

      assert result == {:ok, "data"}
    end
  end
end
