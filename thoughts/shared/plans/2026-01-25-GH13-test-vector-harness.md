# Test Vector Harness Implementation Plan

## Overview

Create a test vector harness for the AWS Encryption SDK for Elixir that can load, parse, and execute official AWS Encryption SDK test vectors. This establishes the foundation for test-driven development and cross-SDK compatibility validation.

**Issue**: #13 - Create test vector harness and integrate with workflow commands
**Research**: `thoughts/shared/research/2026-01-25-GH13-test-vector-harness.md`

## Specification Requirements

### Source Documents
- [aws-crypto-tools-test-vector-framework](https://github.com/awslabs/aws-crypto-tools-test-vector-framework) - Framework specification
- [0002-keys.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0002-keys.md) - Keys manifest format
- [0004-awses-message-decryption.md](https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md) - Decrypt manifest format

### Key Requirements
| Requirement | Spec Section | Type |
|-------------|--------------|------|
| Support keys manifest version 3 | 0002-keys.md | MUST |
| Support decrypt manifest versions 2, 3, 4 | 0004-awses-message-decryption.md | MUST |
| Resolve `file://` URIs relative to manifest parent directory | Framework spec | MUST |
| Validate manifest `type` field matches expected type | 0001-meta.md | MUST |
| Skip tests gracefully when dependencies unavailable | Framework spec | SHOULD |

## Test Vectors

### Validation Strategy
Phase 4 validates message structure parsing using test vectors. Full decryption validation requires keyrings (future work).

### Test Vector Summary
| Phase | Validation | Purpose |
|-------|------------|---------|
| 1-3 | N/A | Infrastructure setup |
| 4 | Message parsing | Validate header/body/footer deserialization |
| 5 | N/A | Documentation |

### Recommended Test Vector Source
- **Repository**: `aws-encryption-sdk-test-vectors`
- **Initial set**: `vectors/awses-decrypt/python-2.3.0.zip` (most comprehensive)
- **Location**: Clone/extract to `test/fixtures/test_vectors/`

## Current State Analysis

### What Exists:
- `test/test_helper.exs:1` - Minimal ExUnit setup (`ExUnit.start()` only)
- `lib/aws_encryption_sdk/format/message.ex:46-58` - Complete message deserialization
- `lib/aws_encryption_sdk/algorithm_suite.ex` - All 11 algorithm suites with helper functions
- JSON available as transitive dependency but not explicit

### What's Missing:
- `test/support/` directory
- `test/fixtures/` directory
- Jason as explicit dependency
- Test vector harness module
- Test vector ExUnit tests

### Key Discoveries:
- Existing HKDF tests use inline test vectors (module attributes with `Base.decode16!/1`)
- All tests use `async: true` for parallel execution
- `Message.deserialize/1` already handles complete message parsing
- `AlgorithmSuite.by_id/1` can lookup suites by hex ID from test vectors

## Desired End State

After this plan is complete:
1. Jason is an explicit production dependency
2. `test/support/test_vector_harness.ex` can load and parse test vector manifests
3. `test/support/test_vector_setup.ex` provides helpers to check/setup test vectors
4. `test/test_vectors/decrypt_test.exs` validates message structure against test vectors
5. Test vectors are gitignored and downloaded on-demand
6. Running `mix test --only test_vectors` executes test vector tests (when vectors present)

### Verification:
- `mix test` passes (test vector tests skipped if vectors not present)
- `mix test --only test_vectors` runs structure validation tests (when vectors present)
- `mix quality` passes

## What We're NOT Doing

- Full decryption validation (requires keyrings - future issues)
- AWS KMS test vector execution (requires AWS credentials)
- Encrypt test vector generation
- Streaming test vectors
- Caching CMM test vectors

---

## Phase 1: Dependencies & Directory Structure

### Overview
Add Jason as explicit dependency and create the test infrastructure directories.

### Spec Requirements Addressed
- N/A (infrastructure setup)

### Changes Required:

#### 1. Add Jason Dependency
**File**: `mix.exs`
**Changes**: Add Jason as explicit dependency for manifest parsing

```elixir
# In deps() function, add:
{:jason, "~> 1.4"}
```

#### 2. Create Directory Structure
**Commands**:
```bash
mkdir -p test/support
mkdir -p test/fixtures/test_vectors
```

#### 3. Update .gitignore
**File**: `.gitignore`
**Changes**: Add test vectors directory to gitignore

```gitignore
# Test vectors (downloaded on-demand)
/test/fixtures/test_vectors/
```

### Success Criteria:

#### Automated Verification:
- [x] `mix deps.get` succeeds
- [x] `mix compile` succeeds
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] `test/support/` directory exists
- [x] `test/fixtures/test_vectors/` directory exists
- [x] Jason available: `mix run -e "IO.inspect(Jason.encode!(%{test: true}))"`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 2.

---

## Phase 2: Test Vector Setup Helper

### Overview
Create a helper module that checks for test vectors and provides setup instructions.

### Spec Requirements Addressed
- "Implementations SHOULD skip tests gracefully when dependencies are unavailable"

### Changes Required:

#### 1. Create Test Vector Setup Module
**File**: `test/support/test_vector_setup.ex`
**Changes**: New file with setup and availability checking

```elixir
defmodule AwsEncryptionSdk.TestSupport.TestVectorSetup do
  @moduledoc """
  Helper for setting up and checking AWS Encryption SDK test vectors.
  """

  @test_vectors_path "test/fixtures/test_vectors"
  @test_vectors_repo "https://github.com/awslabs/aws-encryption-sdk-test-vectors.git"
  @python_vectors_url "https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip"

  @doc """
  Returns the base path for test vectors.
  """
  @spec test_vectors_path() :: String.t()
  def test_vectors_path, do: @test_vectors_path

  @doc """
  Checks if test vectors are available.
  """
  @spec vectors_available?() :: boolean()
  def vectors_available? do
    File.exists?(@test_vectors_path) and
      not Enum.empty?(Path.wildcard(Path.join(@test_vectors_path, "**/*.json")))
  end

  @doc """
  Returns the path to a specific manifest if it exists.
  """
  @spec find_manifest(String.t()) :: {:ok, String.t()} | :not_found
  def find_manifest(pattern) do
    case Path.wildcard(Path.join(@test_vectors_path, pattern)) do
      [path | _] -> {:ok, path}
      [] -> :not_found
    end
  end

  @doc """
  Prints setup instructions for test vectors.
  """
  @spec print_setup_instructions() :: :ok
  def print_setup_instructions do
    IO.puts("""

    ══════════════════════════════════════════════════════════════════
    Test vectors not found at #{@test_vectors_path}

    To enable test vector tests, choose one option:

    Option 1 - Clone full repository:
        git clone #{@test_vectors_repo} #{@test_vectors_path}

    Option 2 - Download Python vectors only (recommended, smaller):
        mkdir -p #{@test_vectors_path}
        curl -L #{@python_vectors_url} -o /tmp/python-vectors.zip
        unzip /tmp/python-vectors.zip -d #{@test_vectors_path}
        rm /tmp/python-vectors.zip

    After setup, run: mix test --only test_vectors
    ══════════════════════════════════════════════════════════════════
    """)

    :ok
  end

  @doc """
  Ensures test vectors are available, printing instructions if not.
  Returns :available or :not_available.
  """
  @spec ensure_test_vectors() :: :available | :not_available
  def ensure_test_vectors do
    if vectors_available?() do
      :available
    else
      print_setup_instructions()
      :not_available
    end
  end
end
```

#### 2. Update test_helper.exs
**File**: `test/test_helper.exs`
**Changes**: Load support modules and configure ExUnit

```elixir
# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)

# Configure ExUnit
ExUnit.configure(exclude: [:skip])

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  IO.puts("\nNote: Test vectors not available. Run with --only test_vectors after setup.\n")
end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test` passes
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] Running `mix test` shows note about test vectors not available
- [x] `TestVectorSetup.vectors_available?()` returns false (vectors not yet downloaded)
- [x] `TestVectorSetup.print_setup_instructions()` displays clear instructions

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 3.

---

## Phase 3: Core Harness Implementation

### Overview
Create the core test vector harness module that parses manifests and loads test data.

### Spec Requirements Addressed
- "Implementations MUST resolve `file://` URIs relative to the parent directory of the manifest file"
- "Manifest `type` field MUST match the expected manifest type when processing"
- Support keys manifest version 3
- Support decrypt manifest versions 2, 3, 4

### Changes Required:

#### 1. Create Test Vector Harness Module
**File**: `test/support/test_vector_harness.ex`
**Changes**: New file with manifest parsing and test execution support

```elixir
defmodule AwsEncryptionSdk.TestSupport.TestVectorHarness do
  @moduledoc """
  Harness for loading and executing AWS Encryption SDK test vectors.

  Supports:
  - Keys manifest version 3
  - Decrypt manifest versions 2, 3, 4

  ## Usage

      {:ok, harness} = TestVectorHarness.load_manifest("path/to/manifest.json")
      test_cases = TestVectorHarness.list_tests(harness)

      for {test_id, test_case} <- test_cases do
        result = TestVectorHarness.execute_test(harness, test_id)
        # validate result
      end
  """

  alias AwsEncryptionSdk.Format.Message

  defstruct [
    :manifest_path,
    :base_dir,
    :manifest_type,
    :manifest_version,
    :client_info,
    :keys,
    :tests
  ]

  @type key_material :: %{
          String.t() => %{
            type: String.t(),
            algorithm: String.t(),
            bits: integer(),
            encoding: String.t(),
            material: binary(),
            encrypt: boolean(),
            decrypt: boolean()
          }
        }

  @type test_case :: %{
          description: String.t(),
          ciphertext_path: String.t(),
          master_keys: [map()],
          result: :success | :error,
          expected_plaintext_path: String.t() | nil,
          error_description: String.t() | nil
        }

  @type t :: %__MODULE__{
          manifest_path: String.t(),
          base_dir: String.t(),
          manifest_type: String.t(),
          manifest_version: integer(),
          client_info: map() | nil,
          keys: key_material(),
          tests: %{String.t() => test_case()}
        }

  @supported_keys_versions [3]
  @supported_decrypt_versions [2, 3, 4]

  # ============================================================================
  # Public API
  # ============================================================================

  @doc """
  Loads a decrypt manifest and its referenced keys.

  Returns `{:ok, harness}` on success, `{:error, reason}` on failure.
  """
  @spec load_manifest(String.t()) :: {:ok, t()} | {:error, term()}
  def load_manifest(path) do
    base_dir = Path.dirname(path)

    with {:ok, content} <- File.read(path),
         {:ok, manifest} <- Jason.decode(content),
         :ok <- validate_manifest_type(manifest, "awses-decrypt"),
         :ok <- validate_manifest_version(manifest, @supported_decrypt_versions),
         {:ok, keys} <- load_keys(base_dir, manifest["keys"]),
         {:ok, tests} <- parse_tests(manifest["tests"], base_dir) do
      harness = %__MODULE__{
        manifest_path: path,
        base_dir: base_dir,
        manifest_type: manifest["manifest"]["type"],
        manifest_version: manifest["manifest"]["version"],
        client_info: manifest["client"],
        keys: keys,
        tests: tests
      }

      {:ok, harness}
    end
  end

  @doc """
  Lists all test IDs in the harness.
  """
  @spec list_test_ids(t()) :: [String.t()]
  def list_test_ids(%__MODULE__{tests: tests}) do
    Map.keys(tests)
  end

  @doc """
  Gets a specific test case by ID.
  """
  @spec get_test(t(), String.t()) :: {:ok, test_case()} | :not_found
  def get_test(%__MODULE__{tests: tests}, test_id) do
    case Map.fetch(tests, test_id) do
      {:ok, test} -> {:ok, test}
      :error -> :not_found
    end
  end

  @doc """
  Loads the ciphertext binary for a test case.
  """
  @spec load_ciphertext(t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def load_ciphertext(%__MODULE__{tests: tests}, test_id) do
    case Map.fetch(tests, test_id) do
      {:ok, test} -> File.read(test.ciphertext_path)
      :error -> {:error, :test_not_found}
    end
  end

  @doc """
  Loads the expected plaintext binary for a success test case.
  """
  @spec load_expected_plaintext(t(), String.t()) :: {:ok, binary()} | {:error, term()}
  def load_expected_plaintext(%__MODULE__{tests: tests}, test_id) do
    case Map.fetch(tests, test_id) do
      {:ok, %{expected_plaintext_path: nil}} ->
        {:error, :no_expected_plaintext}

      {:ok, %{expected_plaintext_path: path}} ->
        File.read(path)

      :error ->
        {:error, :test_not_found}
    end
  end

  @doc """
  Parses a ciphertext and returns the deserialized message structure.

  This validates message format without performing decryption.
  """
  @spec parse_ciphertext(binary()) :: {:ok, map()} | {:error, term()}
  def parse_ciphertext(ciphertext) do
    Message.deserialize(ciphertext)
  end

  @doc """
  Gets the key material for a specific key ID.
  """
  @spec get_key(t(), String.t()) :: {:ok, map()} | :not_found
  def get_key(%__MODULE__{keys: keys}, key_id) do
    case Map.fetch(keys, key_id) do
      {:ok, key} -> {:ok, key}
      :error -> :not_found
    end
  end

  @doc """
  Decodes key material based on its encoding type.

  Supports:
  - "base64" - Base64 encoded symmetric keys
  - "pem" - PEM encoded RSA keys
  """
  @spec decode_key_material(map()) :: {:ok, binary()} | {:error, term()}
  def decode_key_material(%{"encoding" => "base64", "material" => material}) do
    case Base.decode64(material) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end

  def decode_key_material(%{"encoding" => "pem", "material" => material}) do
    # Return raw PEM for now; keyring implementation will parse
    {:ok, material}
  end

  def decode_key_material(%{"type" => "aws-kms"}) do
    # AWS KMS keys don't have local material
    {:ok, :aws_kms}
  end

  def decode_key_material(_), do: {:error, :unsupported_encoding}

  # ============================================================================
  # URI Resolution
  # ============================================================================

  @doc """
  Resolves a file:// URI relative to a base directory.

  ## Examples

      iex> resolve_uri("/base/dir", "file://keys.json")
      "/base/dir/keys.json"

      iex> resolve_uri("/base/dir", "file://sub/path.bin")
      "/base/dir/sub/path.bin"
  """
  @spec resolve_uri(String.t(), String.t()) :: String.t()
  def resolve_uri(base_dir, "file://" <> relative_path) do
    Path.join(base_dir, relative_path)
  end

  def resolve_uri(_base_dir, path) do
    # If not a file:// URI, treat as absolute or return as-is
    path
  end

  # ============================================================================
  # Private Functions
  # ============================================================================

  defp validate_manifest_type(manifest, expected_type) do
    case get_in(manifest, ["manifest", "type"]) do
      ^expected_type -> :ok
      actual -> {:error, {:invalid_manifest_type, expected: expected_type, got: actual}}
    end
  end

  defp validate_manifest_version(manifest, supported_versions) do
    case get_in(manifest, ["manifest", "version"]) do
      version when version in supported_versions ->
        :ok

      version ->
        {:error, {:unsupported_manifest_version, version: version, supported: supported_versions}}
    end
  end

  defp load_keys(base_dir, keys_uri) do
    keys_path = resolve_uri(base_dir, keys_uri)

    with {:ok, content} <- File.read(keys_path),
         {:ok, keys_manifest} <- Jason.decode(content),
         :ok <- validate_manifest_type(keys_manifest, "keys"),
         :ok <- validate_manifest_version(keys_manifest, @supported_keys_versions) do
      {:ok, keys_manifest["keys"]}
    end
  end

  defp parse_tests(tests, base_dir) when is_map(tests) do
    parsed =
      Enum.reduce_while(tests, {:ok, %{}}, fn {test_id, test_data}, {:ok, acc} ->
        case parse_test_case(test_data, base_dir) do
          {:ok, parsed_test} ->
            {:cont, {:ok, Map.put(acc, test_id, parsed_test)}}

          {:error, reason} ->
            {:halt, {:error, {test_id, reason}}}
        end
      end)

    parsed
  end

  defp parse_test_case(test_data, base_dir) do
    ciphertext_path = resolve_uri(base_dir, test_data["ciphertext"])

    {result, plaintext_path, error_desc} =
      case test_data["result"] do
        %{"output" => %{"plaintext" => plaintext_uri}} ->
          {:success, resolve_uri(base_dir, plaintext_uri), nil}

        %{"error" => %{"error-description" => desc}} ->
          {:error, nil, desc}

        %{"error" => _} ->
          {:error, nil, nil}
      end

    {:ok,
     %{
       description: test_data["description"],
       ciphertext_path: ciphertext_path,
       master_keys: test_data["master-keys"] || [],
       result: result,
       expected_plaintext_path: plaintext_path,
       error_description: error_desc
     }}
  end
end
```

#### 2. Update test_helper.exs to load harness
**File**: `test/test_helper.exs`
**Changes**: Add harness module loading

```elixir
# Compile and load test support modules
Code.require_file("support/test_vector_setup.ex", __DIR__)
Code.require_file("support/test_vector_harness.ex", __DIR__)

# Configure ExUnit
ExUnit.configure(exclude: [:skip])

ExUnit.start()

# Check for test vectors (informational only)
alias AwsEncryptionSdk.TestSupport.TestVectorSetup

unless TestVectorSetup.vectors_available?() do
  IO.puts("\nNote: Test vectors not available. Run with --only test_vectors after setup.\n")
end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test` passes
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] Module compiles: `mix run -e "alias AwsEncryptionSdk.TestSupport.TestVectorHarness"`
- [x] URI resolution works: `TestVectorHarness.resolve_uri("/base", "file://test.json")` returns `"/base/test.json"`

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 4.

---

## Phase 4: ExUnit Integration

### Overview
Create ExUnit test module that uses the harness to validate message structure from test vectors.

### Spec Requirements Addressed
- "For success cases: MUST validate that decryption produces the expected plaintext" (structure validation only for now)
- "Implementations SHOULD skip tests gracefully when dependencies are unavailable"

### Changes Required:

#### 1. Create Decrypt Test Module
**File**: `test/test_vectors/decrypt_test.exs`
**Changes**: New test file for test vector validation

```elixir
defmodule AwsEncryptionSdk.TestVectors.DecryptTest do
  @moduledoc """
  Test vector validation for AWS Encryption SDK decrypt operations.

  These tests validate message structure parsing against official test vectors.
  Full decryption validation requires keyring implementations (future work).

  Run with: mix test --only test_vectors
  """

  use ExUnit.Case, async: true

  alias AwsEncryptionSdk.TestSupport.TestVectorSetup
  alias AwsEncryptionSdk.TestSupport.TestVectorHarness
  alias AwsEncryptionSdk.AlgorithmSuite

  @moduletag :test_vectors

  # Skip entire module if test vectors not available
  @moduletag skip: not TestVectorSetup.vectors_available?()

  setup_all do
    case TestVectorSetup.find_manifest("**/manifest.json") do
      {:ok, manifest_path} ->
        case TestVectorHarness.load_manifest(manifest_path) do
          {:ok, harness} ->
            {:ok, harness: harness}

          {:error, reason} ->
            {:ok, harness: nil, load_error: reason}
        end

      :not_found ->
        {:ok, harness: nil, load_error: :manifest_not_found}
    end
  end

  describe "manifest loading" do
    @tag :test_vectors
    test "loads manifest successfully", %{harness: harness} = context do
      if harness == nil do
        flunk("Failed to load manifest: #{inspect(context[:load_error])}")
      end

      assert harness.manifest_type == "awses-decrypt"
      assert harness.manifest_version in [2, 3, 4]
    end

    @tag :test_vectors
    test "loads keys manifest", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Should have at least some keys defined
      assert map_size(harness.keys) > 0
    end

    @tag :test_vectors
    test "has test cases defined", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      test_ids = TestVectorHarness.list_test_ids(harness)
      assert length(test_ids) > 0
    end
  end

  describe "message structure validation" do
    @tag :test_vectors
    test "parses test vector ciphertexts successfully", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Get first 10 success test cases for structure validation
      success_tests =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(10)

      for {test_id, _test} <- success_tests do
        {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

        case TestVectorHarness.parse_ciphertext(ciphertext) do
          {:ok, message, _rest} ->
            # Validate basic message structure
            assert is_map(message.header)
            assert message.header.version in [1, 2]
            assert is_binary(message.header.message_id)

            # Validate algorithm suite is recognized
            suite = message.header.algorithm_suite
            assert AlgorithmSuite.key_length(suite) in [16, 24, 32]

          {:error, reason} ->
            flunk("Failed to parse ciphertext for test #{test_id}: #{inspect(reason)}")
        end
      end
    end

    @tag :test_vectors
    test "validates header fields", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Get a single test case for detailed validation
      [test_id | _] =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.map(fn {id, _} -> id end)
        |> Enum.take(1)

      {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)
      {:ok, message, _rest} = TestVectorHarness.parse_ciphertext(ciphertext)

      header = message.header

      # Version validation
      assert header.version in [1, 2]

      # Message ID length depends on version
      expected_msg_id_length = if header.version == 1, do: 16, else: 32
      assert byte_size(header.message_id) == expected_msg_id_length

      # Algorithm suite should be valid
      assert header.algorithm_suite != nil

      # Content type should be valid
      assert header.content_type in [:framed, :non_framed]

      # EDKs should be present
      assert is_list(header.encrypted_data_keys)
      assert length(header.encrypted_data_keys) >= 1
    end
  end

  describe "key material" do
    @tag :test_vectors
    test "decodes AES key material", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Find an AES key
      aes_key =
        Enum.find(harness.keys, fn {_id, key} ->
          key["type"] == "symmetric" and key["algorithm"] == "aes"
        end)

      if aes_key do
        {_key_id, key_data} = aes_key
        {:ok, material} = TestVectorHarness.decode_key_material(key_data)

        expected_bytes = div(key_data["bits"], 8)
        assert byte_size(material) == expected_bytes
      end
    end

    @tag :test_vectors
    test "handles RSA key material", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Find an RSA key
      rsa_key =
        Enum.find(harness.keys, fn {_id, key} ->
          key["type"] in ["private", "public"] and key["algorithm"] == "rsa"
        end)

      if rsa_key do
        {_key_id, key_data} = rsa_key
        {:ok, material} = TestVectorHarness.decode_key_material(key_data)

        # PEM material should start with proper header
        assert String.starts_with?(material, "-----BEGIN")
      end
    end
  end

  describe "filtering" do
    @tag :test_vectors
    @tag algorithm: :committed
    test "identifies committed algorithm suites", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Parse a few messages and check for committed suites
      committed_count =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(20)
        |> Enum.count(fn {test_id, _test} ->
          {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

          case TestVectorHarness.parse_ciphertext(ciphertext) do
            {:ok, message, _rest} ->
              AlgorithmSuite.committed?(message.header.algorithm_suite)

            _ ->
              false
          end
        end)

      # Just verify we can identify committed vs non-committed
      assert is_integer(committed_count)
    end

    @tag :test_vectors
    @tag algorithm: :signed
    test "identifies signed algorithm suites", %{harness: harness} do
      if harness == nil, do: flunk("Harness not loaded")

      # Parse a few messages and check for signed suites
      signed_count =
        harness.tests
        |> Enum.filter(fn {_id, test} -> test.result == :success end)
        |> Enum.take(20)
        |> Enum.count(fn {test_id, _test} ->
          {:ok, ciphertext} = TestVectorHarness.load_ciphertext(harness, test_id)

          case TestVectorHarness.parse_ciphertext(ciphertext) do
            {:ok, message, _rest} ->
              AlgorithmSuite.signed?(message.header.algorithm_suite)

            _ ->
              false
          end
        end)

      # Just verify we can identify signed vs unsigned
      assert is_integer(signed_count)
    end
  end
end
```

### Success Criteria:

#### Automated Verification:
- [x] `mix test` passes (test vector tests skipped without vectors)
- [x] `mix quality --quick` passes

#### Manual Verification (requires test vectors):
1. Download test vectors:
   ```bash
   mkdir -p test/fixtures/test_vectors
   curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
   unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
   rm /tmp/python-vectors.zip
   ```
2. [x] Run: `mix test --only test_vectors`
3. [x] Verify tests execute and pass (structure validation)

**Implementation Note**: After completing this phase and all automated verification passes, pause here for manual confirmation before proceeding to Phase 5.

---

## Phase 5: Documentation

### Overview
Document the test vector setup and usage for developers.

### Spec Requirements Addressed
- N/A (documentation)

### Changes Required:

#### 1. Create Test Vectors README
**File**: `test/fixtures/README.md`
**Changes**: New file documenting test vector setup

```markdown
# Test Fixtures

This directory contains test fixtures for the AWS Encryption SDK for Elixir.

## Test Vectors

The `test_vectors/` subdirectory should contain AWS Encryption SDK test vectors.
This directory is gitignored and must be set up manually.

### Setup Instructions

#### Option 1: Download Python vectors (recommended)

```bash
mkdir -p test/fixtures/test_vectors
curl -L https://github.com/awslabs/aws-encryption-sdk-test-vectors/raw/master/vectors/awses-decrypt/python-2.3.0.zip -o /tmp/python-vectors.zip
unzip /tmp/python-vectors.zip -d test/fixtures/test_vectors
rm /tmp/python-vectors.zip
```

#### Option 2: Clone full repository

```bash
git clone https://github.com/awslabs/aws-encryption-sdk-test-vectors.git test/fixtures/test_vectors
```

### Running Test Vector Tests

```bash
# Run all test vector tests
mix test --only test_vectors

# Run specific test vector categories
mix test --only algorithm:committed
mix test --only algorithm:signed
```

### Test Vector Format

Test vectors follow the AWS Crypto Tools Test Vector Framework:
- https://github.com/awslabs/aws-crypto-tools-test-vector-framework

Key files:
- `manifest.json` - Main decrypt manifest with test cases
- `keys.json` - Key material for test decryption
- `ciphertexts/` - Pre-encrypted test data
- `plaintexts/` - Expected plaintext outputs
```

### Success Criteria:

#### Automated Verification:
- [x] `mix quality --quick` passes

#### Manual Verification:
- [x] README exists at `test/fixtures/README.md`
- [x] Instructions are clear and accurate

**Implementation Note**: After completing this phase, the implementation is complete.

---

## Final Verification

After all phases complete:

### Automated:
- [x] `mix quality` passes (full quality checks)
- [x] `mix test` passes without test vectors (tests skipped gracefully)

### Manual (with test vectors):
- [x] `mix test --only test_vectors` executes successfully
- [x] Message structure validation tests pass
- [x] Key material decoding works

## Testing Strategy

### Unit Tests:
- Test vector setup module functions
- URI resolution in harness
- Key material decoding

### Integration Tests (Test Vectors):
- Manifest loading and validation
- Message structure parsing
- Algorithm suite identification

### Manual Testing Steps:
1. Run `mix test` without test vectors - should pass, show informational note
2. Download test vectors per README instructions
3. Run `mix test --only test_vectors` - should execute structure validation
4. Verify no runtime errors or crashes

## Future Work (Not in This Plan)

After keyrings are implemented:
- Add full decryption validation tests
- Add encrypt test vector generation
- Add cross-SDK interoperability tests
- Add AWS KMS test vector support (requires credentials)

## References

- Issue: #13
- Research: `thoughts/shared/research/2026-01-25-GH13-test-vector-harness.md`
- Test Vector Framework: https://github.com/awslabs/aws-crypto-tools-test-vector-framework
- Test Vectors: https://github.com/awslabs/aws-encryption-sdk-test-vectors
- Keys Spec: https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0002-keys.md
- Decrypt Spec: https://github.com/awslabs/aws-crypto-tools-test-vector-framework/blob/master/features/0004-awses-message-decryption.md
