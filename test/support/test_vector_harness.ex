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

  def decode_key_material(_key_data), do: {:error, :unsupported_encoding}

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
    version = get_in(manifest, ["manifest", "version"])

    if version in supported_versions do
      :ok
    else
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
      Enum.reduce(tests, %{}, fn {test_id, test_data}, acc ->
        {:ok, parsed_test} = parse_test_case(test_data, base_dir)
        Map.put(acc, test_id, parsed_test)
      end)

    {:ok, parsed}
  end

  defp parse_test_case(test_data, base_dir) do
    ciphertext_path = resolve_uri(base_dir, test_data["ciphertext"])

    {result, plaintext_path, error_desc} =
      case test_data["result"] do
        %{"output" => %{"plaintext" => plaintext_uri}} ->
          {:success, resolve_uri(base_dir, plaintext_uri), nil}

        %{"error" => %{"error-description" => desc}} ->
          {:error, nil, desc}

        %{"error" => _error_data} ->
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
