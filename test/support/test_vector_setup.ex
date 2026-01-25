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
      [path | _rest] -> {:ok, path}
      [] -> :not_found
    end
  end

  @doc """
  Prints setup instructions for test vectors.
  """
  @spec print_setup_instructions() :: :ok
  def print_setup_instructions do
    # credo:disable-for-next-line Credo.Check.Refactor.IoPuts
    IO.puts("""

    ══════════════════════════════════════════════════════════════════
    Test vectors not found at #{@test_vectors_path}

    To enable test vector tests, choose one option:

    Option 1 - Clone full repository (requires extraction):
        git clone #{@test_vectors_repo} #{@test_vectors_path}
        cd #{@test_vectors_path}/vectors/awses-decrypt
        unzip python-2.3.0.zip

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
