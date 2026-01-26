defmodule AwsEncryptionSdk.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/riddler/aws-encryption-sdk-elixir"

  def project do
    [
      app: :aws_encryption_sdk,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.post": :test,
        "coveralls.html": :test
      ],

      # Hex package metadata
      name: "AWS Encryption SDK",
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:excoveralls, "~> 0.18.5", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.22.0", only: :dev},
      {:mix_audit, "~> 2.1", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.35", only: :dev, runtime: false},
      {:ex_quality, "~> 0.2.0", only: [:dev, :test]}
    ]
  end

  defp description do
    """
    AWS Encryption SDK for Elixir - client-side encryption compatible with all
    official AWS Encryption SDK implementations (Python, Java, JavaScript, C, CLI).
    """
  end

  defp package do
    [
      name: "aws_encryption_sdk",
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md",
        "AWS Encryption SDK Specification" =>
          "https://github.com/awslabs/aws-encryption-sdk-specification"
      },
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE CHANGELOG.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      name: "AWS Encryption SDK",
      source_ref: "v#{@version}",
      source_url: @source_url,
      canonical: "https://hexdocs.pm/aws_encryption_sdk",
      extras: [
        "README.md": [title: "Overview"],
        "CHANGELOG.md": [title: "Changelog"],
        "CONTRIBUTING.md": [title: "Contributing"],
        LICENSE: [title: "License"]
      ],
      groups_for_modules: [
        "Core API": [
          AwsEncryptionSdk,
          AwsEncryptionSdk.Encrypt,
          AwsEncryptionSdk.Decrypt,
          AwsEncryptionSdk.AlgorithmSuite
        ],
        Materials: [
          AwsEncryptionSdk.Materials.EncryptionMaterials,
          AwsEncryptionSdk.Materials.DecryptionMaterials,
          AwsEncryptionSdk.Materials.EncryptedDataKey
        ],
        "Message Format": [
          AwsEncryptionSdk.Format.Message,
          AwsEncryptionSdk.Format.Header,
          AwsEncryptionSdk.Format.Body,
          AwsEncryptionSdk.Format.Footer
        ],
        Cryptography: [
          AwsEncryptionSdk.Crypto.AesGcm,
          AwsEncryptionSdk.Crypto.Hkdf,
          AwsEncryptionSdk.Crypto.Commitment
        ]
      ],
      formatters: ["html"]
    ]
  end
end
