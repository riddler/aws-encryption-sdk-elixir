defmodule AwsEncryptionSdk.MixProject do
  use Mix.Project

  @version "0.6.0"
  @source_url "https://github.com/riddler/aws-encryption-sdk-elixir"

  def project do
    [
      app: :aws_encryption_sdk,
      version: @version,
      elixir: "~> 1.16",
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
      extra_applications: [:logger, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},

      # AWS KMS client
      {:ex_aws, "~> 2.5"},
      {:ex_aws_kms, "~> 2.0"},
      {:hackney, "~> 1.20"},
      {:sweet_xml, "~> 0.7"},
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
        "guides/STABILITY.md": [title: "API Stability Policy"],
        LICENSE: [title: "License"]
      ],
      groups_for_modules: [
        "Core API": [
          AwsEncryptionSdk,
          AwsEncryptionSdk.Client,
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
          AwsEncryptionSdk.Format.BodyAad,
          AwsEncryptionSdk.Format.EncryptionContext,
          AwsEncryptionSdk.Format.Footer
        ],
        Cryptography: [
          AwsEncryptionSdk.Crypto.AesGcm,
          AwsEncryptionSdk.Crypto.HKDF,
          AwsEncryptionSdk.Crypto.ECDSA,
          AwsEncryptionSdk.Crypto.HeaderAuth,
          AwsEncryptionSdk.Crypto.Commitment
        ],
        "Keyring Interface": [
          AwsEncryptionSdk.Keyring.Behaviour
        ],
        "Raw Keyrings": [
          AwsEncryptionSdk.Keyring.RawAes,
          AwsEncryptionSdk.Keyring.RawRsa,
          AwsEncryptionSdk.Keyring.Multi
        ],
        "KMS Keyrings": [
          AwsEncryptionSdk.Keyring.AwsKms,
          AwsEncryptionSdk.Keyring.AwsKmsDiscovery,
          AwsEncryptionSdk.Keyring.AwsKmsMrk,
          AwsEncryptionSdk.Keyring.AwsKmsMrkDiscovery
        ],
        "KMS Client Interface": [
          AwsEncryptionSdk.Keyring.KmsClient,
          AwsEncryptionSdk.Keyring.KmsClient.ExAws,
          AwsEncryptionSdk.Keyring.KmsClient.Mock,
          AwsEncryptionSdk.Keyring.KmsKeyArn
        ],
        "Cryptographic Materials Managers": [
          AwsEncryptionSdk.Cmm.Behaviour,
          AwsEncryptionSdk.Cmm.Default,
          AwsEncryptionSdk.Cmm.Caching,
          AwsEncryptionSdk.Cmm.RequiredEncryptionContext
        ],
        Caching: [
          AwsEncryptionSdk.Cache.CryptographicMaterialsCache,
          AwsEncryptionSdk.Cache.LocalCache,
          AwsEncryptionSdk.Cache.CacheEntry
        ],
        Streaming: [
          AwsEncryptionSdk.Stream,
          AwsEncryptionSdk.Stream.Encryptor,
          AwsEncryptionSdk.Stream.Decryptor,
          AwsEncryptionSdk.Stream.SignatureAccumulator
        ]
      ],
      formatters: ["html"]
    ]
  end
end
