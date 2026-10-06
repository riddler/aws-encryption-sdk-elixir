defmodule Hackney1Host.MixProject do
  @moduledoc false
  use Mix.Project

  # A minimal host already on hackney 1.x (through httpoison) that adds
  # the SDK with its KMS client stack. CI resolves and compiles it with no
  # committed lock, the way a real host would, to prove the SDK's
  # dependency ranges admit that tree. It is not part of the SDK build.
  @spec project() :: keyword()
  def project do
    [
      app: :hackney1_host,
      version: "0.1.0",
      elixir: "~> 1.16",
      deps: deps()
    ]
  end

  @spec application() :: keyword()
  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:aws_encryption_sdk, path: "../../.."},
      {:httpoison, "~> 2.2"},
      {:hackney, "~> 1.21"},
      {:ex_aws, "~> 2.6.0"},
      {:ex_aws_kms, "~> 2.6"},
      {:sweet_xml, "~> 0.7"}
    ]
  end
end
