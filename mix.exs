defmodule PKCS12.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/openspb/pkcs12"

  def project do
    [
      app: :pkcs12,
      version: @version,
      elixir: "~> 1.16",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      description: description(),
      package: package(),
      docs: docs(),
      source_url: @source_url,
      dialyzer: [
        plt_core_path: "_build/plts",
        plt_local_path: "_build/plts",
        flags: [:error_handling, :extra_return, :missing_return, :underspecs]
      ]
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  def application do
    [extra_applications: [:crypto, :public_key] ++ test_applications(Mix.env())]
  end

  # The integration tests run a TLS handshake with the decoded material.
  defp test_applications(:test), do: [:ssl]
  defp test_applications(_), do: []

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:stream_data, "~> 1.1", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors --force",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp description do
    "PKCS#12 (.pfx, .p12) reader and writer in pure Elixir: private key and certificate chain, " <>
      "legacy and modern algorithms, with no NIF and no openssl binary."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url},
      files: ~w(lib mix.exs README.md LICENSE NOTICE CHANGELOG.md SECURITY.md)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "SECURITY.md", "CHANGELOG.md"]
    ]
  end
end
