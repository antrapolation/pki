defmodule PkiRaEngine.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_ra_engine,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      deps: deps(),
      test_coverage: [threshold: 70, summary: [threshold: 70]]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {PkiRaEngine.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp aliases do
    [
      setup: ["deps.get"],
      test: ["test"]
    ]
  end

  defp deps do
    [
      {:pki_mnesia, path: "../pki_mnesia"},
      {:pki_crypto, path: "../pki_crypto"},
      {:pki_ca_engine, path: "../pki_ca_engine"},
      {:jason, "~> 1.4"},
      {:plug, "~> 1.16"},
      {:plug_cowboy, "~> 2.7"},
      {:req, "~> 0.5"},
      {:uniq, "~> 0.6"},
      {:hammer, "~> 6.2"},
      {:hammer_backend_mnesia, "~> 0.6"},
      {:keyx, path: "../keyx", override: true},
      {:x509, path: "../x509", override: true},
      {:ex_ccrypto, path: "../ex_ccrypto"},
      {:pki_platform_engine, path: "../pki_platform_engine"},
      {:pki_validation, path: "../pki_validation", only: :test}
    ]
  end
end
