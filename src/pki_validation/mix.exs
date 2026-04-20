defmodule PkiValidation.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_validation,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      erlc_paths: ["src"],
      compilers: [:asn1] ++ Mix.compilers(),
      deps: deps(),
      test_coverage: [threshold: 70, summary: [threshold: 70]]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :mnesia],
      mod: {PkiValidation.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:pki_mnesia, path: "../pki_mnesia"},
      {:pki_crypto, path: "../pki_crypto"},
      {:pki_ca_engine, path: "../pki_ca_engine"},
      {:plug, "~> 1.16"},
      {:plug_cowboy, "~> 2.7"},
      {:jason, "~> 1.4"}
    ]
  end
end
