defmodule PkiPlatformEngine.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_platform_engine,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      test_coverage: [threshold: 70, summary: [threshold: 70]]
    ]
  end

  def application do
    [
      mod: {PkiPlatformEngine.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, "~> 0.18"},
      {:jason, "~> 1.4"},
      {:uniq, "~> 0.6"},
      {:plug, "~> 1.14"},
      {:argon2_elixir, "~> 4.0"},
      {:req, "~> 0.5"},
      {:strap_softhsm_priv_key_store_provider, path: "../strap_softhsm_priv_key_store_provider"},
      {:pki_audit_trail, path: "../pki_audit_trail"}
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "ecto.setup"],
      "ecto.setup": ["ecto.create", "ecto.migrate"],
      "ecto.reset": ["ecto.drop", "ecto.setup"],
      test: ["ecto.create --quiet", "ecto.migrate --quiet", "test"]
    ]
  end
end
