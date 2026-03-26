defmodule PkiCaEngine.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_ca_engine,
      version: "0.1.0",
      elixir: "~> 1.15",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {PkiCaEngine.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, "~> 0.18"},
      {:jason, "~> 1.4"},
      {:plug, "~> 1.16"},
      {:plug_cowboy, "~> 2.7"},
      {:keyx, path: "../keyx"},
      {:x509, path: "../x509"},
      {:ex_ccrypto, path: "../ex_ccrypto"},
      {:pki_audit_trail, path: "../pki_audit_trail", runtime: false},
      {:req, "~> 0.5"},
      {:uniq, "~> 0.6"}
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
