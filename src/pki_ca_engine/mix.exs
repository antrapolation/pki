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
      {:keyx, path: "../keyx", override: true},
      {:x509, path: "../x509", override: true},
      {:ex_ccrypto, path: "../ex_ccrypto", override: true},
      {:ap_java_crypto, path: "../ap_java_crypto"},
      {:pki_crypto, path: "../pki_crypto"},
      {:pki_audit_trail, path: "../pki_audit_trail"},
      {:req, "~> 0.5"},
      {:uniq, "~> 0.6"},
      {:hammer, "~> 6.2"},
      {:pki_platform_engine, path: "../pki_platform_engine"},
      {:kaz_sign, path: "../../../PQC-KAZ/SIGN/bindings/elixir"}
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
