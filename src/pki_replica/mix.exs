defmodule PkiReplica.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_replica,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {PkiReplica.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:pki_mnesia, path: "../pki_mnesia"},
      {:pki_tenant, path: "../pki_tenant"},
      {:pki_tenant_web, path: "../pki_tenant_web"},
      {:libcluster, "~> 3.3"},
      {:req, "~> 0.5"},
      {:jason, "~> 1.4"}
    ]
  end
end
