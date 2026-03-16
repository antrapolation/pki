defmodule PkiAuditTrail.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_audit_trail,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto, :mnesia],
      mod: {PkiAuditTrail.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ecto_sql, "~> 3.11"},
      {:postgrex, "~> 0.18"},
      {:jason, "~> 1.4"},
      {:typed_struct, "~> 0.3"}
    ]
  end
end
