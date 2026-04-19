defmodule PkiTenantWeb.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_tenant_web,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {PkiTenantWeb.Application, []},
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.8.5"},
      {:phoenix_live_view, "~> 1.1.0"},
      {:phoenix_html, "~> 4.1"},
      {:jason, "~> 1.4"},
      {:bandit, "~> 1.5"},
      {:gettext, "~> 0.26"},
      {:argon2_elixir, "~> 4.0"},
      {:bcrypt_elixir, "~> 3.0"},
      {:pki_tenant, path: "../pki_tenant"},
      {:pki_mnesia, path: "../pki_mnesia"},
      {:pki_ca_engine, path: "../pki_ca_engine"},
      {:pki_ra_engine, path: "../pki_ra_engine"},
      {:esbuild, "~> 0.8", runtime: Mix.env() == :dev},
      {:tailwind, "~> 0.3", runtime: Mix.env() == :dev},
      {:phoenix_live_reload, "~> 1.2", only: :dev}
    ]
  end
end
