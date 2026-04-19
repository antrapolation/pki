defmodule PkiTenant.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_tenant,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      mod: {PkiTenant.Application, []},
      extra_applications: [:logger, :mnesia]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:pki_mnesia, path: "../pki_mnesia"},
      {:pki_ca_engine, path: "../pki_ca_engine"},
      {:pki_ra_engine, path: "../pki_ra_engine"},
      {:pki_validation, path: "../pki_validation"},
      # timex needed transitively: pki_validation CrlPublisher uses DateTime with TZ
      {:timex, "~> 3.7"},
      # HTTP client for S3 backup uploads
      {:req, "~> 0.5"},
      # Password hashing — Argon2 for new records, Bcrypt to verify legacy hashes
      {:argon2_elixir, "~> 4.0"},
      {:bcrypt_elixir, "~> 3.0"}
    ]
  end
end
