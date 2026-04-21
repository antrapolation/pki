defmodule ExCcrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_ccrypto,
      version: "0.2.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ExCcrypto.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:x509, path: "../x509"},
      {:argon2_elixir, "~> 4.0"},
      # shamir secret sharing over GF(2^8)
      {:keyx, path: "../keyx"},
      {:timex, "~> 3.0"},
      {:tzdata, "~> 1.1"},
      {:net_address, "~> 0.3.1"},
      {:asn1ex, git: "https://github.com/vicentfg/asn1ex.git"},
      {:typedstruct, "~> 0.5"},
      {:bcrypt_elixir, "~> 3.3"},
      {:scrypt, "~> 2.1"}
      # {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      # {:sobelow, "~> 0.13", only: [:dev, :test], runtime: false},
      # {:luaport, "~> 1.6"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
