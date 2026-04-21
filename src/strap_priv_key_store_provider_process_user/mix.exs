defmodule StrapPrivKeyStoreProviderProcessUser.MixProject do
  use Mix.Project

  def project do
    [
      app: :strap_priv_key_store_provider_process_user,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:typedstruct, "~> 0.5"},
      {:strap_priv_key_store_provider, path: "../strap_priv_key_store_provider"},
      {:strap_proc_reg, path: "../strap_proc_reg"},
      {:ex_ccrypto, path: "../ex_ccrypto"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
