defmodule StrapSofthsmPrivKeyStoreProvider.MixProject do
  use Mix.Project

  def project do
    [
      app: :strap_softhsm_priv_key_store_provider,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      rustler_suites: [
        softhsm_nif: [
          path: "native/softhsm_nif",
          mode: if(Mix.env() == :prod, do: :release, else: :debug)
        ]
      ]
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
      {:strap_priv_key_store_provider, path: "../strap_priv_key_store_provider"},
      {:strap_proc_reg, path: "../strap_proc_reg"},
      {:ex_ccrypto, path: "../ex_ccrypto"},
      {:rustler, "~> 0.35"}
    ]
  end
end
