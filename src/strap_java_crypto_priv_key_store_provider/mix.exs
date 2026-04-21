defmodule StrapJavaCryptoPrivKeyStoreProvider.MixProject do
  use Mix.Project

  def project do
    [
      app: :strap_java_crypto_priv_key_store_provider,
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
      {:strap_priv_key_store_provider, path: "../strap_priv_key_store_provider"},
      {:ap_java_crypto, path: "../ap_java_crypto"},
      {:ex_ccrypto, path: "../ex_ccrypto"},
      {:typedstruct, "~> 0.5"},
      {:strap_proc_reg, path: "../strap_proc_reg", override: true}
    ]
  end
end
