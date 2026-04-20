defmodule PkiCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_crypto,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [threshold: 70, summary: [threshold: 70]]
    ]
  end

  def application do
    [extra_applications: [:logger, :crypto, :public_key]]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:keyx, path: "../keyx", override: true},
      {:uniq, "~> 0.6"},
      {:pki_oqs_nif, path: "../pki_oqs_nif"},
      {:kaz_sign, path: "../../../PQC-KAZ/SIGN/bindings/elixir"},
      {:x509, "~> 0.8", only: :test}
    ]
  end
end
