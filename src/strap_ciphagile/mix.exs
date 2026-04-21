defmodule StrapCiphagile.MixProject do
  use Mix.Project

  def project do
    [
      app: :strap_ciphagile,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {StrapCiphagile.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:typedstruct, "~> 0.5.4"},
      {:ex_ccrypto, path: "../ex_ccrypto", only: :test},
      {:ap_java_crypto, path: "../ap_java_crypto", only: :test},
      {:jason, "~> 1.4"}
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
