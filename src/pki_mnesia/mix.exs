defmodule PkiMnesia.MixProject do
  use Mix.Project

  def project do
    [
      app: :pki_mnesia,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      test_coverage: [threshold: 70, summary: [threshold: 70]]
    ]
  end

  def application do
    [
      extra_applications: [:logger, :mnesia]
    ]
  end

  defp deps do
    [
      {:uniq, "~> 0.6"},
      {:jason, "~> 1.4"}
    ]
  end
end
