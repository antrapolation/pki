defmodule ApJavaCrypto.MixProject do
  use Mix.Project

  def project do
    [
      app: :ap_java_crypto,
      version: "0.1.0",
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {ApJavaCrypto.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_jruby_port, git: "ssh://git@vcs.antrapol.tech:28/MDP/ExJrubyPort.git", tag: "v0.1.1"},
      # path: "/Users/chris/02.Code-Factory/08-Workspace/elixir/08.WS/ex_jruby_port/"},
      {:strap_proc_reg,
       git: "ssh://git@vcs.antrapol.tech:28/MDP/StrapProcReg.git", tag: "v0.1.0"},
      {:ex_ccrypto, path: "../ex_ccrypto"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
