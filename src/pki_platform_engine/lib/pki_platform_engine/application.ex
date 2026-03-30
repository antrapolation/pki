defmodule PkiPlatformEngine.Application do
  use Application

  def start(_type, _args) do
    children = [
      PkiPlatformEngine.PlatformRepo,
      PkiPlatformEngine.EmailVerification
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: PkiPlatformEngine.Supervisor)
  end
end
