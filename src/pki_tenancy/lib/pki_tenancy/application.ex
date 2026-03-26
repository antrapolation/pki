defmodule PkiTenancy.Application do
  use Application

  def start(_type, _args) do
    children = [
      PkiTenancy.PlatformRepo
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: PkiTenancy.Supervisor)
  end
end
