defmodule PkiPlatformEngine.DynamicRepo do
  @moduledoc """
  A generic Ecto Repo that can be started multiple times with different configs.
  Used for per-tenant database connections.
  """
  use Ecto.Repo,
    otp_app: :pki_platform_engine,
    adapter: Ecto.Adapters.Postgres

  def init(_type, config) do
    {:ok, config}
  end
end
