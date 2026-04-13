defmodule PkiPlatformEngine.Plugs.ClearTenantPrefix do
  @moduledoc """
  Clears any stale tenant prefix from the process dictionary at the start
  of each web request. Prevents cross-tenant data leaks when a Cowboy
  process is reused across requests for different tenants.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    Process.delete(:pki_ecto_prefix)
    conn
  end
end
