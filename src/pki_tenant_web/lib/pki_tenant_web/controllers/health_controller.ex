defmodule PkiTenantWeb.HealthController do
  use PkiTenantWeb, :controller

  def show(conn, _params) do
    health = PkiTenant.Health.check()
    status_code = if health.status == "healthy", do: 200, else: 503

    conn
    |> put_status(status_code)
    |> json(health)
  end
end
