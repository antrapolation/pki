defmodule PkiPlatformEngine.Application do
  use Application

  require Logger

  def start(_type, _args) do
    children =
      [
        PkiPlatformEngine.PlatformRepo,
        PkiPlatformEngine.EmailVerification,
        PkiPlatformEngine.TenantRegistry,
        PkiPlatformEngine.TenantSupervisor
      ] ++ date_log_handler_child()

    opts = [strategy: :one_for_one, name: PkiPlatformEngine.Supervisor]
    result = Supervisor.start_link(children, opts)

    # Boot active tenants async (after supervisor tree is ready)
    Task.start(fn ->
      Process.sleep(1_000)
      Logger.info("[Application] Booting active tenant engines...")
      PkiPlatformEngine.TenantSupervisor.boot_active_tenants()
    end)

    result
  end

  defp date_log_handler_child do
    if Application.get_env(:pki_platform_engine, :start_date_log_handler, true) do
      [{PkiPlatformEngine.DateLogHandler, app_name: "pki", log_dir: "logs", retention_days: 7}]
    else
      []
    end
  end
end
