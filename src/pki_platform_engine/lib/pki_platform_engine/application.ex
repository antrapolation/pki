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

    # :rest_for_one — PlatformRepo → TenantRegistry → TenantSupervisor must restart in order
    opts = [strategy: :rest_for_one, name: PkiPlatformEngine.Supervisor]
    result = Supervisor.start_link(children, opts)

    # Boot active tenants async (after supervisor tree is ready)
    Task.start(fn ->
      Process.sleep(1_000)
      Logger.info("[Application] Booting active tenant engines...")
      PkiPlatformEngine.TenantSupervisor.boot_active_tenants()

      # Run tenant schema migrations after boot
      Logger.info("[Application] Running tenant schema migrations...")
      PkiPlatformEngine.TenantMigrator.migrate_all()

      # Dev-only: auto-activate issuer keys via EngineBootstrap behaviour
      if Application.get_env(:pki_platform_engine, :dev_auto_activate_keys, false) do
        Process.sleep(3_000)
        Logger.info("[Application] Dev auto-activating issuer keys...")
        dev_auto_activate_all_keys()
      end
    end)

    result
  end

  defp dev_auto_activate_all_keys do
    case PkiPlatformEngine.PlatformRepo.query("SELECT id FROM tenants WHERE status = 'active'", []) do
      {:ok, %{rows: rows}} ->
        tenant_ids =
          rows
          |> Enum.map(fn [id_bin] -> Ecto.UUID.cast(id_bin) end)
          |> Enum.filter(&match?({:ok, _}, &1))
          |> Enum.map(fn {:ok, id} -> id end)

        PkiPlatformEngine.EngineBootstrap.dev_activate_all(tenant_ids)

      _ ->
        Logger.warning("[DevActivate] Could not list tenants")
    end
  rescue
    e -> Logger.warning("[DevActivate] Failed: #{Exception.message(e)}")
  end

  defp date_log_handler_child do
    if Application.get_env(:pki_platform_engine, :start_date_log_handler, true) do
      [{PkiPlatformEngine.DateLogHandler, app_name: "pki", log_dir: "logs", retention_days: 7}]
    else
      []
    end
  end
end
