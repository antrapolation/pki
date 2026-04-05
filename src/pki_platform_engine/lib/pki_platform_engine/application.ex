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

      # Run tenant schema migrations after boot
      Logger.info("[Application] Running tenant schema migrations...")
      PkiPlatformEngine.TenantMigrator.migrate_all()

      # Dev-only: auto-activate CA issuer keys (bypass ceremony)
      if Application.get_env(:pki_ca_engine, :dev_auto_activate_keys, false) do
        Process.sleep(3_000)
        Logger.info("[Application] Dev auto-activating issuer keys...")
        dev_auto_activate_all_keys()
      end
    end)

    result
  end

  defp dev_auto_activate_all_keys do
    import Ecto.Query

    # Get all active tenants and activate their issuer keys
    case PkiPlatformEngine.PlatformRepo.query("SELECT id, database_name FROM tenants WHERE status = 'active'", []) do
      {:ok, %{rows: rows}} ->
        for [tenant_id_bin, _db_name] <- rows do
          tenant_id = case Ecto.UUID.cast(tenant_id_bin) do
            {:ok, id} -> id
            _ -> nil
          end

          if tenant_id do
            try do
              repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)
              keys = repo.all(from k in PkiCaEngine.Schema.IssuerKey, where: k.status == "active")

              for key <- keys do
                unless PkiCaEngine.KeyActivation.is_active?(key.id) do
                  case PkiCaEngine.KeyCeremony.SyncCeremony.generate_keypair(key.algorithm) do
                    {:ok, %{private_key: priv_key}} ->
                      PkiCaEngine.KeyActivation.dev_activate(key.id, priv_key)
                      Logger.info("[DevActivate] Activated #{key.key_alias} (#{key.algorithm})")

                    {:error, reason} ->
                      Logger.warning("[DevActivate] #{key.key_alias} keygen failed: #{inspect(reason)}")
                  end
                end
              end
            rescue
              e -> Logger.warning("[DevActivate] Tenant #{tenant_id}: #{Exception.message(e)}")
            end
          end
        end

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
