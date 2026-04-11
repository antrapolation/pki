defmodule PkiCaEngine.EngineBootstrapImpl do
  @moduledoc """
  Implements `PkiPlatformEngine.EngineBootstrap` for the CA Engine.
  Provides tenant bootstrapping (default CA instance) and dev key activation.
  """
  @behaviour PkiPlatformEngine.EngineBootstrap

  require Logger

  @impl true
  def engine_name, do: "CA"

  @impl true
  def ensure_default_instance(tenant) do
    case PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant.id) do
      [] ->
        case PkiCaEngine.CaInstanceManagement.create_ca_instance(tenant.id, %{
               name: "#{tenant.name} Root CA",
               status: "active"
             }) do
          {:ok, _ca} -> :ok
          {:error, reason} -> {:error, reason}
        end

      _instances ->
        :ok
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  @impl true
  def dev_activate_keys(tenant_id) do
    import Ecto.Query

    repo = PkiCaEngine.TenantRepo.ca_repo(tenant_id)
    keys = repo.all(from k in PkiCaEngine.Schema.IssuerKey, where: k.status == "active")

    for key <- keys do
      unless PkiCaEngine.KeyActivation.is_active?(key.id) do
        case PkiCaEngine.KeyCeremony.SyncCeremony.generate_keypair(key.algorithm) do
          {:ok, %{private_key: priv_key}} ->
            PkiCaEngine.KeyActivation.dev_activate(key.id, priv_key)
            Logger.info("[CA Bootstrap] Dev-activated #{key.key_alias} (#{key.algorithm})")

          {:error, reason} ->
            Logger.warning("[CA Bootstrap] #{key.key_alias} keygen failed: #{inspect(reason)}")
        end
      end
    end

    :ok
  rescue
    e ->
      Logger.warning("[CA Bootstrap] Dev activate failed for tenant #{tenant_id}: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end
end
