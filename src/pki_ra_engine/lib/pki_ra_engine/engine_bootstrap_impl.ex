defmodule PkiRaEngine.EngineBootstrapImpl do
  @moduledoc """
  Implements `PkiPlatformEngine.EngineBootstrap` for the RA Engine.
  Provides tenant bootstrapping (default RA instance).
  """
  @behaviour PkiPlatformEngine.EngineBootstrap

  require Logger

  @impl true
  def engine_name, do: "RA"

  @impl true
  def ensure_default_instance(tenant) do
    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant.id) do
      [] ->
        case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant.id, %{
               name: "#{tenant.name} RA",
               status: "active"
             }) do
          {:ok, _ra} -> :ok
          {:error, reason} -> {:error, reason}
        end

      _instances ->
        :ok
    end
  rescue
    e -> {:error, Exception.message(e)}
  end

  @impl true
  def dev_activate_keys(_tenant_id) do
    # RA Engine has no key activation — no-op
    :ok
  end
end
