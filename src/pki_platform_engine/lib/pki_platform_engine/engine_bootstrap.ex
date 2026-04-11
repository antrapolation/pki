defmodule PkiPlatformEngine.EngineBootstrap do
  @moduledoc """
  Behaviour for engine-specific tenant bootstrapping.

  CA Engine and RA Engine implement this behaviour to provide
  their default instance creation logic. Platform Engine calls
  them through configuration rather than direct module references,
  breaking the bidirectional coupling.

  ## Configuration

      config :pki_platform_engine, :engine_bootstraps, [
        PkiCaEngine.EngineBootstrapImpl,
        PkiRaEngine.EngineBootstrapImpl
      ]
  """

  @doc """
  Ensures a default instance exists for the given tenant.
  Returns `:ok` or `{:error, reason}`.
  """
  @callback ensure_default_instance(tenant :: map()) :: :ok | {:error, term()}

  @doc """
  Dev-only: auto-activate keys for a tenant (bypass ceremony).
  Returns `:ok` or `{:error, reason}`. May be a no-op for engines
  that don't need key activation.
  """
  @callback dev_activate_keys(tenant_id :: String.t()) :: :ok | {:error, term()}

  @doc """
  Returns the engine name for logging purposes.
  """
  @callback engine_name() :: String.t()

  @doc """
  Runs all configured engine bootstraps for a tenant.
  """
  def ensure_all_instances(tenant) do
    bootstraps = Application.get_env(:pki_platform_engine, :engine_bootstraps, [])

    errors =
      Enum.flat_map(bootstraps, fn mod ->
        case mod.ensure_default_instance(tenant) do
          :ok -> []
          {:error, reason} -> ["#{mod.engine_name()} instance creation failed: #{inspect(reason)}"]
        end
      end)

    case errors do
      [] -> :ok
      _ -> {:error, Enum.join(errors, "; ")}
    end
  end

  @doc """
  Dev-only: runs dev_activate_keys for all configured engines and tenants.
  """
  def dev_activate_all(tenant_ids) do
    bootstraps = Application.get_env(:pki_platform_engine, :engine_bootstraps, [])

    for tenant_id <- tenant_ids, mod <- bootstraps do
      mod.dev_activate_keys(tenant_id)
    end

    :ok
  end
end
