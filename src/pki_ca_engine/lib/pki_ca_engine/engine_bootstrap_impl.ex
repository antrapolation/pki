defmodule PkiCaEngine.EngineBootstrapImpl do
  @moduledoc """
  Implements `PkiPlatformEngine.EngineBootstrap` for the CA Engine.

  In the per-tenant BEAM architecture the platform node spawns one
  BEAM per tenant — the platform layer no longer creates default CA
  instances on behalf of tenants. The default instance is created
  explicitly by a ca_admin through the `/ca-instances` LiveView.
  `ensure_default_instance/1` here is therefore a no-op and the
  dev-only `dev_activate_keys/1` reads from Mnesia directly.
  """
  @behaviour PkiPlatformEngine.EngineBootstrap

  require Logger

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.IssuerKey

  @impl true
  def engine_name, do: "CA"

  @impl true
  def ensure_default_instance(_tenant), do: :ok

  @impl true
  def dev_activate_keys(tenant_id) do
    case Repo.where(IssuerKey, fn k -> k.status == "active" end) do
      {:ok, keys} ->
        Enum.each(keys, &maybe_dev_activate/1)
        :ok

      {:error, reason} ->
        Logger.warning("[CA Bootstrap] Dev activate lookup failed for tenant #{tenant_id}: #{inspect(reason)}")
        {:error, reason}
    end
  rescue
    e ->
      Logger.warning("[CA Bootstrap] Dev activate failed for tenant #{tenant_id}: #{Exception.message(e)}")
      {:error, Exception.message(e)}
  end

  defp maybe_dev_activate(%IssuerKey{} = key) do
    if PkiCaEngine.KeyActivation.is_active?(key.id) do
      :ok
    else
      case generate_keypair(key.algorithm) do
        {:ok, %{private_key: priv_key}} ->
          PkiCaEngine.KeyActivation.dev_activate(key.id, priv_key)
          Logger.info("[CA Bootstrap] Dev-activated #{key.key_alias} (#{key.algorithm})")

        {:error, reason} ->
          Logger.warning("[CA Bootstrap] #{key.key_alias} keygen failed: #{inspect(reason)}")
      end
    end
  end

  defp generate_keypair(algorithm) do
    case PkiCrypto.Registry.get(algorithm) do
      nil -> {:error, {:unsupported_algorithm, algorithm}}
      algo_struct -> PkiCrypto.Algorithm.generate_keypair(algo_struct)
    end
  end
end
