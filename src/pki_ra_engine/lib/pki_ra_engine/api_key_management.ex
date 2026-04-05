defmodule PkiRaEngine.ApiKeyManagement do
  @moduledoc """
  API Key Management — create, verify, list, and revoke API keys.

  Keys are stored as SHA3-256 hashes. The raw key is only returned at creation time.
  """

  import Ecto.Query

  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaApiKey

  @doc """
  Create a new API key for an RA user.

  Generates a 32-byte random key, stores its SHA3-256 hash.
  Returns the raw key (base64-encoded) alongside the persisted record.
  The raw key is only visible at creation time.
  """
  @spec create_api_key(String.t(), map()) :: {:ok, %{raw_key: String.t(), api_key: RaApiKey.t()}} | {:error, Ecto.Changeset.t()}
  def create_api_key(tenant_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)
    raw_key = :crypto.strong_rand_bytes(32)
    hashed = hash_key(raw_key)

    # Auto-generate webhook secret if webhook_url is provided
    webhook_url = attrs[:webhook_url] || attrs["webhook_url"]
    webhook_secret = if is_binary(webhook_url) and webhook_url != "" do
      :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false)
    else
      nil
    end

    api_key_attrs =
      attrs
      |> Map.put(:hashed_key, hashed)
      |> Map.put(:webhook_secret, webhook_secret)

    case %RaApiKey{} |> RaApiKey.changeset(api_key_attrs) |> repo.insert() do
      {:ok, api_key} ->
        audit("api_key_created", tenant_id, "api_key", api_key.id, %{
          ra_user_id: api_key.ra_user_id,
          label: api_key.label,
          key_type: api_key.key_type
        })
        {:ok, %{raw_key: Base.encode64(raw_key), api_key: api_key, webhook_secret: webhook_secret}}

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  @doc """
  Verify a raw API key string.

  Hashes the provided key and looks it up. Checks that the key is active and not expired.
  """
  @spec verify_key(String.t(), String.t()) :: {:ok, RaApiKey.t()} | {:error, :invalid_key | :expired}
  def verify_key(tenant_id, raw_key_base64) do
    repo = TenantRepo.ra_repo(tenant_id)

    with {:ok, raw_key} <- Base.decode64(raw_key_base64) do
      hashed = hash_key(raw_key)

      case repo.one(from k in RaApiKey, where: k.hashed_key == ^hashed and k.status == "active") do
        nil ->
          {:error, :invalid_key}

        %RaApiKey{} = api_key ->
          if expired?(api_key) do
            {:error, :expired}
          else
            {:ok, api_key}
          end
      end
    else
      :error -> {:error, :invalid_key}
    end
  end

  @doc "List all API keys for a given RA user."
  @spec list_keys(String.t(), String.t()) :: [RaApiKey.t()]
  def list_keys(tenant_id, ra_user_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    from(k in RaApiKey, where: k.ra_user_id == ^ra_user_id)
    |> repo.all()
  end

  @doc "Update an API key's mutable fields (label, key_type, rate_limit, allowed_profile_ids, ip_whitelist, webhook_url)."
  @spec update_key(String.t(), String.t(), map()) :: {:ok, RaApiKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def update_key(tenant_id, id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaApiKey, id) do
      nil ->
        {:error, :not_found}

      api_key ->
        # Auto-generate webhook secret if webhook_url is being set for the first time
        webhook_url = attrs[:webhook_url] || attrs["webhook_url"]
        attrs = if is_binary(webhook_url) and webhook_url != "" and (api_key.webhook_secret == nil or api_key.webhook_secret == "") do
          Map.put(attrs, :webhook_secret, :crypto.strong_rand_bytes(32) |> Base.encode64(padding: false))
        else
          attrs
        end

        case api_key |> RaApiKey.update_changeset(attrs) |> repo.update() do
          {:ok, updated} ->
            audit("api_key_updated", tenant_id, "api_key", id, %{
              ra_user_id: updated.ra_user_id,
              label: updated.label
            })
            {:ok, updated}

          error ->
            error
        end
    end
  end

  @doc "Revoke an API key by ID."
  @spec revoke_key(String.t(), String.t()) :: {:ok, RaApiKey.t()} | {:error, :not_found | Ecto.Changeset.t()}
  def revoke_key(tenant_id, id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaApiKey, id) do
      nil ->
        {:error, :not_found}

      api_key ->
        case api_key
             |> RaApiKey.changeset(%{status: "revoked", revoked_at: DateTime.utc_now()})
             |> repo.update() do
          {:ok, revoked} ->
            audit("api_key_revoked", tenant_id, "api_key", id, %{
              ra_user_id: revoked.ra_user_id,
              label: revoked.label
            })
            {:ok, revoked}

          error ->
            error
        end
    end
  end

  # ── Private ─────────────────────────────────────────────────────────

  defp hash_key(raw_key) do
    Base.encode16(:crypto.hash(:sha3_256, raw_key), case: :lower)
  end

  defp audit(action, tenant_id, target_type, target_id, details) do
    PkiPlatformEngine.PlatformAudit.log(action, %{
      target_type: target_type,
      target_id: target_id,
      tenant_id: tenant_id,
      portal: "ra",
      details: details
    })
  rescue
    _ -> :ok
  end

  defp expired?(%RaApiKey{expiry: nil}), do: false

  defp expired?(%RaApiKey{expiry: expiry}) do
    DateTime.compare(DateTime.utc_now(), expiry) == :gt
  end
end
