defmodule PkiRaEngine.Api.ApiKeyController do
  @moduledoc """
  Handles API key management endpoints (protected by InternalAuthPlug).
  """

  import Plug.Conn
  alias PkiRaEngine.ApiKeyManagement

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]
    case conn.query_params do
      %{"ra_user_id" => ra_user_id_str} ->
        keys = ApiKeyManagement.list_keys(tenant_id, ra_user_id_str)
        json(conn, 200, Enum.map(keys, &serialize_key/1))

      _ ->
        # List all keys for this tenant when no user filter is provided
        repo = PkiRaEngine.TenantRepo.ra_repo(tenant_id)
        keys = repo.all(PkiRaEngine.Schema.RaApiKey)
        json(conn, 200, Enum.map(keys, &serialize_key/1))
    end
  end

  def create(conn) do
    tenant_id = conn.assigns[:tenant_id]
    attrs = build_attrs(conn.body_params)

    case ApiKeyManagement.create_api_key(tenant_id, attrs) do
      {:ok, %{raw_key: raw_key, api_key: api_key}} ->
        result =
          api_key
          |> serialize_key()
          |> Map.put(:raw_key, raw_key)

        json(conn, 201, result)

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def update(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    attrs = build_attrs(conn.body_params)

    case ApiKeyManagement.update_key(tenant_id, id, attrs) do
      {:ok, api_key} ->
        json(conn, 200, serialize_key(api_key))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})
    end
  end

  def revoke(conn, id) do
    tenant_id = conn.assigns[:tenant_id]
    case ApiKeyManagement.revoke_key(tenant_id, id) do
      {:ok, api_key} ->
        json(conn, 200, serialize_key(api_key))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  defp build_attrs(params) do
    label = params["label"] || params["name"]
    %{}
    |> maybe_put(:ra_user_id, params["ra_user_id"])
    |> maybe_put(:label, label)
    |> maybe_put(:expiry, params["expiry"])
    |> maybe_put(:rate_limit, params["rate_limit"])
    |> maybe_put(:key_type, params["key_type"])
    |> maybe_put(:allowed_profile_ids, params["allowed_profile_ids"])
    |> maybe_put(:ip_whitelist, params["ip_whitelist"])
    |> maybe_put(:webhook_url, params["webhook_url"])
    |> maybe_put(:ra_instance_id, params["ra_instance_id"])
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp serialize_key(api_key) do
    prefix = if api_key.label, do: String.slice(api_key.label, 0, 8), else: "key_" <> String.slice(api_key.id || "", 0, 4)
    %{
      id: api_key.id,
      ra_user_id: api_key.ra_user_id,
      name: api_key.label,
      label: api_key.label,
      prefix: prefix,
      created_at: api_key.inserted_at,
      expiry: api_key.expiry,
      rate_limit: api_key.rate_limit,
      ra_instance_id: api_key.ra_instance_id,
      key_type: api_key.key_type,
      allowed_profile_ids: api_key.allowed_profile_ids,
      ip_whitelist: api_key.ip_whitelist,
      webhook_url: api_key.webhook_url,
      status: api_key.status,
      revoked_at: api_key.revoked_at,
      inserted_at: api_key.inserted_at,
      updated_at: api_key.updated_at
    }
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
