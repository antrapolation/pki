defmodule PkiCaEngine.Api.CeremonyController do
  @moduledoc """
  Handles key ceremony endpoints.
  """

  import Plug.Conn
  import Ecto.Query
  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.KeyCeremony
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Api.Helpers

  def index(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)

    ceremonies =
      from(c in KeyCeremony, where: c.ca_instance_id == ^ca_instance_id, order_by: [desc: c.inserted_at])
      |> Repo.all()

    json(conn, 200, %{data: Enum.map(ceremonies, &serialize_ceremony/1)})
  end

  def create(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.body_params)

    params = %{
      algorithm: conn.body_params["algorithm"],
      keystore_id: conn.body_params["keystore_id"],
      threshold_k: conn.body_params["threshold_k"],
      threshold_n: conn.body_params["threshold_n"],
      initiated_by: conn.body_params["initiated_by"],
      domain_info: conn.body_params["domain_info"] || %{},
      key_alias: conn.body_params["key_alias"],
      is_root: conn.body_params["is_root"]
    }

    case SyncCeremony.initiate(ca_instance_id, params) do
      {:ok, {ceremony, issuer_key}} ->
        json(conn, 201, %{
          ceremony: serialize_ceremony(ceremony),
          issuer_key: %{
            id: issuer_key.id,
            key_alias: issuer_key.key_alias,
            algorithm: issuer_key.algorithm,
            status: issuer_key.status
          }
        })

      {:error, :invalid_threshold} ->
        json(conn, 422, %{error: "invalid_threshold", message: "k must be >= 2 and <= n"})

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found", message: "keystore not found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        json(conn, 422, %{error: "validation_error", details: changeset_errors(changeset)})

      {:error, reason} ->
        json(conn, 500, %{error: "internal_error", message: inspect(reason)})
    end
  end

  defp serialize_ceremony(ceremony) do
    %{
      id: ceremony.id,
      ca_instance_id: ceremony.ca_instance_id,
      issuer_key_id: ceremony.issuer_key_id,
      ceremony_type: ceremony.ceremony_type,
      status: ceremony.status,
      algorithm: ceremony.algorithm,
      keystore_id: ceremony.keystore_id,
      threshold_k: ceremony.threshold_k,
      threshold_n: ceremony.threshold_n,
      domain_info: ceremony.domain_info,
      initiated_by: ceremony.initiated_by,
      inserted_at: ceremony.inserted_at,
      updated_at: ceremony.updated_at
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
