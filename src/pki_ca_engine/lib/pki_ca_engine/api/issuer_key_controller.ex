defmodule PkiCaEngine.Api.IssuerKeyController do
  @moduledoc """
  Handles issuer key listing endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.Api.Helpers

  def index(conn) do
    tenant_id = conn.assigns[:tenant_id]

    keys =
      if conn.query_params["leaf_only"] == "true" do
        PkiCaEngine.CaInstanceManagement.active_leaf_issuer_keys(tenant_id)
      else
        ca_instance_id = Helpers.resolve_instance_id(conn.query_params)

        if is_nil(ca_instance_id) do
          :missing_ca_instance_id
        else
          opts = if status = conn.query_params["status"], do: [status: status], else: []
          IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id, opts)
        end
      end

    case keys do
      :missing_ca_instance_id ->
        json(conn, 400, %{error: "ca_instance_id is required"})

      keys ->
        json(conn, 200, Enum.map(keys, &serialize_issuer_key/1))
    end
  end

  defp serialize_issuer_key(key) do
    %{
      id: key.id,
      key_alias: key.key_alias,
      algorithm: key.algorithm,
      status: key.status,
      is_root: key.is_root,
      ca_instance_id: key.ca_instance_id,
      certificate_pem: key.certificate_pem,
      threshold_config: key.threshold_config,
      inserted_at: key.inserted_at,
      updated_at: key.updated_at
    }
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
