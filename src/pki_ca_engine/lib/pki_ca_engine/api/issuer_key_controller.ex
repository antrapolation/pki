defmodule PkiCaEngine.Api.IssuerKeyController do
  @moduledoc """
  Handles issuer key listing endpoints.
  """

  import Plug.Conn
  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.Api.Helpers

  def index(conn) do
    ca_instance_id = Helpers.resolve_instance_id(conn.query_params)
    opts = if status = conn.query_params["status"], do: [status: status], else: []
    keys = IssuerKeyManagement.list_issuer_keys(ca_instance_id, opts)
    json(conn, 200, Enum.map(keys, &serialize_issuer_key/1))
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
