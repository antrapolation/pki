defmodule PkiRaEngine.Api.RaInstanceController do
  @moduledoc """
  Handles RA instance CRUD endpoints and proxied issuer key listing.
  """

  import Plug.Conn

  alias PkiRaEngine.RaInstanceManagement

  def create(conn) do
    attrs = Map.drop(conn.body_params, ["id", "status"])

    case RaInstanceManagement.create_ra_instance(attrs) do
      {:ok, ra} ->
        json(conn, 201, serialize(ra))

      {:error, %Ecto.Changeset{} = changeset} ->
        errors = changeset_errors(changeset)
        json(conn, 422, %{errors: errors})

      {:error, reason} ->
        json(conn, 400, %{error: inspect(reason)})
    end
  end

  def index(conn) do
    instances = RaInstanceManagement.list_ra_instances()
    json(conn, 200, Enum.map(instances, &serialize/1))
  end

  def show(conn, id) do
    case RaInstanceManagement.get_ra_instance(id) do
      {:ok, ra} -> json(conn, 200, serialize(ra))
      {:error, :not_found} -> json(conn, 404, %{error: "not_found"})
    end
  end

  def update(conn, id) do
    case conn.body_params do
      %{"status" => new_status} ->
        case RaInstanceManagement.update_status(id, new_status) do
          {:ok, ra} ->
            json(conn, 200, serialize(ra))

          {:error, :not_found} ->
            json(conn, 404, %{error: "not_found"})

          {:error, %Ecto.Changeset{} = changeset} ->
            json(conn, 422, %{errors: changeset_errors(changeset)})
        end

      _ ->
        json(conn, 400, %{error: "invalid_params"})
    end
  end

  def available_issuer_keys(conn) do
    case PkiRaEngine.CsrValidation.HttpCaClient.list_leaf_issuer_keys() do
      {:ok, keys} -> json(conn, 200, keys)
      {:error, :ca_engine_url_not_configured} -> json(conn, 503, %{error: "ca_engine_url_not_configured"})
      {:error, {:ca_engine_error, status, detail}} -> json(conn, 502, %{error: "ca_engine_returned_#{status}", detail: detail})
      {:error, reason} -> json(conn, 502, %{error: inspect(reason)})
    end
  end

  # --- Private ---

  defp serialize(ra) do
    %{
      id: ra.id,
      name: ra.name,
      status: ra.status,
      created_by: ra.created_by
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
