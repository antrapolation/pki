defmodule PkiCaEngine.Api.CaInstanceController do
  import Plug.Conn
  alias PkiCaEngine.CaInstanceManagement

  def create(conn) do
    attrs = Map.drop(conn.body_params, ["id", "status"])

    case CaInstanceManagement.create_ca_instance(attrs) do
      {:ok, ca} ->
        json(conn, 201, %{
          id: ca.id,
          name: ca.name,
          status: ca.status,
          parent_id: ca.parent_id,
          role: CaInstanceManagement.role(ca),
          created_by: ca.created_by
        })

      {:error, :max_depth_exceeded} ->
        json(conn, 422, %{error: "max_depth_exceeded"})

      {:error, :parent_not_found} ->
        json(conn, 404, %{error: "parent_not_found"})

      {:error, %Ecto.Changeset{} = changeset} ->
        errors = PkiCaEngine.Api.Helpers.changeset_errors(changeset)
        json(conn, 422, %{errors: errors})

      {:error, reason} ->
        json(conn, 400, %{error: inspect(reason)})
    end
  end

  def index(conn) do
    instances = CaInstanceManagement.list_hierarchy()
    data = Enum.map(instances, &serialize_tree/1)
    json(conn, 200, data)
  end

  def show(conn, id) do
    case CaInstanceManagement.get_ca_instance(id) do
      {:ok, ca} ->
        json(conn, 200, serialize_with_details(ca))

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  def children(conn, id) do
    case CaInstanceManagement.get_ca_instance(id) do
      {:ok, ca} ->
        data = Enum.map(ca.children, &serialize_basic/1)
        json(conn, 200, data)

      {:error, :not_found} ->
        json(conn, 404, %{error: "not_found"})
    end
  end

  def update(conn, id) do
    case conn.body_params do
      %{"status" => new_status} ->
        case CaInstanceManagement.update_status(id, new_status) do
          {:ok, ca} ->
            json(conn, 200, serialize_basic(ca))

          {:error, :not_found} ->
            json(conn, 404, %{error: "not_found"})

          {:error, %Ecto.Changeset{} = cs} ->
            json(conn, 422, %{errors: PkiCaEngine.Api.Helpers.changeset_errors(cs)})
        end

      _ ->
        json(conn, 400, %{error: "invalid_params"})
    end
  end

  defp serialize_basic(ca) do
    %{
      id: ca.id,
      name: ca.name,
      status: ca.status,
      parent_id: ca.parent_id,
      role: infer_role(ca)
    }
  end

  defp infer_role(ca) do
    children_loaded = if Ecto.assoc_loaded?(ca.children), do: ca.children, else: nil

    cond do
      is_nil(ca.parent_id) -> :root
      children_loaded != nil and children_loaded == [] -> :issuing
      children_loaded != nil and children_loaded != [] -> :intermediate
      true -> CaInstanceManagement.role(ca)
    end
  end

  defp serialize_tree(ca) do
    children = if Ecto.assoc_loaded?(ca.children), do: ca.children, else: []
    Map.put(serialize_basic(ca), :children, Enum.map(children, &serialize_tree/1))
  end

  defp serialize_with_details(ca) do
    issuer_keys = if Ecto.assoc_loaded?(ca.issuer_keys), do: ca.issuer_keys, else: []

    serialize_basic(ca)
    |> Map.put(:children, Enum.map(ca.children || [], &serialize_basic/1))
    |> Map.put(:issuer_keys, Enum.map(issuer_keys, fn k ->
      %{id: k.id, key_alias: k.key_alias, algorithm: k.algorithm, status: k.status}
    end))
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
