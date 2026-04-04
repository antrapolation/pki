defmodule PkiRaEngine.CaConnectionManagement do
  @moduledoc "Manages explicit RA-to-CA issuer key connections."

  import Ecto.Query
  alias PkiRaEngine.TenantRepo
  alias PkiRaEngine.Schema.RaCaConnection

  def connect(tenant_id, ra_instance_id, attrs) do
    repo = TenantRepo.ra_repo(tenant_id)

    %RaCaConnection{}
    |> RaCaConnection.changeset(
      Map.merge(attrs, %{
        ra_instance_id: ra_instance_id,
        connected_at: DateTime.utc_now() |> DateTime.truncate(:second)
      })
    )
    |> repo.insert()
  end

  def disconnect(tenant_id, connection_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    case repo.get(RaCaConnection, connection_id) do
      nil ->
        {:error, :not_found}

      conn ->
        conn
        |> RaCaConnection.changeset(%{status: "revoked"})
        |> repo.update()
    end
  end

  def list_connections(tenant_id, ra_instance_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.ra_instance_id == ^ra_instance_id and c.status == "active")
    |> order_by([c], desc: c.connected_at)
    |> repo.all()
  end

  def list_connected_issuer_keys(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.status == "active")
    |> select([c], c.issuer_key_id)
    |> repo.all()
  end

  def has_connections?(tenant_id) do
    repo = TenantRepo.ra_repo(tenant_id)

    RaCaConnection
    |> where([c], c.status == "active")
    |> repo.aggregate(:count) > 0
  end

end
