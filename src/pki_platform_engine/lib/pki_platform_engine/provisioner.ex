defmodule PkiPlatformEngine.Provisioner do
  @moduledoc "Provisions and manages tenant databases."

  alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantRepo}
  import Ecto.Query

  def create_tenant(name, slug, opts \\ []) do
    attrs = %{
      name: name,
      slug: slug,
      signing_algorithm: Keyword.get(opts, :signing_algorithm, "ECC-P256"),
      kem_algorithm: Keyword.get(opts, :kem_algorithm, "ECDH-P256")
    }

    changeset = Tenant.changeset(%Tenant{}, attrs)

    case Ecto.Changeset.apply_action(changeset, :validate) do
      {:ok, _tenant_data} ->
        db_name = Ecto.Changeset.get_field(changeset, :database_name)

        with :ok <- create_database(db_name),
             :ok <- create_schemas(db_name),
             {:ok, tenant} <- PlatformRepo.insert(changeset) do
          {:ok, tenant}
        else
          {:error, reason} ->
            # Cleanup on failure
            drop_database(db_name)
            {:error, reason}
        end

      {:error, changeset} ->
        {:error, changeset}
    end
  end

  def suspend_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant ->
        tenant
        |> Tenant.changeset(%{status: "suspended"})
        |> PlatformRepo.update()
    end
  end

  def activate_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant ->
        tenant
        |> Tenant.changeset(%{status: "active"})
        |> PlatformRepo.update()
    end
  end

  def delete_tenant(tenant_id) do
    case PlatformRepo.get(Tenant, tenant_id) do
      nil -> {:error, :not_found}
      tenant ->
        drop_database(tenant.database_name)
        PlatformRepo.delete(tenant)
    end
  end

  def list_tenants do
    PlatformRepo.all(from t in Tenant, order_by: [desc: t.inserted_at])
  end

  def get_tenant(id), do: PlatformRepo.get(Tenant, id)
  def get_tenant_by_slug(slug), do: PlatformRepo.get_by(Tenant, slug: slug)

  # --- Private ---

  defp validate_db_name!(db_name) do
    unless db_name =~ ~r/\Apki_tenant_[0-9a-f]{32}\z/ do
      raise ArgumentError, "Invalid database name: #{inspect(db_name)}"
    end

    db_name
  end

  # Uses a direct Postgrex connection to the "postgres" maintenance database
  # because CREATE/DROP DATABASE cannot run inside a transaction block
  # (which Ecto.Adapters.SQL.Sandbox uses).
  defp with_admin_conn(fun) do
    config = Application.get_env(:pki_platform_engine, PlatformRepo, [])

    {:ok, conn} =
      Postgrex.start_link(
        hostname: Keyword.get(config, :hostname, "localhost"),
        port: Keyword.get(config, :port, 5434),
        username: Keyword.get(config, :username, "postgres"),
        password: Keyword.get(config, :password, "postgres"),
        database: "postgres"
      )

    try do
      fun.(conn)
    after
      GenServer.stop(conn)
    end
  end

  defp create_database(db_name) do
    safe = validate_db_name!(db_name)

    with_admin_conn(fn conn ->
      case Postgrex.query(conn, "CREATE DATABASE \"#{safe}\"", []) do
        {:ok, _} -> :ok
        {:error, %{postgres: %{code: :duplicate_database}}} -> :ok
        {:error, reason} -> {:error, {:create_database_failed, reason}}
      end
    end)
  end

  defp create_schemas(db_name) do
    safe = validate_db_name!(db_name)
    schemas = ["ca", "ra", "validation", "audit"]

    valid_schemas = MapSet.new(["ca", "ra", "validation", "audit"])

    Enum.each(schemas, fn schema ->
      unless MapSet.member?(valid_schemas, schema) do
        raise ArgumentError, "Invalid schema name: #{inspect(schema)}"
      end

      TenantRepo.execute_sql(safe, "public", ~s|CREATE SCHEMA IF NOT EXISTS "#{schema}"|, [])
    end)

    :ok
  rescue
    e -> {:error, {:create_schemas_failed, Exception.message(e)}}
  end

  defp drop_database(db_name) do
    safe = validate_db_name!(db_name)

    with_admin_conn(fn conn ->
      # Use WITH (FORCE) to terminate connections and drop in one step (PG >= 13)
      Postgrex.query(conn, "DROP DATABASE IF EXISTS \"#{safe}\" WITH (FORCE)", [])
      :ok
    end)
  rescue
    _ -> :ok
  end
end
