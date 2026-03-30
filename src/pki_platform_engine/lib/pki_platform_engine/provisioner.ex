defmodule PkiPlatformEngine.Provisioner do
  @moduledoc "Provisions and manages tenant databases."

  alias PkiPlatformEngine.{PlatformRepo, Tenant, TenantRepo}
  import Ecto.Query

  def create_tenant(name, slug, opts \\ []) do
    attrs = %{
      name: name,
      slug: slug,
      email: Keyword.get(opts, :email)
    }

    changeset = Tenant.changeset(%Tenant{}, attrs)

    case Ecto.Changeset.apply_action(changeset, :validate) do
      {:ok, _tenant_data} ->
        db_name = Ecto.Changeset.get_field(changeset, :database_name)

        with :ok <- create_database(db_name),
             :ok <- create_tenant_tables(db_name),
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
        case PlatformRepo.delete(tenant) do
          {:ok, deleted} ->
            drop_database(deleted.database_name)
            {:ok, deleted}
          {:error, reason} ->
            {:error, reason}
        end
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

    # Parse DATABASE_URL if config uses :url instead of individual fields
    {hostname, port, username, password} = parse_conn_config(config)

    case Postgrex.start_link(
           hostname: hostname,
           port: port,
           username: username,
           password: password,
           database: "postgres"
         ) do
      {:ok, conn} ->
        try do
          fun.(conn)
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        {:error, {:admin_conn_failed, reason}}
    end
  end

  defp parse_conn_config(config) do
    case Keyword.get(config, :url) do
      nil ->
        {
          Keyword.get(config, :hostname, "localhost"),
          Keyword.get(config, :port, 5432),
          Keyword.get(config, :username, "postgres"),
          Keyword.get(config, :password, "postgres")
        }

      url ->
        uri = URI.parse(url)
        userinfo = String.split(uri.userinfo || "postgres:postgres", ":", parts: 2)
        {
          uri.host || "localhost",
          uri.port || 5432,
          Enum.at(userinfo, 0, "postgres"),
          Enum.at(userinfo, 1, "postgres") |> URI.decode()
        }
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

  defp create_tenant_tables(db_name) do
    safe = validate_db_name!(db_name)

    # Apply CA engine schema (includes audit_events, ca_instances, issuer_keys, etc.)
    ca_sql = read_schema_sql("tenant_ca_schema.sql")
    case apply_schema_sql(safe, ca_sql) do
      :ok -> :ok
      {:error, reason} -> throw {:error, {:ca_schema_failed, reason}}
    end

    # Apply RA engine schema (includes ra_users, cert_profiles, csr_requests, etc.)
    ra_sql = read_schema_sql("tenant_ra_schema.sql")
    case apply_schema_sql(safe, ra_sql) do
      :ok -> :ok
      {:error, reason} -> throw {:error, {:ra_schema_failed, reason}}
    end

    :ok
  catch
    {:error, reason} -> {:error, reason}
  end

  defp read_schema_sql(filename) do
    priv_dir = :code.priv_dir(:pki_platform_engine)
    path = Path.join(priv_dir, filename)
    File.read!(path)
  end

  defp apply_schema_sql(db_name, sql) do
    config = Application.get_env(:pki_platform_engine, TenantRepo, [])
    {hostname, port, username, password} = parse_conn_config(config)

    case Postgrex.start_link(
           hostname: hostname,
           port: port,
           username: username,
           password: password,
           database: db_name
         ) do
      {:ok, conn} ->
        try do
          case Postgrex.query(conn, sql, []) do
            {:ok, _} -> :ok
            {:error, reason} -> {:error, reason}
          end
        after
          GenServer.stop(conn)
        end

      {:error, reason} ->
        {:error, {:connection_failed, reason}}
    end
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
