defmodule PkiRaEngine.CaConnectionManagement do
  @moduledoc """
  RA-to-CA issuer key connections, against Mnesia.

  A connection is an explicit link between an RA instance and a
  specific CA issuer key. Only connected keys are usable when
  approving CSRs and issuing certificates.

  tenant_id is no longer needed since each BEAM node serves a
  single tenant.
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.{IssuerKey, RaCaConnection}

  @doc """
  Create a new active connection between the given RA instance and an
  issuer key. `attrs` must include `:issuer_key_id`. The `ca_instance_id`
  is derived from the issuer key.
  """
  @spec connect(binary(), map()) :: {:ok, RaCaConnection.t()} | {:error, term()}
  def connect(ra_instance_id, attrs) do
    issuer_key_id = Map.get(attrs, :issuer_key_id) || Map.get(attrs, "issuer_key_id")

    cond do
      is_nil(ra_instance_id) or ra_instance_id == "" ->
        {:error, :ra_instance_required}

      is_nil(issuer_key_id) or issuer_key_id == "" ->
        {:error, :issuer_key_required}

      true ->
        with {:ok, %IssuerKey{} = key} <- fetch_issuer_key(issuer_key_id),
             :ok <- guard_unique(ra_instance_id, issuer_key_id) do
          RaCaConnection.new(%{
            ra_instance_id: ra_instance_id,
            ca_instance_id: key.ca_instance_id,
            issuer_key_id: issuer_key_id,
            status: "active"
          })
          |> Repo.insert()
        end
    end
  end

  @doc "Revoke a connection (soft delete — status becomes \"revoked\")."
  @spec disconnect(binary()) :: {:ok, RaCaConnection.t()} | {:error, :not_found | term()}
  def disconnect(connection_id) do
    case Repo.get(RaCaConnection, connection_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, conn} -> Repo.update(conn, %{status: "revoked"})
      {:error, _} = err -> err
    end
  end

  @doc "List active connections for a specific RA instance."
  @spec list_connections(binary()) :: [RaCaConnection.t()]
  def list_connections(ra_instance_id) do
    case Repo.where(RaCaConnection, fn c ->
           c.ra_instance_id == ra_instance_id and c.status == "active"
         end) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "List every active connection across all RA instances (tenant scope)."
  @spec list_all_active() :: [RaCaConnection.t()]
  def list_all_active do
    case Repo.where(RaCaConnection, fn c -> c.status == "active" end) do
      {:ok, list} -> list
      _ -> []
    end
  end

  @doc "issuer_key_ids of every active connection."
  @spec list_connected_issuer_keys() :: [binary()]
  def list_connected_issuer_keys do
    list_all_active() |> Enum.map(& &1.issuer_key_id)
  end

  @doc "True if at least one active connection exists."
  @spec has_connections?() :: boolean()
  def has_connections?, do: list_all_active() != []

  # --- Deprecated legacy wrappers (tenant_id ignored) ---

  @doc false
  def connect(_tenant_id, ra_instance_id, attrs), do: connect(ra_instance_id, attrs)

  @doc false
  def disconnect(_tenant_id, connection_id), do: disconnect(connection_id)

  @doc false
  def list_connections(_tenant_id, ra_instance_id), do: list_connections(ra_instance_id)

  @doc false
  def list_connected_issuer_keys(_tenant_id), do: list_connected_issuer_keys()

  @doc false
  def has_connections?(_tenant_id), do: has_connections?()

  # --- Private ---

  defp fetch_issuer_key(id) do
    case Repo.get(IssuerKey, id) do
      {:ok, nil} -> {:error, :issuer_key_not_found}
      {:ok, key} -> {:ok, key}
      {:error, _} = err -> err
    end
  end

  defp guard_unique(ra_instance_id, issuer_key_id) do
    existing =
      list_connections(ra_instance_id)
      |> Enum.any?(fn c -> c.issuer_key_id == issuer_key_id end)

    if existing, do: {:error, :already_connected}, else: :ok
  end
end
