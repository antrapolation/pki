defmodule PkiPlatformEngine.TenantRegistry do
  @moduledoc """
  ETS-based registry for tenant Repo PIDs/names.

  Maps tenant_id → %{ca_repo: name, ra_repo: name, audit_repo: name, slug: slug}
  Also indexes by slug for portal lookups (user session carries slug).
  """
  use GenServer

  # Client API

  def start_link(opts \\ []) do
    name = Keyword.get(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  def register(registry \\ __MODULE__, tenant_id, refs) do
    GenServer.call(registry, {:register, tenant_id, refs})
  end

  def unregister(registry \\ __MODULE__, tenant_id) do
    GenServer.call(registry, {:unregister, tenant_id})
  end

  def lookup(registry \\ __MODULE__, tenant_id) do
    case :ets.lookup(resolve_table(registry), {:id, tenant_id}) do
      [{_, refs}] -> {:ok, refs}
      [] -> {:error, :not_found}
    end
  end

  def lookup_by_slug(registry \\ __MODULE__, slug) do
    case :ets.lookup(resolve_table(registry), {:slug, slug}) do
      [{_, tenant_id}] -> lookup(registry, tenant_id)
      [] -> {:error, :not_found}
    end
  end

  @doc """
  Returns the CA repo for a tenant, setting the schema prefix in the process dictionary.

  WARNING: For schema-mode tenants, this sets `:pki_ecto_prefix` in the process dict.
  The prefix persists until overwritten or cleared. In HTTP requests, the
  `ClearTenantPrefix` plug handles cleanup. For LiveView, each handle_event is
  sequential per process so the prefix is safe as long as a single event handler
  doesn't mix tenants. Use `with_ca_repo/3` for explicit scoping if needed.
  """
  def ca_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{schema_mode: "schema", ca_prefix: prefix}} ->
        Process.put(:pki_ecto_prefix, prefix)
        PkiCaEngine.Repo
      {:ok, %{ca_repo: repo}} -> repo
      _ -> raise "No CA repo for tenant #{tenant_id}"
    end
  end

  def ra_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{schema_mode: "schema", ra_prefix: prefix}} ->
        Process.put(:pki_ecto_prefix, prefix)
        PkiRaEngine.Repo
      {:ok, %{ra_repo: repo}} -> repo
      _ -> raise "No RA repo for tenant #{tenant_id}"
    end
  end

  def audit_repo(registry \\ __MODULE__, tenant_id) do
    case lookup(registry, tenant_id) do
      {:ok, %{schema_mode: "schema", audit_prefix: prefix}} ->
        Process.put(:pki_ecto_prefix, prefix)
        PkiAuditTrail.Repo
      {:ok, %{audit_repo: repo}} -> repo
      _ -> raise "No audit repo for tenant #{tenant_id}"
    end
  end

  @doc """
  Scope-safe variant: sets the prefix, runs the callback, then restores the
  previous prefix value. Use when a single process may access multiple tenants.

      TenantRegistry.with_ca_repo(tenant_id, fn repo ->
        repo.all(IssuerKey)
      end)
  """
  def with_ca_repo(registry \\ __MODULE__, tenant_id, fun) do
    previous = Process.get(:pki_ecto_prefix)
    repo = ca_repo(registry, tenant_id)
    try do
      fun.(repo)
    after
      if previous, do: Process.put(:pki_ecto_prefix, previous), else: Process.delete(:pki_ecto_prefix)
    end
  end

  def with_ra_repo(registry \\ __MODULE__, tenant_id, fun) do
    previous = Process.get(:pki_ecto_prefix)
    repo = ra_repo(registry, tenant_id)
    try do
      fun.(repo)
    after
      if previous, do: Process.put(:pki_ecto_prefix, previous), else: Process.delete(:pki_ecto_prefix)
    end
  end

  def with_audit_repo(registry \\ __MODULE__, tenant_id, fun) do
    previous = Process.get(:pki_ecto_prefix)
    repo = audit_repo(registry, tenant_id)
    try do
      fun.(repo)
    after
      if previous, do: Process.put(:pki_ecto_prefix, previous), else: Process.delete(:pki_ecto_prefix)
    end
  end

  def list_tenants(registry \\ __MODULE__) do
    :ets.match(resolve_table(registry), {{:id, :"$1"}, :"$2"})
    |> Enum.map(fn [id, refs] -> Map.put(refs, :tenant_id, id) end)
  end

  @doc "Returns the ETS table name for a registry process."
  def table_name(registry \\ __MODULE__) do
    GenServer.call(registry, :table_name)
  end

  # Server

  @impl true
  def init(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    table = :ets.new(ets_name(name), [:set, :public, :named_table, read_concurrency: true])
    {:ok, %{table: table, name: name}}
  end

  @impl true
  def handle_call(:table_name, _from, state) do
    {:reply, state.table, state}
  end

  @impl true
  def handle_call({:register, tenant_id, refs}, _from, state) do
    :ets.insert(state.table, {{:id, tenant_id}, refs})
    if slug = refs[:slug], do: :ets.insert(state.table, {{:slug, slug}, tenant_id})
    {:reply, :ok, state}
  end

  @impl true
  def handle_call({:unregister, tenant_id}, _from, state) do
    case :ets.lookup(state.table, {:id, tenant_id}) do
      [{_, refs}] ->
        :ets.delete(state.table, {:id, tenant_id})
        if slug = refs[:slug], do: :ets.delete(state.table, {:slug, slug})

      [] ->
        :ok
    end

    {:reply, :ok, state}
  end

  # Resolve the ETS table reference from a registry name (atom) or PID.
  # Atom names have a predictable ETS table name; PIDs require a GenServer call.
  defp resolve_table(name) when is_atom(name), do: ets_name(name)
  defp resolve_table(pid) when is_pid(pid), do: GenServer.call(pid, :table_name)

  defp ets_name(name) when is_atom(name), do: :"#{name}_ets"
end
