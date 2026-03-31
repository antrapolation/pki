defmodule PkiCaEngine.CaInstanceManagement do
  @moduledoc """
  Manages CA instances and their hierarchy, including depth enforcement,
  role classification, and leaf-CA issuer key queries.
  """

  import Ecto.Query

  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey}

  @doc """
  Creates a CA instance. If attrs has parent_id, checks that the resulting
  depth does not exceed `max_ca_depth` (default 2).

  Returns `{:ok, ca}`, `{:error, :max_depth_exceeded}`,
  `{:error, :parent_not_found}`, or `{:error, changeset}`.
  """
  def create_ca_instance(tenant_id, attrs, opts \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    max_depth = Keyword.get(opts, :max_ca_depth, 2)

    case Map.get(attrs, :parent_id) || Map.get(attrs, "parent_id") do
      nil ->
        %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()

      parent_id ->
        case repo.get(CaInstance, parent_id) do
          nil ->
            {:error, :parent_not_found}

          parent ->
            if depth(tenant_id, parent) >= max_depth do
              {:error, :max_depth_exceeded}
            else
              %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()
            end
        end
    end
  end

  @doc """
  Gets a single CA instance with children and issuer_keys preloaded.
  Returns `{:ok, ca}` or `{:error, :not_found}`.
  """
  def get_ca_instance(tenant_id, id) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> {:ok, repo.preload(ca, [:children, :issuer_keys])}
    end
  end

  @doc "Returns true if the CA instance is a root (no parent)."
  def is_root?(%CaInstance{parent_id: nil}), do: true
  def is_root?(%CaInstance{}), do: false

  @doc "Returns true if the CA instance has no children in the database."
  def is_leaf?(%CaInstance{} = ca), do: is_leaf?(nil, ca)

  def is_leaf?(tenant_id, %CaInstance{} = ca) do
    repo = TenantRepo.ca_repo(tenant_id)
    not repo.exists?(from c in CaInstance, where: c.parent_id == ^ca.id)
  end

  @doc "Returns the depth of a CA instance (root = 1). Walks up the parent chain."
  def depth(%CaInstance{} = ca), do: depth(nil, ca)

  def depth(_tenant_id, %CaInstance{parent_id: nil}), do: 1
  def depth(tenant_id, %CaInstance{parent_id: parent_id}) do
    repo = TenantRepo.ca_repo(tenant_id)
    do_depth(repo, parent_id, 2)
  end

  defp do_depth(_repo, _parent_id, acc) when acc > 20, do: acc
  defp do_depth(repo, parent_id, acc) do
    case repo.get(CaInstance, parent_id) do
      nil -> acc
      %CaInstance{parent_id: nil} -> acc
      %CaInstance{parent_id: next_parent} -> do_depth(repo, next_parent, acc + 1)
    end
  end

  @doc "Returns the role: `:root`, `:intermediate`, or `:issuing`."
  def role(%CaInstance{} = ca), do: role(nil, ca)

  def role(tenant_id, %CaInstance{} = ca) do
    cond do
      is_root?(ca) -> :root
      is_leaf?(tenant_id, ca) -> :issuing
      true -> :intermediate
    end
  end

  @doc "Lists all root CA instances with children preloaded two levels deep."
  def list_hierarchy(tenant_id) do
    repo = TenantRepo.ca_repo(tenant_id)

    CaInstance
    |> where([c], is_nil(c.parent_id))
    |> repo.all()
    |> repo.preload(children: [:children, :issuer_keys])
  end

  @doc """
  Updates a CA instance's status.

  Rules:
  - Suspend: cascades to all children recursively
  - Activate: blocked if parent is suspended (must activate parent first)
  - Activate: children stay suspended (must be manually activated)
  """
  def update_status(tenant_id, id, "suspended") do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil ->
        {:error, :not_found}

      ca ->
        # Suspend this instance
        case ca |> CaInstance.changeset(%{status: "suspended"}) |> repo.update() do
          {:ok, updated} ->
            # Cascade: suspend all children recursively
            suspend_children(tenant_id, repo, id)
            {:ok, updated}

          error ->
            error
        end
    end
  end

  def update_status(tenant_id, id, "active") do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil ->
        {:error, :not_found}

      %{parent_id: nil} = ca ->
        # Root CA — no parent to check
        ca |> CaInstance.changeset(%{status: "active"}) |> repo.update()

      %{parent_id: parent_id} = ca ->
        # Check parent is active before allowing activation
        case repo.get(CaInstance, parent_id) do
          %{status: "active"} ->
            ca |> CaInstance.changeset(%{status: "active"}) |> repo.update()

          %{status: parent_status} ->
            {:error, {:parent_suspended, "Cannot activate: parent CA is #{parent_status}. Activate the parent first."}}

          nil ->
            {:error, :parent_not_found}
        end
    end
  end

  def update_status(tenant_id, id, new_status) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> ca |> CaInstance.changeset(%{status: new_status}) |> repo.update()
    end
  end

  defp suspend_children(tenant_id, repo, parent_id) do
    children =
      CaInstance
      |> where([c], c.parent_id == ^parent_id)
      |> repo.all()

    Enum.each(children, fn child ->
      child |> CaInstance.changeset(%{status: "suspended"}) |> repo.update()
      suspend_children(tenant_id, repo, child.id)
    end)
  end

  @doc "Renames a CA instance."
  def rename(tenant_id, id, new_name) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> ca |> CaInstance.changeset(%{name: new_name}) |> repo.update()
    end
  end

  @doc """
  Returns issuer keys that belong to leaf CA instances only.
  A leaf CA is one whose id does NOT appear as parent_id in any other ca_instance.
  """
  def leaf_ca_issuer_keys(tenant_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id)
    )
    |> repo.all()
    |> repo.preload(:ca_instance)
  end

  @doc "Same as `leaf_ca_issuer_keys/1` but filtered to status=\"active\" keys only."
  def active_leaf_issuer_keys(tenant_id) do
    repo = TenantRepo.ca_repo(tenant_id)
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id),
      where: k.status == "active"
    )
    |> repo.all()
    |> repo.preload(:ca_instance)
  end
end
