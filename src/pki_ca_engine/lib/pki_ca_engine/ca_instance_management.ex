defmodule PkiCaEngine.CaInstanceManagement do
  @moduledoc """
  Manages CA instances and their hierarchy, including depth enforcement,
  role classification, and leaf-CA issuer key queries.
  """

  import Ecto.Query

  alias PkiCaEngine.{TenantRepo, Audit}
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey}

  @doc """
  Creates a CA instance. If attrs has parent_id, validates the parent exists.

  Returns `{:ok, ca}`, `{:error, :parent_not_found}`, or `{:error, changeset}`.
  """
  def create_ca_instance(tenant_id, attrs, opts \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    actor = Keyword.get(opts, :actor, %{actor_did: "system", actor_role: "system"})

    result =
      case Map.get(attrs, :parent_id) || Map.get(attrs, "parent_id") do
        nil ->
          %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()

        parent_id ->
          case repo.get(CaInstance, parent_id) do
            nil ->
              {:error, :parent_not_found}

            _parent ->
              %CaInstance{} |> CaInstance.changeset(attrs) |> repo.insert()
          end
      end

    case result do
      {:ok, ca} ->
        Audit.log(tenant_id, actor, "ca_instance_created",
          %{resource_type: "ca_instance", resource_id: ca.id, details: %{name: ca.name, parent_id: ca.parent_id}})
        {:ok, ca}

      error -> error
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
    |> repo.preload([:issuer_keys, children: [:children, :issuer_keys]])
  end

  @doc """
  Updates a CA instance's status.

  Rules:
  - Suspend: cascades to all children recursively
  - Activate: blocked if parent is suspended (must activate parent first)
  - Activate: children stay suspended (must be manually activated)
  """
  def update_status(tenant_id, id, status, opts \\ [])

  def update_status(tenant_id, id, "suspended", opts) do
    actor = Keyword.get(opts, :actor, %{actor_did: "system", actor_role: "system"})
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil ->
        {:error, :not_found}

      ca ->
        case ca |> CaInstance.changeset(%{status: "suspended"}) |> repo.update() do
          {:ok, updated} ->
            Audit.log(tenant_id, actor, "ca_instance_status_changed",
              %{resource_type: "ca_instance", resource_id: id, ca_instance_id: id, details: %{name: ca.name, from: ca.status, to: "suspended"}})
            suspend_children(tenant_id, repo, id, actor)
            {:ok, updated}

          error ->
            error
        end
    end
  end

  def update_status(tenant_id, id, "active", opts) do
    actor = Keyword.get(opts, :actor, %{actor_did: "system", actor_role: "system"})
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil ->
        {:error, :not_found}

      %{parent_id: nil} = ca ->
        case ca |> CaInstance.changeset(%{status: "active"}) |> repo.update() do
          {:ok, updated} ->
            Audit.log(tenant_id, actor, "ca_instance_status_changed",
              %{resource_type: "ca_instance", resource_id: id, ca_instance_id: id, details: %{name: ca.name, from: ca.status, to: "active"}})
            {:ok, updated}
          error -> error
        end

      %{parent_id: parent_id} = ca ->
        case repo.get(CaInstance, parent_id) do
          %{status: "active"} ->
            case ca |> CaInstance.changeset(%{status: "active"}) |> repo.update() do
              {:ok, updated} ->
                Audit.log(tenant_id, actor, "ca_instance_status_changed",
                  %{resource_type: "ca_instance", resource_id: id, ca_instance_id: id, details: %{name: ca.name, from: ca.status, to: "active"}})
                {:ok, updated}
              error -> error
            end

          %{status: parent_status} ->
            {:error, {:parent_suspended, "Cannot activate: parent CA is #{parent_status}. Activate the parent first."}}

          nil ->
            {:error, :parent_not_found}
        end
    end
  end

  def update_status(tenant_id, id, new_status, _opts) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> ca |> CaInstance.changeset(%{status: new_status}) |> repo.update()
    end
  end

  defp suspend_children(tenant_id, repo, parent_id, actor \\ %{actor_did: "system", actor_role: "system"}) do
    children =
      CaInstance
      |> where([c], c.parent_id == ^parent_id)
      |> repo.all()

    Enum.each(children, fn child ->
      case child |> CaInstance.changeset(%{status: "suspended"}) |> repo.update() do
        {:ok, _} ->
          Audit.log(tenant_id, actor, "ca_instance_status_changed",
            %{resource_type: "ca_instance", resource_id: child.id, ca_instance_id: child.id,
              details: %{name: child.name, from: child.status, to: "suspended", reason: "parent_suspended"}})
        _ -> :ok
      end
      suspend_children(tenant_id, repo, child.id, actor)
    end)
  end

  @doc """
  Sets a CA instance offline. Used by ceremony completion to auto-offline root CAs.

  Returns `{:ok, ca}` or `{:error, :not_found}`.
  """
  def set_offline(tenant_id, ca_instance_id) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(CaInstance, ca_instance_id) do
      nil ->
        {:error, :not_found}

      ca ->
        ca
        |> CaInstance.changeset(%{is_offline: true})
        |> repo.update()
        |> case do
          {:ok, updated} ->
            Audit.log(tenant_id, %{actor_did: "system", actor_role: "system"},
              "ca_instance_auto_offline",
              %{resource_type: "ca_instance", resource_id: ca_instance_id,
                ca_instance_id: ca_instance_id,
                details: %{name: ca.name, reason: "root_ca_ceremony_completed"}})
            {:ok, updated}

          error ->
            error
        end
    end
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
