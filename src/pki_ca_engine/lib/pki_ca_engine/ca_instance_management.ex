defmodule PkiCaEngine.CaInstanceManagement do
  @moduledoc """
  Manages CA instances and their hierarchy, including depth enforcement,
  role classification, and leaf-CA issuer key queries.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.{CaInstance, IssuerKey}

  @doc """
  Creates a CA instance. If attrs has parent_id, checks that the resulting
  depth does not exceed `max_ca_depth` (default 2).

  Returns `{:ok, ca}`, `{:error, :max_depth_exceeded}`,
  `{:error, :parent_not_found}`, or `{:error, changeset}`.
  """
  def create_ca_instance(attrs, opts \\ []) do
    max_depth = Keyword.get(opts, :max_ca_depth, 2)

    case Map.get(attrs, :parent_id) do
      nil ->
        %CaInstance{} |> CaInstance.changeset(attrs) |> Repo.insert()

      parent_id ->
        case Repo.get(CaInstance, parent_id) do
          nil ->
            {:error, :parent_not_found}

          parent ->
            if depth(parent) >= max_depth do
              {:error, :max_depth_exceeded}
            else
              %CaInstance{} |> CaInstance.changeset(attrs) |> Repo.insert()
            end
        end
    end
  end

  @doc """
  Gets a single CA instance with children and issuer_keys preloaded.
  Returns `{:ok, ca}` or `{:error, :not_found}`.
  """
  def get_ca_instance(id) do
    case Repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> {:ok, Repo.preload(ca, [:children, :issuer_keys])}
    end
  end

  @doc "Returns true if the CA instance is a root (no parent)."
  def is_root?(%CaInstance{parent_id: nil}), do: true
  def is_root?(%CaInstance{}), do: false

  @doc "Returns true if the CA instance has no children in the database."
  def is_leaf?(%CaInstance{} = ca) do
    not Repo.exists?(from c in CaInstance, where: c.parent_id == ^ca.id)
  end

  @doc "Returns the depth of a CA instance (root = 1). Walks up the parent chain."
  def depth(%CaInstance{parent_id: nil}), do: 1

  def depth(%CaInstance{parent_id: parent_id}) do
    parent = Repo.get!(CaInstance, parent_id)
    1 + depth(parent)
  end

  @doc "Returns the role: `:root`, `:intermediate`, or `:issuing`."
  def role(%CaInstance{} = ca) do
    cond do
      is_root?(ca) -> :root
      is_leaf?(ca) -> :issuing
      true -> :intermediate
    end
  end

  @doc "Lists all root CA instances with children preloaded two levels deep."
  def list_hierarchy do
    CaInstance
    |> where([c], is_nil(c.parent_id))
    |> Repo.all()
    |> Repo.preload(children: [:children, :issuer_keys])
  end

  @doc "Updates a CA instance's status."
  def update_status(id, new_status) do
    case Repo.get(CaInstance, id) do
      nil -> {:error, :not_found}
      ca -> ca |> CaInstance.changeset(%{status: new_status}) |> Repo.update()
    end
  end

  @doc """
  Returns issuer keys that belong to leaf CA instances only.
  A leaf CA is one whose id does NOT appear as parent_id in any other ca_instance.
  """
  def leaf_ca_issuer_keys do
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id)
    )
    |> Repo.all()
    |> Repo.preload(:ca_instance)
  end

  @doc "Same as `leaf_ca_issuer_keys/0` but filtered to status=\"active\" keys only."
  def active_leaf_issuer_keys do
    non_leaf_ids = from(c in CaInstance, where: not is_nil(c.parent_id), select: c.parent_id)

    from(k in IssuerKey,
      where: k.ca_instance_id not in subquery(non_leaf_ids),
      where: not is_nil(k.ca_instance_id),
      where: k.status == "active"
    )
    |> Repo.all()
    |> Repo.preload(:ca_instance)
  end
end
