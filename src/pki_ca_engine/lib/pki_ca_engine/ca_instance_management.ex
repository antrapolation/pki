defmodule PkiCaEngine.CaInstanceManagement do
  @moduledoc """
  CA instance CRUD and hierarchy management.
  Rewritten against Mnesia (was Ecto/PostgreSQL).
  """

  alias PkiMnesia.Repo
  alias PkiMnesia.Structs.CaInstance

  def create_ca_instance(attrs) do
    ca = CaInstance.new(attrs)
    Repo.insert(ca)
  end

  def get_ca_instance(id) do
    case Repo.get(CaInstance, id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ca} -> {:ok, ca}
      {:error, _} = err -> err
    end
  end

  def list_ca_instances do
    Repo.all(CaInstance)
  end

  def is_root?(%CaInstance{is_root: true}), do: true
  def is_root?(_), do: false

  def is_leaf?(ca) do
    case Repo.where(CaInstance, fn c -> c.parent_id == ca.id end) do
      {:ok, children} -> children == []
      {:error, _} -> false
    end
  end

  def set_offline(ca_instance_id) do
    case Repo.get(CaInstance, ca_instance_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ca} -> Repo.update(ca, %{is_offline: true, updated_at: DateTime.utc_now() |> DateTime.truncate(:second)})
      {:error, _} = err -> err
    end
  end

  def set_online(ca_instance_id) do
    case Repo.get(CaInstance, ca_instance_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ca} -> Repo.update(ca, %{is_offline: false, updated_at: DateTime.utc_now() |> DateTime.truncate(:second)})
      {:error, _} = err -> err
    end
  end

  @doc "Rename a CA instance. Trims whitespace; rejects empty."
  def update_name(ca_instance_id, new_name) when is_binary(new_name) do
    trimmed = String.trim(new_name)

    if trimmed == "" do
      {:error, :empty_name}
    else
      case Repo.get(CaInstance, ca_instance_id) do
        {:ok, nil} -> {:error, :not_found}
        {:ok, ca} ->
          Repo.update(ca, %{
            name: trimmed,
            updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
          })
        {:error, _} = err -> err
      end
    end
  end

  def update_name(_ca_instance_id, _), do: {:error, :empty_name}

  @valid_statuses ["active", "inactive", "suspended"]

  @doc """
  Update a CA instance's status. Does NOT cascade to children yet — that
  rule is tracked as a TODO in the product spec. Current caller surface
  is the LiveView which only flips status on one instance at a time.

  Valid statuses: "active" | "inactive" | "suspended".
  """
  def update_status(ca_instance_id, new_status) when new_status in @valid_statuses do
    case Repo.get(CaInstance, ca_instance_id) do
      {:ok, nil} -> {:error, :not_found}
      {:ok, ca} ->
        Repo.update(ca, %{
          status: new_status,
          updated_at: DateTime.utc_now() |> DateTime.truncate(:second)
        })
      {:error, _} = err -> err
    end
  end

  def update_status(_, _), do: {:error, :invalid_status}
end
