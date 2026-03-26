defmodule PkiCaEngine.KeypairAccessControl do
  @moduledoc """
  Binds selected private keys to users that are allowed to access them.

  Tracks who granted access and when, enforcing a unique constraint
  so duplicate grants are rejected.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.KeypairAccess

  @doc """
  Grants a user access to a key, recording who granted it.
  """
  @spec grant_access(String.t(), String.t(), String.t()) :: {:ok, KeypairAccess.t()} | {:error, Ecto.Changeset.t()}
  def grant_access(issuer_key_id, user_id, granted_by) do
    %KeypairAccess{}
    |> KeypairAccess.changeset(%{
      issuer_key_id: issuer_key_id,
      user_id: user_id,
      granted_by: granted_by,
      granted_at: DateTime.utc_now() |> DateTime.truncate(:second)
    })
    |> Repo.insert()
  end

  @doc """
  Revokes a user's access to a key (deletes the record).
  Returns `{:ok, count}` where count is the number of deleted records.
  """
  @spec revoke_access(String.t(), String.t()) :: {:ok, non_neg_integer()}
  def revoke_access(issuer_key_id, user_id) do
    {count, _} =
      from(a in KeypairAccess,
        where: a.issuer_key_id == ^issuer_key_id and a.user_id == ^user_id
      )
      |> Repo.delete_all()

    {:ok, count}
  end

  @doc """
  Returns true if the user has access to the given key.
  """
  @spec has_access?(String.t(), String.t()) :: boolean()
  def has_access?(issuer_key_id, user_id) do
    from(a in KeypairAccess,
      where: a.issuer_key_id == ^issuer_key_id and a.user_id == ^user_id
    )
    |> Repo.exists?()
  end

  @doc """
  Lists all access records for a given key.
  """
  @spec list_access(String.t()) :: [KeypairAccess.t()]
  def list_access(issuer_key_id) do
    from(a in KeypairAccess, where: a.issuer_key_id == ^issuer_key_id)
    |> Repo.all()
  end

  @doc """
  Lists all access records for a given user.
  """
  @spec list_keys_for_user(String.t()) :: [KeypairAccess.t()]
  def list_keys_for_user(user_id) do
    from(a in KeypairAccess, where: a.user_id == ^user_id)
    |> Repo.all()
  end
end
