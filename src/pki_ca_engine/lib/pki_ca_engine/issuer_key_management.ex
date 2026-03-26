defmodule PkiCaEngine.IssuerKeyManagement do
  @moduledoc """
  Manages issuer key records and their status state machine.

  Issuer keys progress through a defined lifecycle:

      pending → active → suspended → active (re-activate)
      any status → archived (terminal)

  This module handles CRUD operations and status transitions.
  Actual cryptographic operations (key generation, signing) are
  handled by the Key Ceremony modules.
  """

  import Ecto.Query

  alias PkiCaEngine.Repo
  alias PkiCaEngine.Schema.IssuerKey

  # Valid status transitions: {from, to}
  @valid_transitions %{
    {"pending", "active"} => true,
    {"pending", "archived"} => true,
    {"active", "suspended"} => true,
    {"active", "archived"} => true,
    {"suspended", "active"} => true,
    {"suspended", "archived"} => true,
    {"archived", "archived"} => true
  }

  @doc """
  Creates an issuer key record for a CA instance.
  """
  @spec create_issuer_key(String.t(), map()) :: {:ok, IssuerKey.t()} | {:error, Ecto.Changeset.t()}
  def create_issuer_key(ca_instance_id, attrs) do
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    %IssuerKey{}
    |> IssuerKey.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Gets an issuer key by ID.
  """
  @spec get_issuer_key(String.t()) :: {:ok, IssuerKey.t()} | {:error, :not_found}
  def get_issuer_key(id) do
    case Repo.get(IssuerKey, id) do
      nil -> {:error, :not_found}
      key -> {:ok, key}
    end
  end

  @doc """
  Lists issuer keys for a CA instance, with optional status filter.
  """
  @spec list_issuer_keys(String.t(), keyword()) :: [IssuerKey.t()]
  def list_issuer_keys(ca_instance_id, opts \\ []) do
    query = from(k in IssuerKey, where: k.ca_instance_id == ^ca_instance_id)

    query =
      case Keyword.get(opts, :status) do
        nil -> query
        status -> from(k in query, where: k.status == ^status)
      end

    Repo.all(query)
  end

  @doc """
  Transitions an issuer key's status with state machine validation.

  Valid transitions:
  - pending → active
  - active → suspended
  - suspended → active
  - any → archived
  - archived → archived (noop)

  Invalid transitions return `{:error, {:invalid_transition, from, to}}`.
  """
  @spec update_status(IssuerKey.t(), String.t()) ::
          {:ok, IssuerKey.t()} | {:error, {:invalid_transition, String.t(), String.t()}}
  def update_status(%IssuerKey{} = key, new_status) do
    current = key.status

    if valid_transition?(current, new_status) do
      key
      |> IssuerKey.update_status_changeset(%{status: new_status})
      |> Repo.update()
    else
      {:error, {:invalid_transition, current, new_status}}
    end
  end

  @doc """
  Activates a pending issuer key by setting certificate data and status to "active".

  Only valid when the key's current status is "pending".
  """
  @spec activate_by_certificate(IssuerKey.t(), map()) ::
          {:ok, IssuerKey.t()} | {:error, {:invalid_status, String.t()}}
  def activate_by_certificate(%IssuerKey{status: "pending"} = key, cert_attrs) do
    key
    |> IssuerKey.activate_changeset(cert_attrs)
    |> Repo.update()
  end

  def activate_by_certificate(%IssuerKey{status: status}, _cert_attrs) do
    {:error, {:invalid_status, status}}
  end

  @doc """
  Stores certificate DER and PEM on the issuer key without changing its status.
  """
  @spec set_certificate(IssuerKey.t(), map()) ::
          {:ok, IssuerKey.t()} | {:error, Ecto.Changeset.t()}
  def set_certificate(%IssuerKey{} = key, cert_attrs) do
    key
    |> IssuerKey.certificate_changeset(cert_attrs)
    |> Repo.update()
  end

  defp valid_transition?(from, to) do
    Map.get(@valid_transitions, {from, to}, false)
  end
end
