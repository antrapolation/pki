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

  alias PkiCaEngine.TenantRepo
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
  @spec create_issuer_key(term(), String.t(), map()) :: {:ok, IssuerKey.t()} | {:error, Ecto.Changeset.t()}
  def create_issuer_key(tenant_id, ca_instance_id, attrs) do
    repo = TenantRepo.ca_repo(tenant_id)
    attrs = Map.put(attrs, :ca_instance_id, ca_instance_id)

    %IssuerKey{}
    |> IssuerKey.changeset(attrs)
    |> repo.insert()
  end

  @doc """
  Gets an issuer key by ID.
  """
  @spec get_issuer_key(term(), String.t()) :: {:ok, IssuerKey.t()} | {:error, :not_found}
  def get_issuer_key(tenant_id, id) do
    repo = TenantRepo.ca_repo(tenant_id)

    case repo.get(IssuerKey, id) do
      nil -> {:error, :not_found}
      key -> {:ok, key}
    end
  end

  @doc """
  Lists issuer keys for a CA instance, with optional status filter.
  """
  @spec list_issuer_keys(term(), String.t(), keyword()) :: [IssuerKey.t()]
  def list_issuer_keys(tenant_id, ca_instance_id, opts \\ []) do
    repo = TenantRepo.ca_repo(tenant_id)
    query = from(k in IssuerKey, where: k.ca_instance_id == ^ca_instance_id)

    query =
      case Keyword.get(opts, :status) do
        nil -> query
        status -> from(k in query, where: k.status == ^status)
      end

    repo.all(query)
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
  @spec update_status(term(), IssuerKey.t(), String.t()) ::
          {:ok, IssuerKey.t()} | {:error, {:invalid_transition, String.t(), String.t()}}
  def update_status(tenant_id, %IssuerKey{} = key, new_status) do
    repo = TenantRepo.ca_repo(tenant_id)
    current = key.status

    if valid_transition?(current, new_status) do
      with :ok <- maybe_pre_archive_check(key, new_status) do
        key
        |> IssuerKey.update_status_changeset(%{status: new_status})
        |> repo.update()
      end
    else
      {:error, {:invalid_transition, current, new_status}}
    end
  end

  @doc """
  Activates a pending issuer key by setting certificate data and status to "active".

  Only valid when the key's current status is "pending".
  """
  @spec activate_by_certificate(term(), IssuerKey.t(), map()) ::
          {:ok, IssuerKey.t()} | {:error, {:invalid_status, String.t()}}
  def activate_by_certificate(tenant_id, %IssuerKey{status: "pending"} = key, cert_attrs) do
    repo = TenantRepo.ca_repo(tenant_id)

    key
    |> IssuerKey.activate_changeset(cert_attrs)
    |> repo.update()
  end

  def activate_by_certificate(_tenant_id, %IssuerKey{status: status}, _cert_attrs) do
    {:error, {:invalid_status, status}}
  end

  @doc """
  Stores certificate DER and PEM on the issuer key without changing its status.
  """
  @spec set_certificate(term(), IssuerKey.t(), map()) ::
          {:ok, IssuerKey.t()} | {:error, Ecto.Changeset.t()}
  def set_certificate(tenant_id, %IssuerKey{} = key, cert_attrs) do
    repo = TenantRepo.ca_repo(tenant_id)

    key
    |> IssuerKey.certificate_changeset(cert_attrs)
    |> repo.update()
  end

  # Cross-engine integration point: cert profiles live in the RA database,
  # so the CA engine cannot directly query whether active profiles reference
  # this issuer key.  Configure :pki_ca_engine, :archive_check_fn with a
  # 1-arity function (receives key id) that returns :ok or {:error, reason}.
  # When wired up, the RA engine adapter will check for active cert profile
  # references and block archival if any exist.  Until then, the permissive
  # default allows archival unconditionally.
  defp maybe_pre_archive_check(_key, status) when status != "archived", do: :ok

  defp maybe_pre_archive_check(%IssuerKey{} = key, "archived") do
    pre_archive_check(key)
  end

  defp pre_archive_check(%IssuerKey{} = key) do
    case Application.get_env(:pki_ca_engine, :archive_check_fn) do
      nil ->
        # No check configured — allow (will be wired to RA engine later)
        :ok

      check_fn when is_function(check_fn, 1) ->
        check_fn.(key.id)
    end
  end

  defp valid_transition?(from, to) do
    Map.get(@valid_transitions, {from, to}, false)
  end
end
