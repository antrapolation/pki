defmodule PkiRaPortal.RaEngineClient.Direct do
  @moduledoc """
  Direct (in-process) implementation of the RA engine client.

  Calls RA engine modules directly via Elixir function calls instead of HTTP.
  Converts Ecto structs returned by engine modules into plain maps with atom keys
  to match the contract expected by the portal.
  """

  @behaviour PkiRaPortal.RaEngineClient

  require Logger

  # --- Auth endpoints ---

  @impl true
  def authenticate(username, password) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ra") do
      {:ok, user, role} ->
        {:ok, %{
          id: user.id,
          username: user.username,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def authenticate_with_session(username, password) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ra") do
      {:ok, user, role} ->
        user_map = %{
          id: user.id,
          username: user.username,
          email: user.email,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }
        {:ok, user_map, %{}}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def register_user(attrs) do
    case PkiRaEngine.UserManagement.register_user(nil, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def needs_setup? do
    PkiRaEngine.UserManagement.needs_setup?(nil)
  end

  @impl true
  def needs_setup?(tenant_id) do
    PkiRaEngine.UserManagement.needs_setup?(tenant_id)
  end

  @impl true
  def get_user_by_username(username, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.get_user_by_username(tenant_id, username) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_password(user_id, new_password, opts \\ []) do
    tenant_id = opts[:tenant_id]

    with {:ok, user} <- PkiRaEngine.UserManagement.get_user(tenant_id, user_id),
         {:ok, _} <- PkiRaEngine.UserManagement.update_user_password(tenant_id, user, %{password: new_password}) do
      :ok
    end
  end

  @impl true
  def update_user_profile(user_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.update_user_profile(tenant_id, user_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, format_changeset_errors(cs)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.verify_and_change_password(tenant_id, user_id, current_password, new_password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, :invalid_current_password} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, format_changeset_errors(cs)}
      {:error, _} = err -> err
    end
  end

  # --- User management ---

  @impl true
  def list_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    filters = Keyword.drop(opts, [:tenant_id])

    users = PkiRaEngine.UserManagement.list_users(tenant_id, filters)
    {:ok, Enum.map(users, &to_map/1)}
  end

  @impl true
  def create_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.create_user(tenant_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def create_user(attrs, admin_context, opts) do
    tenant_id = opts[:tenant_id]

    merged_attrs =
      attrs
      |> Map.put(:admin_user_id, admin_context[:user_id] || admin_context["user_id"])
      |> Map.put(:admin_password, admin_context[:password] || admin_context["password"])

    case PkiRaEngine.UserManagement.create_user(tenant_id, merged_attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.UserManagement.delete_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _} = err -> err
    end
  end

  # --- CSR management ---

  @impl true
  def list_csrs(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]

    csrs = PkiRaEngine.CsrValidation.list_csrs(tenant_id, filters)
    {:ok, Enum.map(csrs, &to_map/1)}
  end

  @impl true
  def get_csr(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CsrValidation.get_csr(tenant_id, id) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def approve_csr(id, meta, opts \\ []) do
    tenant_id = opts[:tenant_id]
    reviewer_user_id = meta[:reviewer_user_id] || meta["reviewer_user_id"]

    case PkiRaEngine.CsrValidation.approve_csr(tenant_id, id, reviewer_user_id) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def reject_csr(id, reason, meta, opts \\ []) do
    tenant_id = opts[:tenant_id]
    reviewer_user_id = meta[:reviewer_user_id] || meta["reviewer_user_id"]

    case PkiRaEngine.CsrValidation.reject_csr(tenant_id, id, reviewer_user_id, reason) do
      {:ok, csr} -> {:ok, to_map(csr)}
      {:error, _} = err -> err
    end
  end

  # --- Cert profiles ---

  @impl true
  def list_cert_profiles(opts \\ []) do
    tenant_id = opts[:tenant_id]

    profiles = PkiRaEngine.CertProfileConfig.list_profiles(tenant_id)
    {:ok, Enum.map(profiles, &to_map/1)}
  end

  @impl true
  def create_cert_profile(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.create_profile(tenant_id, attrs) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def update_cert_profile(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.update_profile(tenant_id, id, attrs) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_cert_profile(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CertProfileConfig.delete_profile(tenant_id, id) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  # --- Service configs ---

  @impl true
  def list_service_configs(opts \\ []) do
    tenant_id = opts[:tenant_id]

    configs = PkiRaEngine.ServiceConfig.list_service_configs(tenant_id)
    {:ok, Enum.map(configs, &to_map/1)}
  end

  @impl true
  def configure_service(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ServiceConfig.configure_service(tenant_id, attrs) do
      {:ok, config} -> {:ok, to_map(config)}
      {:error, _} = err -> err
    end
  end

  # --- RA instances ---

  @impl true
  def list_ra_instances(opts \\ []) do
    tenant_id = opts[:tenant_id]

    instances = PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id)
    {:ok, Enum.map(instances, &to_map/1)}
  end

  @impl true
  def create_ra_instance(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant_id, attrs) do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def available_issuer_keys(opts \\ []) do
    tenant_id = opts[:tenant_id]

    keys = PkiCaEngine.CaInstanceManagement.active_leaf_issuer_keys(tenant_id)
    {:ok, Enum.map(keys, &to_map/1)}
  end

  # --- API keys ---

  @impl true
  def list_api_keys(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    ra_user_id = filters[:ra_user_id] || filters["ra_user_id"]

    keys = PkiRaEngine.ApiKeyManagement.list_keys(tenant_id, ra_user_id)
    {:ok, Enum.map(keys, &to_map/1)}
  end

  @impl true
  def create_api_key(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.create_api_key(tenant_id, attrs) do
      {:ok, key} -> {:ok, to_map(key)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def revoke_api_key(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.revoke_key(tenant_id, id) do
      {:ok, key} -> {:ok, to_map(key)}
      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Platform-level User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_portal_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    {:ok, PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ra")}
  end

  @impl true
  def create_portal_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ra_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant_id, "ra", attrs,
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, user} ->
        PkiPlatformEngine.PlatformAudit.log("user_created", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user.id,
          tenant_id: tenant_id,
          portal: "ra",
          details: %{username: user.username, role: attrs[:role] || attrs["role"]}
        })
        {:ok, %{id: user.id, username: user.username, display_name: user.display_name, email: user.email}}

      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, format_changeset_errors(cs)}}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def suspend_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.suspend_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_suspended", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ra"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def activate_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.activate_user_role(role_id) do
      {:ok, role} ->
        PkiPlatformEngine.PlatformAudit.log("user_activated", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ra"
        })
        {:ok, %{id: role.id, status: role.status}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def delete_user_role(role_id, opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.delete_user_role(role_id) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("user_deleted", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_tenant_role",
          target_id: role_id,
          tenant_id: opts[:tenant_id],
          portal: "ra"
        })
        {:ok, %{id: role_id}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_user_password(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ra_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    role_label = case PkiPlatformEngine.PlatformAuth.get_tenant_roles_any_status(user_id, portal: "ra") do
      [role | _] -> PkiPlatformEngine.PlatformAuth.format_role_label(role.role, "ra")
      [] -> "RA User"
    end

    case PkiPlatformEngine.PlatformAuth.reset_user_password(user_id, "ra",
      portal_url: portal_url,
      tenant_name: tenant_name,
      role_label: role_label
    ) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("password_reset", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: tenant_id,
          portal: "ra"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  @impl true
  def resend_invitation(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ra_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.resend_invitation(user_id, "ra",
      portal_url: portal_url,
      tenant_name: tenant_name
    ) do
      {:ok, _} ->
        PkiPlatformEngine.PlatformAudit.log("invitation_resent", %{
          actor_id: opts[:actor_id],
          actor_username: opts[:actor_username],
          target_type: "user_profile",
          target_id: user_id,
          tenant_id: tenant_id,
          portal: "ra"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  # --- Certificates (issued CSRs) ---

  @impl true
  def list_certificates(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]

    import Ecto.Query

    query =
      PkiRaEngine.Schema.CsrRequest
      |> where([c], c.status == "issued")
      |> order_by([c], desc: c.reviewed_at)

    query = case Keyword.get(filters, :status) do
      "active" -> where(query, [c], not is_nil(c.issued_cert_serial))
      "revoked" -> where(query, [c], is_nil(c.issued_cert_serial))
      _ -> query
    end

    query = if tenant_id do
      query
    else
      query
    end

    certs = PkiRaEngine.Repo.all(query) |> PkiRaEngine.Repo.preload(:cert_profile)
    {:ok, Enum.map(certs, &cert_to_map/1)}
  end

  @impl true
  def revoke_certificate(serial_number, reason, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CsrValidation.revoke_certificate(tenant_id, serial_number, reason) do
      {:ok, result} -> {:ok, result}
      {:error, _} = err -> err
    end
  end

  @impl true
  def get_certificate(serial, opts \\ []) do
    _tenant_id = opts[:tenant_id]

    import Ecto.Query

    case PkiRaEngine.Repo.one(
      from c in PkiRaEngine.Schema.CsrRequest,
        where: c.issued_cert_serial == ^serial,
        preload: [:cert_profile]
    ) do
      nil -> {:error, :not_found}
      csr -> {:ok, cert_to_map(csr)}
    end
  end

  defp cert_to_map(csr) do
    %{
      id: csr.id,
      serial_number: csr.issued_cert_serial,
      subject_dn: csr.subject_dn,
      status: "issued",
      cert_profile_id: csr.cert_profile_id,
      cert_profile_name: if(csr.cert_profile, do: csr.cert_profile.name, else: nil),
      submitted_at: csr.submitted_at,
      reviewed_at: csr.reviewed_at,
      reviewed_by: csr.reviewed_by
    }
  end

  @impl true
  def list_audit_events(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    full_filters = [{:tenant_id, tenant_id} | filters]
    events = PkiPlatformEngine.PlatformAudit.list_events(full_filters)
    {:ok, Enum.map(events, &to_map/1)}
  end

  defp get_tenant_name(nil), do: ""
  defp get_tenant_name(tenant_id) do
    case PkiPlatformEngine.PlatformRepo.get(PkiPlatformEngine.Tenant, tenant_id) do
      nil -> ""
      tenant -> tenant.name
    end
  end

  defp format_changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map_join(", ", fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
  end

  # --- DCV (Domain Control Validation) ---

  @impl true
  def start_dcv(csr_id, method, opts \\ []) do
    tenant_id = Keyword.get(opts, :tenant_id)
    user_id = Keyword.get(opts, :user_id)

    case PkiRaEngine.CsrValidation.get_csr(tenant_id, csr_id) do
      {:ok, csr} ->
        domain = extract_domain_from_dn(csr.subject_dn)
        timeout_hours = Keyword.get(opts, :timeout_hours, 24)
        PkiRaEngine.DcvChallenge.create(tenant_id, csr_id, domain, method, user_id, timeout_hours)

      error ->
        error
    end
  end

  @impl true
  def verify_dcv(csr_id, opts \\ []) do
    tenant_id = Keyword.get(opts, :tenant_id)

    case PkiRaEngine.DcvChallenge.get_for_csr(tenant_id, csr_id) do
      challenges when is_list(challenges) ->
        pending = Enum.find(challenges, &(&1.status == "pending"))

        if pending do
          PkiRaEngine.DcvChallenge.verify(tenant_id, pending.id)
        else
          {:error, :no_pending_challenge}
        end

      error ->
        error
    end
  end

  @impl true
  def get_dcv_status(csr_id, opts \\ []) do
    tenant_id = Keyword.get(opts, :tenant_id)
    PkiRaEngine.DcvChallenge.get_for_csr(tenant_id, csr_id)
  end

  defp extract_domain_from_dn(dn) do
    case Regex.run(~r/CN=([^,\/]+)/i, dn || "") do
      [_, cn] -> String.trim(cn)
      _ -> "unknown"
    end
  end

  # --- Struct to map conversion helpers ---

  defp to_map(%{__struct__: _} = struct) do
    struct
    |> Map.from_struct()
    |> Map.drop([:__meta__])
    |> Map.new(fn {k, v} -> {k, to_map_value(v)} end)
  end

  defp to_map(other), do: other

  defp to_map_value(%{__struct__: Ecto.Association.NotLoaded}), do: nil
  defp to_map_value(%{__struct__: _} = s), do: to_map(s)
  defp to_map_value(list) when is_list(list), do: Enum.map(list, &to_map_value/1)
  defp to_map_value(other), do: other
end
