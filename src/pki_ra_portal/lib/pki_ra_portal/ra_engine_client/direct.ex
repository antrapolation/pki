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
    else
      {:error, _} = err -> err
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
    {:ok, to_map_list(users)}
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
    {:ok, to_map_list(csrs)}
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
    {:ok, to_map_list(profiles)}
  end

  @impl true
  def create_cert_profile(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    # Resolve digest_algo for PQC algorithms — disabled dropdown submits nil
    attrs = normalize_digest_algo(attrs, tenant_id)

    case PkiRaEngine.CertProfileConfig.create_profile(tenant_id, attrs) do
      {:ok, profile} -> {:ok, to_map(profile)}
      {:error, _} = err -> err
    end
  end

  @impl true
  def update_cert_profile(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]
    attrs = normalize_digest_algo(attrs, tenant_id)

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
    {:ok, to_map_list(configs)}
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
    {:ok, to_map_list(instances)}
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
    {:ok, Enum.map(keys, &issuer_key_to_map/1)}
  end

  defp issuer_key_to_map(key) do
    ca_name = case key.ca_instance do
      %{name: name} -> name
      _ -> nil
    end

    %{
      id: key.id,
      name: key.key_alias,
      algorithm: key.algorithm,
      status: key.status,
      ca_instance_name: ca_name,
      ca_instance_id: key.ca_instance_id,
      is_root: key.is_root
    }
  end

  # --- CA connections ---

  @impl true
  def list_ca_connections(_filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    instances = PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id)

    connections =
      Enum.flat_map(instances, fn ra ->
        PkiRaEngine.CaConnectionManagement.list_connections(tenant_id, ra.id)
      end)

    {:ok, Enum.map(connections, &connection_to_map/1)}
  rescue
    _ -> {:ok, []}
  end

  @impl true
  def create_ca_connection(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id) do
      [ra | _] ->
        case PkiRaEngine.CaConnectionManagement.connect(tenant_id, ra.id, attrs) do
          {:ok, conn} -> {:ok, connection_to_map(conn)}
          {:error, _} = err -> err
        end

      _ ->
        {:error, :no_ra_instance}
    end
  end

  @impl true
  def delete_ca_connection(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.CaConnectionManagement.disconnect(tenant_id, id) do
      {:ok, conn} -> {:ok, connection_to_map(conn)}
      {:error, _} = err -> err
    end
  end

  @pqc_algorithms ~w(KAZ-SIGN KAZ-SIGN-128 KAZ-SIGN-192 KAZ-SIGN-256 ML-DSA-44 ML-DSA-65 ML-DSA-87 Ed25519 Ed448)

  defp normalize_digest_algo(attrs, tenant_id) do
    issuer_key_id = attrs[:issuer_key_id] || attrs["issuer_key_id"]
    digest_algo = attrs[:digest_algo] || attrs["digest_algo"]

    if is_nil(digest_algo) or digest_algo == "" do
      # Digest not submitted (PQC disabled dropdown) — check issuer key algorithm
      algo = resolve_issuer_key_algorithm(issuer_key_id, tenant_id)

      if algo in @pqc_algorithms do
        Map.put(attrs, :digest_algo, "algorithm-default")
      else
        Map.put(attrs, :digest_algo, "SHA-256")
      end
    else
      attrs
    end
  end

  defp resolve_issuer_key_algorithm(nil, _tenant_id), do: nil
  defp resolve_issuer_key_algorithm(issuer_key_id, tenant_id) do
    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant_id) do
      [ra | _] ->
        connections = PkiRaEngine.CaConnectionManagement.list_connections(tenant_id, ra.id)
        case Enum.find(connections, &(&1.issuer_key_id == issuer_key_id)) do
          nil -> nil
          conn -> conn.algorithm
        end
      _ -> nil
    end
  rescue
    _ -> nil
  end

  defp connection_to_map(conn) do
    %{
      id: conn.id,
      ra_instance_id: conn.ra_instance_id,
      issuer_key_id: conn.issuer_key_id,
      issuer_key_name: conn.issuer_key_name,
      algorithm: conn.algorithm,
      ca_instance_name: conn.ca_instance_name,
      status: conn.status,
      connected_at: conn.connected_at
    }
  end

  # --- API keys ---

  @impl true
  def list_api_keys(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]
    ra_user_id = case filters do
      kw when is_list(kw) -> Keyword.get(kw, :ra_user_id)
      map when is_map(map) -> Map.get(map, :ra_user_id) || Map.get(map, "ra_user_id")
      _ -> nil
    end

    if ra_user_id do
      keys = PkiRaEngine.ApiKeyManagement.list_keys(tenant_id, ra_user_id)
      {:ok, to_map_list(keys)}
    else
      # No user filter — list all keys for this tenant
      repo = PkiRaEngine.TenantRepo.ra_repo(tenant_id)
      keys = repo.all(PkiRaEngine.Schema.RaApiKey)
      {:ok, to_map_list(keys)}
    end
  end

  @impl true
  def create_api_key(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.create_api_key(tenant_id, attrs) do
      {:ok, %{raw_key: raw_key, api_key: api_key, webhook_secret: ws}} ->
        flat = api_key |> to_map() |> Map.merge(%{raw_key: raw_key, webhook_secret: ws})
        {:ok, flat}

      {:ok, key} ->
        {:ok, to_map(key)}

      {:error, _} = err ->
        err
    end
  end

  @impl true
  def update_api_key(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case PkiRaEngine.ApiKeyManagement.update_key(tenant_id, id, attrs) do
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

  @impl true
  def list_webhook_deliveries(api_key_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    deliveries = PkiRaEngine.WebhookDelivery.list_deliveries(tenant_id, api_key_id)
    {:ok, to_map_list(deliveries)}
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

    repo = PkiRaEngine.TenantRepo.ra_repo(tenant_id)

    certs = repo.all(query) |> repo.preload(:cert_profile)
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
    tenant_id = opts[:tenant_id]
    repo = PkiRaEngine.TenantRepo.ra_repo(tenant_id)

    import Ecto.Query

    case repo.one(
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
    {:ok, to_map_list(events)}
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

  defp to_map(value), do: PkiRaPortal.ResponseNormalizer.normalize(value)
  defp to_map_list(list), do: PkiRaPortal.ResponseNormalizer.normalize_list(list)
end
