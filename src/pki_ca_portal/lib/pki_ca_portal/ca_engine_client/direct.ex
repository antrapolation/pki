defmodule PkiCaPortal.CaEngineClient.Direct do
  @moduledoc """
  Direct (in-process) implementation of the CA engine client.

  Calls CA engine modules directly via Elixir function calls instead of HTTP.
  Converts Ecto structs to plain maps with atom keys to maintain the same
  interface contract as the HTTP implementation.
  """

  @behaviour PkiCaPortal.CaEngineClient

  require Logger

  import Ecto.Query

  alias PkiCaEngine.UserManagement
  alias PkiCaEngine.CaInstanceManagement
  alias PkiCaEngine.KeystoreManagement
  alias PkiCaEngine.HsmDeviceManagement
  alias PkiCaEngine.IssuerKeyManagement
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.TenantRepo
  alias PkiCaEngine.Schema.KeyCeremony

  # ---------------------------------------------------------------------------
  # Authentication
  # ---------------------------------------------------------------------------

  @impl true
  def authenticate(username, password, _opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
      {:ok, user, role} ->
        {:ok, %{
          id: user.id,
          username: user.username,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          ca_instance_id: role.ca_instance_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def authenticate_with_session(username, password, _opts \\ []) do
    case PkiPlatformEngine.PlatformAuth.authenticate_for_portal(username, password, "ca") do
      {:ok, user, role} ->
        user_map = %{
          id: user.id,
          username: user.username,
          email: user.email,
          role: role.role,
          display_name: user.display_name,
          tenant_id: role.tenant_id,
          ca_instance_id: role.ca_instance_id,
          must_change_password: user.must_change_password,
          credential_expires_at: user.credential_expires_at
        }
        {:ok, user_map, %{}}

      {:error, :invalid_credentials} = err -> err
      {:error, :no_tenant_assigned} -> {:error, :invalid_credentials}
    end
  end

  @impl true
  def register_user(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.register_user(tenant_id, ca_instance_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def needs_setup?(_ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    if tenant_id do
      count = PkiPlatformEngine.PlatformRepo.one(
        from r in PkiPlatformEngine.UserTenantRole,
          where: r.tenant_id == ^tenant_id and r.portal == "ca" and r.status == "active",
          select: count(r.id)
      )
      count == 0
    else
      true
    end
  end

  @impl true
  def get_user_by_username(username, ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.get_user_by_username(tenant_id, username, ca_instance_id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def update_user_profile(user_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.update_user_profile(tenant_id, user_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def verify_and_change_password(user_id, current_password, new_password, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.verify_and_change_password(tenant_id, user_id, current_password, new_password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, :invalid_current_password} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def reset_password(user_id, new_password, opts \\ []) do
    # Try platform DB first
    case PkiPlatformEngine.PlatformAuth.reset_password(user_id, new_password, must_change_password: false) do
      {:ok, _} -> :ok
      {:error, :not_found} ->
        # Fallback: try tenant DB for legacy users
        tenant_id = opts[:tenant_id]
        with {:ok, user} <- UserManagement.get_user(tenant_id, user_id),
             {:ok, _} <- UserManagement.update_user_password(tenant_id, user, %{password: new_password}) do
          :ok
        end
      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_users(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    filter_opts = Keyword.drop(opts, [:tenant_id])
    users = UserManagement.list_users(tenant_id, ca_instance_id, filter_opts)
    {:ok, Enum.map(users || [], &to_map/1)}
  end

  @impl true
  def create_user(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.create_user(tenant_id, ca_instance_id, attrs) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def create_user_with_admin(ca_instance_id, attrs, admin_context, opts \\ []) do
    tenant_id = opts[:tenant_id]
    password = admin_context[:password] || admin_context["password"]

    case UserManagement.create_user_with_credentials(tenant_id, ca_instance_id, attrs, password) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def get_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.get_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
    end
  end

  @impl true
  def delete_user(id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case UserManagement.delete_user(tenant_id, id) do
      {:ok, user} -> {:ok, to_map(user)}
      {:error, :not_found} = err -> err
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Keystore Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_keystores(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    keystores = KeystoreManagement.list_keystores(tenant_id, ca_instance_id)

    # Enrich with CA instance names
    instance_names = flatten_tree(CaInstanceManagement.list_hierarchy(tenant_id))
      |> Map.new(fn i -> {i[:id], i[:name]} end)

    enriched = Enum.map(keystores, fn ks ->
      map = to_map(ks)
      Map.put(map, :ca_instance_name, Map.get(instance_names, map[:ca_instance_id], "-"))
    end)

    {:ok, enriched}
  end

  @impl true
  def configure_keystore(ca_instance_id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case KeystoreManagement.configure_keystore(tenant_id, ca_instance_id, attrs) do
      {:ok, keystore} -> {:ok, to_map(keystore)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Issuer Key Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_issuer_keys(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    keys = IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id, opts)
    {:ok, Enum.map(keys, &to_map/1)}
  end

  # ---------------------------------------------------------------------------
  # Engine Status
  # ---------------------------------------------------------------------------

  @impl true
  def get_engine_status(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]

    issuer_keys = IssuerKeyManagement.list_issuer_keys(tenant_id, ca_instance_id)
    keystores = KeystoreManagement.list_keystores(tenant_id, ca_instance_id)

    active_keys = Enum.count(issuer_keys, fn k -> k.status == "active" end)

    status = %{
      status: "running",
      uptime_seconds: 0,
      ca_instance_id: ca_instance_id,
      issuer_keys: %{
        total: length(issuer_keys),
        active: active_keys
      },
      keystores: %{
        total: length(keystores)
      },
      active_keys: active_keys
    }

    {:ok, status}
  end

  # ---------------------------------------------------------------------------
  # Key Ceremony
  # ---------------------------------------------------------------------------

  @impl true
  def initiate_ceremony(ca_instance_id, params, opts \\ []) do
    ceremony_params = %{
      algorithm: params[:algorithm] || params["algorithm"],
      keystore_id: params[:keystore_id] || params["keystore_id"],
      threshold_k: parse_int(params[:threshold_k] || params["threshold_k"]),
      threshold_n: parse_int(params[:threshold_n] || params["threshold_n"]),
      initiated_by: params[:initiated_by] || params["initiated_by"],
      domain_info: params[:domain_info] || params["domain_info"] || %{},
      key_alias: params[:key_alias] || params["key_alias"],
      is_root: params[:is_root] || params["is_root"]
    }

    tenant_id = opts[:tenant_id]

    case SyncCeremony.initiate(tenant_id, ca_instance_id, ceremony_params) do
      {:ok, {ceremony, _issuer_key}} ->
        {:ok, to_map(ceremony)}

      {:error, :invalid_threshold} ->
        {:error, {:validation_error, %{threshold: ["k must be >= 2 and <= n"]}}}

      {:error, :not_found} ->
        {:error, :not_found}

      {:error, %Ecto.Changeset{} = cs} ->
        {:error, {:validation_error, changeset_errors(cs)}}

      {:error, _reason} = err ->
        err
    end
  end

  @impl true
  def list_ceremonies(ca_instance_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    repo = TenantRepo.ca_repo(tenant_id)

    ceremonies =
      from(c in KeyCeremony,
        where: c.ca_instance_id == ^ca_instance_id,
        order_by: [desc: c.inserted_at]
      )
      |> repo.all()

    {:ok, Enum.map(ceremonies, &to_map/1)}
  end

  # ---------------------------------------------------------------------------
  # CA Instance Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_ca_instances(opts \\ []) do
    tenant_id = opts[:tenant_id]
    instances = CaInstanceManagement.list_hierarchy(tenant_id)
    {:ok, flatten_tree(instances)}
  end

  @impl true
  def create_ca_instance(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    case CaInstanceManagement.create_ca_instance(tenant_id, attrs, actor: opts[:actor]) do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  @impl true
  def update_ca_instance(id, attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]

    result =
      cond do
        Map.has_key?(attrs, :status) || Map.has_key?(attrs, "status") ->
          status = attrs[:status] || attrs["status"]
          CaInstanceManagement.update_status(tenant_id, id, status, actor: opts[:actor])

        Map.has_key?(attrs, :name) || Map.has_key?(attrs, "name") ->
          name = attrs[:name] || attrs["name"]
          CaInstanceManagement.rename(tenant_id, id, name)

        true ->
          # For general updates, try status first as the most common case
          {:error, :no_updatable_fields}
      end

    case result do
      {:ok, instance} -> {:ok, to_map(instance)}
      {:error, :not_found} = err -> err
      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
      {:error, _reason} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # Platform-level User Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_portal_users(opts \\ []) do
    tenant_id = opts[:tenant_id]
    {:ok, PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ca")}
  end

  @impl true
  def create_portal_user(attrs, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant_id, "ca", attrs,
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
          portal: "ca",
          details: %{username: user.username, role: attrs[:role] || attrs["role"]}
        })
        {:ok, %{id: user.id, username: user.username, display_name: user.display_name, email: user.email}}

      {:error, %Ecto.Changeset{} = cs} -> {:error, {:validation_error, changeset_errors(cs)}}
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
          portal: "ca"
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
          portal: "ca"
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
          portal: "ca"
        })
        {:ok, %{id: role_id}}

      {:error, _} = err -> err
    end
  end

  @impl true
  def reset_user_password(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    role_label = case PkiPlatformEngine.PlatformAuth.get_tenant_roles_any_status(user_id, portal: "ca") do
      [role | _] -> PkiPlatformEngine.PlatformAuth.format_role_label(role.role, "ca")
      [] -> "CA User"
    end

    case PkiPlatformEngine.PlatformAuth.reset_user_password(user_id, "ca",
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
          portal: "ca"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  @impl true
  def resend_invitation(user_id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    portal_url = Application.get_env(:pki_ca_portal, :portal_url, "")
    tenant_name = get_tenant_name(tenant_id)

    case PkiPlatformEngine.PlatformAuth.resend_invitation(user_id, "ca",
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
          portal: "ca"
        })
        :ok

      {:error, _} = err -> err
    end
  end

  # ---------------------------------------------------------------------------
  # HSM Device Management
  # ---------------------------------------------------------------------------

  @impl true
  def list_hsm_devices(opts \\ []) do
    tenant_id = opts[:tenant_id]
    devices = HsmDeviceManagement.list_devices_for_tenant(tenant_id)
    {:ok, Enum.map(devices, &to_map/1)}
  end

  @impl true
  def register_hsm_device(_attrs, _opts \\ []) do
    {:error, :not_permitted}
  end

  @impl true
  def probe_hsm_device(id, opts \\ []) do
    tenant_id = opts[:tenant_id]
    with {:ok, _} <- PkiPlatformEngine.HsmManagement.get_device_for_tenant(tenant_id, id),
         {:ok, device} <- PkiPlatformEngine.HsmManagement.probe_device(id) do
      {:ok, to_map(device)}
    end
  end

  @impl true
  def deactivate_hsm_device(_id, _opts \\ []) do
    {:error, :not_permitted}
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

  # ---------------------------------------------------------------------------
  # Audit Log
  # ---------------------------------------------------------------------------

  @impl true
  def query_audit_log(filters, opts \\ []) do
    tenant_id = opts[:tenant_id]

    audit_filters = build_audit_filters(filters)

    # TODO: pass tenant_id to PkiAuditTrail.query when audit trail is made tenant-aware
    _ = tenant_id
    events = PkiAuditTrail.query(audit_filters)
    {:ok, Enum.map(events, &to_map/1)}
  rescue
    e ->
      Logger.error("Audit trail query error: #{Exception.message(e)}")
      {:error, :query_failed}
  end

  # ---------------------------------------------------------------------------
  # Private Helpers
  # ---------------------------------------------------------------------------

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

  # Flatten a tree of CA instances (with nested :children) into a flat list
  defp flatten_tree(instances) do
    Enum.flat_map(instances, fn instance ->
      map = to_map(instance)
      children = map[:children] || []
      parent = Map.put(map, :children, nil)
      [parent | flatten_tree_maps(children)]
    end)
  end

  defp flatten_tree_maps(nil), do: []
  defp flatten_tree_maps(children) when is_list(children) do
    Enum.flat_map(children, fn child ->
      grandchildren = child[:children] || []
      [Map.put(child, :children, nil) | flatten_tree_maps(grandchildren)]
    end)
  end

  defp changeset_errors(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
  end

  defp parse_int(v) when is_integer(v), do: v

  defp parse_int(v) when is_binary(v) do
    case Integer.parse(v) do
      {n, _} -> n
      :error -> nil
    end
  end

  defp parse_int(_), do: nil

  defp build_audit_filters(filters) do
    Enum.reduce(filters, [], fn
      {:action, v}, acc when is_binary(v) and v != "" -> [{:action, v} | acc]
      {:actor_did, v}, acc when is_binary(v) and v != "" -> [{:actor_did, v} | acc]
      {:resource_type, v}, acc when is_binary(v) and v != "" -> [{:resource_type, v} | acc]
      {:resource_id, v}, acc when is_binary(v) and v != "" -> [{:resource_id, v} | acc]
      {:date_from, v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:since, v, acc)
      {:date_to, v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:until, v, acc)
      {"action", v}, acc when is_binary(v) and v != "" -> [{:action, v} | acc]
      {"actor_did", v}, acc when is_binary(v) and v != "" -> [{:actor_did, v} | acc]
      {"resource_type", v}, acc when is_binary(v) and v != "" -> [{:resource_type, v} | acc]
      {"resource_id", v}, acc when is_binary(v) and v != "" -> [{:resource_id, v} | acc]
      {"date_from", v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:since, v, acc)
      {"date_to", v}, acc when is_binary(v) and v != "" -> maybe_parse_date(:until, v, acc)
      _, acc -> acc
    end)
  end

  defp maybe_parse_date(key, date_string, acc) do
    case DateTime.from_iso8601(date_string) do
      {:ok, datetime, _offset} ->
        [{key, datetime} | acc]

      {:error, _} ->
        case Date.from_iso8601(date_string) do
          {:ok, date} ->
            datetime =
              case key do
                :since -> DateTime.new!(date, ~T[00:00:00], "Etc/UTC")
                :until -> DateTime.new!(date, ~T[23:59:59], "Etc/UTC")
              end

            [{key, datetime} | acc]

          {:error, _} ->
            Logger.warning("Invalid date filter #{key}: #{inspect(date_string)}")
            acc
        end
    end
  end
end
