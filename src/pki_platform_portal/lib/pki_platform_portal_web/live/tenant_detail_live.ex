defmodule PkiPlatformPortalWeb.TenantDetailLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.{Mailer, EmailTemplates}
  import PkiPlatformPortalWeb.ErrorHelpers, only: [sanitize_error: 2]

  require Logger

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    case PkiPlatformEngine.Provisioner.get_tenant(id) do
      nil ->
        {:ok,
         socket
         |> put_flash(:error, "Tenant not found.")
         |> push_navigate(to: "/tenants")}

      tenant ->
        if connected?(socket) do
          send(self(), :load_metrics)
          send(self(), :check_engines)
          send(self(), :load_hsm_access)
        end
        ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
        ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

        {:ok,
         assign(socket,
           page_title: "Tenant Detail",
           tenant: tenant,
           metrics: %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0, ca_instances: 0, ra_instances: 0},
           ca_setup_url: "https://#{ca_host}/setup?tenant=#{tenant.slug}",
           ra_setup_url: "https://#{ra_host}/setup?tenant=#{tenant.slug}",
           ca_engine_status: :checking,
           ra_engine_status: :checking,
           engine_check_us: nil,
           hsm_devices: [],
           assigned_hsm_ids: [],
           all_hsm_devices: []
         )}
    end
  end

  @impl true
  def handle_event("suspend", _params, socket) do
    case PkiPlatformEngine.Provisioner.suspend_tenant(socket.assigns.tenant.id) do
      {:ok, updated_tenant} ->
        {:noreply,
         socket
         |> assign(tenant: updated_tenant)
         |> put_flash(:info, "Tenant \"#{updated_tenant.name}\" suspended.")}

      {:error, reason} ->
        Logger.error("[tenant_detail] Failed to suspend tenant: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to suspend tenant", reason))}
    end
  end

  def handle_event("activate", _params, socket) do
    # Activation now starts engines via BEAM TenantSupervisor — no HTTP check needed
    send(self(), :do_activate)
    {:noreply, put_flash(socket, :info, "Activating tenant and starting engine processes...")}
  end

  def handle_event("check_engines", _params, socket) do
    send(self(), :check_engines)
    {:noreply, assign(socket, ca_engine_status: :checking, ra_engine_status: :checking)}
  end

  def handle_event("delete", _params, socket) do
    case PkiPlatformEngine.Provisioner.delete_tenant(socket.assigns.tenant.id) do
      {:ok, _tenant} ->
        {:noreply,
         socket
         |> put_flash(:info, "Tenant deleted successfully.")
         |> push_navigate(to: "/tenants")}

      {:error, reason} ->
        Logger.error("[tenant_detail] Failed to delete tenant: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to delete tenant", reason))}
    end
  end

  def handle_event("resend_credentials", _params, socket) do
    tenant = socket.assigns.tenant
    send(self(), {:credential_action, :resend})
    {:noreply, put_flash(socket, :info, "Resending credentials to #{tenant.email}...")}
  end

  def handle_event("reset_ca_admin", _params, socket) do
    send(self(), {:credential_action, :reset_ca})
    {:noreply, put_flash(socket, :info, "Resetting CA Admin...")}
  end

  def handle_event("reset_ra_admin", _params, socket) do
    send(self(), {:credential_action, :reset_ra})
    {:noreply, put_flash(socket, :info, "Resetting RA Admin...")}
  end

  def handle_event("grant_hsm", %{"device-id" => device_id}, socket) do
    tenant_id = socket.assigns.tenant.id
    case PkiPlatformEngine.HsmManagement.grant_tenant_access(tenant_id, device_id) do
      {:ok, _} ->
        send(self(), :load_hsm_access)
        {:noreply, put_flash(socket, :info, "HSM device access granted.")}

      {:error, %Ecto.Changeset{}} ->
        {:noreply, put_flash(socket, :error, "Already assigned.")}

      {:error, reason} ->
        Logger.error("[tenant_detail] HSM grant failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("HSM access grant failed", reason))}
    end
  end

  def handle_event("revoke_hsm", %{"device-id" => device_id}, socket) do
    tenant_id = socket.assigns.tenant.id
    case PkiPlatformEngine.HsmManagement.revoke_tenant_access(tenant_id, device_id) do
      {:ok, _} ->
        send(self(), :load_hsm_access)
        {:noreply, put_flash(socket, :info, "HSM device access revoked.")}

      {:error, reason} ->
        Logger.error("[tenant_detail] HSM revoke failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("HSM access revoke failed", reason))}
    end
  end

  @impl true
  def handle_info(:check_engines, socket) do
    tenant_id = socket.assigns.tenant.id

    start = System.monotonic_time(:microsecond)

    status =
      case PkiPlatformEngine.TenantRegistry.lookup(tenant_id) do
        {:ok, _refs} -> :online
        {:error, :not_found} -> :offline
      end

    elapsed_us = System.monotonic_time(:microsecond) - start

    {:noreply, assign(socket, ca_engine_status: status, ra_engine_status: status, engine_check_us: elapsed_us)}
  end

  @impl true
  def handle_info(:do_activate, socket) do
    tenant = socket.assigns.tenant

    case PkiPlatformEngine.Provisioner.activate_tenant(tenant.id) do
      {:ok, updated_tenant} ->
        # Engines are now running — auto-create admins and send email
        socket = assign(socket, tenant: updated_tenant, ca_engine_status: :online, ra_engine_status: :online)
        send(self(), :ensure_admins)
        {:noreply, put_flash(socket, :info, "Tenant activated. Creating admin accounts...")}

      {:error, reason} ->
        Logger.error("[tenant_detail] Failed to activate tenant: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to activate tenant", reason))}
    end
  end

  @impl true
  def handle_info(:ensure_admins, socket) do
    tenant = socket.assigns.tenant
    ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
    ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

    ca_username = "#{tenant.slug}-ca-admin"
    ra_username = "#{tenant.slug}-ra-admin"
    ca_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
    ra_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()

    errors = []

    # Ensure default CA instance exists in tenant DB
    errors = errors ++ ensure_default_ca_instance(tenant)

    # Ensure default RA instance exists in tenant DB
    errors = errors ++ ensure_default_ra_instance(tenant)

    # Create CA admin if none exists
    ca_instance_id = get_default_ca_instance_id(tenant)

    errors =
      if ca_instance_id do
        ca_users = PkiCaEngine.UserManagement.list_users(tenant.id, ca_instance_id, role: "ca_admin")
        if ca_users == [] do
          case create_ca_admin(tenant, ca_instance_id, ca_username, ca_password) do
            :ok -> errors
            {:error, reason} ->
              Logger.error("[tenant_detail] CA admin creation failed: #{inspect(reason)}")
              errors ++ ["CA admin creation failed"]
          end
        else
          Logger.info("[TenantDetail] CA admin already exists for #{tenant.slug}")
          errors
        end
      else
        errors ++ ["CA admin: no default CA instance"]
      end

    # Create RA admin if none exists
    errors =
      if PkiRaEngine.UserManagement.needs_setup?(tenant.id) do
        case create_ra_admin(tenant, ra_username, ra_password) do
          :ok -> errors
          {:error, reason} ->
            Logger.error("[tenant_detail] RA admin creation failed: #{inspect(reason)}")
            errors ++ ["RA admin creation failed"]
        end
      else
        Logger.info("[TenantDetail] RA admin already exists for #{tenant.slug}")
        errors
      end

    # Send credential email
    if errors == [] and tenant.email do
      html = EmailTemplates.admin_credentials(
        tenant.name, ca_username, ca_password, ra_username, ra_password,
        "https://#{ca_host}", "https://#{ra_host}"
      )

      case Mailer.send_email(tenant.email, "Your #{tenant.name} admin credentials", html) do
        {:ok, _} ->
          Logger.info("[TenantDetail] Credentials sent to #{tenant.email}")
        {:error, reason} ->
          Logger.error("[TenantDetail] Failed to send email: #{inspect(reason)}")
      end
    end

    # Refresh metrics to show updated admin counts
    send(self(), :load_metrics)

    socket =
      if errors == [] do
        put_flash(socket, :info, "Tenant activated. Admin credentials sent to #{tenant.email}.")
      else
        put_flash(socket, :warning, "Tenant activated but: #{Enum.join(errors, "; ")}")
      end

    {:noreply, socket}
  end

  @impl true
  def handle_info({:credential_action, action}, socket) do
    tenant = socket.assigns.tenant
    ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
    ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

    {errors, email_result} =
      case action do
        :resend ->
          ca_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
          ra_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
          ca_username = "#{tenant.slug}-ca-admin"
          ra_username = "#{tenant.slug}-ra-admin"

          errs = recreate_ca_admin(tenant, ca_username, ca_password) ++
                   recreate_ra_admin(tenant, ra_username, ra_password)

          html = EmailTemplates.admin_credentials(
            tenant.name, ca_username, ca_password, ra_username, ra_password,
            "https://#{ca_host}", "https://#{ra_host}"
          )
          {errs, {:send, "All admin credentials", html}}

        :reset_ca ->
          ca_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
          ca_username = "#{tenant.slug}-ca-admin"
          errs = recreate_ca_admin(tenant, ca_username, ca_password)

          html = EmailTemplates.single_admin_credential(
            tenant.name, "CA Administrator", "https://#{ca_host}", ca_username, ca_password
          )
          {errs, {:send, "CA admin credentials", html}}

        :reset_ra ->
          ra_password = :crypto.strong_rand_bytes(12) |> Base.url_encode64()
          ra_username = "#{tenant.slug}-ra-admin"
          errs = recreate_ra_admin(tenant, ra_username, ra_password)

          html = EmailTemplates.single_admin_credential(
            tenant.name, "RA Administrator", "https://#{ra_host}", ra_username, ra_password
          )
          {errs, {:send, "RA admin credentials", html}}
      end

    if errors == [] do
      {:send, subject, html} = email_result

      case Mailer.send_email(tenant.email, "#{subject} for #{tenant.name}", html) do
        {:ok, _} -> :ok
        {:error, reason} -> Logger.error("Failed to send credential email: #{inspect(reason)}")
      end
    end

    send(self(), :load_metrics)

    socket =
      if errors == [] do
        put_flash(socket, :info, "Credentials reset and emailed to #{tenant.email}")
      else
        put_flash(socket, :error, Enum.join(errors, "; "))
      end

    {:noreply, socket}
  end

  def handle_info(:load_hsm_access, socket) do
    tenant_id = socket.assigns.tenant.id
    all_devices = PkiPlatformEngine.HsmManagement.list_devices()
    assigned = PkiPlatformEngine.HsmManagement.list_devices_for_tenant(tenant_id)
    assigned_ids = Enum.map(assigned, & &1.id) |> MapSet.new()

    {:noreply,
     assign(socket,
       all_hsm_devices: all_devices,
       hsm_devices: assigned,
       assigned_hsm_ids: assigned_ids
     )}
  end

  def handle_info(:load_metrics, socket) do
    metrics =
      try do
        PkiPlatformEngine.TenantMetrics.get_metrics(socket.assigns.tenant)
      catch
        _, _ -> %{db_size: 0, ca_users: 0, ra_users: 0, certificates_issued: 0, active_certificates: 0, pending_csrs: 0, ca_instances: 0, ra_instances: 0}
      end

    {:noreply, assign(socket, metrics: metrics)}
  end

  # --- Direct engine calls for admin management ---

  defp create_ca_admin(tenant, ca_instance_id, username, password) do
    alias PkiPlatformEngine.PlatformAuth

    expires_at = DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)
    display_name = "#{tenant.name} CA Admin"

    with {:ok, profile} <-
           PlatformAuth.find_or_create_user_profile(%{
             username: username,
             password: password,
             display_name: display_name,
             email: tenant.email,
             must_change_password: true
           }),
         {:ok, _role} <-
           PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
             role: "ca_admin",
             portal: "ca",
             ca_instance_id: ca_instance_id
           }),
         {:ok, _user} <-
           PkiCaEngine.UserManagement.register_user(tenant.id, ca_instance_id, %{
             username: username,
             password: password,
             role: "ca_admin",
             display_name: display_name,
             email: tenant.email,
             must_change_password: true,
             credential_expires_at: expires_at
           }) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  rescue
    e ->
      Logger.error("[tenant_detail] CA admin creation failed: #{Exception.message(e)}")
      {:error, "operation failed"}
  end

  defp create_ra_admin(tenant, username, password) do
    alias PkiPlatformEngine.PlatformAuth

    expires_at = DateTime.utc_now() |> DateTime.add(24, :hour) |> DateTime.truncate(:second)
    display_name = "#{tenant.name} RA Admin"

    with {:ok, profile} <-
           PlatformAuth.find_or_create_user_profile(%{
             username: username,
             password: password,
             display_name: display_name,
             email: tenant.email,
             must_change_password: true
           }),
         {:ok, _role} <-
           PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
             role: "ra_admin",
             portal: "ra"
           }),
         {:ok, _user} <-
           PkiRaEngine.UserManagement.register_user(tenant.id, %{
             username: username,
             password: password,
             role: "ra_admin",
             display_name: display_name,
             email: tenant.email,
             tenant_id: tenant.id,
             must_change_password: true,
             credential_expires_at: expires_at
           }) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  rescue
    e ->
      Logger.error("[tenant_detail] RA admin creation failed: #{Exception.message(e)}")
      {:error, "operation failed"}
  end

  defp recreate_ca_admin(tenant, username, password) do
    ca_instance_id = get_default_ca_instance_id(tenant)

    if ca_instance_id do
      # Find existing admin and reset password, or create new
      existing =
        PkiCaEngine.UserManagement.list_users(tenant.id, ca_instance_id, role: "ca_admin")
        |> Enum.find(&(&1.username == username))

      case existing do
        nil ->
          case create_ca_admin(tenant, ca_instance_id, username, password) do
            :ok -> []
            {:error, reason} ->
              Logger.error("[tenant_detail] CA admin reset failed: #{inspect(reason)}")
              ["CA admin reset failed"]
          end

        user ->
          alias PkiPlatformEngine.PlatformAuth

          # Ensure platform profile exists, reset password
          case PlatformAuth.get_by_username(username) do
            {:ok, profile} ->
              PlatformAuth.reset_password(profile.id, password)
              if profile.status == "suspended", do: PlatformAuth.reactivate(profile.id)

            {:error, :not_found} ->
              # Platform profile missing — create it + assign role
              case PlatformAuth.find_or_create_user_profile(%{
                     username: username, password: password,
                     display_name: user.display_name, email: tenant.email,
                     must_change_password: true
                   }) do
                {:ok, profile} ->
                  PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
                    role: "ca_admin", portal: "ca", ca_instance_id: ca_instance_id
                  })
                _ -> :ok
              end
          end

          # Reactivate tenant DB user if suspended, reset password
          if user.status == "suspended" do
            PkiCaEngine.UserManagement.update_user(tenant.id, user.id, %{status: "active"})
          end

          case PkiCaEngine.UserManagement.update_user_password(tenant.id, user, %{
                 password: password,
                 must_change_password: true
               }) do
            {:ok, _} -> []
            {:error, reason} ->
              Logger.error("[tenant_detail] CA admin password reset failed: #{inspect(reason)}")
              ["CA admin reset failed"]
          end
      end
    else
      ["CA admin reset failed: no default CA instance"]
    end
  rescue
    e ->
      Logger.error("[tenant_detail] CA admin reset failed: #{Exception.message(e)}")
      ["CA admin reset failed"]
  end

  # --- Tenant instance bootstrapping ---

  defp ensure_default_ca_instance(tenant) do
    case PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant.id) do
      [] ->
        case PkiCaEngine.CaInstanceManagement.create_ca_instance(tenant.id, %{
               name: "#{tenant.name} Root CA",
               status: "active"
             }) do
          {:ok, ca} ->
            Logger.info("[TenantDetail] Created default CA instance #{ca.id} for #{tenant.slug}")
            []

          {:error, reason} ->
            Logger.error("[tenant_detail] CA instance creation failed: #{inspect(reason)}")
            ["CA instance creation failed"]
        end

      _instances ->
        []
    end
  rescue
    e ->
      Logger.error("[tenant_detail] CA instance creation failed: #{Exception.message(e)}")
      ["CA instance creation failed"]
  end

  defp ensure_default_ra_instance(tenant) do
    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant.id) do
      [] ->
        case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant.id, %{
               name: "#{tenant.name} RA",
               status: "active"
             }) do
          {:ok, ra} ->
            Logger.info("[TenantDetail] Created default RA instance #{ra.id} for #{tenant.slug}")
            []

          {:error, reason} ->
            Logger.error("[tenant_detail] RA instance creation failed: #{inspect(reason)}")
            ["RA instance creation failed"]
        end

      _instances ->
        []
    end
  rescue
    e ->
      Logger.error("[tenant_detail] RA instance creation failed: #{Exception.message(e)}")
      ["RA instance creation failed"]
  end

  defp get_default_ca_instance_id(tenant) do
    case PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant.id) do
      [first | _] -> first.id
      [] -> nil
    end
  rescue
    _ -> nil
  end

  defp recreate_ra_admin(tenant, username, password) do
    existing =
      PkiRaEngine.UserManagement.list_users(tenant.id, role: "ra_admin")
      |> Enum.find(&(&1.username == username))

    case existing do
      nil ->
        case create_ra_admin(tenant, username, password) do
          :ok -> []
          {:error, reason} ->
            Logger.error("[tenant_detail] RA admin reset failed: #{inspect(reason)}")
            ["RA admin reset failed"]
        end

      user ->
        alias PkiPlatformEngine.PlatformAuth

        # Ensure platform profile exists, reset password
        case PlatformAuth.get_by_username(username) do
          {:ok, profile} ->
            PlatformAuth.reset_password(profile.id, password)
            if profile.status == "suspended", do: PlatformAuth.reactivate(profile.id)

          {:error, :not_found} ->
            case PlatformAuth.find_or_create_user_profile(%{
                   username: username, password: password,
                   display_name: user.display_name, email: tenant.email,
                   must_change_password: true
                 }) do
              {:ok, profile} ->
                PlatformAuth.assign_tenant_role(profile.id, tenant.id, %{
                  role: "ra_admin", portal: "ra"
                })
              _ -> :ok
            end
        end

        if user.status == "suspended" do
          PkiRaEngine.UserManagement.update_user(tenant.id, user.id, %{status: "active"})
        end

        case PkiRaEngine.UserManagement.update_user_password(tenant.id, user, %{
               password: password,
               must_change_password: true
             }) do
          {:ok, _} -> []
          {:error, reason} ->
            Logger.error("[tenant_detail] RA admin password reset failed: #{inspect(reason)}")
            ["RA admin reset failed"]
        end
    end
  rescue
    e ->
      Logger.error("[tenant_detail] RA admin reset failed: #{Exception.message(e)}")
      ["RA admin reset failed"]
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-detail" class="space-y-6">
      <%!-- Back link --%>
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1.5 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%!-- Tenant info card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <div class="flex items-start justify-between gap-4">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-building-office-2" class="size-5 text-primary" />
              </div>
              <div>
                <h2 class="text-xl font-bold text-base-content">{@tenant.name}</h2>
                <span class={[
                  "badge badge-sm mt-1",
                  @tenant.status == "active" && "badge-success",
                  @tenant.status == "suspended" && "badge-warning",
                  @tenant.status == "initialized" && "badge-ghost"
                ]}>{@tenant.status}</span>
              </div>
            </div>

            <%!-- Action buttons --%>
            <div class="flex items-center gap-2 flex-shrink-0">
              <button
                :if={@tenant.status in ["initialized", "suspended"]}
                phx-click="activate"
                class="btn btn-sm btn-success btn-outline"
              >
                <.icon name="hero-play-circle" class="size-4" />
                Activate
              </button>
              <button
                :if={@tenant.status == "active"}
                phx-click="suspend"
                data-confirm={"Are you sure you want to suspend \"#{@tenant.name}\"?"}
                class="btn btn-sm btn-warning btn-outline"
              >
                <.icon name="hero-pause-circle" class="size-4" />
                Suspend
              </button>
              <button
                :if={@tenant.status == "suspended"}
                phx-click="delete"
                data-confirm={"This will permanently delete \"#{@tenant.name}\" and its database. This action cannot be undone. Continue?"}
                class="btn btn-sm btn-error btn-outline"
              >
                <.icon name="hero-trash" class="size-4" />
                Delete
              </button>
              <button phx-click={JS.push("check_engines")} class="btn btn-sm btn-ghost">
                <.icon name="hero-arrow-path" class="size-4" />
                Refresh
              </button>
            </div>
          </div>

          <%!-- Engine Status --%>
          <div id="engine-status" class="flex items-center gap-4 px-1" phx-hook="EngineTimer">
            <div class="flex items-center gap-2 text-sm">
              <span class="text-base-content/50">CA Engine:</span>
              <%= case @ca_engine_status do %>
                <% :online -> %>
                  <span data-status="ready" class="badge badge-sm badge-success gap-1"><.icon name="hero-check-circle" class="size-3" /> Online</span>
                <% :offline -> %>
                  <span data-status="ready" class="badge badge-sm badge-error gap-1"><.icon name="hero-x-circle" class="size-3" /> Offline</span>
                <% :checking -> %>
                  <span data-status="checking" class="badge badge-sm badge-ghost gap-1"><span class="loading loading-spinner loading-xs"></span> Checking</span>
              <% end %>
            </div>
            <div class="flex items-center gap-2 text-sm">
              <span class="text-base-content/50">RA Engine:</span>
              <%= case @ra_engine_status do %>
                <% :online -> %>
                  <span data-status="ready" class="badge badge-sm badge-success gap-1"><.icon name="hero-check-circle" class="size-3" /> Online</span>
                <% :offline -> %>
                  <span data-status="ready" class="badge badge-sm badge-error gap-1"><.icon name="hero-x-circle" class="size-3" /> Offline</span>
                <% :checking -> %>
                  <span data-status="checking" class="badge badge-sm badge-ghost gap-1"><span class="loading loading-spinner loading-xs"></span> Checking</span>
              <% end %>
            </div>
            <span id="engine-timer" class="text-xs text-base-content/40 font-mono"></span>
          </div>

          <%!-- Tenant details grid --%>
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-5 pt-5 border-t border-base-300">
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Slug</p>
              <p class="font-mono text-sm font-medium">{@tenant.slug}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Email</p>
              <p class="font-mono text-sm font-medium">{@tenant.email}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Database</p>
              <p class="font-mono text-sm font-medium truncate" title={@tenant.database_name}>{@tenant.database_name}</p>
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider mb-1">Created</p>
              <p class="text-sm font-medium">{Calendar.strftime(@tenant.inserted_at, "%Y-%m-%d")}</p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Admin setup status --%>
      <div>
        <div class="flex items-center justify-between mb-3">
          <h3 class="text-sm font-semibold text-base-content">Admin Setup Status</h3>
          <button
            :if={@tenant.status == "active" && @tenant.email}
            phx-click="resend_credentials"
            data-confirm="This will reset ALL admin passwords and send new credentials. Continue?"
            class="btn btn-ghost btn-xs text-primary"
            phx-disable-with="Sending..."
          >
            <.icon name="hero-envelope" class="size-3.5" />
            Resend All Credentials
          </button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <%!-- CA Admin --%>
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-5">
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                    <.icon name="hero-shield-check" class="size-4 text-primary" />
                  </div>
                  <h4 class="text-sm font-semibold">CA Admin</h4>
                </div>
                <span :if={@metrics.ca_users > 0} class="badge badge-sm badge-success">Configured</span>
                <span :if={@metrics.ca_users == 0} class="badge badge-sm badge-warning">Pending</span>
              </div>
              <p :if={@metrics.ca_users > 0} class="text-sm text-base-content/60">
                {@metrics.ca_users} user{if @metrics.ca_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ca_users == 0 && @tenant.status != "active"} class="text-xs text-base-content/50">
                Activate the tenant first, then admin credentials will be provisioned.
              </div>
              <div class="flex gap-2 mt-3">
                <button
                  :if={@tenant.status == "active" && @tenant.email}
                  phx-click="reset_ca_admin"
                  data-confirm="This will delete the existing CA admin and create a new one with a temporary password. Continue?"
                  class="btn btn-ghost btn-xs text-warning"
                  phx-disable-with="Resetting..."
                >
                  <.icon name="hero-arrow-path" class="size-3.5" />
                  Reset CA Admin
                </button>
              </div>
            </div>
          </div>

          <%!-- RA Admin --%>
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-5">
              <div class="flex items-center justify-between mb-3">
                <div class="flex items-center gap-2">
                  <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10">
                    <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
                  </div>
                  <h4 class="text-sm font-semibold">RA Admin</h4>
                </div>
                <span :if={@metrics.ra_users > 0} class="badge badge-sm badge-success">Configured</span>
                <span :if={@metrics.ra_users == 0} class="badge badge-sm badge-warning">Pending</span>
              </div>
              <p :if={@metrics.ra_users > 0} class="text-sm text-base-content/60">
                {@metrics.ra_users} user{if @metrics.ra_users != 1, do: "s", else: ""} configured.
              </p>
              <div :if={@metrics.ra_users == 0 && @tenant.status != "active"} class="text-xs text-base-content/50">
                Activate the tenant first, then admin credentials will be provisioned.
              </div>
              <div class="flex gap-2 mt-3">
                <button
                  :if={@tenant.status == "active" && @tenant.email}
                  phx-click="reset_ra_admin"
                  data-confirm="This will delete the existing RA admin and create a new one with a temporary password. Continue?"
                  class="btn btn-ghost btn-xs text-warning"
                  phx-disable-with="Resetting..."
                >
                  <.icon name="hero-arrow-path" class="size-3.5" />
                  Reset RA Admin
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Health metrics --%>
      <div>
        <h3 class="text-sm font-semibold text-base-content mb-3">Health Metrics</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-4 gap-4">
          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-info/10 mb-2">
                <.icon name="hero-circle-stack" class="size-4 text-info" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">DB Size</p>
              <p class="text-lg font-bold mt-0.5">{PkiPlatformEngine.TenantMetrics.format_bytes(@metrics.db_size)}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 mb-2">
                <.icon name="hero-shield-check" class="size-4 text-primary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">CA Users</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ca_users}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10 mb-2">
                <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">RA Users</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ra_users}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-success/10 mb-2">
                <.icon name="hero-document-check" class="size-4 text-success" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Certs Issued</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.certificates_issued}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-success/10 mb-2">
                <.icon name="hero-check-badge" class="size-4 text-success" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active Certs</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.active_certificates}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-warning/10 mb-2">
                <.icon name="hero-clock" class="size-4 text-warning" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Pending CSRs</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.pending_csrs}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10 mb-2">
                <.icon name="hero-server-stack" class="size-4 text-primary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">CA Instances</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ca_instances}</p>
            </div>
          </div>

          <div class="card bg-base-100 shadow-sm border border-base-300">
            <div class="card-body p-4">
              <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-secondary/10 mb-2">
                <.icon name="hero-server" class="size-4 text-secondary" />
              </div>
              <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">RA Instances</p>
              <p class="text-lg font-bold mt-0.5">{@metrics.ra_instances}</p>
            </div>
          </div>
        </div>
      </div>
      <%!-- HSM Device Access (only for active tenants) --%>
      <div :if={@tenant.status == "active"}>
        <h3 class="text-sm font-semibold text-base-content mb-3">HSM Device Access</h3>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <p class="text-xs text-base-content/50 mb-4">
              Assign PKCS#11 HSM devices to this tenant. The tenant's CA admin will see assigned devices when creating HSM-backed keystores.
            </p>

            <%!-- Available devices to assign --%>
            <% unassigned = Enum.filter(@all_hsm_devices, fn d -> d.status == "active" and not MapSet.member?(@assigned_hsm_ids, d.id) end) %>
            <div :if={not Enum.empty?(unassigned)} class="mb-4">
              <p class="text-xs font-medium text-base-content/60 mb-2">Available Devices</p>
              <div class="flex flex-wrap gap-2">
                <button
                  :for={dev <- unassigned}
                  phx-click="grant_hsm"
                  phx-value-device-id={dev.id}
                  class="btn btn-sm btn-outline btn-success gap-1"
                >
                  <.icon name="hero-plus" class="size-3" />
                  {dev.label}
                  <span class="text-xs opacity-60">({dev.manufacturer || "PKCS#11"})</span>
                </button>
              </div>
            </div>
            <div :if={Enum.empty?(unassigned) and Enum.empty?(@hsm_devices)} class="text-xs text-base-content/40 mb-4">
              No HSM devices registered. <a href="/hsm-devices" class="link link-primary">Register one first.</a>
            </div>

            <%!-- Assigned devices --%>
            <div :if={not Enum.empty?(@hsm_devices)}>
              <p class="text-xs font-medium text-base-content/60 mb-2">Assigned Devices</p>
              <div>
                <table class="table table-sm table-fixed w-full">
                  <thead>
                    <tr class="text-xs uppercase text-base-content/50">
                      <th class="w-[30%]">Device</th>
                      <th class="w-[30%]">Manufacturer</th>
                      <th class="w-[15%]">Slot</th>
                      <th class="w-[25%] text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr :for={dev <- @hsm_devices} class="hover">
                      <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">
                        <div class="flex items-center gap-2">
                          <.icon name="hero-cpu-chip" class="size-4 text-warning" />
                          <span class="overflow-hidden text-ellipsis whitespace-nowrap">{dev.label}</span>
                        </div>
                      </td>
                      <td class="text-sm text-base-content/60 overflow-hidden text-ellipsis whitespace-nowrap">{dev.manufacturer || "-"}</td>
                      <td>{dev.slot_id}</td>
                      <td class="text-right">
                        <button
                          phx-click="revoke_hsm"
                          phx-value-device-id={dev.id}
                          data-confirm={"Revoke #{dev.label} access from this tenant? Existing keystores using this device will still work, but no new keystores can be created with it."}
                          title="Revoke"
                          class="btn btn-ghost btn-xs text-error"
                        >
                          <.icon name="hero-no-symbol" class="size-4" />
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
