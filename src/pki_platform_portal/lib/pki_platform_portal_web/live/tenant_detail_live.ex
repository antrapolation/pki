defmodule PkiPlatformPortalWeb.TenantDetailLive do
  use PkiPlatformPortalWeb, :live_view

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
          send(self(), :load_users)
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
           all_hsm_devices: [],
           user_management: %{
             ca_users: [],
             ra_users: [],
             show_form: nil,
             form_error: nil
           }
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
        socket = assign(socket, tenant: updated_tenant, ca_engine_status: :online, ra_engine_status: :online)
        send(self(), :load_users)
        {:noreply, put_flash(socket, :info, "Tenant activated.")}

      {:error, reason} ->
        Logger.error("[tenant_detail] Failed to activate tenant: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to activate tenant", reason))}
    end
  end

  def handle_event("show_user_form", %{"portal" => portal}, socket) do
    user_management = %{socket.assigns.user_management | show_form: portal, form_error: nil}
    {:noreply, assign(socket, user_management: user_management)}
  end

  def handle_event("cancel_user_form", _params, socket) do
    user_management = %{socket.assigns.user_management | show_form: nil, form_error: nil}
    {:noreply, assign(socket, user_management: user_management)}
  end

  def handle_event("create_user", %{"portal" => portal, "username" => username, "display_name" => display_name, "email" => email, "role" => role}, socket) do
    tenant = socket.assigns.tenant
    ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
    ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

    portal_url = if portal == "ca", do: "https://#{ca_host}", else: "https://#{ra_host}"

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant.id, portal, %{
      username: String.trim(username),
      display_name: String.trim(display_name),
      email: String.trim(email),
      role: role
    }, portal_url: portal_url, tenant_name: tenant.name) do
      {:ok, _user} ->
        send(self(), :load_users)
        user_management = %{socket.assigns.user_management | show_form: nil, form_error: nil}
        {:noreply,
         socket
         |> assign(user_management: user_management)
         |> put_flash(:info, "User created. Credentials sent to #{String.trim(email)}.")}

      {:error, :tenant_not_active} ->
        user_management = %{socket.assigns.user_management | form_error: "Tenant must be activated before creating users."}
        {:noreply, assign(socket, user_management: user_management)}

      {:error, reason} ->
        user_management = %{socket.assigns.user_management | form_error: inspect(reason)}
        {:noreply, assign(socket, user_management: user_management)}
    end
  end

  def handle_event("suspend_user_role", %{"role-id" => role_id}, socket) do
    tenant_id = socket.assigns.tenant.id
    case verify_role_belongs_to_tenant(role_id, tenant_id) do
      :ok ->
        case PkiPlatformEngine.PlatformAuth.suspend_user_role(role_id) do
          {:ok, _} ->
            send(self(), :load_users)
            {:noreply, put_flash(socket, :info, "User suspended.")}
          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to suspend user: #{inspect(reason)}")}
        end
      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "User role not found for this tenant.")}
    end
  end

  def handle_event("activate_user_role", %{"role-id" => role_id}, socket) do
    tenant_id = socket.assigns.tenant.id
    case verify_role_belongs_to_tenant(role_id, tenant_id) do
      :ok ->
        case PkiPlatformEngine.PlatformAuth.activate_user_role(role_id) do
          {:ok, _} ->
            send(self(), :load_users)
            {:noreply, put_flash(socket, :info, "User activated.")}
          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to activate user: #{inspect(reason)}")}
        end
      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "User role not found for this tenant.")}
    end
  end

  def handle_event("delete_user_role", %{"role-id" => role_id}, socket) do
    tenant_id = socket.assigns.tenant.id
    case verify_role_belongs_to_tenant(role_id, tenant_id) do
      :ok ->
        case PkiPlatformEngine.PlatformAuth.delete_user_role(role_id) do
          {:ok, _} ->
            send(self(), :load_users)
            {:noreply, put_flash(socket, :info, "User removed.")}
          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to remove user: #{inspect(reason)}")}
        end
      {:error, :not_found} ->
        {:noreply, put_flash(socket, :error, "User role not found for this tenant.")}
    end
  end

  def handle_info(:load_users, socket) do
    tenant_id = socket.assigns.tenant.id
    ca_users = PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ca")
    ra_users = PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ra")

    user_management = %{socket.assigns.user_management |
      ca_users: ca_users,
      ra_users: ra_users
    }

    {:noreply, assign(socket, user_management: user_management)}
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

  defp verify_role_belongs_to_tenant(role_id, tenant_id) do
    import Ecto.Query
    alias PkiPlatformEngine.{PlatformRepo, UserTenantRole}

    case PlatformRepo.one(from r in UserTenantRole, where: r.id == ^role_id and r.tenant_id == ^tenant_id) do
      nil -> {:error, :not_found}
      _role -> :ok
    end
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
            <div :if={@current_user["role"] == "super_admin"} class="flex items-center gap-2 flex-shrink-0">
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
              <p class="text-sm font-medium"><.local_time dt={@tenant.inserted_at} format="date" /></p>
            </div>
          </div>
        </div>
      </div>

      <%!-- User Management --%>
      <div :if={@tenant.status == "active"}>
        <h3 class="text-sm font-semibold text-base-content mb-3">User Management</h3>

        <%!-- CA Users --%>
        <div class="card bg-base-100 shadow-sm border border-base-300 mb-4">
          <div class="card-body p-5">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <.icon name="hero-shield-check" class="size-4 text-primary" />
                <h4 class="text-sm font-semibold">CA Portal Users</h4>
                <span class="badge badge-sm badge-ghost">{length(@user_management.ca_users)}</span>
              </div>
              <button phx-click="show_user_form" phx-value-portal="ca" class="btn btn-ghost btn-xs text-primary">
                <.icon name="hero-plus" class="size-3.5" /> Add User
              </button>
            </div>

            <%= if @user_management.show_form == "ca" do %>
              <div class="bg-base-200 rounded-lg p-4 mb-3">
                <%= if @user_management.form_error do %>
                  <div class="alert alert-error text-sm mb-3">
                    <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                    <span>{@user_management.form_error}</span>
                  </div>
                <% end %>
                <form phx-submit="create_user" class="grid grid-cols-2 gap-3">
                  <input type="hidden" name="portal" value="ca" />
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Username</label>
                    <input type="text" name="username" required class="input input-bordered input-sm w-full" placeholder="e.g. jdoe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Display Name</label>
                    <input type="text" name="display_name" required class="input input-bordered input-sm w-full" placeholder="e.g. Jane Doe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Email</label>
                    <input type="email" name="email" required class="input input-bordered input-sm w-full" placeholder="jane@example.com" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Role</label>
                    <select name="role" class="select select-bordered select-sm w-full">
                      <option value="ca_admin">CA Admin</option>
                      <option value="key_manager">Key Manager</option>
                      <option value="auditor">Auditor</option>
                    </select>
                  </div>
                  <div class="col-span-2 flex justify-end gap-2 pt-1">
                    <button type="button" phx-click="cancel_user_form" class="btn btn-ghost btn-xs">Cancel</button>
                    <button type="submit" class="btn btn-primary btn-xs" phx-disable-with="Creating...">Create & Send Invite</button>
                  </div>
                </form>
              </div>
            <% end %>

            <table :if={@user_management.ca_users != []} class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={user <- @user_management.ca_users} class="hover">
                  <td class="font-mono text-sm">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td><span class="badge badge-sm badge-ghost">{user.role}</span></td>
                  <td>
                    <span class={["badge badge-sm", user.status == "active" && "badge-success", user.status == "suspended" && "badge-warning"]}>{user.status}</span>
                  </td>
                  <td class="text-right">
                    <button :if={user.status == "active"} phx-click="suspend_user_role" phx-value-role-id={user.role_id} data-confirm={"Suspend #{user.username}?"} class="btn btn-ghost btn-xs text-warning" title="Suspend">
                      <.icon name="hero-pause-circle" class="size-4" />
                    </button>
                    <button :if={user.status == "suspended"} phx-click="activate_user_role" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-success" title="Activate">
                      <.icon name="hero-play-circle" class="size-4" />
                    </button>
                    <button phx-click="delete_user_role" phx-value-role-id={user.role_id} data-confirm={"Remove #{user.username} from CA portal?"} class="btn btn-ghost btn-xs text-error" title="Remove">
                      <.icon name="hero-trash" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={@user_management.ca_users == []} class="text-xs text-base-content/40">No CA users yet.</p>
          </div>
        </div>

        <%!-- RA Users --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
                <h4 class="text-sm font-semibold">RA Portal Users</h4>
                <span class="badge badge-sm badge-ghost">{length(@user_management.ra_users)}</span>
              </div>
              <button phx-click="show_user_form" phx-value-portal="ra" class="btn btn-ghost btn-xs text-secondary">
                <.icon name="hero-plus" class="size-3.5" /> Add User
              </button>
            </div>

            <%= if @user_management.show_form == "ra" do %>
              <div class="bg-base-200 rounded-lg p-4 mb-3">
                <%= if @user_management.form_error do %>
                  <div class="alert alert-error text-sm mb-3">
                    <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                    <span>{@user_management.form_error}</span>
                  </div>
                <% end %>
                <form phx-submit="create_user" class="grid grid-cols-2 gap-3">
                  <input type="hidden" name="portal" value="ra" />
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Username</label>
                    <input type="text" name="username" required class="input input-bordered input-sm w-full" placeholder="e.g. jdoe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Display Name</label>
                    <input type="text" name="display_name" required class="input input-bordered input-sm w-full" placeholder="e.g. Jane Doe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Email</label>
                    <input type="email" name="email" required class="input input-bordered input-sm w-full" placeholder="jane@example.com" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Role</label>
                    <select name="role" class="select select-bordered select-sm w-full">
                      <option value="ra_admin">RA Admin</option>
                      <option value="ra_officer">RA Officer</option>
                      <option value="auditor">Auditor</option>
                    </select>
                  </div>
                  <div class="col-span-2 flex justify-end gap-2 pt-1">
                    <button type="button" phx-click="cancel_user_form" class="btn btn-ghost btn-xs">Cancel</button>
                    <button type="submit" class="btn btn-primary btn-xs" phx-disable-with="Creating...">Create & Send Invite</button>
                  </div>
                </form>
              </div>
            <% end %>

            <table :if={@user_management.ra_users != []} class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={user <- @user_management.ra_users} class="hover">
                  <td class="font-mono text-sm">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td><span class="badge badge-sm badge-ghost">{user.role}</span></td>
                  <td>
                    <span class={["badge badge-sm", user.status == "active" && "badge-success", user.status == "suspended" && "badge-warning"]}>{user.status}</span>
                  </td>
                  <td class="text-right">
                    <button :if={user.status == "active"} phx-click="suspend_user_role" phx-value-role-id={user.role_id} data-confirm={"Suspend #{user.username}?"} class="btn btn-ghost btn-xs text-warning" title="Suspend">
                      <.icon name="hero-pause-circle" class="size-4" />
                    </button>
                    <button :if={user.status == "suspended"} phx-click="activate_user_role" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-success" title="Activate">
                      <.icon name="hero-play-circle" class="size-4" />
                    </button>
                    <button phx-click="delete_user_role" phx-value-role-id={user.role_id} data-confirm={"Remove #{user.username} from RA portal?"} class="btn btn-ghost btn-xs text-error" title="Remove">
                      <.icon name="hero-trash" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={@user_management.ra_users == []} class="text-xs text-base-content/40">No RA users yet.</p>
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
      <%!-- HSM Device Access (only for active tenants, super_admin only) --%>
      <div :if={@tenant.status == "active" && @current_user["role"] == "super_admin"}>
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
                          class="btn btn-ghost btn-xs text-rose-400"
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
