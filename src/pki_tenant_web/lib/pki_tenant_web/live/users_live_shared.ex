defmodule PkiTenantWeb.UsersLiveShared do
  @moduledoc """
  Rendering + event handling shared by CA and RA user management
  LiveViews. The caller provides the portal scope (`:ca` or `:ra`) and
  the role string required for mutations (`"ca_admin"` / `"ra_admin"`).

  Backed by `PkiTenant.PortalUserAdmin` against Mnesia.
  """

  use Phoenix.Component

  import PkiTenantWeb.CoreComponents, only: [icon: 1]

  require Logger

  alias Phoenix.LiveView
  alias PkiTenant.PortalUserAdmin

  @doc """
  Initial assigns. Call from `mount/3` of the wrapping LiveView.
  """
  def initial_assigns(scope, admin_role) when scope in [:ca, :ra] do
    %{
      scope: scope,
      admin_role: admin_role,
      roles: PortalUserAdmin.roles_for(scope),
      page_title: "User Management",
      users: [],
      filtered_users: [],
      role_filter: "all",
      loading: true,
      page: 1,
      per_page: 10,
      credentials_flash: nil
    }
  end

  @doc "Load users for the current scope."
  def handle_load_data(socket) do
    users = PortalUserAdmin.list_users(socket.assigns.scope)

    Phoenix.Component.assign(socket,
      users: users,
      filtered_users: filter_users(users, socket.assigns.role_filter),
      loading: false
    )
  end

  @doc "Dispatch a UI event to the shared handler."
  def handle_event(event, params, socket) do
    do_event(event, params, socket)
  end

  # --- Event handlers ---

  defp do_event("create_user", params, socket) do
    if socket.assigns.current_user[:role] != socket.assigns.admin_role do
      {:noreply, LiveView.put_flash(socket, :error, "You don't have permission to create users.")}
    else
      attrs = %{
        username: params["username"],
        display_name: params["display_name"],
        email: params["email"],
        role: params["role"]
      }

      case PortalUserAdmin.create_user(attrs) do
        {:ok, user, plaintext} ->
          {:noreply,
           socket
           |> refresh_users()
           |> Phoenix.Component.assign(credentials_flash: %{
             kind: :created,
             username: user.username,
             password: plaintext
           })
           |> LiveView.put_flash(:info, "User created.")}

        {:error, reason} ->
          {:noreply, LiveView.put_flash(socket, :error, create_error_message(reason))}
      end
    end
  end

  defp do_event("suspend_user", %{"user-id" => user_id}, socket) do
    if socket.assigns.current_user[:role] != socket.assigns.admin_role do
      {:noreply, LiveView.put_flash(socket, :error, "Not allowed.")}
    else
      case PortalUserAdmin.set_status(user_id, "suspended") do
        {:ok, _} ->
          {:noreply, socket |> refresh_users() |> LiveView.put_flash(:info, "User suspended.")}

        {:error, reason} ->
          Logger.error("[users_live] suspend failed: #{inspect(reason)}")
          {:noreply, LiveView.put_flash(socket, :error, "Failed to suspend user.")}
      end
    end
  end

  defp do_event("activate_user", %{"user-id" => user_id}, socket) do
    if socket.assigns.current_user[:role] != socket.assigns.admin_role do
      {:noreply, LiveView.put_flash(socket, :error, "Not allowed.")}
    else
      case PortalUserAdmin.set_status(user_id, "active") do
        {:ok, _} ->
          {:noreply, socket |> refresh_users() |> LiveView.put_flash(:info, "User activated.")}

        {:error, reason} ->
          Logger.error("[users_live] activate failed: #{inspect(reason)}")
          {:noreply, LiveView.put_flash(socket, :error, "Failed to activate user.")}
      end
    end
  end

  defp do_event("delete_user", %{"user-id" => user_id}, socket) do
    cond do
      socket.assigns.current_user[:role] != socket.assigns.admin_role ->
        {:noreply, LiveView.put_flash(socket, :error, "Not allowed.")}

      socket.assigns.current_user[:id] == user_id ->
        {:noreply, LiveView.put_flash(socket, :error, "You cannot remove your own account.")}

      true ->
        case PortalUserAdmin.delete_user(user_id) do
          {:ok, _} ->
            {:noreply, socket |> refresh_users() |> LiveView.put_flash(:info, "User removed.")}

          {:error, reason} ->
            Logger.error("[users_live] delete failed: #{inspect(reason)}")
            {:noreply, LiveView.put_flash(socket, :error, "Failed to remove user.")}
        end
    end
  end

  defp do_event("reset_password", %{"user-id" => user_id}, socket) do
    if socket.assigns.current_user[:role] != socket.assigns.admin_role do
      {:noreply, LiveView.put_flash(socket, :error, "Not allowed.")}
    else
      case PortalUserAdmin.reset_password(user_id) do
        {:ok, user, plaintext} ->
          {:noreply,
           socket
           |> Phoenix.Component.assign(credentials_flash: %{
             kind: :reset,
             username: user.username,
             password: plaintext
           })
           |> LiveView.put_flash(:info, "Password reset.")}

        {:error, reason} ->
          Logger.error("[users_live] reset_password failed: #{inspect(reason)}")
          {:noreply, LiveView.put_flash(socket, :error, "Failed to reset password.")}
      end
    end
  end

  defp do_event("dismiss_credentials", _params, socket) do
    {:noreply, Phoenix.Component.assign(socket, credentials_flash: nil)}
  end

  defp do_event("filter_role", %{"role" => role}, socket) do
    filtered = filter_users(socket.assigns.users, role)
    {:noreply, Phoenix.Component.assign(socket, role_filter: role, filtered_users: filtered, page: 1)}
  end

  defp do_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, Phoenix.Component.assign(socket, page: p)}
      _ -> {:noreply, socket}
    end
  end

  # --- Helpers ---

  defp refresh_users(socket) do
    users = PortalUserAdmin.list_users(socket.assigns.scope)

    Phoenix.Component.assign(socket,
      users: users,
      filtered_users: filter_users(users, socket.assigns.role_filter)
    )
  end

  defp filter_users(users, "all"), do: users
  defp filter_users(users, role), do: Enum.filter(users, fn u -> to_string(u.role) == role end)

  defp create_error_message(:invalid_username), do: "Username must be 3–50 characters, letters/numbers/._- only."
  defp create_error_message(:invalid_display_name), do: "Display name is required (up to 128 characters)."
  defp create_error_message(:invalid_email), do: "A valid email address is required."
  defp create_error_message(:invalid_role), do: "Invalid role for this portal."
  defp create_error_message(:username_taken), do: "That username is already taken."
  defp create_error_message(_), do: "Failed to create user."

  defp role_badge_class("ca_admin"), do: "badge-primary"
  defp role_badge_class("ra_admin"), do: "badge-primary"
  defp role_badge_class("key_manager"), do: "badge-info"
  defp role_badge_class("ra_officer"), do: "badge-info"
  defp role_badge_class("auditor"), do: "badge-warning"
  defp role_badge_class(_), do: "badge-ghost"

  # --- Render ---

  @doc "Renders the shared user-management page."
  def render_page(assigns) do
    ~H"""
    <div id="users-page" class="space-y-6">
      <%!-- One-time credential display --%>
      <div
        :if={@credentials_flash}
        id="credentials-flash"
        class="alert alert-warning shadow-sm"
      >
        <.icon name="hero-key" class="size-5" />
        <div class="flex-1">
          <p class="font-semibold text-sm">
            <%= case @credentials_flash.kind do %>
              <% :created -> %>Initial password for <code class="font-mono">{@credentials_flash.username}</code>
              <% :reset -> %>New password for <code class="font-mono">{@credentials_flash.username}</code>
            <% end %>
          </p>
          <p class="font-mono text-sm mt-1">{@credentials_flash.password}</p>
          <p class="text-xs text-base-content/60 mt-1">
            Copy this now — it will not be shown again. Share it with the user securely.
          </p>
        </div>
        <button phx-click="dismiss_credentials" class="btn btn-ghost btn-xs">Dismiss</button>
      </div>

      <%!-- Create user form --%>
      <div
        :if={@current_user[:role] == @admin_role}
        id="create-user-form"
        class="card bg-base-100 shadow-sm border border-base-300"
      >
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Create User</h2>
          <form phx-submit="create_user" class="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label for="user-username" class="block text-xs font-medium text-base-content/60 mb-1">
                Username
              </label>
              <input
                type="text"
                name="username"
                id="user-username"
                required
                maxlength="50"
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div>
              <label for="user-display-name" class="block text-xs font-medium text-base-content/60 mb-1">
                Display Name
              </label>
              <input
                type="text"
                name="display_name"
                id="user-display-name"
                required
                maxlength="128"
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div>
              <label for="user-email" class="block text-xs font-medium text-base-content/60 mb-1">
                Email
              </label>
              <input
                type="email"
                name="email"
                id="user-email"
                required
                maxlength="254"
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div>
              <label for="user-role" class="block text-xs font-medium text-base-content/60 mb-1">
                Role
              </label>
              <select name="role" id="user-role" class="select select-bordered select-sm w-full">
                <option :for={r <- @roles} value={r}>{r}</option>
              </select>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-plus" class="size-4" /> Create
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Filter --%>
      <div id="user-filter" class="flex items-center justify-between">
        <form phx-change="filter_role" class="flex items-center gap-2">
          <label for="role-filter" class="text-sm text-base-content/60">Filter by role:</label>
          <select name="role" id="role-filter" class="select select-sm select-bordered">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option :for={r <- @roles} value={r} selected={@role_filter == r}>{r}</option>
          </select>
        </form>
        <span class="text-sm text-base-content/50">{length(@filtered_users)} user(s)</span>
      </div>

      <%!-- Users table --%>
      <% paginated = @filtered_users |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total = length(@filtered_users) %>
      <% total_pages = max(ceil(total / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total) %>
      <% end_idx = min(@page * @per_page, total) %>
      <div id="user-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">Loading…</div>

          <div :if={not @loading and total == 0} class="p-8 text-center text-base-content/50 text-sm">
            No users yet.
          </div>

          <div :if={not @loading and total > 0}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[20%]">Username</th>
                  <th class="w-[18%]">Name</th>
                  <th class="w-[24%]">Email</th>
                  <th class="w-[12%]">Role</th>
                  <th class="w-[8%]">Status</th>
                  <th class="w-[18%] text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="user-list">
                <tr :for={user <- paginated} id={"user-#{user.id}"} class="hover">
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                    {user.username}
                  </td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{user.display_name}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                    {user.email}
                  </td>
                  <td>
                    <span class={"badge badge-sm #{role_badge_class(to_string(user.role))}"}>
                      {user.role}
                    </span>
                  </td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      user.status == "active" && "badge-success",
                      user.status != "active" && "badge-warning"
                    ]}>
                      {user.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <div
                      :if={user.id != @current_user[:id] and @current_user[:role] == @admin_role}
                      class="flex items-center justify-end gap-1"
                    >
                      <%= if user.status == "active" do %>
                        <button
                          phx-click="suspend_user"
                          phx-value-user-id={user.id}
                          title="Suspend"
                          class="btn btn-ghost btn-xs text-amber-400"
                        >
                          <.icon name="hero-pause" class="size-4" />
                        </button>
                      <% else %>
                        <button
                          phx-click="activate_user"
                          phx-value-user-id={user.id}
                          title="Activate"
                          class="btn btn-ghost btn-xs text-emerald-400"
                        >
                          <.icon name="hero-play" class="size-4" />
                        </button>
                      <% end %>
                      <button
                        phx-click="reset_password"
                        phx-value-user-id={user.id}
                        title="Reset password"
                        class="btn btn-ghost btn-xs text-sky-400"
                      >
                        <.icon name="hero-key" class="size-4" />
                      </button>
                      <button
                        phx-click="delete_user"
                        phx-value-user-id={user.id}
                        data-confirm="Remove this user? They will no longer be able to log in to this portal."
                        title="Remove user"
                        class="btn btn-ghost btn-xs text-rose-400"
                      >
                        <.icon name="hero-trash" class="size-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
            <div
              :if={total > 0}
              class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm"
            >
              <span class="text-base-content/60">Showing {start_idx}–{end_idx} of {total}</span>
              <div class="join">
                <button
                  class="join-item btn btn-sm"
                  phx-click="change_page"
                  phx-value-page={@page - 1}
                  disabled={@page == 1}
                >
                  «
                </button>
                <button class="join-item btn btn-sm btn-active">{@page}</button>
                <button
                  class="join-item btn btn-sm"
                  phx-click="change_page"
                  phx-value-page={@page + 1}
                  disabled={@page >= total_pages}
                >
                  »
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
