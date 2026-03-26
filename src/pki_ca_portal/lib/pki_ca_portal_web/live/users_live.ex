defmodule PkiCaPortalWeb.UsersLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    ca_id = ca_instance_id(socket)
    {:ok, users} = CaEngineClient.list_users(ca_id)

    {:ok,
     assign(socket,
       page_title: "User Management",
       users: users,
       filtered_users: users,
       role_filter: "all",
       form: to_form(%{"username" => "", "display_name" => "", "role" => "ca_admin"}),
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_event("create_user", %{"username" => username, "display_name" => name, "role" => role}, socket) do
    ca_id = ca_instance_id(socket)
    attrs = %{username: username, display_name: name, role: role}

    case CaEngineClient.create_user(ca_id, attrs) do
      {:ok, user} ->
        users = [user | socket.assigns.users]
        filtered = filter_users(users, socket.assigns.role_filter)

        {:noreply,
         socket
         |> assign(users: users, filtered_users: filtered)
         |> put_flash(:info, "User created successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_user", %{"id" => id}, socket) do
    case CaEngineClient.delete_user(id) do
      {:ok, _} ->
        users = Enum.reject(socket.assigns.users, &(&1.id == id))
        filtered = filter_users(users, socket.assigns.role_filter)

        {:noreply,
         socket
         |> assign(users: users, filtered_users: filtered)
         |> put_flash(:info, "User deleted")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_role", %{"role" => role}, socket) do
    filtered = filter_users(socket.assigns.users, role)
    {:noreply, assign(socket, role_filter: role, filtered_users: filtered, page: 1)}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp filter_users(users, "all"), do: users
  defp filter_users(users, role), do: Enum.filter(users, &(&1.role == role))

  defp ca_instance_id(socket) do
    socket.assigns.current_user["ca_instance_id"] || 1
  end

  defp role_badge_class(role) do
    case role do
      "ca_admin" -> "badge-primary"
      "key_manager" -> "badge-info"
      "auditor" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  defp status_badge_class(status) do
    case status do
      "active" -> "badge-success"
      "inactive" -> "badge-ghost"
      "suspended" -> "badge-error"
      _ -> "badge-ghost"
    end
  end

  defp has_credential?(user, type) do
    creds = Map.get(user, :credentials, [])
    Enum.any?(creds, fn c ->
      (c[:credential_type] || c["credential_type"]) == type
    end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="users-page" class="space-y-6">
      <%!-- Header with filter --%>
      <div id="user-filter" class="flex items-center justify-between">
        <div></div>
        <form phx-change="filter_role" class="flex items-center gap-2">
          <label for="role" class="text-sm text-base-content/60">Filter by role:</label>
          <select name="role" id="role-filter" class="select select-sm select-bordered">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option value="ca_admin" selected={@role_filter == "ca_admin"}>CA Admin</option>
            <option value="key_manager" selected={@role_filter == "key_manager"}>Key Manager</option>
            <option value="auditor" selected={@role_filter == "auditor"}>Auditor</option>
          </select>
        </form>
      </div>

      <%!-- Users table --%>
      <% paginated_users = @filtered_users |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_users = length(@filtered_users) %>
      <% total_pages = max(ceil(total_users / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_users) %>
      <% end_idx = min(@page * @per_page, total_users) %>
      <div id="user-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Name</th>
                  <th>Role</th>
                  <th>Credentials</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="user-list">
                <tr :for={user <- paginated_users} id={"user-#{user.id}"} class="hover">
                  <td class="font-mono-data">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td>
                    <span class={"badge badge-sm #{role_badge_class(user.role)}"}>{user.role}</span>
                  </td>
                  <td>
                    <span :if={has_credential?(user, "signing")} class="badge badge-sm badge-success mr-1">Signing &#10003;</span>
                    <span :if={has_credential?(user, "kem")} class="badge badge-sm badge-info mr-1">KEM &#10003;</span>
                    <span :if={!has_credential?(user, "signing") and !has_credential?(user, "kem")} class="badge badge-sm badge-ghost">No credentials</span>
                  </td>
                  <td>
                    <span class={"badge badge-sm #{status_badge_class(user.status)}"}>{user.status}</span>
                  </td>
                  <td class="text-right">
                    <button phx-click="delete_user" phx-value-id={user.id} class="btn btn-error btn-sm btn-outline">
                      <.icon name="hero-trash" class="size-3.5" />
                      Delete
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_users > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_users}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Create user form --%>
      <div id="create-user-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Create User</h2>
          <form phx-submit="create_user" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div>
              <label for="username" class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <input type="text" name="username" id="user-username" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input type="text" name="display_name" id="user-display-name" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="role" class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <select name="role" id="user-role" class="select select-bordered select-sm w-full">
                <option value="ca_admin">CA Admin</option>
                <option value="key_manager">Key Manager</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-plus" class="size-4" />
                Create User
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
