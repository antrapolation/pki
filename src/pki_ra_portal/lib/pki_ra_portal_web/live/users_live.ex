defmodule PkiRaPortalWeb.UsersLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, users} = RaEngineClient.list_users()

    {:ok,
     socket
     |> assign(
       page_title: "Users",
       users: users,
       filtered_users: users,
       role_filter: "all",
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("create_user", %{"username" => username, "password" => password, "display_name" => name, "role" => role}, socket) do
    attrs = %{username: username, password: password, display_name: name, role: role}

    case RaEngineClient.create_user(attrs) do
      {:ok, user} ->
        users = [user | socket.assigns.users]
        filtered = filter_users(users, socket.assigns.role_filter)

        {:noreply,
         socket
         |> assign(users: users, filtered_users: filtered, page: 1)
         |> apply_pagination()
         |> put_flash(:info, "User created successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("delete_user", %{"id" => id}, socket) do
    case RaEngineClient.delete_user(id) do
      {:ok, _} ->
        users = Enum.reject(socket.assigns.users, &(&1.id == id))
        filtered = filter_users(users, socket.assigns.role_filter)

        {:noreply,
         socket
         |> assign(users: users, filtered_users: filtered)
         |> apply_pagination()
         |> put_flash(:info, "User suspended")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_role", %{"role" => role}, socket) do
    filtered = filter_users(socket.assigns.users, role)
    {:noreply, socket |> assign(role_filter: role, filtered_users: filtered, page: 1) |> apply_pagination()}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, socket |> assign(page: String.to_integer(page)) |> apply_pagination()}
  end

  defp filter_users(users, "all"), do: users
  defp filter_users(users, role), do: Enum.filter(users, &(&1.role == role))

  defp apply_pagination(socket) do
    items = socket.assigns.filtered_users
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_users: paged, total_pages: total_pages, page: page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="users-page" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">User Management</h1>

      <%!-- Filter --%>
      <section id="user-filter">
        <form phx-change="filter_role" class="flex items-center gap-3">
          <label for="role" class="text-sm font-medium text-base-content/60">Filter by role:</label>
          <select name="role" id="role-filter" class="select select-sm select-bordered">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option value="ra_admin" selected={@role_filter == "ra_admin"}>RA Admin</option>
            <option value="ra_officer" selected={@role_filter == "ra_officer"}>RA Officer</option>
            <option value="auditor" selected={@role_filter == "auditor"}>Auditor</option>
          </select>
        </form>
      </section>

      <%!-- Users Table --%>
      <section id="user-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider">Username</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Name</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Role</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Credentials</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody id="user-list">
                <tr :for={user <- @paged_users} id={"user-#{user.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-mono text-xs">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      user.role == "ra_admin" && "badge-primary",
                      user.role == "ra_officer" && "badge-info",
                      user.role == "auditor" && "badge-neutral"
                    ]}>
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
                  <td>
                    <span class={[
                      "badge badge-sm",
                      Map.get(user, :has_credentials, false) && "badge-success",
                      !Map.get(user, :has_credentials, false) && "badge-ghost"
                    ]}>
                      {if Map.get(user, :has_credentials, false), do: "configured", else: "not set"}
                    </span>
                  </td>
                  <td>
                    <button phx-click="delete_user" phx-value-id={user.id} class="btn btn-xs btn-warning btn-outline">
                      Suspend
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total_pages > 1} class="flex justify-center mt-4">
            <div class="join">
              <button
                :for={p <- 1..@total_pages}
                phx-click="change_page"
                phx-value-page={p}
                class={["join-item btn btn-sm", p == @page && "btn-active"]}
              >
                {p}
              </button>
            </div>
          </div>
        </div>
      </section>

      <%!-- Create User Form --%>
      <section id="create-user-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Create User</h2>
          <form phx-submit="create_user" class="grid grid-cols-1 md:grid-cols-5 gap-4 mt-2">
            <div>
              <label for="username" class="label text-xs font-medium">Username</label>
              <input type="text" name="username" id="user-username" required class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="password" class="label text-xs font-medium">Password</label>
              <input type="password" name="password" id="user-password" required minlength="8" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="display_name" class="label text-xs font-medium">Display Name</label>
              <input type="text" name="display_name" id="user-display-name" required class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="role" class="label text-xs font-medium">Role</label>
              <select name="role" id="user-role" class="select select-sm select-bordered w-full">
                <option value="ra_admin">RA Admin</option>
                <option value="ra_officer">RA Officer</option>
              </select>
            </div>
            <div class="flex items-end">
              <button type="submit" class="btn btn-sm btn-primary w-full">
                Create User
              </button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
