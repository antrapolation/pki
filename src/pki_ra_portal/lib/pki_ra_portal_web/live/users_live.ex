defmodule PkiRaPortalWeb.UsersLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, users} = RaEngineClient.list_users()

    {:ok,
     assign(socket,
       page_title: "Users",
       users: users,
       filtered_users: users,
       role_filter: "all"
     )}
  end

  @impl true
  def handle_event("create_user", %{"username" => username, "display_name" => name, "role" => role}, socket) do
    attrs = %{username: username, display_name: name, role: role}

    case RaEngineClient.create_user(attrs) do
      {:ok, user} ->
        users = socket.assigns.users ++ [user]
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
    case RaEngineClient.delete_user(id) do
      {:ok, _} ->
        users = Enum.reject(socket.assigns.users, &(&1.id == id))
        filtered = filter_users(users, socket.assigns.role_filter)

        {:noreply,
         socket
         |> assign(users: users, filtered_users: filtered)
         |> put_flash(:info, "User suspended")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete user: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_role", %{"role" => role}, socket) do
    filtered = filter_users(socket.assigns.users, role)
    {:noreply, assign(socket, role_filter: role, filtered_users: filtered)}
  end

  defp filter_users(users, "all"), do: users
  defp filter_users(users, role), do: Enum.filter(users, &(&1.role == role))

  @impl true
  def render(assigns) do
    ~H"""
    <div id="users-page">
      <h1>User Management</h1>

      <section id="user-filter">
        <form phx-change="filter_role">
          <label for="role">Filter by role:</label>
          <select name="role" id="role-filter">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option value="ra_admin" selected={@role_filter == "ra_admin"}>RA Admin</option>
            <option value="ra_officer" selected={@role_filter == "ra_officer"}>RA Officer</option>
            <option value="auditor" selected={@role_filter == "auditor"}>Auditor</option>
          </select>
        </form>
      </section>

      <section id="user-table">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="user-list">
            <tr :for={user <- @filtered_users} id={"user-#{user.id}"}>
              <td>{user.username}</td>
              <td>{user.display_name}</td>
              <td>{user.role}</td>
              <td>{user.status}</td>
              <td>
                <button phx-click="delete_user" phx-value-id={user.id}>Suspend</button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="create-user-form">
        <h2>Create User</h2>
        <form phx-submit="create_user">
          <div>
            <label for="username">Username:</label>
            <input type="text" name="username" id="user-username" required />
          </div>
          <div>
            <label for="display_name">Display Name:</label>
            <input type="text" name="display_name" id="user-display-name" required />
          </div>
          <div>
            <label for="role">Role:</label>
            <select name="role" id="user-role">
              <option value="ra_admin">RA Admin</option>
              <option value="ra_officer">RA Officer</option>
            </select>
          </div>
          <button type="submit">Create User</button>
        </form>
      </section>
    </div>
    """
  end
end
