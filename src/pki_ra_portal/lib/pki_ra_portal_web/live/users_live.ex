defmodule PkiRaPortalWeb.UsersLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "User Management",
       users: [],
       filtered_users: [],
       role_filter: "all",
       loading: true,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = actor_opts(socket)
    users = case RaEngineClient.list_portal_users(opts) do
      {:ok, u} -> u
      {:error, _} -> []
    end

    {:noreply,
     assign(socket,
       users: users,
       filtered_users: users,
       loading: false
     )}
  end

  @impl true
  def handle_event("create_user", params, socket) do
    attrs = %{
      username: params["username"],
      display_name: params["display_name"],
      email: params["email"],
      role: params["role"]
    }

    case RaEngineClient.create_portal_user(attrs, actor_opts(socket)) do
      {:ok, _user} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User created. Invitation email sent.")}

      {:error, {:validation_error, errors}} ->
        msg = format_validation_errors(errors)
        {:noreply, put_flash(socket, :error, "Failed to create user: #{msg}")}

      {:error, reason} ->
        Logger.error("[users] Failed to create user: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to create user", reason))}
    end
  end

  @impl true
  def handle_event("suspend_user", %{"role-id" => role_id}, socket) do
    case RaEngineClient.suspend_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User suspended.")}

      {:error, reason} ->
        Logger.error("[users] Failed to suspend user: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to suspend user", reason))}
    end
  end

  @impl true
  def handle_event("activate_user", %{"role-id" => role_id}, socket) do
    case RaEngineClient.activate_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User activated.")}

      {:error, reason} ->
        Logger.error("[users] Failed to activate user: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to activate user", reason))}
    end
  end

  @impl true
  def handle_event("reset_password", %{"user-id" => user_id}, socket) do
    case RaEngineClient.reset_user_password(user_id, actor_opts(socket)) do
      :ok ->
        {:noreply, put_flash(socket, :info, "Password reset. New credentials emailed.")}

      {:error, reason} ->
        Logger.error("[users] Failed to reset password: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to reset password", reason))}
    end
  end

  @impl true
  def handle_event("resend_invitation", %{"user-id" => user_id}, socket) do
    case RaEngineClient.resend_invitation(user_id, actor_opts(socket)) do
      :ok ->
        {:noreply, put_flash(socket, :info, "Invitation email resent.")}

      {:error, reason} ->
        Logger.error("[users] Failed to resend invitation: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to resend invitation", reason))}
    end
  end

  @impl true
  def handle_event("delete_user", %{"role-id" => role_id}, socket) do
    case RaEngineClient.delete_user_role(role_id, actor_opts(socket)) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "User removed.")}

      {:error, reason} ->
        Logger.error("[users] Failed to remove user: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to remove user", reason))}
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

  defp actor_opts(socket) do
    user = socket.assigns.current_user
    base = [
      actor_id: user[:id] || user["id"],
      actor_username: user[:username] || user["username"]
    ]

    case socket.assigns[:tenant_id] do
      nil -> base
      tid -> [{:tenant_id, tid} | base]
    end
  end

  defp format_validation_errors(errors) when is_map(errors) do
    Enum.map_join(errors, ", ", fn {field, msgs} -> "#{field}: #{Enum.join(List.wrap(msgs), ", ")}" end)
  end
  defp format_validation_errors(errors), do: inspect(errors)

  defp role_badge_class(role) do
    case role do
      "ra_admin" -> "badge-primary"
      "ra_officer" -> "badge-info"
      "auditor" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="users-page" class="space-y-6">
      <%!-- Create user form --%>
      <div id="create-user-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Create User & Send Invite</h2>
          <form phx-submit="create_user" class="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label for="username" class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <input type="text" name="username" id="user-username" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input type="text" name="display_name" id="user-display-name" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input type="email" name="email" id="user-email" required class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label for="role" class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <select name="role" id="user-role" class="select select-bordered select-sm w-full">
                <option value="ra_admin">RA Admin</option>
                <option value="ra_officer">RA Officer</option>
                <option value="auditor">Auditor</option>
              </select>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-envelope" class="size-4" />
                Create & Send Invite
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Filter --%>
      <div id="user-filter" class="flex items-center justify-end">
        <form phx-change="filter_role" class="flex items-center gap-2">
          <label for="role" class="text-sm text-base-content/60">Filter by role:</label>
          <select name="role" id="role-filter" class="select select-sm select-bordered">
            <option value="all" selected={@role_filter == "all"}>All</option>
            <option value="ra_admin" selected={@role_filter == "ra_admin"}>RA Admin</option>
            <option value="ra_officer" selected={@role_filter == "ra_officer"}>RA Officer</option>
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
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[20%]">Username</th>
                  <th class="w-[17%]">Name</th>
                  <th class="w-[22%]">Email</th>
                  <th class="w-[10%]">Role</th>
                  <th class="w-[10%]">Status</th>
                  <th class="w-[21%] text-right">Actions</th>
                </tr>
              </thead>
              <tbody id="user-list">
                <tr :for={user <- paginated_users} id={"user-#{user.id}"} class="hover">
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{user.username}</td>
                  <td class="overflow-hidden text-ellipsis whitespace-nowrap">{user.display_name}</td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">{user.email}</td>
                  <td>
                    <span class={"badge badge-sm #{role_badge_class(user.role)}"}>{user.role}</span>
                  </td>
                  <td>
                    <span class={["badge badge-sm", if(user.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {user.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <div :if={user.id != @current_user[:id]} class="flex items-center justify-end gap-1">
                      <%= if user.status == "active" do %>
                        <div class="tooltip" data-tip="Suspend">
                          <button phx-click="suspend_user" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-warning">
                            <.icon name="hero-pause" class="size-4" />
                          </button>
                        </div>
                      <% else %>
                        <div class="tooltip" data-tip="Activate">
                          <button phx-click="activate_user" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-success">
                            <.icon name="hero-play" class="size-4" />
                          </button>
                        </div>
                      <% end %>
                      <div :if={user[:must_change_password]} class="tooltip" data-tip="Resend Invite">
                        <button phx-click="resend_invitation" phx-value-user-id={user.id} class="btn btn-ghost btn-xs text-accent">
                          <.icon name="hero-envelope" class="size-4" />
                        </button>
                      </div>
                      <div class="tooltip" data-tip="Reset Password">
                        <button phx-click="reset_password" phx-value-user-id={user.id} class="btn btn-ghost btn-xs text-info">
                          <.icon name="hero-key" class="size-4" />
                        </button>
                      </div>
                      <div class="tooltip" data-tip="Remove User">
                        <button phx-click="delete_user" phx-value-role-id={user.role_id}
                          data-confirm="Remove this user's access? They will no longer be able to log in to this portal."
                          class="btn btn-ghost btn-xs text-error">
                          <.icon name="hero-trash" class="size-4" />
                        </button>
                      </div>
                    </div>
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
    </div>
    """
  end
end
