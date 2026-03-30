defmodule PkiPlatformPortalWeb.AdminsLive do
  use PkiPlatformPortalWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Admins",
       admins: [],
       loading: true,
       show_form: false,
       form_error: nil,
       pw_error: nil
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    admins = list_admins()
    {:noreply, assign(socket, admins: admins, loading: false)}
  end

  @impl true
  def handle_event("toggle_form", _params, socket) do
    {:noreply, assign(socket, show_form: !socket.assigns.show_form, form_error: nil, pw_error: nil)}
  end

  @impl true
  def handle_event(
        "create_admin",
        %{
          "username" => username,
          "display_name" => display_name,
          "password" => password,
          "password_confirmation" => password_confirmation
        },
        socket
      ) do
    cond do
      String.length(password) < 8 ->
        {:noreply, assign(socket, pw_error: "Password must be at least 8 characters.")}

      password != password_confirmation ->
        {:noreply, assign(socket, pw_error: "Passwords do not match.")}

      true ->
        attrs = %{
          username: username,
          display_name: display_name,
          password: password
        }

        case PkiPlatformEngine.AdminManagement.register_admin(attrs) do
          {:ok, _admin} ->
            {:noreply,
             socket
             |> assign(admins: list_admins(), show_form: false, form_error: nil, pw_error: nil)
             |> put_flash(:info, "Admin \"#{username}\" created successfully.")}

          {:error, %Ecto.Changeset{} = changeset} ->
            errors =
              Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
                Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
                  opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
                end)
              end)

            error_msg =
              errors
              |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
              |> Enum.join("; ")

            {:noreply, assign(socket, form_error: error_msg, pw_error: nil)}

          {:error, reason} ->
            {:noreply, assign(socket, form_error: "Failed to create admin: #{inspect(reason)}", pw_error: nil)}
        end
    end
  end

  @impl true
  def handle_event("suspend_admin", %{"id" => id}, socket) do
    case PkiPlatformEngine.AdminManagement.get_admin(id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Admin not found.")}

      admin ->
        case PkiPlatformEngine.AdminManagement.suspend_admin(admin) do
          {:ok, _admin} ->
            {:noreply,
             socket
             |> assign(admins: list_admins())
             |> put_flash(:info, "Admin \"#{admin.username}\" suspended.")}

          {:error, :last_active_admin} ->
            {:noreply, put_flash(socket, :error, "Cannot suspend the last active admin.")}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to suspend admin: #{inspect(reason)}")}
        end
    end
  end

  @impl true
  def handle_event("activate_admin", %{"id" => id}, socket) do
    case PkiPlatformEngine.AdminManagement.get_admin(id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Admin not found.")}

      admin ->
        case PkiPlatformEngine.AdminManagement.activate_admin(admin) do
          {:ok, _admin} ->
            {:noreply,
             socket
             |> assign(admins: list_admins())
             |> put_flash(:info, "Admin \"#{admin.username}\" activated.")}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to activate admin: #{inspect(reason)}")}
        end
    end
  end

  @impl true
  def handle_event("delete_admin", %{"id" => id}, socket) do
    case PkiPlatformEngine.AdminManagement.get_admin(id) do
      nil ->
        {:noreply, put_flash(socket, :error, "Admin not found.")}

      admin ->
        case PkiPlatformEngine.AdminManagement.delete_admin(admin) do
          {:ok, _admin} ->
            {:noreply,
             socket
             |> assign(admins: list_admins())
             |> put_flash(:info, "Admin \"#{admin.username}\" deleted.")}

          {:error, :last_active_admin} ->
            {:noreply, put_flash(socket, :error, "Cannot delete the last active admin.")}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to delete admin: #{inspect(reason)}")}
        end
    end
  end

  defp list_admins do
    PkiPlatformEngine.AdminManagement.list_admins()
  rescue
    _ -> []
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="admins-page" class="space-y-6">
      <%!-- Header with toggle button --%>
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-lg font-semibold text-base-content">Platform Admins</h1>
          <p class="text-sm text-base-content/50 mt-0.5">Manage platform administrator accounts.</p>
        </div>
        <button
          phx-click="toggle_form"
          class={["btn btn-sm", @show_form && "btn-ghost", !@show_form && "btn-primary"]}
        >
          <.icon name={if @show_form, do: "hero-x-mark", else: "hero-plus"} class="size-4" />
          {if @show_form, do: "Cancel", else: "New Admin"}
        </button>
      </div>

      <%!-- Create Admin Form --%>
      <div :if={@show_form} class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <h2 class="text-sm font-semibold text-base-content mb-3">Create New Admin</h2>

          <div :if={@form_error} class="alert alert-error text-sm mb-3">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@form_error}</span>
          </div>

          <div :if={@pw_error} class="alert alert-error text-sm mb-3">
            <.icon name="hero-exclamation-circle" class="size-4" />
            <span>{@pw_error}</span>
          </div>

          <form id="create-admin-form" phx-submit="create_admin" class="space-y-3">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label for="admin-username" class="block text-xs font-medium text-base-content/60 mb-1">
                  Username
                </label>
                <input
                  type="text"
                  name="username"
                  id="admin-username"
                  required
                  autocomplete="off"
                  class="input input-bordered input-sm w-full"
                  placeholder="e.g. jdoe"
                />
              </div>
              <div>
                <label for="admin-display-name" class="block text-xs font-medium text-base-content/60 mb-1">
                  Display Name
                </label>
                <input
                  type="text"
                  name="display_name"
                  id="admin-display-name"
                  required
                  class="input input-bordered input-sm w-full"
                  placeholder="e.g. Jane Doe"
                />
              </div>
              <div>
                <label for="admin-password" class="block text-xs font-medium text-base-content/60 mb-1">
                  Password
                </label>
                <input
                  type="password"
                  name="password"
                  id="admin-password"
                  required
                  minlength="8"
                  autocomplete="new-password"
                  class="input input-bordered input-sm w-full"
                  placeholder="Min. 8 characters"
                />
              </div>
              <div>
                <label for="admin-password-confirm" class="block text-xs font-medium text-base-content/60 mb-1">
                  Confirm Password
                </label>
                <input
                  type="password"
                  name="password_confirmation"
                  id="admin-password-confirm"
                  required
                  minlength="8"
                  autocomplete="new-password"
                  class="input input-bordered input-sm w-full"
                  placeholder="Re-enter password"
                />
              </div>
            </div>
            <div class="flex justify-end">
              <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Creating...">
                <.icon name="hero-user-plus" class="size-4" />
                Create Admin
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Admins Table --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-base-content">All Admins</h2>
            <span class="text-xs text-base-content/50">{length(@admins)} total</span>
          </div>
          <div class="overflow-x-auto">
            <table id="admin-list" class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :if={@admins == []}>
                  <td colspan="6" class="text-center text-base-content/50 py-8">No admins found.</td>
                </tr>
                <tr :for={admin <- @admins} id={"admin-#{admin.id}"} class="hover">
                  <td class="font-mono text-sm">
                    <div class="flex items-center gap-2">
                      {admin.username}
                      <span :if={admin.id == @current_user["id"]} class="badge badge-xs badge-neutral">you</span>
                    </div>
                  </td>
                  <td class="font-medium">{admin.display_name}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      admin.role == "super_admin" && "badge-primary",
                      admin.role != "super_admin" && "badge-ghost"
                    ]}>
                      {admin.role}
                    </span>
                  </td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      admin.status == "active" && "badge-success",
                      admin.status == "suspended" && "badge-warning"
                    ]}>
                      {admin.status}
                    </span>
                  </td>
                  <td class="text-base-content/60 text-sm">
                    {Calendar.strftime(admin.inserted_at, "%Y-%m-%d")}
                  </td>
                  <td>
                    <div class="flex gap-1">
                      <button
                        :if={admin.status == "active" and admin.id != @current_user["id"]}
                        phx-click="suspend_admin"
                        phx-value-id={admin.id}
                        data-confirm={"Suspend admin \"#{admin.username}\"? They will lose access immediately."}
                        class="btn btn-ghost btn-xs text-warning"
                      >
                        <.icon name="hero-pause" class="size-3" />
                        Suspend
                      </button>
                      <button
                        :if={admin.status == "suspended"}
                        phx-click="activate_admin"
                        phx-value-id={admin.id}
                        class="btn btn-ghost btn-xs text-success"
                      >
                        <.icon name="hero-play" class="size-3" />
                        Activate
                      </button>
                      <button
                        :if={admin.id != @current_user["id"]}
                        phx-click="delete_admin"
                        phx-value-id={admin.id}
                        data-confirm={"Permanently delete admin \"#{admin.username}\"? This cannot be undone."}
                        class="btn btn-ghost btn-xs text-error"
                      >
                        <.icon name="hero-trash" class="size-3" />
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
