defmodule PkiRaPortalWeb.ProfileLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {:ok,
     assign(socket,
       page_title: "Profile",
       profile_form: %{"display_name" => user[:display_name] || user["display_name"] || "", "email" => user[:email] || user["email"] || ""},
       password_form: %{"current_password" => "", "new_password" => "", "password_confirmation" => ""},
       profile_error: nil,
       password_error: nil
     )}
  end

  @impl true
  def handle_event("update_profile", %{"display_name" => display_name, "email" => email}, socket) do
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    case RaEngineClient.update_user_profile(user_id, %{display_name: display_name, email: email}, opts) do
      {:ok, _updated} ->
        {:noreply,
         socket
         |> put_flash(:info, "Profile updated successfully.")
         |> push_navigate(to: "/profile")}

      {:error, reason} ->
        {:noreply, assign(socket, :profile_error, format_error(reason))}
    end
  end

  @impl true
  def handle_event("change_password", params, socket) do
    %{"current_password" => current, "new_password" => new_pw, "password_confirmation" => confirm} = params
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    cond do
      String.length(new_pw) < 8 ->
        {:noreply, assign(socket, :password_error, "New password must be at least 8 characters.")}

      new_pw != confirm ->
        {:noreply, assign(socket, :password_error, "New password and confirmation do not match.")}

      true ->
        case RaEngineClient.verify_and_change_password(user_id, current, new_pw, opts) do
          {:ok, _} ->
            {:noreply,
             socket
             |> assign(:password_form, %{"current_password" => "", "new_password" => "", "password_confirmation" => ""})
             |> assign(:password_error, nil)
             |> put_flash(:info, "Password changed successfully.")}

          {:error, :invalid_current_password} ->
            {:noreply, assign(socket, :password_error, "Current password is incorrect.")}

          {:error, reason} ->
            {:noreply, assign(socket, :password_error, format_error(reason))}
        end
    end
  end

  defp format_error({:validation_error, errors}) when is_map(errors) do
    Enum.map_join(errors, ", ", fn {field, msgs} -> "#{field}: #{Enum.join(List.wrap(msgs), ", ")}" end)
  end
  defp format_error(:invalid_current_password), do: "Current password is incorrect."
  defp format_error(:not_found), do: "User not found."
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(_), do: "An unexpected error occurred."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-2xl mx-auto space-y-6">
      <%!-- Profile Information Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-user-circle" class="size-4 inline -mt-0.5" /> Profile Information
          </h2>

          <%!-- Read-only fields --%>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <p class="text-sm text-base-content font-mono">{@current_user[:username] || @current_user["username"]}</p>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <span class="badge badge-sm badge-primary">{@current_user[:role] || @current_user["role"]}</span>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Status</label>
              <span class={["badge badge-sm", if((@current_user[:status] || @current_user["status"] || "active") == "active", do: "badge-success", else: "badge-warning")]}>
                {@current_user[:status] || @current_user["status"] || "active"}
              </span>
            </div>
          </div>

          <%= if @profile_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@profile_error}</span>
            </div>
          <% end %>

          <%!-- Editable fields --%>
          <form phx-submit="update_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input
                type="text"
                name="display_name"
                id="display_name"
                value={@profile_form["display_name"]}
                class="input input-bordered input-sm w-full"
                maxlength="100"
              />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input
                type="email"
                name="email"
                id="email"
                value={@profile_form["email"]}
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="md:col-span-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-check" class="size-4" /> Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Change Password Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-lock-closed" class="size-4 inline -mt-0.5" /> Change Password
          </h2>

          <%= if @password_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@password_error}</span>
            </div>
          <% end %>

          <form phx-submit="change_password" class="space-y-4">
            <div>
              <label for="current_password" class="block text-xs font-medium text-base-content/60 mb-1">Current Password</label>
              <input
                type="password"
                name="current_password"
                id="current_password"
                required
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="new_password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
                <input
                  type="password"
                  name="new_password"
                  id="new_password"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
              <div>
                <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  name="password_confirmation"
                  id="password_confirmation"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-lock-closed" class="size-4" /> Change Password
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
