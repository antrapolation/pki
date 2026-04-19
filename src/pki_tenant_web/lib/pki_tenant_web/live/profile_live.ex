defmodule PkiTenantWeb.ProfileLive do
  @moduledoc """
  Self-service user profile. Shared between CA and RA portals — whichever
  live_session the user is in, this module mounts under the right layout
  (ca_app for CA, ra_app for RA) via the router config.

  Two forms:
    * Profile — display_name + email
    * Change password — current + new + confirmation
  """
  use PkiTenantWeb, :live_view

  alias PkiTenant.PortalUserManagement

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {:ok,
     assign(socket,
       page_title: "Profile",
       profile_form:
         to_form(%{
           "display_name" => user[:display_name] || "",
           "email" => user[:email] || ""
         }),
       password_form:
         to_form(%{
           "current_password" => "",
           "new_password" => "",
           "password_confirmation" => ""
         }),
       profile_error: nil,
       profile_notice: nil,
       password_error: nil,
       password_notice: nil
     )}
  end

  @impl true
  def handle_event("update_profile", params, socket) do
    user = socket.assigns.current_user
    user_id = user[:id]

    case PortalUserManagement.update_profile(user_id, %{
           display_name: params["display_name"],
           email: params["email"]
         }) do
      {:ok, updated} ->
        PkiTenant.AuditBridge.log("profile_updated", %{
          user_id: user_id,
          display_name: updated.display_name,
          email: updated.email
        })

        # Keep the session store in sync so the sidebar avatar etc.
        # reflect the change without re-login.
        if sid = socket.assigns[:session_id] do
          PkiTenantWeb.SessionStore.update_profile(sid, %{
            display_name: updated.display_name,
            email: updated.email
          })
        end

        refreshed_user = Map.merge(user, %{display_name: updated.display_name, email: updated.email})

        {:noreply,
         socket
         |> assign(
           current_user: refreshed_user,
           profile_form:
             to_form(%{
               "display_name" => updated.display_name || "",
               "email" => updated.email || ""
             }),
           profile_error: nil,
           profile_notice: "Profile updated."
         )}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(
           profile_notice: nil,
           profile_error: profile_error_message(reason)
         )}
    end
  end

  def handle_event("change_password", params, socket) do
    user = socket.assigns.current_user
    user_id = user[:id]

    case PortalUserManagement.verify_and_change_password(
           user_id,
           params["current_password"] || "",
           params["new_password"] || "",
           params["password_confirmation"] || ""
         ) do
      {:ok, _updated} ->
        PkiTenant.AuditBridge.log("password_changed", %{user_id: user_id})

        {:noreply,
         socket
         |> assign(
           password_form:
             to_form(%{
               "current_password" => "",
               "new_password" => "",
               "password_confirmation" => ""
             }),
           password_error: nil,
           password_notice: "Password changed."
         )}

      {:error, reason} ->
        {:noreply,
         socket
         |> assign(
           password_notice: nil,
           password_error: password_error_message(reason)
         )}
    end
  end

  defp profile_error_message(:not_found), do: "User record not found."
  defp profile_error_message(:invalid_email), do: "Email doesn't look valid."
  defp profile_error_message(:invalid_display_name), do: "Display name is too long (max 128)."
  defp profile_error_message(_), do: "Unexpected error. Try again."

  defp password_error_message(:not_found), do: "User record not found."
  defp password_error_message(:wrong_password), do: "Current password is incorrect."
  defp password_error_message(:password_mismatch), do: "New password and confirmation don't match."
  defp password_error_message(:weak_password), do: "New password must be at least 12 characters."
  defp password_error_message(_), do: "Unexpected error. Try again."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 class="text-lg font-semibold text-base-content">Profile</h1>
        <p class="text-xs text-base-content/60">
          Update your display name, email, and password. Username and role are
          managed by a CA administrator.
        </p>
      </div>

      <%!-- Profile form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold">Display</h2>

          <.form for={@profile_form} phx-submit="update_profile" class="space-y-3" id="profile-form">
            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">Username</label>
              <input
                type="text"
                value={@current_user[:username]}
                class="input input-bordered input-sm w-full bg-base-200"
                disabled
                readonly
              />
              <p class="text-xs text-base-content/40 mt-1">
                Username is set by the CA admin and can't be changed here.
              </p>
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">Display name</label>
              <input
                type="text"
                name="display_name"
                value={@profile_form.params["display_name"]}
                maxlength="128"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">Email</label>
              <input
                type="email"
                name="email"
                value={@profile_form.params["email"]}
                maxlength="320"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div :if={@profile_error} class="alert alert-error text-sm py-2">
              <span>{@profile_error}</span>
            </div>

            <div :if={@profile_notice} class="alert alert-success text-sm py-2">
              <span>{@profile_notice}</span>
            </div>

            <div class="flex justify-end">
              <button type="submit" class="btn btn-primary btn-sm">Save profile</button>
            </div>
          </.form>
        </div>
      </div>

      <%!-- Change password form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold">Change password</h2>

          <.form for={@password_form} phx-submit="change_password" class="space-y-3" id="password-form" autocomplete="off">
            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">Current password</label>
              <input
                type="password"
                name="current_password"
                required
                autocomplete="current-password"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">New password (min 12 characters)</label>
              <input
                type="password"
                name="new_password"
                minlength="12"
                required
                autocomplete="new-password"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/70 mb-1">Confirm new password</label>
              <input
                type="password"
                name="password_confirmation"
                minlength="12"
                required
                autocomplete="new-password"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div :if={@password_error} class="alert alert-error text-sm py-2">
              <span>{@password_error}</span>
            </div>

            <div :if={@password_notice} class="alert alert-success text-sm py-2">
              <span>{@password_notice}</span>
            </div>

            <div class="flex justify-end">
              <button type="submit" class="btn btn-primary btn-sm">Change password</button>
            </div>
          </.form>
        </div>
      </div>
    </div>
    """
  end
end
