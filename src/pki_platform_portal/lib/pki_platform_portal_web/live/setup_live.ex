defmodule PkiPlatformPortalWeb.SetupLive do
  use Phoenix.LiveView, layout: false

  use Gettext, backend: PkiPlatformPortalWeb.Gettext
  import Phoenix.HTML
  import PkiPlatformPortalWeb.CoreComponents
  alias Phoenix.LiveView.JS

  @impl true
  def mount(_params, _session, socket) do
    if PkiPlatformEngine.AdminManagement.needs_setup?() do
      {:ok,
       assign(socket,
         page_title: "Initial Setup",
         form_error: nil
       )}
    else
      {:ok, push_navigate(socket, to: "/login")}
    end
  end

  @impl true
  def handle_event("create_admin", params, socket) do
    %{"username" => username, "display_name" => display_name, "password" => password, "password_confirmation" => confirmation} = params

    cond do
      String.length(password) < 8 ->
        {:noreply, assign(socket, form_error: "Password must be at least 8 characters.")}

      password != confirmation ->
        {:noreply, assign(socket, form_error: "Passwords do not match.")}

      true ->
        case PkiPlatformEngine.AdminManagement.register_admin(%{
               username: username,
               display_name: display_name,
               password: password
             }) do
          {:ok, _admin} ->
            {:noreply, push_navigate(socket, to: "/login")}

          {:error, changeset} ->
            error =
              Ecto.Changeset.traverse_errors(changeset, fn {msg, _} -> msg end)
              |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
              |> Enum.join("; ")

            {:noreply, assign(socket, form_error: error)}
        end
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
      <div class="card bg-base-100 shadow-lg w-full max-w-md">
        <div class="card-body">
          <div class="flex items-center gap-3 mb-4">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary">
              <.icon name="hero-server-stack" class="size-5 text-primary-content" />
            </div>
            <div>
              <h1 class="text-lg font-bold">Platform Setup</h1>
              <p class="text-xs text-base-content/50">Create the first administrator account</p>
            </div>
          </div>

          <%= if @form_error do %>
            <div class="alert alert-error text-sm mb-3">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@form_error}</span>
            </div>
          <% end %>

          <form phx-submit="create_admin" class="space-y-4">
            <div>
              <label class="block text-sm font-medium mb-1">Username</label>
              <input type="text" name="username" required class="input input-bordered w-full" placeholder="admin" autocomplete="username" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Display Name</label>
              <input type="text" name="display_name" required class="input input-bordered w-full" placeholder="Platform Admin" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Password</label>
              <input type="password" name="password" required minlength="8" class="input input-bordered w-full" autocomplete="new-password" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-1">Confirm Password</label>
              <input type="password" name="password_confirmation" required minlength="8" class="input input-bordered w-full" autocomplete="new-password" />
            </div>
            <button type="submit" class="btn btn-primary w-full" phx-disable-with="Creating account...">
              Create Admin Account
            </button>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
