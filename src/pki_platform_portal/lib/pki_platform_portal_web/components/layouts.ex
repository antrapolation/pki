defmodule PkiPlatformPortalWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use PkiPlatformPortalWeb, :html

  embed_templates "layouts/*"

  @doc """
  Renders your app layout with sidebar navigation and topbar.
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    assigns = assign_new(assigns, :current_user, fn -> nil end)
    assigns = assign_new(assigns, :page_title, fn -> nil end)

    ~H"""
    <div class="flex min-h-screen bg-base-200">
      <%!-- Sidebar --%>
      <aside class="fixed top-0 left-0 h-screen w-64 flex flex-col bg-base-100 border-r border-base-300">
        <%!-- Logo --%>
        <div class="flex items-center gap-3 px-4 py-4 border-b border-base-300">
          <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary">
            <.icon name="hero-server-stack" class="size-4 text-primary-content" />
          </div>
          <div>
            <span class="text-sm font-bold text-base-content">Platform Admin</span>
            <span class="block text-xs text-base-content/40">Tenant Management</span>
          </div>
        </div>

        <%!-- Navigation --%>
        <nav class="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
          <.sidebar_link href="/tenants" icon="hero-building-office-2" label="Tenants" current={@page_title} />
          <.sidebar_link href="/system" icon="hero-server-stack" label="System" current={@page_title} />
          <.sidebar_link href="/admins" icon="hero-users" label="Admins" current={@page_title} />
        </nav>

        <%!-- Sidebar footer --%>
        <div class="px-4 py-3 border-t border-base-300 flex items-center justify-between">
          <p class="text-xs text-base-content/30">PQC Platform Administration</p>
          <.theme_toggle />
        </div>
      </aside>

      <%!-- Main content area --%>
      <div class="flex-1 ml-64 flex flex-col min-h-screen">
        <%!-- Topbar --%>
        <header class="sticky top-0 z-10 flex items-center justify-between px-6 py-3 bg-base-100 border-b border-base-300">
          <h1 class="text-sm font-semibold text-base-content">
            {@page_title || "Platform Admin"}
          </h1>
          <div class="flex items-center gap-3">
            <%= if @current_user do %>
              <span class="text-xs text-base-content/50">
                <.icon name="hero-user-circle" class="size-3.5 inline -mt-0.5" />
                {@current_user[:display_name] || @current_user[:username]}
              </span>
              <form method="post" action="/logout">
                <input type="hidden" name="_csrf_token" value={Plug.CSRFProtection.get_csrf_token()} />
                <input type="hidden" name="_method" value="delete" />
                <button type="submit" class="btn btn-ghost btn-xs text-base-content/50 hover:text-error">
                  <.icon name="hero-arrow-right-on-rectangle" class="size-3.5" />
                  Sign out
                </button>
              </form>
            <% end %>
          </div>
        </header>

        <%!-- Flash messages --%>
        <.flash_group flash={@flash} />

        <%!-- Page content --%>
        <main class="flex-1 p-6">
          {@inner_content}
        </main>
      </div>
    </div>
    """
  end

  attr :href, :string, required: true
  attr :icon, :string, required: true
  attr :label, :string, required: true
  attr :current, :string, default: nil

  defp sidebar_link(assigns) do
    active = is_active?(assigns.label, assigns.current)
    assigns = assign(assigns, :active, active)

    ~H"""
    <.link
      navigate={@href}
      class={[
        "flex items-center gap-2.5 px-3 py-2 rounded-md text-sm font-medium transition-colors",
        if(@active,
          do: "bg-primary/10 text-primary",
          else: "text-base-content/60 hover:bg-base-200 hover:text-base-content"
        )
      ]}
    >
      <.icon name={@icon} class="size-5 shrink-0" />
      <span>{@label}</span>
    </.link>
    """
  end

  defp is_active?("Dashboard", "Dashboard"), do: true
  defp is_active?("Tenants", page) when page in ["Tenants", "New Tenant", "Tenant Detail"], do: true
  defp is_active?("System", "System"), do: true
  defp is_active?("Admins", "Admins"), do: true
  defp is_active?(_, _), do: false

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite" class="px-6 pt-4">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @doc """
  Provides dark vs light theme toggle based on themes defined in app.css.

  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <div class="card relative flex flex-row items-center border-2 border-base-300 bg-base-300 rounded-full">
      <div class="absolute w-1/3 h-full rounded-full border-1 border-base-200 bg-base-100 brightness-200 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 transition-[left]" />

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="system"
      >
        <.icon name="hero-computer-desktop-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="light"
      >
        <.icon name="hero-sun-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="flex p-2 cursor-pointer w-1/3"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="dark"
      >
        <.icon name="hero-moon-micro" class="size-4 opacity-75 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
