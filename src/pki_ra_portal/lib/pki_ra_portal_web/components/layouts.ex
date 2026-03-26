defmodule PkiRaPortalWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use PkiRaPortalWeb, :html

  # Embed all files in layouts/* within this module.
  # The default root.html.heex file contains the HTML
  # skeleton of your application, namely HTML headers
  # and other static content.
  embed_templates "layouts/*"

  @doc """
  Renders your app layout.

  This function is typically invoked from every template,
  and it often contains your application menu, sidebar,
  or similar.

  ## Examples

      <Layouts.app flash={@flash}>
        <h1>Content</h1>
      </Layouts.app>

  """
  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current [scope](https://hexdocs.pm/phoenix/scopes.html)"

  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <div class="flex h-screen bg-base-200">
      <%!-- Sidebar --%>
      <aside class="w-64 bg-slate-800 text-slate-100 flex flex-col flex-shrink-0">
        <div class="px-6 py-5 border-b border-slate-700">
          <div class="flex items-center gap-2">
            <.icon name="hero-shield-check" class="size-5 text-teal-400" />
            <h1 class="text-lg font-bold tracking-tight text-teal-400">RA Portal</h1>
          </div>
          <p class="text-xs text-slate-400 mt-0.5">Registration Authority</p>
        </div>

        <nav class="flex-1 px-3 py-4 space-y-1">
          <.sidebar_link href="/" icon="hero-home" label="Dashboard" />
          <.sidebar_link href="/users" icon="hero-users" label="Users" />
          <.sidebar_link href="/csrs" icon="hero-document-check" label="CSRs" />
          <.sidebar_link href="/cert-profiles" icon="hero-clipboard-document-list" label="Cert Profiles" />
          <.sidebar_link href="/service-configs" icon="hero-cog-6-tooth" label="Service Configs" />
          <.sidebar_link href="/api-keys" icon="hero-key" label="API Keys" />
        </nav>

        <div class="px-3 py-4 border-t border-slate-700">
          <.theme_toggle />
        </div>
      </aside>

      <%!-- Main content area --%>
      <div class="flex-1 flex flex-col overflow-hidden">
        <%!-- Topbar --%>
        <header class="bg-base-100 border-b border-base-300 px-6 py-3 flex items-center justify-between flex-shrink-0">
          <span class="text-sm font-semibold text-base-content/70">Registration Authority Management</span>
          <a href="/logout" method="post" class="btn btn-ghost btn-sm text-base-content/60 hover:text-base-content">
            <.icon name="hero-arrow-right-on-rectangle" class="size-4" /> Logout
          </a>
        </header>

        <%!-- Page content --%>
        <main class="flex-1 overflow-y-auto p-6">
          {render_slot(@inner_block)}
        </main>
      </div>
    </div>

    <.flash_group flash={@flash} />
    """
  end

  attr :href, :string, required: true
  attr :icon, :string, required: true
  attr :label, :string, required: true

  defp sidebar_link(assigns) do
    ~H"""
    <a
      href={@href}
      class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-slate-300 hover:bg-slate-700 hover:text-teal-400 transition-colors"
    >
      <.icon name={@icon} class="size-5" />
      {@label}
    </a>
    """
  end

  @doc """
  Shows the flash group with standard titles and content.

  ## Examples

      <.flash_group flash={@flash} />
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
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
    <div class="card relative flex flex-row items-center border-2 border-slate-700 bg-slate-700 rounded-full">
      <div class="absolute w-1/3 h-full rounded-full border-1 border-slate-600 bg-slate-500 brightness-200 left-0 [[data-theme=light]_&]:left-1/3 [[data-theme=dark]_&]:left-2/3 transition-[left]" />

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
