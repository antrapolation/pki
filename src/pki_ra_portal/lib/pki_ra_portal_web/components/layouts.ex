defmodule PkiRaPortalWeb.Layouts do
  @moduledoc """
  This module holds layouts and related functionality
  used by your application.
  """
  use PkiRaPortalWeb, :html

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
    <div class="min-h-screen bg-base-200">
      <%!-- Sidebar --%>
      <aside class="fixed top-0 left-0 h-screen w-64 flex flex-col bg-base-100 border-r border-base-300 z-20">
        <%!-- Logo --%>
        <div class="flex items-center gap-3 px-4 py-4 border-b border-base-300">
          <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary">
            <.icon name="hero-shield-check" class="size-4 text-primary-content" />
          </div>
          <div>
            <span class="text-sm font-bold text-base-content">RA Portal</span>
            <span class="block text-xs text-base-content/40">Registration Authority</span>
          </div>
        </div>

        <%!-- Navigation --%>
        <nav class="flex-1 px-2 py-3 space-y-1 overflow-y-auto">
          <%!-- OVERVIEW — all roles --%>
          <.sidebar_section label="OVERVIEW">
            <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
          </.sidebar_section>

          <%!-- OPERATIONS — ra_admin and ra_officer only --%>
          <.sidebar_section :if={user_role(@current_user) in ["ra_admin", "ra_officer"]} label="OPERATIONS">
            <.sidebar_link href="/csrs" icon="hero-document-check" label="CSR Management" current={@page_title} />
            <.sidebar_link href="/certificates" icon="hero-shield-exclamation" label="Certificates" current={@page_title} />
            <.sidebar_link href="/validation" icon="hero-shield-check" label="Validation Services" current={@page_title} />
          </.sidebar_section>

          <%!-- CONFIGURATION — ra_admin only --%>
          <.sidebar_section :if={user_role(@current_user) == "ra_admin"} label="CONFIGURATION">
            <.sidebar_link href="/cert-profiles" icon="hero-clipboard-document-list" label="Certificate Profiles" current={@page_title} />
            <.sidebar_link href="/ca-connection" icon="hero-link" label="CA Connection" current={@page_title} />
            <.sidebar_link href="/service-configs" icon="hero-cog-6-tooth" label="Service Configs" current={@page_title} />
          </.sidebar_section>

          <%!-- ADMINISTRATION — ra_admin gets all, auditor gets only Audit Log --%>
          <.sidebar_section :if={user_role(@current_user) in ["ra_admin", "auditor"]} label="ADMINISTRATION">
            <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/users" icon="hero-users" label="Users" current={@page_title} />
            <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/api-keys" icon="hero-key" label="API Keys" current={@page_title} />
            <.sidebar_link :if={user_role(@current_user) == "ra_admin"} href="/ra-instances" icon="hero-server" label="RA Instances" current={@page_title} />
            <.sidebar_link href="/audit-log" icon="hero-document-text" label="Audit Log" current={@page_title} />
          </.sidebar_section>

          <div class="divider my-1 px-3"></div>
          <.sidebar_link href="/profile" icon="hero-user-circle" label="My Profile" current={@page_title} />
        </nav>

        <%!-- Sidebar footer --%>
        <div class="px-4 py-3 border-t border-base-300 flex items-center justify-between">
          <p class="text-xs text-base-content/30">PQC Registration Authority</p>
          <.theme_toggle />
        </div>
      </aside>

      <%!-- Main content area --%>
      <div class="ml-64 min-h-screen flex flex-col w-[calc(100vw-16rem)]">
        <%!-- Topbar --%>
        <header class="sticky top-0 z-10 flex items-center justify-between px-6 py-3 bg-base-100 border-b border-base-300">
          <h1 class="text-sm font-semibold text-base-content">
            {@page_title || "RA Portal"}
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

        <%!-- Session timeout warning --%>
        <div id="session-timeout-hook"
             phx-hook="SessionTimeout"
             data-warning-ms={assigns[:session_warning_ms] || 25 * 60 * 1000}
             data-timeout-ms={assigns[:session_timeout_ms] || 30 * 60 * 1000}>
        </div>
        <div id="session-timeout-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div class="bg-base-100 rounded-lg shadow-xl p-6 max-w-md mx-4">
            <h3 class="text-lg font-bold text-warning mb-2">Session Expiring</h3>
            <p class="mb-4">Your session will expire in <span id="session-timeout-countdown" class="font-mono font-bold">5:00</span> due to inactivity.</p>
            <button id="session-continue-btn" class="btn btn-primary w-full">Continue Working</button>
          </div>
        </div>

        <%!-- Page content --%>
        <main class="flex-1 p-6">
          {@inner_content}
        </main>
      </div>
    </div>
    """
  end

  attr :label, :string, required: true
  slot :inner_block, required: true

  defp sidebar_section(assigns) do
    ~H"""
    <div class="pt-3 first:pt-0">
      <p class="px-3 pb-1 text-[10px] font-bold uppercase tracking-wider text-base-content/30">{@label}</p>
      <div class="space-y-0.5">
        {render_slot(@inner_block)}
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
    <a
      href={@href}
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
    </a>
    """
  end

  defp user_role(nil), do: nil
  defp user_role(user), do: user[:role] || user["role"]

  defp is_active?("Dashboard", "Dashboard"), do: true
  defp is_active?("RA Instances", "RA Instances"), do: true
  defp is_active?("Users", page) when page in ["Users", "User Management"], do: true
  defp is_active?("CSRs", page) when page in ["CSRs", "CSR Management"], do: true
  defp is_active?("CSR Management", page) when page in ["CSRs", "CSR Management"], do: true
  defp is_active?("Cert Profiles", page) when page in ["Cert Profiles", "Certificate Profiles"], do: true
  defp is_active?("Certificate Profiles", page) when page in ["Cert Profiles", "Certificate Profiles"], do: true
  defp is_active?("Service Configs", page) when page in ["Service Configs", "Service Configuration"], do: true
  defp is_active?("Validation", page) when page in ["Validation", "Validation Services"], do: true
  defp is_active?("Validation Services", page) when page in ["Validation", "Validation Services"], do: true
  defp is_active?("API Keys", page) when page in ["API Keys", "API Key Management"], do: true
  defp is_active?("Certificates", "Certificates"), do: true
  defp is_active?("Audit Log", "Audit Log"), do: true
  defp is_active?("CA Connection", "CA Connection"), do: true
  defp is_active?("Profile", "Profile"), do: true
  defp is_active?("My Profile", "Profile"), do: true
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
