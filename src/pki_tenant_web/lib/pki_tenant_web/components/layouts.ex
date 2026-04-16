defmodule PkiTenantWeb.Layouts do
  @moduledoc """
  Layout module for the tenant web portal.

  Provides:
  - `root` layout (HTML skeleton, shared by all pages)
  - `ca_app` layout (CA portal sidebar + topbar)
  - `ra_app` layout (RA portal sidebar + topbar)

  The `app` function delegates to the appropriate layout based on
  the `:portal` assign set by the AuthHook.
  """
  use PkiTenantWeb, :html

  embed_templates "layouts/*"

  @doc """
  Dispatches to ca_app or ra_app based on the :portal assign.
  Falls back to ca_app if not set.
  """
  attr :flash, :map, required: true
  slot :inner_block, required: true

  def app(assigns) do
    assigns = assign_new(assigns, :current_user, fn -> nil end)
    assigns = assign_new(assigns, :page_title, fn -> nil end)
    assigns = assign_new(assigns, :portal, fn -> :ca end)

    case assigns.portal do
      :ra -> ra_app(assigns)
      _ -> ca_app(assigns)
    end
  end

  # --- Shared sidebar helpers used by ca_app and ra_app templates ---

  attr :label, :string, required: true
  slot :inner_block, required: true

  def sidebar_section(assigns) do
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

  def sidebar_link(assigns) do
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

  def user_role(nil), do: nil
  def user_role(user), do: to_string(user[:role] || user["role"])

  # CA page matching
  defp is_active?("Dashboard", "Dashboard"), do: true
  defp is_active?("CA Instances", "CA Instances"), do: true
  defp is_active?("Users", page) when page in ["Users", "User Management"], do: true
  defp is_active?("HSM Devices", "HSM Devices"), do: true
  defp is_active?("Keystores", page) when page in ["Keystores", "Keystore Management"], do: true
  defp is_active?("Key Ceremony", "Key Ceremony"), do: true
  defp is_active?("My Shares", "My Ceremony Shares"), do: true
  defp is_active?("Witness", "Ceremony Witness"), do: true
  defp is_active?("Issuer Keys", "Issuer Keys"), do: true
  defp is_active?("Certificates", "Certificates"), do: true
  defp is_active?("Audit Log", "Audit Log"), do: true
  defp is_active?("Quick Setup", "Quick Setup"), do: true
  defp is_active?("Profile", "Profile"), do: true
  defp is_active?("My Profile", "Profile"), do: true
  # RA page matching
  defp is_active?("RA Instances", "RA Instances"), do: true
  defp is_active?("CSRs", page) when page in ["CSRs", "CSR Management"], do: true
  defp is_active?("CSR Management", page) when page in ["CSRs", "CSR Management"], do: true
  defp is_active?("Cert Profiles", page) when page in ["Cert Profiles", "Certificate Profiles"], do: true
  defp is_active?("Certificate Profiles", page) when page in ["Cert Profiles", "Certificate Profiles"], do: true
  defp is_active?("Service Configs", page) when page in ["Service Configs", "Service Configuration", "Validation Endpoints"], do: true
  defp is_active?("Validation Endpoints", page) when page in ["Service Configs", "Service Configuration", "Validation Endpoints"], do: true
  defp is_active?("Validation", page) when page in ["Validation", "Validation Services"], do: true
  defp is_active?("Validation Services", page) when page in ["Validation", "Validation Services"], do: true
  defp is_active?("API Keys", page) when page in ["API Keys", "API Key Management"], do: true
  defp is_active?("CA Connection", "CA Connection"), do: true
  defp is_active?(_, _), do: false

  @doc """
  Shows the flash group with standard titles and content.
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
