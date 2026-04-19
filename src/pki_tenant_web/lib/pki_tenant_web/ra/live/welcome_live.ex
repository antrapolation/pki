defmodule PkiTenantWeb.Ra.WelcomeLive do
  @moduledoc """
  One-shot onboarding splash for the RA portal. If the tenant already
  has both an active CA connection and at least one certificate
  profile, it redirects to the dashboard — otherwise it shows a
  "Start Setup" CTA that points at the setup wizard.
  """
  use PkiTenantWeb, :live_view

  alias PkiRaEngine.{CaConnectionManagement, CertProfileConfig, RaInstanceManagement}

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :check_setup)

    {:ok,
     assign(socket,
       page_title: "Welcome",
       ra_name: "Registration Authority",
       loading: true
     )}
  end

  @impl true
  def handle_info(:check_setup, socket) do
    has_connections = CaConnectionManagement.has_connections?()
    has_profiles = has_active_profiles?()

    if has_connections and has_profiles do
      {:noreply, push_navigate(socket, to: "/")}
    else
      ra_name =
        case RaInstanceManagement.list_ra_instances() do
          [first | _] -> first.name || "Registration Authority"
          _ -> "Registration Authority"
        end

      {:noreply, assign(socket, ra_name: ra_name, loading: false)}
    end
  end

  defp has_active_profiles? do
    case CertProfileConfig.list_profiles() do
      {:ok, list} -> list != []
      _ -> false
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 bg-base-200 flex items-center justify-center">
      <div :if={@loading}>
        <span class="loading loading-spinner loading-lg"></span>
      </div>

      <div :if={not @loading} class="card bg-base-100 shadow-xl max-w-lg w-full mx-4">
        <div class="card-body text-center">
          <div class="flex justify-center mb-4">
            <div class="flex items-center justify-center w-16 h-16 rounded-2xl bg-primary/10">
              <.icon name="hero-shield-check" class="size-8 text-primary" />
            </div>
          </div>
          <h1 class="text-2xl font-bold">{@ra_name}</h1>
          <p class="text-base-content/60 mt-2">
            Let's configure your Registration Authority. This will take a few minutes.
          </p>
          <div class="mt-8 space-y-3">
            <.link navigate="/setup-wizard" class="btn btn-primary btn-block">
              Start Setup
            </.link>
            <.link navigate="/ra-instances" class="btn btn-outline btn-sm btn-block">
              Manage RA Instances
            </.link>
            <.link navigate="/" class="btn btn-ghost btn-sm text-base-content/50">
              Skip, I'll configure manually
            </.link>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
