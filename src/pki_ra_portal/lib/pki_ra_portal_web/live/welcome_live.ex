defmodule PkiRaPortalWeb.WelcomeLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      send(self(), :check_setup)
    end

    {:ok,
     assign(socket,
       page_title: "Welcome",
       ra_name: "Registration Authority",
       loading: true
     )}
  end

  @impl true
  def handle_info(:check_setup, socket) do
    opts = tenant_opts(socket)

    has_connections =
      case RaEngineClient.list_ca_connections([], opts) do
        {:ok, conns} -> length(conns) > 0
        _ -> false
      end

    has_profiles =
      case RaEngineClient.list_cert_profiles(opts) do
        {:ok, profiles} -> length(profiles) > 0
        _ -> false
      end

    if has_connections and has_profiles do
      {:noreply, push_navigate(socket, to: "/")}
    else
      ra_name =
        case RaEngineClient.list_ra_instances(opts) do
          {:ok, [first | _]} -> first[:name] || first["name"] || "Registration Authority"
          _ -> "Registration Authority"
        end

      {:noreply, assign(socket, ra_name: ra_name, loading: false)}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="fixed inset-0 z-50 bg-base-200 flex items-center justify-center">
      <%= if @loading do %>
        <span class="loading loading-spinner loading-lg"></span>
      <% else %>
        <div class="card bg-base-100 shadow-xl max-w-lg w-full mx-4">
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
      <% end %>
    </div>
    """
  end
end
