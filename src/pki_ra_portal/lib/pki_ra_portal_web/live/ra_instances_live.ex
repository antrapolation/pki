defmodule PkiRaPortalWeb.RaInstancesLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "RA Instances",
       instances: [],
       loading: true,
       show_create_modal: false,
       create_name: "",
       creating: false
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    instances = fetch_instances(tenant_opts(socket))
    {:noreply, assign(socket, instances: instances, loading: false)}
  end

  @impl true
  def handle_event("open_create_modal", _params, socket) do
    {:noreply, assign(socket, show_create_modal: true, create_name: "")}
  end

  @impl true
  def handle_event("close_create_modal", _params, socket) do
    {:noreply, assign(socket, show_create_modal: false)}
  end

  @impl true
  def handle_event("create_instance", %{"name" => name}, socket) do
    case RaEngineClient.create_ra_instance(%{name: name}, tenant_opts(socket)) do
      {:ok, _instance} ->
        instances = fetch_instances(tenant_opts(socket))

        {:noreply,
         socket
         |> assign(instances: instances, show_create_modal: false)
         |> put_flash(:info, "RA instance created successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create RA instance: #{inspect(reason)}")}
    end
  end

  defp fetch_instances(opts) do
    case RaEngineClient.list_ra_instances(opts) do
      {:ok, instances} -> instances
      {:error, _} -> []
    end
  end

  defp status_badge_class(status) do
    case status do
      "active" -> "badge-success"
      "inactive" -> "badge-ghost"
      "suspended" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ra-instances-page" class="space-y-6">
      <%!-- Header --%>
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-lg font-semibold text-base-content">RA Instances</h1>
          <p class="text-xs text-base-content/50 mt-0.5">Manage Registration Authority instances</p>
        </div>
        <button
          id="btn-new-ra-instance"
          class="btn btn-primary btn-sm"
          phx-click="open_create_modal"
        >
          <.icon name="hero-plus" class="size-4" />
          New RA Instance
        </button>
      </div>

      <%!-- Instance List --%>
      <div id="ra-instance-list" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Instances</h2>
          </div>
          <div :if={Enum.empty?(@instances)} class="p-8 text-center text-base-content/50 text-sm">
            No RA instances configured. Create one to get started.
          </div>
          <div :if={not Enum.empty?(@instances)} class="divide-y divide-base-300">
            <div
              :for={instance <- @instances}
              id={"ra-instance-#{instance.id}"}
              class="flex items-center justify-between px-5 py-4 hover:bg-base-200/50"
            >
              <div class="flex items-center gap-3">
                <div class="flex items-center justify-center w-8 h-8 rounded-lg bg-primary/10">
                  <.icon name="hero-server" class="size-4 text-primary" />
                </div>
                <div>
                  <p class="text-sm font-medium text-base-content">{instance.name}</p>
                  <div class="flex items-center gap-2 mt-0.5">
                    <span class={"badge badge-xs #{status_badge_class(instance[:status] || "active")}"}>
                      {instance[:status] || "active"}
                    </span>
                    <span class="text-xs text-base-content/40">
                      {Map.get(instance, :cert_profile_count, 0)} cert profile(s)
                    </span>
                    <span class="text-xs text-base-content/40">
                      {Map.get(instance, :api_key_count, 0)} API key(s)
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Create RA Instance Modal --%>
      <div
        :if={@show_create_modal}
        id="create-ra-modal"
        class="modal modal-open"
        phx-window-keydown="close_create_modal"
        phx-key="Escape"
      >
        <div class="modal-box">
          <h3 class="font-bold text-lg">Create RA Instance</h3>
          <form phx-submit="create_instance" class="space-y-4 mt-4">
            <div>
              <label for="ra-name" class="block text-xs font-medium text-base-content/60 mb-1">
                Name <span class="text-error">*</span>
              </label>
              <input
                type="text"
                name="name"
                id="ra-name"
                required
                value={@create_name}
                placeholder="e.g. Production RA, Staging RA"
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="modal-action">
              <button type="button" class="btn btn-ghost btn-sm" phx-click="close_create_modal">
                Cancel
              </button>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-plus" class="size-4" />
                Create
              </button>
            </div>
          </form>
        </div>
        <div class="modal-backdrop" phx-click="close_create_modal"></div>
      </div>
    </div>
    """
  end
end
