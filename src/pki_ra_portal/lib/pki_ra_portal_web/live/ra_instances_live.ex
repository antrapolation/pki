defmodule PkiRaPortalWeb.RaInstancesLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "RA Instances",
       instances: [],
       profiles: [],
       api_keys: [],
       loading: true,
       show_create_modal: false,
       create_name: "",
       selected: nil
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)
    {instances, socket} = case RaEngineClient.list_ra_instances(opts) do
      {:ok, i} -> {i, socket}
      {:error, _} -> {[], put_flash(socket, :error, "Failed to load data. Try refreshing.")}
    end

    profiles = case RaEngineClient.list_cert_profiles(opts) do
      {:ok, p} -> p
      {:error, _} -> []
    end

    api_keys = case RaEngineClient.list_api_keys([], opts) do
      {:ok, k} -> k
      {:error, _} -> []
    end

    {:noreply, assign(socket, instances: instances, profiles: profiles, api_keys: api_keys, loading: false)}
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
  def handle_event("select_instance", %{"id" => id}, socket) do
    instance = Enum.find(socket.assigns.instances, &(&1.id == id))
    {:noreply, assign(socket, selected: instance)}
  end

  @impl true
  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, selected: nil)}
  end

  @impl true
  def handle_event("create_instance", %{"name" => name}, socket) do
    if get_role(socket) == "ra_admin" do
      case RaEngineClient.create_ra_instance(%{name: name}, tenant_opts(socket)) do
        {:ok, _instance} ->
          send(self(), :load_data)
          {:noreply, socket |> assign(show_create_modal: false) |> put_flash(:info, "RA instance created")}

        {:error, reason} ->
          Logger.error("[ra_instances] Failed to create: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to create RA instance", reason))}
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end


  defp profile_count(instance_id, profiles) do
    Enum.count(profiles, fn p ->
      (p[:ra_instance_id] || p["ra_instance_id"]) == instance_id
    end)
  end

  defp key_count(instance_id, api_keys) do
    Enum.count(api_keys, fn k ->
      (k[:ra_instance_id] || k["ra_instance_id"]) == instance_id
    end)
  end

  defp instance_profiles(instance_id, profiles) do
    Enum.filter(profiles, fn p ->
      (p[:ra_instance_id] || p["ra_instance_id"]) == instance_id
    end)
  end

  defp instance_keys(instance_id, api_keys) do
    Enum.filter(api_keys, fn k ->
      (k[:ra_instance_id] || k["ra_instance_id"]) == instance_id
    end)
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
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-lg font-semibold text-base-content">RA Instances</h1>
          <p class="text-xs text-base-content/50 mt-0.5">Manage Registration Authority instances</p>
        </div>
        <button id="btn-new-ra-instance" class="btn btn-primary btn-sm" phx-click="open_create_modal">
          <.icon name="hero-plus" class="size-4" /> New RA Instance
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
              class={["flex items-center justify-between px-5 py-4 hover:bg-base-200/50 cursor-pointer",
                       @selected && @selected.id == instance.id && "bg-primary/5 border-l-2 border-primary"]}
              phx-click="select_instance"
              phx-value-id={instance.id}
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
                      {profile_count(instance.id, @profiles)} profile(s)
                    </span>
                    <span class="text-xs text-base-content/40">
                      {key_count(instance.id, @api_keys)} API key(s)
                    </span>
                  </div>
                </div>
              </div>
              <.icon name="hero-chevron-right" class="size-4 text-base-content/30" />
            </div>
          </div>
        </div>
      </div>

      <%!-- Detail Panel --%>
      <section :if={@selected} id="ra-instance-detail" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
              {@selected.name}
              <span class={"badge badge-sm ml-2 #{status_badge_class(@selected[:status] || "active")}"}>
                {@selected[:status] || "active"}
              </span>
            </h2>
            <button phx-click="close_detail" class="btn btn-ghost btn-xs">Close</button>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mt-4">
            <%!-- Assigned Cert Profiles --%>
            <div>
              <h3 class="text-xs font-semibold uppercase tracking-wide text-base-content/60 mb-2">
                Certificate Profiles ({profile_count(@selected.id, @profiles)})
              </h3>
              <div :if={instance_profiles(@selected.id, @profiles) == []} class="text-xs text-base-content/40 italic">
                No profiles assigned. Go to Certificate Profiles to assign.
              </div>
              <div class="space-y-1">
                <div :for={p <- instance_profiles(@selected.id, @profiles)}
                  class="flex items-center justify-between px-3 py-2 rounded bg-base-200/50 text-xs">
                  <span class="font-medium">{p.name}</span>
                  <span class={"badge badge-xs #{if (p[:approval_mode] || "manual") == "auto", do: "badge-info", else: "badge-ghost"}"}>
                    {p[:approval_mode] || "manual"}
                  </span>
                </div>
              </div>
            </div>

            <%!-- Assigned API Keys --%>
            <div>
              <h3 class="text-xs font-semibold uppercase tracking-wide text-base-content/60 mb-2">
                API Keys ({key_count(@selected.id, @api_keys)})
              </h3>
              <div :if={instance_keys(@selected.id, @api_keys) == []} class="text-xs text-base-content/40 italic">
                No API keys assigned. Go to API Keys to assign.
              </div>
              <div class="space-y-1">
                <div :for={k <- instance_keys(@selected.id, @api_keys)}
                  class="flex items-center justify-between px-3 py-2 rounded bg-base-200/50 text-xs">
                  <span class="font-medium">{k[:label] || k[:name] || k["label"] || "-"}</span>
                  <div class="flex items-center gap-2">
                    <span class={"badge badge-xs #{if (k[:key_type] || "client") == "service", do: "badge-info", else: "badge-ghost"}"}>
                      {k[:key_type] || "client"}
                    </span>
                    <span class={"badge badge-xs #{if (k[:status] || "active") == "active", do: "badge-success", else: "badge-error"}"}>
                      {k[:status] || "active"}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <%!-- Create Modal --%>
      <div :if={@show_create_modal} id="create-ra-modal" class="modal modal-open"
        phx-window-keydown="close_create_modal" phx-key="Escape">
        <div class="modal-box">
          <h3 class="font-bold text-lg">Create RA Instance</h3>
          <form phx-submit="create_instance" class="space-y-4 mt-4">
            <div>
              <label for="ra-name" class="block text-xs font-medium text-base-content/60 mb-1">
                Name <span class="text-error">*</span>
              </label>
              <input type="text" name="name" id="ra-name" required maxlength="100"
                value={@create_name} placeholder="e.g. Production RA, Staging RA"
                class="input input-bordered input-sm w-full" />
            </div>
            <div class="modal-action">
              <button type="button" class="btn btn-ghost btn-sm" phx-click="close_create_modal">Cancel</button>
              <button type="submit" phx-disable-with="Saving..." class="btn btn-primary btn-sm">
                <.icon name="hero-plus" class="size-4" /> Create
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
