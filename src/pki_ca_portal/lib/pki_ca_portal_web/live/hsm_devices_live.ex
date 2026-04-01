defmodule PkiCaPortalWeb.HsmDevicesLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "HSM Devices",
       devices: [],
       loading: true
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    devices = case CaEngineClient.list_hsm_devices(tenant_opts(socket)) do
      {:ok, d} -> d
      {:error, _} -> []
    end

    {:noreply, assign(socket, devices: devices, loading: false)}
  end

  @impl true
  def handle_event("probe_device", %{"id" => id}, socket) do
    case CaEngineClient.probe_hsm_device(id, tenant_opts(socket)) do
      {:ok, device} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device probed: #{device[:manufacturer] || "OK"}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Probe failed: #{inspect(reason)}")}
    end
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="hsm-devices-page" class="space-y-6">
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">HSM devices are managed by the platform administrator.</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            The devices below have been assigned to your tenant. Contact the platform administrator to add or change HSM device assignments.
          </p>
        </div>
      </div>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Assigned HSM Devices</h2>
          </div>
          <div :if={Enum.empty?(@devices)} class="p-8 text-center text-base-content/50 text-sm">
            No HSM devices assigned to your tenant.
          </div>
          <div :if={not Enum.empty?(@devices)} class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Label</th>
                  <th>Manufacturer</th>
                  <th>Slot</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={dev <- @devices} class="hover">
                  <td class="font-medium">{dev.label}</td>
                  <td class="text-sm">{dev[:manufacturer] || "-"}</td>
                  <td>{dev.slot_id}</td>
                  <td>
                    <span class={["badge badge-sm", if(dev.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {dev.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <div class="tooltip" data-tip="Test connectivity">
                      <button phx-click="probe_device" phx-value-id={dev.id} class="btn btn-ghost btn-xs text-info">
                        <.icon name="hero-signal" class="size-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
