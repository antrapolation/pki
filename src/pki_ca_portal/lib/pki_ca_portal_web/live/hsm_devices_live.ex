defmodule PkiCaPortalWeb.HsmDevicesLive do
  use PkiCaPortalWeb, :live_view

  require Logger

  alias PkiCaPortal.CaEngineClient
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 4, audit_log: 5]
  import PkiCaPortalWeb.ErrorHelpers, only: [sanitize_error: 2]

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
    import PkiCaPortalWeb.SafeEngine, only: [safe_load: 3]

    safe_load(socket, fn ->
      devices = case CaEngineClient.list_hsm_devices(tenant_opts(socket)) do
        {:ok, d} -> d
        {:error, _} -> []
      end

      {:noreply, assign(socket, devices: devices, loading: false)}
    end, retry_msg: :load_data)
  end

  @impl true
  def handle_event("probe_device", %{"id" => id}, socket) do
    case CaEngineClient.probe_hsm_device(id, tenant_opts(socket)) do
      {:ok, device} ->
        audit_log(socket, "hsm_device_probed", "hsm_device", id, %{manufacturer: device[:manufacturer]})
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device probed: #{device[:manufacturer] || "OK"}")}

      {:error, reason} ->
        Logger.error("[hsm_devices] Probe failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Probe failed", reason))}
    end
  end

  defp tenant_opts(socket) do
    opts = case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end

    case get_in(socket.assigns, [:current_user, :role]) do
      nil -> opts
      role -> [{:user_role, role} | opts]
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
          <div :if={not Enum.empty?(@devices)}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[28%]">Label</th>
                  <th class="w-[28%]">Manufacturer</th>
                  <th class="w-[12%]">Slot</th>
                  <th class="w-[12%]">Status</th>
                  <th class="w-[20%] text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={dev <- @devices} class="hover">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">{dev.label}</td>
                  <td class="text-sm overflow-hidden text-ellipsis whitespace-nowrap">{dev[:manufacturer] || "-"}</td>
                  <td>{dev.slot_id}</td>
                  <td>
                    <span class={["badge badge-sm", if(dev.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {dev.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <button phx-click="probe_device" phx-value-id={dev.id} title="Test connectivity" class="btn btn-ghost btn-xs text-sky-400">
                      <.icon name="hero-signal" class="size-4" />
                    </button>
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
