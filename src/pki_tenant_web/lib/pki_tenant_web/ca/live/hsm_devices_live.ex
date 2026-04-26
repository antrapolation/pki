defmodule PkiTenantWeb.Ca.HsmDevicesLive do
  @moduledoc """
  Read-only list of HSM devices assigned to this tenant.

  HSM devices are a PLATFORM-level resource managed by the platform
  admin. Tenants see only the subset assigned to them via
  `PkiCaEngine.HsmDeviceManagement.list_devices_for_tenant/1`. The
  only action available to a tenant is "Probe" — a connectivity
  sanity-check that pings the device through its PKCS#11 adapter.

  Registration, assignment changes, decommission — all happen in the
  platform portal.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{HsmDeviceManagement, HsmAgentSetup}

  @impl true
  def mount(_params, _session, socket) do
    tenant_id = current_tenant_id(socket)
    ca_instance_id = socket.assigns[:current_user][:ca_instance_id]

    if connected?(socket) do
      send(self(), :load_data)
      Phoenix.PubSub.subscribe(PkiTenantWeb.PubSub, "hsm_gateway:#{tenant_id}")
    end

    {:ok,
     assign(socket,
       page_title: "HSM Devices",
       devices: [],
       loading: true,
       pending_setup: nil,
       ca_instance_id: ca_instance_id
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    devices =
      socket
      |> current_tenant_id()
      |> HsmDeviceManagement.list_devices_for_tenant()

    pending =
      case socket.assigns.ca_instance_id do
        nil -> nil
        ca_id -> HsmAgentSetup.pending_for_ca(ca_id) |> elem_if_ok()
      end

    {:noreply, assign(socket, devices: devices, loading: false, pending_setup: pending)}
  end

  @impl true
  def handle_info({:agent_connected, agent_id, _key_labels}, socket) do
    pending =
      case socket.assigns.pending_setup do
        %{agent_id: ^agent_id} = s -> %{s | status: "agent_connected"}
        other -> other
      end

    {:noreply, assign(socket, pending_setup: pending)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def handle_event("probe_device", %{"id" => id}, socket) do
    tenant_id = current_tenant_id(socket)

    case HsmDeviceManagement.probe_device_for_tenant(tenant_id, id) do
      {:ok, device} ->
        PkiTenant.AuditBridge.log("hsm_device_probed", %{
          device_id: id,
          manufacturer: device[:manufacturer] || device.manufacturer
        })

        send(self(), :load_data)

        manufacturer = device[:manufacturer] || device.manufacturer || "OK"
        {:noreply, put_flash(socket, :info, "Device probed: #{manufacturer}")}

      {:error, :tenant_id_required} ->
        {:noreply, put_flash(socket, :error, "This node isn't bound to a tenant. Contact your platform admin.")}

      {:error, reason} ->
        Logger.warning("[hsm_devices_live] Probe failed for #{id}: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Probe failed: #{humanize(reason)}")}
    end
  end

  defp current_tenant_id(socket) do
    socket.assigns[:tenant_id] || PkiTenant.tenant_id()
  end

  defp elem_if_ok({:ok, val}), do: val
  defp elem_if_ok(_), do: nil

  defp humanize(:not_found), do: "device not found"
  defp humanize(:tenant_id_required), do: "no tenant context"
  defp humanize(atom) when is_atom(atom), do: Atom.to_string(atom) |> String.replace("_", " ")
  defp humanize(bin) when is_binary(bin), do: bin
  defp humanize(_), do: "unexpected error"

  @impl true
  def render(assigns) do
    ~H"""
    <div id="hsm-devices-page" class="space-y-6">
      <%!-- Resume banner: pending wizard setup --%>
      <div
        :if={@pending_setup}
        class={[
          "alert border",
          if(@pending_setup.status == "agent_connected",
            do: "border-success/40 bg-success/5",
            else: "border-warning/40 bg-warning/5"
          )
        ]}
      >
        <.icon
          name={if(@pending_setup.status == "agent_connected", do: "hero-check-circle", else: "hero-clock")}
          class={["size-5 shrink-0", if(@pending_setup.status == "agent_connected", do: "text-success", else: "text-warning")]}
        />
        <div class="flex-1">
          <%= if @pending_setup.status == "agent_connected" do %>
            <p class="text-sm font-medium text-base-content">Agent <strong>{@pending_setup.agent_id}</strong> connected!</p>
            <p class="text-xs text-base-content/60">Continue the wizard to select a key and create the keystore.</p>
          <% else %>
            <p class="text-sm font-medium text-base-content">HSM setup in progress — waiting for agent <strong>{@pending_setup.agent_id}</strong>.</p>
            <p class="text-xs text-base-content/60">This page will update automatically when the agent connects.</p>
          <% end %>
        </div>
        <.link navigate={"/hsm-wizard/#{@pending_setup.id}"} class="btn btn-sm btn-ghost">
          Resume setup →
        </.link>
      </div>

      <%!-- Connect agent CTA --%>
      <div :if={is_nil(@pending_setup)} class="flex justify-end">
        <.link navigate="/hsm-wizard" class="btn btn-primary btn-sm">
          <.icon name="hero-plus" class="size-4" /> Connect HSM Agent
        </.link>
      </div>

      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">HSM devices are managed by the platform administrator.</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            The devices below have been assigned to your tenant. Contact the
            platform administrator to add or change HSM device assignments.
          </p>
        </div>
      </div>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Assigned HSM Devices</h2>
          </div>

          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">
            Loading…
          </div>

          <div :if={not @loading and Enum.empty?(@devices)} class="p-8 text-center text-base-content/50 text-sm">
            No HSM devices assigned to your tenant.
          </div>

          <div :if={not @loading and not Enum.empty?(@devices)}>
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
                  <td class="text-sm overflow-hidden text-ellipsis whitespace-nowrap">{dev[:manufacturer] || "—"}</td>
                  <td>{dev.slot_id}</td>
                  <td>
                    <span class={["badge badge-sm", if(dev.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {dev.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <button
                      phx-click="probe_device"
                      phx-value-id={dev.id}
                      title="Test connectivity"
                      class="btn btn-ghost btn-xs text-sky-400"
                    >
                      <.icon name="hero-signal" class="size-4" /> Probe
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
