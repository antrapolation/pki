defmodule PkiPlatformPortalWeb.HsmDevicesLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.HsmManagement
  import PkiPlatformPortalWeb.ErrorHelpers, only: [sanitize_error: 2]

  require Logger

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
    devices = HsmManagement.list_devices()

    # Enrich with tenant count
    all_access = PkiPlatformEngine.PlatformRepo.all(PkiPlatformEngine.TenantHsmAccess)
    access_counts = Enum.frequencies_by(all_access, & &1.hsm_device_id)

    devices_with_counts = Enum.map(devices, fn dev ->
      Map.put(dev, :tenant_count, Map.get(access_counts, dev.id, 0))
    end)

    {:noreply, assign(socket, devices: devices_with_counts, loading: false)}
  end

  @impl true
  def handle_event("register_device", params, socket) do
    attrs = %{
      label: params["label"],
      pkcs11_lib_path: params["pkcs11_lib_path"],
      slot_id: parse_int(params["slot_id"])
    }

    case HsmManagement.register_device(attrs) do
      {:ok, _device} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "HSM device registered and verified.")}

      {:error, {:pkcs11_unreachable, reason}} ->
        Logger.error("[hsm_devices] Cannot reach PKCS#11 library: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Cannot reach PKCS#11 library. Check the path and try again.")}

      {:error, {:validation_error, errors}} ->
        {:noreply, put_flash(socket, :error, "Validation failed: #{format_errors(errors)}")}

      {:error, %Ecto.Changeset{} = cs} ->
        {:noreply, put_flash(socket, :error, "Validation failed: #{format_changeset(cs)}")}

      {:error, reason} ->
        Logger.error("[hsm_devices] Register device failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Registration failed", reason))}
    end
  end

  @impl true
  def handle_event("probe_device", %{"id" => id}, socket) do
    case HsmManagement.probe_device(id) do
      {:ok, device} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device probed: #{device.manufacturer || "OK"}")}

      {:error, {:pkcs11_unreachable, reason}} ->
        Logger.error("[hsm_devices] Probe failed - PKCS#11 unreachable: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, "Probe failed: device unreachable.")}

      {:error, reason} ->
        Logger.error("[hsm_devices] Probe failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Probe failed", reason))}
    end
  end

  @impl true
  def handle_event("deactivate_device", %{"id" => id}, socket) do
    case HsmManagement.deactivate_device(id) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device deactivated.")}

      {:error, {:has_tenant_assignments, count}} ->
        {:noreply, put_flash(socket, :error, "Cannot deactivate: #{count} tenant(s) still assigned. Revoke all tenant access first.")}

      {:error, reason} ->
        Logger.error("[hsm_devices] Deactivate device failed: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Deactivation failed", reason))}
    end
  end

  defp parse_int(nil), do: 0
  defp parse_int(""), do: 0
  defp parse_int(v) when is_integer(v), do: v
  defp parse_int(v) when is_binary(v) do
    case Integer.parse(String.trim(v)) do
      {n, ""} -> n
      _ -> 0
    end
  end

  defp format_errors(errors) when is_map(errors) do
    Enum.map_join(errors, ", ", fn {field, msgs} -> "#{field}: #{Enum.join(List.wrap(msgs), ", ")}" end)
  end
  defp format_errors(errors), do: inspect(errors)

  defp format_changeset(cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        atom_key = try do
          String.to_existing_atom(key)
        rescue
          ArgumentError -> nil
        end
        case atom_key && Keyword.get(opts, atom_key) do
          nil -> key
          val -> to_string(val)
        end
      end)
    end)
    |> format_errors()
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="hsm-devices-page" class="space-y-6">
      <%!-- Register HSM Device --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-2">Register HSM Device</h2>
          <p class="text-xs text-base-content/50 mb-4">
            Register any PKCS#11 compatible HSM (SoftHSM2, Thales Luna, YubiHSM 2, etc.).
            The library will be probed to verify connectivity.
          </p>
          <form phx-submit="register_device" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Label</label>
              <input type="text" name="label" required placeholder="e.g. SoftHSM2 Dev" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">PKCS#11 Library Path</label>
              <input type="text" name="pkcs11_lib_path" required
                placeholder="/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so"
                class="input input-bordered input-sm w-full font-mono text-xs" />
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Slot ID</label>
              <input type="number" name="slot_id" value="0" min="0" class="input input-bordered input-sm w-full" />
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-plus" class="size-4" />
                Register & Probe
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Devices table --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Registered HSM Devices</h2>
          </div>
          <div :if={Enum.empty?(@devices)} class="p-8 text-center text-base-content/50 text-sm">
            No HSM devices registered.
          </div>
          <div :if={not Enum.empty?(@devices)}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[16%]">Label</th>
                  <th class="w-[14%]">Manufacturer</th>
                  <th class="w-[25%]">Library Path</th>
                  <th class="w-[8%]">Slot</th>
                  <th class="w-[9%]">Tenants</th>
                  <th class="w-[10%]">Status</th>
                  <th class="w-[18%] text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={dev <- @devices} id={"hsm-#{dev.id}"} class="hover">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">
                    <div class="flex items-center gap-2">
                      <.icon name="hero-cpu-chip" class="size-4 text-warning" />
                      <span class="overflow-hidden text-ellipsis whitespace-nowrap">{dev.label}</span>
                    </div>
                  </td>
                  <td class="text-sm overflow-hidden text-ellipsis whitespace-nowrap">{dev.manufacturer || "-"}</td>
                  <td class="font-mono text-xs text-base-content/50 overflow-hidden text-ellipsis whitespace-nowrap">{dev.pkcs11_lib_path}</td>
                  <td>{dev.slot_id}</td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{dev.tenant_count}</span>
                  </td>
                  <td>
                    <span class={["badge badge-sm", if(dev.status == "active", do: "badge-success", else: "badge-warning")]}>
                      {dev.status}
                    </span>
                  </td>
                  <td class="text-right">
                    <div class="flex items-center justify-end gap-1">
                      <button phx-click="probe_device" phx-value-id={dev.id} title="Probe connectivity" class="btn btn-ghost btn-xs text-sky-400">
                        <.icon name="hero-signal" class="size-4" />
                      </button>
                      <button :if={dev.status == "active"} phx-click="deactivate_device" phx-value-id={dev.id} title="Deactivate" class="btn btn-ghost btn-xs text-amber-400">
                        <.icon name="hero-pause" class="size-4" />
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
