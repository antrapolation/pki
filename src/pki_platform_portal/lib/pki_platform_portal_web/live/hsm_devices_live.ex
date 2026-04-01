defmodule PkiPlatformPortalWeb.HsmDevicesLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.HsmManagement

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "HSM Devices",
       devices: [],
       tenants: [],
       loading: true
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    devices = HsmManagement.list_devices()
    tenants = PkiPlatformEngine.PlatformRepo.all(PkiPlatformEngine.Tenant)
    all_access = PkiPlatformEngine.PlatformRepo.all(PkiPlatformEngine.TenantHsmAccess)

    # D19: Single bulk query instead of N+1
    tenant_by_id = Map.new(tenants, fn t -> {t.id, t} end)
    access_by_device = Enum.group_by(all_access, & &1.hsm_device_id, fn a ->
      Map.get(tenant_by_id, a.tenant_id)
    end)

    devices_with_tenants = Enum.map(devices, fn dev ->
      assigned = Map.get(access_by_device, dev.id, []) |> Enum.reject(&is_nil/1)
      Map.put(dev, :assigned_tenants, assigned)
    end)

    {:noreply, assign(socket, devices: devices_with_tenants, tenants: tenants, loading: false)}
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
        {:noreply, put_flash(socket, :error, "Cannot reach PKCS#11 library: #{inspect(reason)}")}

      {:error, {:validation_error, errors}} ->
        {:noreply, put_flash(socket, :error, "Validation failed: #{format_errors(errors)}")}

      {:error, %Ecto.Changeset{} = cs} ->
        {:noreply, put_flash(socket, :error, "Validation failed: #{format_changeset(cs)}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("probe_device", %{"id" => id}, socket) do
    case HsmManagement.probe_device(id) do
      {:ok, device} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device probed: #{device.manufacturer || "OK"}")}

      {:error, {:pkcs11_unreachable, reason}} ->
        {:noreply, put_flash(socket, :error, "Probe failed: #{inspect(reason)}")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Probe failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("deactivate_device", %{"id" => id}, socket) do
    case HsmManagement.deactivate_device(id) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Device deactivated.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("grant_access", %{"hsm_device_id" => device_id, "tenant_id" => tenant_id}, socket) do
    if tenant_id == "" do
      {:noreply, put_flash(socket, :error, "Please select a tenant.")}
    else
      case HsmManagement.grant_tenant_access(tenant_id, device_id) do
        {:ok, _} ->
          send(self(), :load_data)
          {:noreply, put_flash(socket, :info, "Tenant access granted.")}

        {:error, %Ecto.Changeset{}} ->
          {:noreply, put_flash(socket, :error, "Tenant already has access to this device.")}

        {:error, reason} ->
          {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
      end
    end
  end

  @impl true
  def handle_event("revoke_access", %{"hsm-device-id" => device_id, "tenant-id" => tenant_id}, socket) do
    case HsmManagement.revoke_tenant_access(tenant_id, device_id) do
      {:ok, _} ->
        send(self(), :load_data)
        {:noreply, put_flash(socket, :info, "Tenant access revoked.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed: #{inspect(reason)}")}
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
          <div :if={not Enum.empty?(@devices)} class="divide-y divide-base-300">
            <div :for={dev <- @devices} id={"hsm-#{dev.id}"} class="p-5 space-y-3">
              <%!-- Device info row --%>
              <div class="flex items-center justify-between">
                <div class="flex items-center gap-3">
                  <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-warning/10">
                    <.icon name="hero-cpu-chip" class="size-5 text-warning" />
                  </div>
                  <div>
                    <p class="text-sm font-semibold text-base-content">{dev.label}</p>
                    <p class="text-xs text-base-content/50 font-mono">{dev.pkcs11_lib_path}</p>
                  </div>
                </div>
                <div class="flex items-center gap-3">
                  <div class="text-right text-xs">
                    <p class="text-base-content/50">Slot {dev.slot_id}</p>
                    <p class="text-base-content/50">{dev.manufacturer || "Unknown"}</p>
                  </div>
                  <span class={["badge badge-sm", if(dev.status == "active", do: "badge-success", else: "badge-warning")]}>
                    {dev.status}
                  </span>
                  <div class="flex gap-1">
                    <div class="tooltip" data-tip="Probe">
                      <button phx-click="probe_device" phx-value-id={dev.id} class="btn btn-ghost btn-xs text-info">
                        <.icon name="hero-signal" class="size-4" />
                      </button>
                    </div>
                    <div :if={dev.status == "active"} class="tooltip" data-tip="Deactivate">
                      <button phx-click="deactivate_device" phx-value-id={dev.id} class="btn btn-ghost btn-xs text-warning">
                        <.icon name="hero-pause" class="size-4" />
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <%!-- Tenant access --%>
              <div class="ml-13 pl-4 border-l-2 border-base-300">
                <p class="text-xs font-medium text-base-content/60 mb-2">Tenant Access</p>
                <div class="flex flex-wrap gap-2 mb-2">
                  <%= if Enum.empty?(dev.assigned_tenants) do %>
                    <span class="text-xs text-base-content/40">No tenants assigned</span>
                  <% else %>
                    <div :for={tenant <- dev.assigned_tenants} class="badge badge-sm badge-outline gap-1">
                      {tenant.name}
                      <button phx-click="revoke_access" phx-value-hsm-device-id={dev.id} phx-value-tenant-id={tenant.id}
                        class="hover:text-error cursor-pointer">
                        <.icon name="hero-x-mark" class="size-3" />
                      </button>
                    </div>
                  <% end %>
                </div>
                <form phx-submit="grant_access" class="flex items-center gap-2">
                  <input type="hidden" name="hsm_device_id" value={dev.id} />
                  <select name="tenant_id" class="select select-bordered select-xs">
                    <option value="">Assign tenant...</option>
                    <option :for={t <- @tenants} value={t.id}>{t.name}</option>
                  </select>
                  <button type="submit" class="btn btn-ghost btn-xs text-success">
                    <.icon name="hero-plus" class="size-3" /> Grant
                  </button>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
