defmodule PkiCaPortalWeb.KeystoresLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient
  import PkiCaPortalWeb.AuditHelpers, only: [audit_log: 4, audit_log: 5]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Keystore Management",
       keystores: [],
       ca_instances: [],
       hsm_devices: [],
       loading: true,
       show_hsm_picker: false,
       form_ca_instance_id: "",
       selected_ca_instance_id: "",
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    keystores = case CaEngineClient.list_keystores(nil, opts) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    hsm_devices =
      case CaEngineClient.list_hsm_devices(opts) do
        {:ok, devices} -> Enum.filter(devices, &(&1[:status] == "active"))
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       keystores: keystores,
       ca_instances: ca_instances,
       hsm_devices: hsm_devices,
       loading: false
     )}
  end

  @impl true
  def handle_event("configure_keystore", params, socket) do
    type = params["type"]
    ca_instance_id = params["ca_instance_id"]
    hsm_device_id = params["hsm_device_id"]

    cond do
      ca_instance_id == "" or is_nil(ca_instance_id) ->
        {:noreply, put_flash(socket, :error, "Please select a CA Instance.")}

      type == "hsm" and (hsm_device_id == "" or is_nil(hsm_device_id)) ->
        {:noreply, put_flash(socket, :error, "Please select an HSM device.")}

      true ->
        # Check for duplicate keystore type on same CA instance
        existing = Enum.find(socket.assigns.keystores, fn ks ->
          ks[:ca_instance_id] == ca_instance_id and ks[:type] == type
        end)

        if existing do
          {:noreply, put_flash(socket, :error, "This CA instance already has a #{type} keystore.")}
        else
          attrs = %{type: type}
          attrs = if type == "hsm", do: Map.put(attrs, :hsm_device_id, hsm_device_id), else: attrs

          case CaEngineClient.configure_keystore(ca_instance_id, attrs, tenant_opts(socket)) do
            {:ok, keystore} ->
              ks_details = %{ca_instance_id: ca_instance_id, type: type}
              ks_details = if type == "hsm", do: Map.put(ks_details, :hsm_device_id, hsm_device_id), else: ks_details
              audit_log(socket, "keystore_configured", "keystore", keystore[:id] || keystore["id"], ks_details)
              send(self(), :load_data)
              {:noreply, put_flash(socket, :info, "Keystore configured successfully.")}

            {:error, reason} ->
              {:noreply, put_flash(socket, :error, "Failed to configure keystore: #{inspect(reason)}")}
          end
        end
    end
  end

  @impl true
  def handle_event("form_change", params, socket) do
    {:noreply, assign(socket,
      show_hsm_picker: params["type"] == "hsm",
      form_ca_instance_id: params["ca_instance_id"] || socket.assigns.form_ca_instance_id
    )}
  end

  @impl true
  def handle_event("filter_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id = if ca_instance_id == "", do: nil, else: ca_instance_id

    keystores = case CaEngineClient.list_keystores(ca_id, tenant_opts(socket)) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    {:noreply, assign(socket, keystores: keystores, selected_ca_instance_id: ca_instance_id, page: 1)}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp type_badge_class(type) do
    case type do
      "software" -> "badge-info"
      "hsm" -> "badge-warning"
      _ -> "badge-ghost"
    end
  end

  defp status_badge_class(status) do
    case status do
      "active" -> "badge-success"
      "configured" -> "badge-info"
      "inactive" -> "badge-ghost"
      _ -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="keystores-page" class="space-y-6">
      <%!-- CA Instance filter --%>
      <div class="flex items-center gap-3">
        <label for="ca-instance-filter" class="text-xs font-medium text-base-content/60">Filter by CA Instance</label>
        <form phx-change="filter_ca_instance">
          <select name="ca_instance_id" id="ca-instance-filter" class="select select-bordered select-sm">
            <option value="">All</option>
            <option
              :for={inst <- @ca_instances}
              value={inst.id}
              selected={@selected_ca_instance_id == inst.id}
            >
              {inst.name}
            </option>
          </select>
        </form>
      </div>

      <%!-- Configure keystore form --%>
      <div id="configure-keystore-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Configure Keystore</h2>
          <form phx-submit="configure_keystore" phx-change="form_change" class="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">CA Instance</label>
              <select name="ca_instance_id" class="select select-bordered select-sm w-full" required>
                <option value="" disabled selected={@form_ca_instance_id == ""}>Select CA Instance</option>
                <option :for={inst <- @ca_instances} value={inst.id} selected={@form_ca_instance_id == inst.id}>{inst.name}</option>
              </select>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Type</label>
              <select name="type" class="select select-bordered select-sm w-full">
                <option value="software">Software</option>
                <option value="hsm">HSM (PKCS#11)</option>
              </select>
            </div>
            <div :if={@show_hsm_picker} class="md:col-span-2">
              <label class="block text-xs font-medium text-base-content/60 mb-1">HSM Device</label>
              <%= if Enum.empty?(@hsm_devices) do %>
                <p class="text-xs text-error mt-1">No HSM devices assigned to your tenant. Contact the platform administrator.</p>
              <% else %>
                <select name="hsm_device_id" class="select select-bordered select-sm w-full" required>
                  <option value="" disabled selected>Select HSM Device</option>
                  <option :for={dev <- @hsm_devices} value={dev.id}>{dev.label} ({dev[:manufacturer] || "PKCS#11"})</option>
                </select>
              <% end %>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm w-full">
                <.icon name="hero-plus" class="size-4" />
                Configure
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Keystores table --%>
      <% paginated_keystores = @keystores |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_keystores = length(@keystores) %>
      <% total_pages = max(ceil(total_keystores / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_keystores) %>
      <% end_idx = min(@page * @per_page, total_keystores) %>
      <div id="keystore-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Configured Keystores</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>CA Instance</th>
                  <th>Type</th>
                  <th>HSM Device</th>
                  <th>Status</th>
                  <th>ID</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody id="keystore-list">
                <% decoded_keystores = Enum.map(paginated_keystores, fn ks ->
                  config = if ks[:config], do: PkiCaEngine.Schema.Keystore.decode_config(ks.config), else: nil
                  Map.put(ks, :decoded_config, config)
                end) %>
                <tr :for={ks <- decoded_keystores} id={"keystore-#{ks.id}"} class="hover">
                  <td class="font-medium text-sm">{Map.get(ks, :ca_instance_name, "-")}</td>
                  <td>
                    <span class={"badge badge-sm #{type_badge_class(ks.type)}"}>{ks.type}</span>
                  </td>
                  <td class="text-xs">
                    {if ks.decoded_config, do: ks.decoded_config["label"] || "-", else: "-"}
                  </td>
                  <td>
                    <span class={"badge badge-sm #{status_badge_class(ks.status)}"}>{ks.status}</span>
                  </td>
                  <td class="font-mono text-xs text-base-content/50">{String.slice(ks.id || "", 0..7)}</td>
                  <td class="text-xs text-base-content/50">
                    {if ks[:inserted_at], do: Calendar.strftime(ks.inserted_at, "%Y-%m-%d %H:%M"), else: "-"}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_keystores > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_keystores}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
