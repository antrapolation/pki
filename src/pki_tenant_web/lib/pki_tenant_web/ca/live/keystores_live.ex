defmodule PkiTenantWeb.Ca.KeystoresLive do
  @moduledoc """
  Keystore configuration: one keystore per CA instance per type.

  Supports two types:

    - software — `StrapSoftPrivKeyStoreProvider`, opaque filesystem-backed
      keystore on the tenant node.
    - hsm      — `StrapSofthsmPrivKeyStoreProvider`, bound to an HSM device
      that the platform admin has assigned to this tenant
      (`HsmDeviceManagement.list_devices_for_tenant/1`).

  Read + create only in this port. Delete / decommission stays in the
  admin flow until we have a separate audit-trail requirement story.

  Backed by legacy `PkiCaEngine.KeystoreManagement` which still uses
  `TenantRepo`-based Ecto — migration to Mnesia is tracked for M4.
  Functionally this works today on the schema-mode VPS deployment.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiCaEngine.{CaInstanceManagement, HsmDeviceManagement, KeystoreManagement}

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "Keystores",
       keystores: [],
       ca_instances: [],
       ca_instance_names: %{},
       hsm_devices: [],
       loading: true,
       selected_ca_instance_id: "",
       form_ca_instance_id: "",
       form_type: "software",
       show_hsm_picker: false
     )}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    if connected?(socket), do: send(self(), {:load_data, params["ca"]})
    {:noreply, socket}
  end

  @impl true
  def handle_info({:load_data, url_ca_id}, socket) do
    tenant_id = PkiTenant.tenant_id()

    ca_instances =
      case CaInstanceManagement.list_ca_instances() do
        {:ok, list} -> list
        _ -> []
      end

    ca_instance_names = Map.new(ca_instances, fn i -> {i.id, i.name} end)

    ca_filter =
      case url_ca_id do
        id when is_binary(id) and id != "" -> id
        _ -> nil
      end

    keystores = safely_list_keystores(ca_filter)

    hsm_devices =
      tenant_id
      |> HsmDeviceManagement.list_devices_for_tenant()
      |> Enum.filter(fn d -> Map.get(d, :status) == "active" end)

    {:noreply,
     assign(socket,
       keystores: keystores,
       ca_instances: ca_instances,
       ca_instance_names: ca_instance_names,
       hsm_devices: hsm_devices,
       selected_ca_instance_id: url_ca_id || "",
       loading: false
     )}
  end

  @impl true
  def handle_event("filter_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    path = if ca_instance_id == "", do: "/keystores", else: "/keystores?ca=#{ca_instance_id}"
    {:noreply, push_patch(socket, to: path)}
  end

  def handle_event("form_change", params, socket) do
    {:noreply,
     assign(socket,
       form_ca_instance_id: params["ca_instance_id"] || socket.assigns.form_ca_instance_id,
       form_type: params["type"] || socket.assigns.form_type,
       show_hsm_picker: params["type"] == "hsm"
     )}
  end

  def handle_event("configure_keystore", params, socket) do
    if socket.assigns.current_user[:role] not in ["ca_admin", "key_manager"] do
      {:noreply, put_flash(socket, :error, "You don't have permission to configure keystores.")}
    else
      do_configure_keystore(params, socket)
    end
  end

  defp do_configure_keystore(params, socket) do
    type = params["type"]
    ca_instance_id = params["ca_instance_id"]
    hsm_device_id = params["hsm_device_id"]

    cond do
      blank?(ca_instance_id) ->
        {:noreply, put_flash(socket, :error, "Select a CA instance.")}

      type == "hsm" and blank?(hsm_device_id) ->
        {:noreply, put_flash(socket, :error, "Select an HSM device.")}

      duplicate_keystore?(socket.assigns.keystores, ca_instance_id, type) ->
        {:noreply, put_flash(socket, :error, "That CA instance already has a #{type} keystore.")}

      true ->
        attrs =
          %{type: type}
          |> maybe_put(:hsm_device_id, type == "hsm" && hsm_device_id)

        case KeystoreManagement.configure_keystore(ca_instance_id, attrs) do
          {:ok, keystore} ->
            PkiTenant.AuditBridge.log("keystore_configured", %{
              keystore_id: keystore.id,
              ca_instance_id: ca_instance_id,
              type: type,
              hsm_device_id: hsm_device_id
            })

            send(self(), {:load_data, socket.assigns.selected_ca_instance_id})
            {:noreply, put_flash(socket, :info, "Keystore configured.")}

          {:error, :hsm_device_not_found} ->
            {:noreply, put_flash(socket, :error, "HSM device not found or not assigned to your tenant.")}

          {:error, reason} ->
            Logger.error("[keystores_live] configure failed: #{inspect(reason)}")
            {:noreply, put_flash(socket, :error, "Failed to configure keystore.")}
        end
    end
  end

  # --- Private helpers ---

  defp safely_list_keystores(ca_filter) do
    KeystoreManagement.list_keystores(ca_filter)
  rescue
    e ->
      Logger.warning("[keystores_live] list_keystores raised: #{Exception.message(e)}")
      []
  end

  defp duplicate_keystore?(keystores, ca_instance_id, type) do
    Enum.any?(keystores, fn ks ->
      ks.ca_instance_id == ca_instance_id and ks.type == type
    end)
  end

  defp blank?(nil), do: true
  defp blank?(""), do: true
  defp blank?(s) when is_binary(s), do: String.trim(s) == ""
  defp blank?(_), do: false

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, false), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp type_badge_class("software"), do: "badge-info"
  defp type_badge_class("hsm"), do: "badge-warning"
  defp type_badge_class(_), do: "badge-ghost"

  defp status_badge_class("active"), do: "badge-success"
  defp status_badge_class("configured"), do: "badge-info"
  defp status_badge_class("inactive"), do: "badge-ghost"
  defp status_badge_class(_), do: "badge-ghost"

  defp hsm_label_for(%{config: %{} = config}) do
    case PkiMnesia.Structs.Keystore.decode_config(config) do
      %{"label" => label} -> label
      _ -> "—"
    end
  rescue
    _ -> "—"
  end

  defp hsm_label_for(_), do: "—"

  @impl true
  def render(assigns) do
    ~H"""
    <div id="keystores-page" class="space-y-6">
      <%!-- CA instance filter --%>
      <div class="flex items-center gap-3">
        <label for="ca-instance-filter" class="text-xs font-medium text-base-content/60">
          Filter by CA instance
        </label>
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

      <%!-- Configure form --%>
      <div
        :if={@current_user[:role] in ["ca_admin", "key_manager"]}
        id="configure-keystore-form"
        class="card bg-base-100 shadow-sm border border-base-300"
      >
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Configure Keystore</h2>

          <form phx-submit="configure_keystore" phx-change="form_change" class="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">CA instance</label>
              <select name="ca_instance_id" class="select select-bordered select-sm w-full" required>
                <option value="" disabled selected={@form_ca_instance_id == ""}>Select CA instance</option>
                <option :for={inst <- @ca_instances} value={inst.id} selected={@form_ca_instance_id == inst.id}>
                  {inst.name}
                </option>
              </select>
            </div>

            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Type</label>
              <select name="type" class="select select-bordered select-sm w-full">
                <option value="software" selected={@form_type == "software"}>Software</option>
                <option value="hsm" selected={@form_type == "hsm"}>HSM (PKCS#11)</option>
              </select>
            </div>

            <div :if={@show_hsm_picker} class="md:col-span-2">
              <label class="block text-xs font-medium text-base-content/60 mb-1">HSM device</label>
              <%= if Enum.empty?(@hsm_devices) do %>
                <p class="text-xs text-error mt-1">
                  No HSM devices assigned to your tenant. Contact the platform administrator.
                </p>
              <% else %>
                <select name="hsm_device_id" class="select select-bordered select-sm w-full" required>
                  <option value="" disabled selected>Select HSM device</option>
                  <option :for={dev <- @hsm_devices} value={dev.id}>
                    {dev.label} ({Map.get(dev, :manufacturer) || "PKCS#11"})
                  </option>
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

      <%!-- Keystore table --%>
      <div id="keystore-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Configured Keystores</h2>
          </div>

          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">Loading…</div>

          <div :if={not @loading and Enum.empty?(@keystores)} class="p-8 text-center text-base-content/50 text-sm">
            No keystores configured yet.
          </div>

          <div :if={not @loading and not Enum.empty?(@keystores)}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[28%]">CA instance</th>
                  <th class="w-[12%]">Type</th>
                  <th class="w-[25%]">HSM label</th>
                  <th class="w-[12%]">Status</th>
                  <th class="w-[10%]">ID</th>
                  <th class="w-[13%]">Created</th>
                </tr>
              </thead>
              <tbody id="keystore-list">
                <tr :for={ks <- @keystores} id={"keystore-#{ks.id}"} class="hover">
                  <td class="font-medium text-sm overflow-hidden text-ellipsis whitespace-nowrap">
                    {Map.get(@ca_instance_names, ks.ca_instance_id, "—")}
                  </td>
                  <td>
                    <span class={"badge badge-sm #{type_badge_class(ks.type)}"}>{ks.type}</span>
                  </td>
                  <td class="text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                    {if ks.type == "hsm", do: hsm_label_for(ks), else: "—"}
                  </td>
                  <td>
                    <span class={"badge badge-sm #{status_badge_class(ks.status)}"}>{ks.status}</span>
                  </td>
                  <td class="font-mono text-xs text-base-content/50 overflow-hidden text-ellipsis whitespace-nowrap">
                    {String.slice(ks.id || "", 0..7)}
                  </td>
                  <td class="text-xs text-base-content/50">
                    <.local_time dt={ks.inserted_at} />
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
