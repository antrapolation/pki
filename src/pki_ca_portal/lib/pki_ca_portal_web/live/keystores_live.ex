defmodule PkiCaPortalWeb.KeystoresLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id] || "default"

    keystores = case CaEngineClient.list_keystores(ca_id) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    ca_instances =
      case CaEngineClient.list_ca_instances() do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    {:ok,
     assign(socket,
       page_title: "Keystore Management",
       keystores: keystores,
       ca_instances: ca_instances,
       selected_ca_instance_id: "",
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_event("configure_keystore", %{"type" => type}, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id] || "default"

    case CaEngineClient.configure_keystore(ca_id, %{type: type}) do
      {:ok, keystore} ->
        keystores = [keystore | socket.assigns.keystores]

        {:noreply,
         socket
         |> assign(keystores: keystores)
         |> put_flash(:info, "Keystore configured successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to configure keystore: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id =
      if ca_instance_id == "",
        do: socket.assigns.current_user[:ca_instance_id] || "default",
        else: ca_instance_id

    keystores = case CaEngineClient.list_keystores(ca_id) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    {:noreply, assign(socket, keystores: keystores, selected_ca_instance_id: ca_instance_id, page: 1)}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
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
                  <th>Type</th>
                  <th>Provider</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody id="keystore-list">
                <tr :for={ks <- paginated_keystores} id={"keystore-#{ks.id}"} class="hover">
                  <td>
                    <span class={"badge badge-sm #{type_badge_class(ks.type)}"}>{ks.type}</span>
                  </td>
                  <td class="font-mono-data">{Map.get(ks, :provider_name, "-")}</td>
                  <td>
                    <span class={"badge badge-sm #{status_badge_class(ks.status)}"}>{ks.status}</span>
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

      <%!-- Configure keystore form --%>
      <div id="configure-keystore-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Configure Keystore</h2>
          <form phx-submit="configure_keystore" class="flex items-end gap-4">
            <div class="flex-1 max-w-xs">
              <label for="type" class="block text-xs font-medium text-base-content/60 mb-1">Type</label>
              <select name="type" id="keystore-type" class="select select-bordered select-sm w-full">
                <option value="software">Software</option>
                <option value="hsm">HSM</option>
              </select>
            </div>
            <button type="submit" class="btn btn-primary btn-sm">
              <.icon name="hero-plus" class="size-4" />
              Configure
            </button>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
