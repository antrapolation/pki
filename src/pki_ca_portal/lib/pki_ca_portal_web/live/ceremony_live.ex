defmodule PkiCaPortalWeb.CeremonyLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    ca_id = socket.assigns.current_user["ca_instance_id"] || 1
    {:ok, ceremonies} = CaEngineClient.list_ceremonies(ca_id)
    {:ok, keystores} = CaEngineClient.list_keystores(ca_id)

    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: ceremonies,
       keystores: keystores,
       ceremony_result: nil,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_event("initiate_ceremony", params, socket) do
    ca_id = socket.assigns.current_user["ca_instance_id"] || 1

    ceremony_params = [
      algorithm: params["algorithm"],
      keystore_id: params["keystore_id"],
      threshold_k: params["threshold_k"],
      threshold_n: params["threshold_n"],
      domain_info: params["domain_info"]
    ]

    case CaEngineClient.initiate_ceremony(ca_id, ceremony_params) do
      {:ok, result} ->
        {:ok, ceremonies} = CaEngineClient.list_ceremonies(ca_id)

        {:noreply,
         socket
         |> assign(ceremonies: ceremonies, ceremony_result: result)
         |> put_flash(:info, "Ceremony initiated successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate ceremony: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-page" class="space-y-6">
      <%!-- Ceremony status card (shown after initiation) --%>
      <div :if={@ceremony_result} id="ceremony-status" class="card bg-success/5 border border-success/20 shadow-sm">
        <div class="card-body p-5">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
              <.icon name="hero-check-circle" class="size-6 text-success" />
            </div>
            <div>
              <h2 class="text-sm font-semibold text-base-content">Ceremony Initiated</h2>
              <p class="text-xs text-base-content/50 mt-0.5">
                ID: <span class="font-mono-data">{@ceremony_result.id}</span>
              </p>
            </div>
          </div>
          <div class="mt-3 flex gap-4 text-sm">
            <span>Status: <span id="ceremony-state" class="badge badge-sm badge-success">{@ceremony_result.status}</span></span>
            <span>Algorithm: <span class="font-mono-data">{@ceremony_result.algorithm}</span></span>
          </div>
        </div>
      </div>

      <%!-- Past ceremonies table --%>
      <% paginated_ceremonies = @ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_ceremonies = length(@ceremonies) %>
      <% total_pages = max(ceil(total_ceremonies / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_ceremonies) %>
      <% end_idx = min(@page * @per_page, total_ceremonies) %>
      <div id="ceremony-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Past Ceremonies</h2>
          </div>
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>ID</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Algorithm</th>
                </tr>
              </thead>
              <tbody id="ceremony-list">
                <tr :for={c <- paginated_ceremonies} id={"ceremony-#{c.id}"} class="hover">
                  <td class="font-mono-data">{c.id}</td>
                  <td>{c.ceremony_type}</td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{c.status}</span>
                  </td>
                  <td class="font-mono-data">{c.algorithm}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_ceremonies > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_ceremonies}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Initiate ceremony form --%>
      <div id="initiate-ceremony-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Initiate Ceremony</h2>
          <form phx-submit="initiate_ceremony" class="space-y-4">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="algorithm" class="block text-xs font-medium text-base-content/60 mb-1">Algorithm</label>
                <select name="algorithm" id="ceremony-algorithm" class="select select-bordered select-sm w-full">
                  <option value="KAZ-SIGN-256">KAZ-SIGN-256</option>
                  <option value="ML-DSA-65">ML-DSA-65</option>
                  <option value="RSA-4096">RSA-4096</option>
                  <option value="ECC-P256">ECC-P256</option>
                </select>
              </div>
              <div>
                <label for="keystore_id" class="block text-xs font-medium text-base-content/60 mb-1">Keystore</label>
                <select name="keystore_id" id="ceremony-keystore" class="select select-bordered select-sm w-full">
                  <option :for={ks <- @keystores} value={ks.id}>{ks.type} - {ks.provider_name}</option>
                </select>
              </div>
              <div>
                <label for="threshold_k" class="block text-xs font-medium text-base-content/60 mb-1">Threshold K</label>
                <input type="number" name="threshold_k" id="ceremony-k" min="1" value="2" class="input input-bordered input-sm w-full" />
              </div>
              <div>
                <label for="threshold_n" class="block text-xs font-medium text-base-content/60 mb-1">Threshold N</label>
                <input type="number" name="threshold_n" id="ceremony-n" min="1" value="3" class="input input-bordered input-sm w-full" />
              </div>
            </div>
            <div>
              <label for="domain_info" class="block text-xs font-medium text-base-content/60 mb-1">Domain Info</label>
              <textarea name="domain_info" id="ceremony-domain-info" rows="3" class="textarea textarea-bordered w-full text-sm"></textarea>
            </div>
            <div class="pt-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-shield-check" class="size-4" />
                Initiate Ceremony
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
