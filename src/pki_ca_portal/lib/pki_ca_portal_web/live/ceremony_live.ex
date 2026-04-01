defmodule PkiCaPortalWeb.CeremonyLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: [],
       keystores: [],
       ca_instances: [],
       loading: true,
       selected_ca_instance_id: "",
       ceremony_result: nil,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id]
    opts = tenant_opts(socket)

    ceremonies = case CaEngineClient.list_ceremonies(ca_id, opts) do
      {:ok, c} -> c
      {:error, _} -> []
    end

    keystores = case CaEngineClient.list_keystores(ca_id, opts) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       ca_instances: ca_instances,
       loading: false
     )}
  end

  @impl true
  def handle_event("initiate_ceremony", params, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id]
    opts = tenant_opts(socket)

    ceremony_params = [
      algorithm: params["algorithm"],
      keystore_id: params["keystore_id"],
      threshold_k: params["threshold_k"],
      threshold_n: params["threshold_n"],
      domain_info: params["domain_info"]
    ]

    case CaEngineClient.initiate_ceremony(ca_id, ceremony_params, opts) do
      {:ok, result} ->
        ceremonies = case CaEngineClient.list_ceremonies(ca_id, opts) do
          {:ok, c} -> c
          {:error, _} -> []
        end

        {:noreply,
         socket
         |> assign(ceremonies: ceremonies, ceremony_result: result)
         |> put_flash(:info, "Ceremony initiated successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to initiate ceremony: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("filter_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id =
      if ca_instance_id == "",
        do: socket.assigns.current_user[:ca_instance_id],
        else: ca_instance_id

    ceremonies = case CaEngineClient.list_ceremonies(ca_id, tenant_opts(socket)) do
      {:ok, c} -> c
      {:error, _} -> []
    end

    keystores = case CaEngineClient.list_keystores(ca_id, tenant_opts(socket)) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       selected_ca_instance_id: ca_instance_id,
       page: 1
     )}
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

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ceremony-page" class="space-y-6">
      <%!-- Server-side HSM disclaimer --%>
      <div class="alert border border-info/30 bg-info/5">
        <.icon name="hero-information-circle" class="size-5 text-info shrink-0" />
        <div>
          <p class="text-sm font-medium text-base-content">Server-Side HSM Only</p>
          <p class="text-xs text-base-content/60 mt-0.5">
            Key ceremonies use server-side HSM devices managed by the platform. Keys are generated and stored on the server's HSM hardware via PKCS#11.
            Client-side HSM (e.g., USB tokens on your laptop) is not supported in this version.
            All Key Managers participate via this web portal — PIN entry is transmitted securely to the server.
          </p>
        </div>
      </div>

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
            <h2 class="text-sm font-semibold text-base-content">Ceremony History</h2>
            <p class="text-xs text-base-content/50 mt-0.5">Ceremonies require auditor attestation before finalization.</p>
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
          <h2 class="text-sm font-semibold text-base-content mb-4">Initiate Key Ceremony</h2>
          <div class="alert alert-info text-sm mb-4">
            <span class="hero-information-circle text-lg" />
            <div>
              <p class="font-medium">Multi-manager ceremony with auditor finalization</p>
              <p class="text-xs mt-1">
                Requires multiple Key Managers to contribute shares (threshold K of N).
                An Auditor must finalize and attest the ceremony before the root key becomes active.
              </p>
            </div>
          </div>
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
                <label for="threshold_k" class="block text-xs font-medium text-base-content/60 mb-1">Threshold K (min. managers to reconstruct)</label>
                <input type="number" name="threshold_k" id="ceremony-k" min="1" value="2" class="input input-bordered input-sm w-full" />
              </div>
              <div>
                <label for="threshold_n" class="block text-xs font-medium text-base-content/60 mb-1">Threshold N (total key managers)</label>
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
                Initiate Key Ceremony
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
