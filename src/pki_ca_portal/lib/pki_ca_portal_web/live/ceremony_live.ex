defmodule PkiCaPortalWeb.CeremonyLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @algorithms [
    {"KAZ-SIGN-128", "Post-Quantum — KAZ-Sign level 1"},
    {"KAZ-SIGN-192", "Post-Quantum — KAZ-Sign level 3"},
    {"KAZ-SIGN-256", "Post-Quantum — KAZ-Sign level 5"},
    {"ML-DSA-44", "Post-Quantum — NIST FIPS 204 level 2"},
    {"ML-DSA-65", "Post-Quantum — NIST FIPS 204 level 3"},
    {"ML-DSA-87", "Post-Quantum — NIST FIPS 204 level 5"},
    {"ECC-P256", "Classical — fast, widely supported"},
    {"ECC-P384", "Classical — stronger"},
    {"RSA-2048", "Classical — legacy compatibility"},
    {"RSA-4096", "Classical — legacy, stronger"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Key Ceremony",
       ceremonies: [],
       keystores: [],
       ca_instances: [],
       algorithms: @algorithms,
       effective_ca_id: nil,
       selected_ca_id: "",
       loading: true,
       ceremony_result: nil,
       page: 1,
       per_page: 10
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ca_id = socket.assigns.current_user[:ca_instance_id]
    opts = tenant_opts(socket)

    ca_instances =
      case CaEngineClient.list_ca_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    effective_ca_id = ca_id || case ca_instances do
      [first | _] -> first[:id]
      [] -> nil
    end

    {ceremonies, keystores} = load_for_ca(effective_ca_id, opts)

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       ca_instances: ca_instances,
       effective_ca_id: effective_ca_id,
       selected_ca_id: effective_ca_id || "",
       loading: false
     )}
  end

  @impl true
  def handle_event("initiate_ceremony", params, socket) do
    ca_id = params["ca_instance_id"]
    opts = tenant_opts(socket)

    cond do
      is_nil(ca_id) or ca_id == "" ->
        {:noreply, put_flash(socket, :error, "Please select a CA Instance.")}

      is_nil(params["keystore_id"]) or params["keystore_id"] == "" ->
        {:noreply, put_flash(socket, :error, "Please select a Keystore.")}

      true ->
        ceremony_params = %{
          algorithm: params["algorithm"],
          keystore_id: params["keystore_id"],
          threshold_k: params["threshold_k"],
          threshold_n: params["threshold_n"],
          domain_info: params["domain_info"] || %{},
          initiated_by: socket.assigns.current_user[:id]
        }

        case CaEngineClient.initiate_ceremony(ca_id, ceremony_params, opts) do
          {:ok, result} ->
            {ceremonies, keystores} = load_for_ca(ca_id, opts)

            {:noreply,
             socket
             |> assign(ceremonies: ceremonies, keystores: keystores, ceremony_result: result, effective_ca_id: ca_id)
             |> put_flash(:info, "Ceremony initiated successfully")}

          {:error, reason} ->
            {:noreply, put_flash(socket, :error, "Failed to initiate ceremony: #{inspect(reason)}")}
        end
    end
  end

  @impl true
  def handle_event("select_ca_instance", %{"ca_instance_id" => ca_instance_id}, socket) do
    ca_id = if ca_instance_id == "", do: nil, else: ca_instance_id
    {ceremonies, keystores} = load_for_ca(ca_id, tenant_opts(socket))

    {:noreply,
     assign(socket,
       ceremonies: ceremonies,
       keystores: keystores,
       effective_ca_id: ca_id,
       selected_ca_id: ca_instance_id,
       page: 1
     )}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp load_for_ca(nil, _opts), do: {[], []}
  defp load_for_ca(ca_id, opts) do
    ceremonies = case CaEngineClient.list_ceremonies(ca_id, opts) do
      {:ok, c} -> c
      {:error, _} -> []
    end
    keystores = case CaEngineClient.list_keystores(ca_id, opts) do
      {:ok, ks} -> ks
      {:error, _} -> []
    end
    {ceremonies, keystores}
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp keystore_display(ks) do
    config = if ks[:config], do: PkiCaEngine.Schema.Keystore.decode_config(ks.config), else: nil
    label = if config, do: config["label"], else: nil

    case {ks.type, label} do
      {"hsm", l} when is_binary(l) -> "HSM — #{l}"
      {"hsm", _} -> "HSM"
      {"software", _} -> "Software"
      {type, _} -> type
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
          </p>
        </div>
      </div>

      <%!-- CA Instance selector --%>
      <div class="flex items-center gap-3">
        <label class="text-xs font-medium text-base-content/60">CA Instance</label>
        <form phx-change="select_ca_instance">
          <select name="ca_instance_id" class="select select-bordered select-sm">
            <option value="">Select CA Instance</option>
            <option
              :for={inst <- @ca_instances}
              value={inst.id}
              selected={@selected_ca_id == inst.id}
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
                ID: <span class="font-mono">{String.slice(@ceremony_result.id || "", 0..7)}</span>
              </p>
            </div>
          </div>
          <div class="mt-3 flex gap-4 text-sm">
            <span>Status: <span class="badge badge-sm badge-success">{@ceremony_result.status}</span></span>
            <span>Algorithm: <span class="font-mono">{@ceremony_result.algorithm}</span></span>
          </div>
        </div>
      </div>

      <%!-- Initiate ceremony form --%>
      <div :if={@effective_ca_id} id="initiate-ceremony-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Initiate Key Ceremony</h2>

          <div :if={Enum.empty?(@keystores)} class="alert alert-warning text-sm mb-4">
            <.icon name="hero-exclamation-triangle" class="size-4" />
            <span>No keystores configured for this CA instance. <a href="/keystores" class="link link-primary">Configure one first.</a></span>
          </div>

          <form :if={not Enum.empty?(@keystores)} phx-submit="initiate_ceremony" class="space-y-4">
            <input type="hidden" name="ca_instance_id" value={@effective_ca_id} />
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Algorithm</label>
                <select name="algorithm" class="select select-bordered select-sm w-full">
                  <%= for {algo, desc} <- @algorithms do %>
                    <option value={algo}>{algo} — {desc}</option>
                  <% end %>
                </select>
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Keystore</label>
                <select name="keystore_id" class="select select-bordered select-sm w-full" required>
                  <option value="" disabled selected>Select Keystore</option>
                  <option :for={ks <- @keystores} value={ks.id}>{keystore_display(ks)}</option>
                </select>
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold K (min. managers to reconstruct)</label>
                <input type="number" name="threshold_k" min="2" value="2" class="input input-bordered input-sm w-full" />
              </div>
              <div>
                <label class="block text-xs font-medium text-base-content/60 mb-1">Threshold N (total key managers)</label>
                <input type="number" name="threshold_n" min="2" value="3" class="input input-bordered input-sm w-full" />
              </div>
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

      <%!-- No CA instance selected --%>
      <div :if={is_nil(@effective_ca_id) and not @loading} class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body text-center py-8 text-base-content/50 text-sm">
          Select a CA instance above to view ceremonies and initiate new ones.
        </div>
      </div>

      <%!-- Past ceremonies table --%>
      <div :if={@effective_ca_id} id="ceremony-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Ceremony History</h2>
          </div>
          <% paginated = @ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
          <% total = length(@ceremonies) %>
          <% total_pages = max(ceil(total / @per_page), 1) %>
          <div :if={Enum.empty?(@ceremonies)} class="p-8 text-center text-base-content/50 text-sm">
            No ceremonies yet for this CA instance.
          </div>
          <div :if={not Enum.empty?(@ceremonies)} class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>ID</th>
                  <th>Type</th>
                  <th>Algorithm</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={c <- paginated} class="hover">
                  <td class="font-mono text-xs">{String.slice(c.id || "", 0..7)}</td>
                  <td class="text-sm">{c.ceremony_type}</td>
                  <td class="font-mono text-sm">{c.algorithm}</td>
                  <td><span class="badge badge-sm badge-ghost">{c.status}</span></td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total > @per_page} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {min((@page - 1) * @per_page + 1, total)}–{min(@page * @per_page, total)} of {total}
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
