defmodule PkiRaPortalWeb.ServiceConfigsLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, configs} = RaEngineClient.list_service_configs(tenant_opts(socket))

    {:ok,
     socket
     |> assign(
       page_title: "Service Configuration",
       configs: configs,
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("configure_service", params, socket) do
    attrs = %{
      service_type: params["service_type"],
      port: parse_int(params["port"], 8080),
      url: params["url"],
      rate_limit: parse_int(params["rate_limit"], 1000)
    }

    case RaEngineClient.configure_service(attrs, tenant_opts(socket)) do
      {:ok, config} ->
        configs =
          case Enum.find_index(socket.assigns.configs, &(&1.service_type == config.service_type)) do
            nil -> [config | socket.assigns.configs]
            idx -> List.replace_at(socket.assigns.configs, idx, Map.merge(Enum.at(socket.assigns.configs, idx), config))
          end

        {:noreply,
         socket
         |> assign(configs: configs)
         |> apply_pagination()
         |> put_flash(:info, "Service configured successfully")}

      {:error, reason} ->
        Logger.error("[service_configs] Failed to configure service: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to configure service", reason))}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, socket |> assign(page: String.to_integer(page)) |> apply_pagination()}
  end

  defp format_ip_field(v) when is_map(v) and map_size(v) == 0, do: ""
  defp format_ip_field(v) when is_map(v), do: Jason.encode!(v)
  defp format_ip_field(v) when is_binary(v), do: v
  defp format_ip_field(_), do: ""

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  defp apply_pagination(socket) do
    items = socket.assigns.configs
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_configs: paged, total_pages: total_pages, page: page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="service-configs-page" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">Service Configuration</h1>

      <%!-- Config Table --%>
      <section id="config-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider w-[15%]">Service Type</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[8%]">Port</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[22%]">URL</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[10%]">Rate Limit</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[16%]">IP Whitelist</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[16%]">IP Blacklist</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[13%]">Status</th>
                </tr>
              </thead>
              <tbody id="config-list">
                <tr :for={config <- @paged_configs} id={"config-#{config.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">{config.service_type}</td>
                  <td class="font-mono text-xs">{config.port}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{config.url}</td>
                  <td>{config.rate_limit}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{format_ip_field(Map.get(config, :ip_whitelist, ""))}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{format_ip_field(Map.get(config, :ip_blacklist, ""))}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      config.status == "active" && "badge-success",
                      config.status != "active" && "badge-warning"
                    ]}>
                      {config.status}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total_pages > 1} class="flex justify-center mt-4">
            <div class="join">
              <button
                :for={p <- 1..@total_pages}
                phx-click="change_page"
                phx-value-page={p}
                class={["join-item btn btn-sm", p == @page && "btn-active"]}
              >
                {p}
              </button>
            </div>
          </div>
        </div>
      </section>

      <%!-- Configure Service Form --%>
      <section id="configure-service-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Configure Service</h2>
          <form phx-submit="configure_service" class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
            <div>
              <label for="service-type" class="label text-xs font-medium">Service Type</label>
              <select name="service_type" id="service-type" class="select select-sm select-bordered w-full">
                <option value="OCSP Responder">OCSP Responder</option>
                <option value="CRL Distribution">CRL Distribution</option>
                <option value="TSA">TSA</option>
              </select>
            </div>
            <div>
              <label for="service-port" class="label text-xs font-medium">Port</label>
              <input type="number" name="port" id="service-port" value="8080" min="1" max="65535" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="service-url" class="label text-xs font-medium">URL</label>
              <input type="text" name="url" id="service-url" required class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="service-rate-limit" class="label text-xs font-medium">Rate Limit</label>
              <input type="number" name="rate_limit" id="service-rate-limit" value="1000" min="1" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="service-ip-whitelist" class="label text-xs font-medium">IP Whitelist (CIDR)</label>
              <input type="text" name="ip_whitelist" id="service-ip-whitelist" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="service-ip-blacklist" class="label text-xs font-medium">IP Blacklist (CIDR)</label>
              <input type="text" name="ip_blacklist" id="service-ip-blacklist" class="input input-sm input-bordered w-full" />
            </div>
            <div class="md:col-span-2">
              <button type="submit" class="btn btn-sm btn-primary">Configure</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
