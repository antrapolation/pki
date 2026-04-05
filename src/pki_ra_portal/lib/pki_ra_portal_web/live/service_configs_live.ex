defmodule PkiRaPortalWeb.ServiceConfigsLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @service_types [
    {"OCSP Responder", "ocsp_responder"},
    {"CRL Distribution", "crl_distribution"},
    {"TSA (Time Stamping)", "tsa"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     socket
     |> assign(
       page_title: "Validation Endpoints",
       configs: [],
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    {configs, socket} = case RaEngineClient.list_service_configs(tenant_opts(socket)) do
      {:ok, c} -> {c, socket}
      {:error, _} -> {[], put_flash(socket, :error, "Failed to load data. Try refreshing.")}
    end

    {:noreply, socket |> assign(configs: configs) |> apply_pagination()}
  end

  @impl true
  def handle_event("configure_service", params, socket) do
    if get_role(socket) == "ra_admin" do
      url = params["url"] || ""

      if not (String.starts_with?(url, "http://") or String.starts_with?(url, "https://")) do
        {:noreply, put_flash(socket, :error, "URL must start with http:// or https://")}
      else
        attrs = %{
          service_type: params["service_type"],
          url: url,
          port: parse_int(params["port"], 8080)
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
             |> put_flash(:info, "Validation endpoint configured")}

          {:error, reason} ->
            Logger.error("[service_configs] Failed to configure service: #{inspect(reason)}")
            {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to configure endpoint", reason))}
        end
      end
    else
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, socket |> assign(page: p) |> apply_pagination()}
      _ -> {:noreply, socket}
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp service_type_label(type) do
    case Enum.find(@service_types, fn {_, v} -> v == type end) do
      {label, _} -> label
      nil -> type
    end
  end

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
      <h1 class="text-2xl font-bold tracking-tight">Validation Endpoints</h1>

      <div class="alert alert-info shadow-sm">
        <.icon name="hero-information-circle" class="size-5" />
        <p class="text-sm">
          Configure certificate validation service endpoints. These URLs are embedded in issued certificates
          as CRL Distribution Points, OCSP Responder, and TSA extensions.
        </p>
      </div>

      <%!-- Endpoints Table --%>
      <section id="config-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider w-[20%]">Service Type</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[10%]">Port</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[45%]">URL</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[12%]">Status</th>
                </tr>
              </thead>
              <tbody id="config-list">
                <tr :for={config <- @paged_configs} id={"config-#{config.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium">{service_type_label(config.service_type)}</td>
                  <td class="font-mono text-xs">{config.port}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{config.url}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      (config[:status] || "active") == "active" && "badge-success",
                      (config[:status] || "active") != "active" && "badge-warning"
                    ]}>
                      {config[:status] || "active"}
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

      <%!-- Configure Endpoint Form --%>
      <section id="configure-service-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Configure Endpoint</h2>
          <form phx-submit="configure_service" class="grid grid-cols-1 md:grid-cols-3 gap-4 mt-2">
            <div>
              <label for="service-type" class="label text-xs font-medium">Service Type</label>
              <select name="service_type" id="service-type" class="select select-sm select-bordered w-full">
                <option :for={{label, value} <- service_types()} value={value}>{label}</option>
              </select>
            </div>
            <div>
              <label for="service-url" class="label text-xs font-medium">URL <span class="text-error">*</span></label>
              <input type="text" name="url" id="service-url" required maxlength="255"
                placeholder="http://ocsp.example.com" class="input input-sm input-bordered w-full" />
            </div>
            <div>
              <label for="service-port" class="label text-xs font-medium">Port</label>
              <input type="number" name="port" id="service-port" value="8080" min="1" max="65535" class="input input-sm input-bordered w-full" />
            </div>
            <div class="md:col-span-3">
              <button type="submit" phx-disable-with="Saving..." class="btn btn-sm btn-primary">Configure</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end

  defp service_types, do: @service_types
end
