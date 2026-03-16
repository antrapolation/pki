defmodule PkiRaPortalWeb.ServiceConfigsLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, configs} = RaEngineClient.list_service_configs()

    {:ok,
     assign(socket,
       page_title: "Service Configuration",
       configs: configs
     )}
  end

  @impl true
  def handle_event("configure_service", params, socket) do
    attrs = %{
      service_type: params["service_type"],
      port: parse_int(params["port"], 8080),
      url: params["url"],
      rate_limit: parse_int(params["rate_limit"], 1000),
      ip_whitelist: params["ip_whitelist"] || "",
      ip_blacklist: params["ip_blacklist"] || ""
    }

    case RaEngineClient.configure_service(attrs) do
      {:ok, config} ->
        configs = socket.assigns.configs ++ [config]

        {:noreply,
         socket
         |> assign(configs: configs)
         |> put_flash(:info, "Service configured successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to configure service: #{inspect(reason)}")}
    end
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end

  defp parse_int(_, default), do: default

  @impl true
  def render(assigns) do
    ~H"""
    <div id="service-configs-page">
      <h1>Service Configuration</h1>

      <section id="config-table">
        <table>
          <thead>
            <tr>
              <th>Service Type</th>
              <th>Port</th>
              <th>URL</th>
              <th>Rate Limit</th>
              <th>IP Whitelist</th>
              <th>IP Blacklist</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="config-list">
            <tr :for={config <- @configs} id={"config-#{config.id}"}>
              <td>{config.service_type}</td>
              <td>{config.port}</td>
              <td>{config.url}</td>
              <td>{config.rate_limit}</td>
              <td>{Map.get(config, :ip_whitelist, "")}</td>
              <td>{Map.get(config, :ip_blacklist, "")}</td>
              <td>{config.status}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="configure-service-form">
        <h2>Configure Service</h2>
        <form phx-submit="configure_service">
          <div>
            <label for="service-type">Service Type:</label>
            <select name="service_type" id="service-type">
              <option value="OCSP Responder">OCSP Responder</option>
              <option value="CRL Distribution">CRL Distribution</option>
              <option value="TSA">TSA</option>
            </select>
          </div>
          <div>
            <label for="service-port">Port:</label>
            <input type="number" name="port" id="service-port" value="8080" min="1" max="65535" />
          </div>
          <div>
            <label for="service-url">URL:</label>
            <input type="text" name="url" id="service-url" required />
          </div>
          <div>
            <label for="service-rate-limit">Rate Limit:</label>
            <input type="number" name="rate_limit" id="service-rate-limit" value="1000" min="1" />
          </div>
          <div>
            <label for="service-ip-whitelist">IP Whitelist (CIDR):</label>
            <input type="text" name="ip_whitelist" id="service-ip-whitelist" />
          </div>
          <div>
            <label for="service-ip-blacklist">IP Blacklist (CIDR):</label>
            <input type="text" name="ip_blacklist" id="service-ip-blacklist" />
          </div>
          <button type="submit">Configure</button>
        </form>
      </section>
    </div>
    """
  end
end
