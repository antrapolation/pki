defmodule PkiTenantWeb.Ra.ServiceConfigsLive do
  @moduledoc """
  Validation endpoint configuration (CRL / OCSP / TSA URLs embedded in
  issued certificates). Backed by Mnesia `PkiRaEngine.ServiceConfig`
  — upsert by `service_type`.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiRaEngine.ServiceConfig

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
       loading: true
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    configs = ServiceConfig.list_service_configs()
    {:noreply, assign(socket, configs: configs, loading: false)}
  end

  @impl true
  def handle_event("configure_service", params, socket) do
    if get_role(socket) == "ra_admin" do
      url = params["url"] || ""

      cond do
        not (String.starts_with?(url, "http://") or String.starts_with?(url, "https://")) ->
          {:noreply, put_flash(socket, :error, "URL must start with http:// or https://")}

        true ->
          attrs = %{
            service_type: params["service_type"],
            url: url,
            port: parse_int(params["port"], 8080)
          }

          case ServiceConfig.configure_service(attrs) do
            {:ok, config} ->
              configs =
                case Enum.find_index(socket.assigns.configs, &(&1.service_type == config.service_type)) do
                  nil -> [config | socket.assigns.configs]
                  idx -> List.replace_at(socket.assigns.configs, idx, config)
                end

              {:noreply,
               socket
               |> assign(configs: configs)
               |> put_flash(:info, "Validation endpoint configured")}

            {:error, :invalid_service_type} ->
              {:noreply, put_flash(socket, :error, "Unknown service type")}

            {:error, :service_type_required} ->
              {:noreply, put_flash(socket, :error, "Select a service type")}

            {:error, reason} ->
              Logger.error("[service_configs] configure failed: #{inspect(reason)}")
              {:noreply, put_flash(socket, :error, "Failed to configure endpoint")}
          end
      end
    else
      {:noreply, put_flash(socket, :error, "You don't have permission to configure endpoints.")}
    end
  end

  # --- Private helpers ---

  defp get_role(socket) do
    user = socket.assigns[:current_user] || %{}
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

  defp service_types, do: @service_types

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
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Configured Endpoints</h2>
          </div>

          <div :if={@loading} class="p-8 text-center text-base-content/40 text-sm">Loading…</div>

          <div :if={not @loading and Enum.empty?(@configs)} class="p-8 text-center text-base-content/50 text-sm">
            No validation endpoints configured yet.
          </div>

          <div :if={not @loading and not Enum.empty?(@configs)}>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[25%]">Service Type</th>
                  <th class="w-[10%]">Port</th>
                  <th class="w-[50%]">URL</th>
                  <th class="w-[15%]">Status</th>
                </tr>
              </thead>
              <tbody id="config-list">
                <tr :for={config <- @configs} id={"config-#{config.id}"} class="hover">
                  <td class="font-medium">{service_type_label(config.service_type)}</td>
                  <td class="font-mono text-xs">{config.port}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{config.url}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      (config.status || "active") == "active" && "badge-success",
                      (config.status || "active") != "active" && "badge-warning"
                    ]}>
                      {config.status || "active"}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <%!-- Configure Endpoint Form --%>
      <section
        :if={@current_user[:role] == "ra_admin"}
        id="configure-service-form"
        class="card bg-base-100 shadow-sm border border-base-300"
      >
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">Configure Endpoint</h2>

          <form phx-submit="configure_service" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
            <div>
              <label for="service-type" class="block text-xs font-medium text-base-content/60 mb-1">Service type</label>
              <select name="service_type" id="service-type" class="select select-bordered select-sm w-full">
                <option :for={{label, value} <- service_types()} value={value}>{label}</option>
              </select>
            </div>

            <div class="md:col-span-2">
              <label for="service-url" class="block text-xs font-medium text-base-content/60 mb-1">
                URL <span class="text-error">*</span>
              </label>
              <input
                type="text"
                name="url"
                id="service-url"
                required
                maxlength="255"
                placeholder="http://ocsp.example.com"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div>
              <label for="service-port" class="block text-xs font-medium text-base-content/60 mb-1">Port</label>
              <input
                type="number"
                name="port"
                id="service-port"
                value="8080"
                min="1"
                max="65535"
                class="input input-bordered input-sm w-full"
              />
            </div>

            <div class="md:col-span-4">
              <button type="submit" phx-disable-with="Saving…" class="btn btn-primary btn-sm">
                <.icon name="hero-plus" class="size-4" />
                Configure
              </button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
