defmodule PkiRaPortalWeb.CaConnectionLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "CA Connections",
       connections: [],
       available_keys: [],
       loading: true,
       connecting_key_id: nil,
       disconnecting_id: nil
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    connections =
      case RaEngineClient.list_ca_connections([], opts) do
        {:ok, conns} -> conns
        {:error, _} -> []
      end

    available_keys =
      case RaEngineClient.available_issuer_keys(opts) do
        {:ok, keys} -> keys
        {:error, _} -> []
      end

    # Filter out already-connected keys
    connected_key_ids = MapSet.new(connections, & &1.issuer_key_id)

    filtered_keys =
      Enum.reject(available_keys, fn key ->
        key_id = Map.get(key, :id) || Map.get(key, "id")
        MapSet.member?(connected_key_ids, key_id)
      end)

    {:noreply,
     assign(socket,
       connections: connections,
       available_keys: filtered_keys,
       loading: false,
       connecting_key_id: nil,
       disconnecting_id: nil
     )}
  end

  @impl true
  def handle_event("connect_key", %{"key-id" => key_id} = params, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      attrs = %{
        issuer_key_id: key_id,
        issuer_key_name: params["key-name"] || "",
        algorithm: params["algorithm"] || "",
        ca_instance_name: params["ca-instance"] || ""
      }

      socket = assign(socket, connecting_key_id: key_id)

      case RaEngineClient.create_ca_connection(attrs, tenant_opts(socket)) do
        {:ok, _conn} ->
          send(self(), :load_data)
          {:noreply, put_flash(socket, :info, "Key connected successfully")}

        {:error, reason} ->
          Logger.error("[ca_connection] Failed to connect key: #{inspect(reason)}")

          {:noreply,
           socket
           |> assign(connecting_key_id: nil)
           |> put_flash(
             :error,
             PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to connect key", reason)
           )}
      end
    end
  end

  @impl true
  def handle_event("disconnect_key", %{"id" => id}, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      socket = assign(socket, disconnecting_id: id)

      case RaEngineClient.delete_ca_connection(id, tenant_opts(socket)) do
        {:ok, _conn} ->
          send(self(), :load_data)
          {:noreply, put_flash(socket, :info, "Key disconnected successfully")}

        {:error, reason} ->
          Logger.error("[ca_connection] Failed to disconnect key: #{inspect(reason)}")

          {:noreply,
           socket
           |> assign(disconnecting_id: nil)
           |> put_flash(
             :error,
             PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to disconnect key", reason)
           )}
      end
    end
  end

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp format_datetime(nil), do: "-"

  defp format_datetime(dt) do
    Calendar.strftime(dt, "%Y-%m-%d %H:%M")
  end

  defp algorithm_badge_class(algorithm) do
    cond do
      algorithm in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] -> "badge-primary"
      algorithm in ["KAZ-SIGN"] -> "badge-secondary"
      String.starts_with?(to_string(algorithm), "RSA") -> "badge-warning"
      String.starts_with?(to_string(algorithm), "EC") -> "badge-info"
      true -> "badge-ghost"
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="ca-connection-page" class="space-y-6">
      <%!-- Header --%>
      <div>
        <h1 class="text-lg font-semibold text-base-content">CA Connections</h1>
        <p class="text-xs text-base-content/50 mt-0.5">
          Manage which CA issuer keys this RA instance can use for certificate issuance
        </p>
      </div>

      <%!-- Info banner --%>
      <div class="alert alert-info text-sm">
        <.icon name="hero-information-circle" class="size-5" />
        <div>
          <p class="font-medium">What are CA Connections?</p>
          <p class="text-xs mt-0.5">
            CA Connections link your RA instance to specific issuer keys from the Certificate Authority.
            Only connected keys can be used when approving CSRs and issuing certificates.
            Connect at least one key to begin processing certificate requests.
          </p>
        </div>
      </div>

      <%!-- Loading state --%>
      <div :if={@loading} class="flex items-center justify-center py-12">
        <span class="loading loading-spinner loading-md text-primary"></span>
        <span class="ml-2 text-sm text-base-content/60">Loading CA connections...</span>
      </div>

      <div :if={not @loading} class="space-y-6">
        <%!-- Section 1: Connected Keys --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-0">
            <div class="px-5 py-4 border-b border-base-300 flex items-center justify-between">
              <div class="flex items-center gap-2">
                <.icon name="hero-link" class="size-4 text-success" />
                <h2 class="text-sm font-semibold text-base-content">Connected Keys</h2>
                <span class="badge badge-sm badge-ghost">{length(@connections)}</span>
              </div>
            </div>

            <div
              :if={Enum.empty?(@connections)}
              class="p-8 text-center text-base-content/50 text-sm"
            >
              No keys connected yet. Connect a key from the available list below.
            </div>

            <div :if={not Enum.empty?(@connections)} class="overflow-x-auto">
              <table class="table table-sm">
                <thead>
                  <tr class="text-xs text-base-content/50">
                    <th>Key Name</th>
                    <th>Algorithm</th>
                    <th>CA Instance</th>
                    <th>Connected</th>
                    <th class="text-right">Action</th>
                  </tr>
                </thead>
                <tbody>
                  <tr :for={conn <- @connections} id={"conn-#{conn.id}"} class="hover:bg-base-200/50">
                    <td class="font-medium text-sm">{conn.issuer_key_name || "-"}</td>
                    <td>
                      <span class={"badge badge-xs #{algorithm_badge_class(conn.algorithm)}"}>
                        {conn.algorithm || "-"}
                      </span>
                    </td>
                    <td class="text-sm text-base-content/70">{conn.ca_instance_name || "-"}</td>
                    <td class="text-xs text-base-content/50">{format_datetime(conn.connected_at)}</td>
                    <td class="text-right">
                      <button
                        class="btn btn-ghost btn-xs text-error"
                        phx-click="disconnect_key"
                        phx-value-id={conn.id}
                        disabled={@disconnecting_id == conn.id}
                      >
                        <span
                          :if={@disconnecting_id == conn.id}
                          class="loading loading-spinner loading-xs"
                        >
                        </span>
                        <.icon :if={@disconnecting_id != conn.id} name="hero-x-mark" class="size-3" />
                        Disconnect
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <%!-- Section 2: Available CA Keys --%>
        <div>
          <div class="flex items-center gap-2 mb-3">
            <.icon name="hero-key" class="size-4 text-primary" />
            <h2 class="text-sm font-semibold text-base-content">Available CA Keys</h2>
            <span class="badge badge-sm badge-ghost">{length(@available_keys)}</span>
          </div>

          <div
            :if={Enum.empty?(@available_keys)}
            class="card bg-base-100 shadow-sm border border-base-300"
          >
            <div class="card-body p-8 text-center text-base-content/50 text-sm">
              No additional CA keys available to connect.
            </div>
          </div>

          <div
            :if={not Enum.empty?(@available_keys)}
            class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3"
          >
            <div
              :for={key <- @available_keys}
              id={"avail-key-#{Map.get(key, :id) || Map.get(key, "id")}"}
              class="card bg-base-100 shadow-sm border border-base-300 hover:border-primary/30 transition-colors"
            >
              <div class="card-body p-4 space-y-3">
                <div class="flex items-start justify-between">
                  <div class="flex items-center gap-2">
                    <div class="flex items-center justify-center w-7 h-7 rounded-md bg-primary/10">
                      <.icon name="hero-key" class="size-3.5 text-primary" />
                    </div>
                    <div>
                      <p class="text-sm font-medium text-base-content">
                        {Map.get(key, :name) || Map.get(key, "name") || "-"}
                      </p>
                    </div>
                  </div>
                  <span class={"badge badge-xs #{algorithm_badge_class(to_string(Map.get(key, :algorithm) || Map.get(key, "algorithm") || ""))}"}>
                    {Map.get(key, :algorithm) || Map.get(key, "algorithm") || "-"}
                  </span>
                </div>

                <div class="text-xs text-base-content/50">
                  CA: {Map.get(key, :ca_instance_name) || Map.get(key, "ca_instance_name") || "-"}
                </div>

                <button
                  class="btn btn-primary btn-xs btn-block"
                  phx-click="connect_key"
                  phx-value-key-id={Map.get(key, :id) || Map.get(key, "id")}
                  phx-value-key-name={Map.get(key, :name) || Map.get(key, "name") || ""}
                  phx-value-algorithm={Map.get(key, :algorithm) || Map.get(key, "algorithm") || ""}
                  phx-value-ca-instance={Map.get(key, :ca_instance_name) || Map.get(key, "ca_instance_name") || ""}
                  disabled={@connecting_key_id == (Map.get(key, :id) || Map.get(key, "id"))}
                >
                  <span
                    :if={@connecting_key_id == (Map.get(key, :id) || Map.get(key, "id"))}
                    class="loading loading-spinner loading-xs"
                  >
                  </span>
                  <.icon
                    :if={@connecting_key_id != (Map.get(key, :id) || Map.get(key, "id"))}
                    name="hero-plus"
                    class="size-3"
                  />
                  Connect
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
