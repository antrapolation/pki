defmodule PkiTenantWeb.Ra.CaConnectionLive do
  @moduledoc """
  RA-to-CA key connections: connect / disconnect issuer keys to the
  first configured RA instance. Backed by Mnesia
  `PkiRaEngine.CaConnectionManagement`.

  Display fields (key name, algorithm, CA instance name) are joined
  from `PkiMnesia.Structs.{IssuerKey, CaInstance}` at render time.
  """
  use PkiTenantWeb, :live_view

  require Logger

  alias PkiMnesia.{Repo, Structs.CaInstance, Structs.IssuerKey}
  alias PkiRaEngine.{CaConnectionManagement, RaInstanceManagement}

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "CA Connections",
       connections: [],
       available_keys: [],
       loading: true,
       ra_instance_id: nil,
       connecting_key_id: nil,
       disconnecting_id: nil
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    ra_instance_id =
      case RaInstanceManagement.list_ra_instances() do
        [ra | _] -> ra.id
        _ -> nil
      end

    connections = if ra_instance_id, do: CaConnectionManagement.list_connections(ra_instance_id), else: []

    issuer_keys =
      case Repo.where(IssuerKey, fn k -> k.status == "active" and k.certificate_pem != nil end) do
        {:ok, list} -> list
        _ -> []
      end

    ca_name_by_id = ca_name_map()

    connected_key_ids = MapSet.new(connections, & &1.issuer_key_id)

    available_keys =
      issuer_keys
      |> Enum.reject(fn key -> MapSet.member?(connected_key_ids, key.id) end)
      |> Enum.map(&to_key_row(&1, ca_name_by_id))

    connection_rows = Enum.map(connections, &to_connection_row(&1, issuer_keys, ca_name_by_id))

    {:noreply,
     assign(socket,
       connections: connection_rows,
       available_keys: available_keys,
       ra_instance_id: ra_instance_id,
       loading: false,
       connecting_key_id: nil,
       disconnecting_id: nil
     )}
  end

  @impl true
  def handle_event("connect_key", %{"key-id" => key_id}, socket) do
    cond do
      get_role(socket) != "ra_admin" ->
        {:noreply, put_flash(socket, :error, "You don't have permission to manage CA connections.")}

      is_nil(socket.assigns.ra_instance_id) ->
        {:noreply, put_flash(socket, :error, "Create an RA instance first.")}

      true ->
        socket = assign(socket, connecting_key_id: key_id)

        case CaConnectionManagement.connect(socket.assigns.ra_instance_id, %{issuer_key_id: key_id}) do
          {:ok, _conn} ->
            send(self(), :load_data)
            {:noreply, put_flash(socket, :info, "Key connected successfully")}

          {:error, :already_connected} ->
            {:noreply,
             socket
             |> assign(connecting_key_id: nil)
             |> put_flash(:error, "Key is already connected to this RA instance.")}

          {:error, :issuer_key_not_found} ->
            {:noreply,
             socket
             |> assign(connecting_key_id: nil)
             |> put_flash(:error, "Issuer key not found.")}

          {:error, reason} ->
            Logger.error("[ca_connection] connect failed: #{inspect(reason)}")

            {:noreply,
             socket
             |> assign(connecting_key_id: nil)
             |> put_flash(:error, "Failed to connect key.")}
        end
    end
  end

  def handle_event("disconnect_key", %{"id" => id}, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "You don't have permission to manage CA connections.")}
    else
      socket = assign(socket, disconnecting_id: id)

      case CaConnectionManagement.disconnect(id) do
        {:ok, _conn} ->
          send(self(), :load_data)
          {:noreply, put_flash(socket, :info, "Key disconnected successfully")}

        {:error, :not_found} ->
          {:noreply,
           socket
           |> assign(disconnecting_id: nil)
           |> put_flash(:error, "Connection not found.")}

        {:error, reason} ->
          Logger.error("[ca_connection] disconnect failed: #{inspect(reason)}")

          {:noreply,
           socket
           |> assign(disconnecting_id: nil)
           |> put_flash(:error, "Failed to disconnect key.")}
      end
    end
  end

  # --- Private helpers ---

  defp get_role(socket) do
    user = socket.assigns[:current_user] || %{}
    user[:role] || user["role"]
  end

  defp ca_name_map do
    case Repo.all(CaInstance) do
      {:ok, list} -> Map.new(list, fn ca -> {ca.id, ca.name} end)
      _ -> %{}
    end
  end

  defp to_key_row(key, ca_name_by_id) do
    %{
      id: key.id,
      name: key.key_alias,
      algorithm: key.algorithm,
      ca_instance_id: key.ca_instance_id,
      ca_instance_name: Map.get(ca_name_by_id, key.ca_instance_id, "-")
    }
  end

  defp to_connection_row(conn, issuer_keys, ca_name_by_id) do
    key = Enum.find(issuer_keys, &(&1.id == conn.issuer_key_id))

    %{
      id: conn.id,
      issuer_key_id: conn.issuer_key_id,
      issuer_key_name: key && key.key_alias,
      algorithm: key && key.algorithm,
      ca_instance_name: Map.get(ca_name_by_id, conn.ca_instance_id, "-"),
      connected_at: conn.inserted_at
    }
  end

  defp algorithm_badge_class(algorithm) do
    cond do
      algorithm in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] -> "badge-primary"
      algorithm in ["KAZ-SIGN"] -> "badge-secondary"
      String.starts_with?(to_string(algorithm || ""), "RSA") -> "badge-warning"
      String.starts_with?(to_string(algorithm || ""), "EC") -> "badge-info"
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

      <%!-- No RA instance warning --%>
      <div
        :if={not @loading and is_nil(@ra_instance_id)}
        class="alert alert-warning text-sm"
      >
        <.icon name="hero-exclamation-triangle" class="size-5" />
        <span>No RA instance configured. Create one in <a href="/ra-instances" class="link">RA Instances</a> first.</span>
      </div>

      <%!-- Loading state --%>
      <div :if={@loading} class="flex items-center justify-center py-12">
        <span class="loading loading-spinner loading-md text-primary"></span>
        <span class="ml-2 text-sm text-base-content/60">Loading CA connections…</span>
      </div>

      <div :if={not @loading and @ra_instance_id} class="space-y-6">
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
                    <td class="text-xs text-base-content/50">
                      <.local_time dt={conn.connected_at} />
                    </td>
                    <td class="text-right">
                      <button
                        :if={@current_user[:role] == "ra_admin"}
                        class="btn btn-ghost btn-xs text-error"
                        phx-click="disconnect_key"
                        phx-value-id={conn.id}
                        disabled={@disconnecting_id == conn.id}
                        data-confirm="Disconnect this issuer key? The RA will no longer be able to use it for new certificate issuance."
                      >
                        <span
                          :if={@disconnecting_id == conn.id}
                          class="loading loading-spinner loading-xs"
                        />
                        <.icon
                          :if={@disconnecting_id != conn.id}
                          name="hero-x-mark"
                          class="size-3"
                        />
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
              id={"avail-key-#{key.id}"}
              class="card bg-base-100 shadow-sm border border-base-300 hover:border-primary/30 transition-colors"
            >
              <div class="card-body p-4 space-y-3">
                <div class="flex items-start justify-between">
                  <div class="flex items-center gap-2">
                    <div class="flex items-center justify-center w-7 h-7 rounded-md bg-primary/10">
                      <.icon name="hero-key" class="size-3.5 text-primary" />
                    </div>
                    <div>
                      <p class="text-sm font-medium text-base-content">{key.name || "-"}</p>
                    </div>
                  </div>
                  <span class={"badge badge-xs #{algorithm_badge_class(key.algorithm)}"}>
                    {key.algorithm || "-"}
                  </span>
                </div>

                <div class="text-xs text-base-content/50">CA: {key.ca_instance_name || "-"}</div>

                <button
                  :if={@current_user[:role] == "ra_admin"}
                  class="btn btn-primary btn-xs btn-block"
                  phx-click="connect_key"
                  phx-value-key-id={key.id}
                  disabled={@connecting_key_id == key.id}
                >
                  <span
                    :if={@connecting_key_id == key.id}
                    class="loading loading-spinner loading-xs"
                  />
                  <.icon :if={@connecting_key_id != key.id} name="hero-plus" class="size-3" />
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
