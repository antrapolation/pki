defmodule PkiCaPortalWeb.KeystoresLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    ca_id = socket.assigns.current_user["ca_instance_id"] || 1
    {:ok, keystores} = CaEngineClient.list_keystores(ca_id)

    {:ok,
     assign(socket,
       page_title: "Keystores",
       keystores: keystores
     )}
  end

  @impl true
  def handle_event("configure_keystore", %{"type" => type}, socket) do
    ca_id = socket.assigns.current_user["ca_instance_id"] || 1

    case CaEngineClient.configure_keystore(ca_id, %{type: type}) do
      {:ok, keystore} ->
        keystores = socket.assigns.keystores ++ [keystore]

        {:noreply,
         socket
         |> assign(keystores: keystores)
         |> put_flash(:info, "Keystore configured successfully")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to configure keystore: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="keystores-page">
      <h1>Keystore Management</h1>

      <section id="keystore-table">
        <table>
          <thead>
            <tr>
              <th>Type</th>
              <th>Provider</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody id="keystore-list">
            <tr :for={ks <- @keystores} id={"keystore-#{ks.id}"}>
              <td>{ks.type}</td>
              <td>{Map.get(ks, :provider_name, "-")}</td>
              <td>{ks.status}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="configure-keystore-form">
        <h2>Configure Keystore</h2>
        <form phx-submit="configure_keystore">
          <div>
            <label for="type">Type:</label>
            <select name="type" id="keystore-type">
              <option value="software">Software</option>
              <option value="hsm">HSM</option>
            </select>
          </div>
          <button type="submit">Configure</button>
        </form>
      </section>
    </div>
    """
  end
end
