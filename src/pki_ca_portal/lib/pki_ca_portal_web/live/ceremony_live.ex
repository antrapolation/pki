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
       ceremony_result: nil
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
  def render(assigns) do
    ~H"""
    <div id="ceremony-page">
      <h1>Key Ceremony</h1>

      <section :if={@ceremony_result} id="ceremony-status">
        <h2>Ceremony Status</h2>
        <p>ID: {@ceremony_result.id}</p>
        <p>Status: <span id="ceremony-state">{@ceremony_result.status}</span></p>
        <p>Algorithm: {@ceremony_result.algorithm}</p>
      </section>

      <section id="ceremony-table">
        <h2>Past Ceremonies</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Type</th>
              <th>Status</th>
              <th>Algorithm</th>
            </tr>
          </thead>
          <tbody id="ceremony-list">
            <tr :for={c <- @ceremonies} id={"ceremony-#{c.id}"}>
              <td>{c.id}</td>
              <td>{c.ceremony_type}</td>
              <td>{c.status}</td>
              <td>{c.algorithm}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="initiate-ceremony-form">
        <h2>Initiate Ceremony</h2>
        <form phx-submit="initiate_ceremony">
          <div>
            <label for="algorithm">Algorithm:</label>
            <select name="algorithm" id="ceremony-algorithm">
              <option value="KAZ-SIGN-256">KAZ-SIGN-256</option>
              <option value="ML-DSA-65">ML-DSA-65</option>
              <option value="RSA-4096">RSA-4096</option>
              <option value="ECC-P256">ECC-P256</option>
            </select>
          </div>
          <div>
            <label for="keystore_id">Keystore:</label>
            <select name="keystore_id" id="ceremony-keystore">
              <option :for={ks <- @keystores} value={ks.id}>{ks.type} - {ks.provider_name}</option>
            </select>
          </div>
          <div>
            <label for="threshold_k">Threshold K:</label>
            <input type="number" name="threshold_k" id="ceremony-k" min="1" value="2" />
          </div>
          <div>
            <label for="threshold_n">Threshold N:</label>
            <input type="number" name="threshold_n" id="ceremony-n" min="1" value="3" />
          </div>
          <div>
            <label for="domain_info">Domain Info:</label>
            <textarea name="domain_info" id="ceremony-domain-info"></textarea>
          </div>
          <button type="submit">Initiate Ceremony</button>
        </form>
      </section>
    </div>
    """
  end
end
