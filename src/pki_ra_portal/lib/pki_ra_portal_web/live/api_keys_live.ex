defmodule PkiRaPortalWeb.ApiKeysLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, keys} = RaEngineClient.list_api_keys()

    {:ok,
     assign(socket,
       page_title: "API Keys",
       api_keys: keys,
       new_raw_key: nil
     )}
  end

  @impl true
  def handle_event("create_api_key", %{"name" => name}, socket) do
    case RaEngineClient.create_api_key(%{name: name}) do
      {:ok, key} ->
        keys = socket.assigns.api_keys ++ [Map.drop(key, [:raw_key])]

        {:noreply,
         socket
         |> assign(api_keys: keys, new_raw_key: key.raw_key)
         |> put_flash(:info, "API key created. Copy the key now - it will not be shown again.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to create API key: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("dismiss_raw_key", _params, socket) do
    {:noreply, assign(socket, new_raw_key: nil)}
  end

  @impl true
  def handle_event("revoke_api_key", %{"id" => id}, socket) do
    key_id = String.to_integer(id)

    case RaEngineClient.revoke_api_key(key_id) do
      {:ok, _} ->
        keys =
          Enum.map(socket.assigns.api_keys, fn k ->
            if k.id == key_id, do: Map.put(k, :status, "revoked"), else: k
          end)

        {:noreply,
         socket
         |> assign(api_keys: keys)
         |> put_flash(:info, "API key revoked")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to revoke API key: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="api-keys-page">
      <h1>API Key Management</h1>

      <section :if={@new_raw_key} id="raw-key-display">
        <h2>New API Key Created</h2>
        <p>Copy this key now. It will not be shown again:</p>
        <code id="raw-key-value">{@new_raw_key}</code>
        <button phx-click="dismiss_raw_key">Dismiss</button>
      </section>

      <section id="api-key-table">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="api-key-list">
            <tr :for={key <- @api_keys} id={"api-key-#{key.id}"}>
              <td>{key.name}</td>
              <td>{key.prefix}</td>
              <td>{key.status}</td>
              <td>{Calendar.strftime(key.created_at, "%Y-%m-%d")}</td>
              <td>
                <button
                  :if={key.status == "active"}
                  phx-click="revoke_api_key"
                  phx-value-id={key.id}
                >
                  Revoke
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section id="create-api-key-form">
        <h2>Create API Key</h2>
        <form phx-submit="create_api_key">
          <div>
            <label for="api-key-name">Name:</label>
            <input type="text" name="name" id="api-key-name" required />
          </div>
          <button type="submit">Create Key</button>
        </form>
      </section>
    </div>
    """
  end
end
