defmodule PkiRaPortalWeb.ApiKeysLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    {:ok, keys} = RaEngineClient.list_api_keys()

    {:ok,
     socket
     |> assign(
       page_title: "API Keys",
       api_keys: keys,
       new_raw_key: nil,
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("create_api_key", %{"name" => name}, socket) do
    case RaEngineClient.create_api_key(%{name: name}) do
      {:ok, key} ->
        keys = [Map.drop(key, [:raw_key]) | socket.assigns.api_keys]

        {:noreply,
         socket
         |> assign(api_keys: keys, new_raw_key: key.raw_key)
         |> apply_pagination()
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
    case RaEngineClient.revoke_api_key(id) do
      {:ok, _} ->
        keys =
          Enum.map(socket.assigns.api_keys, fn k ->
            if k.id == id, do: Map.put(k, :status, "revoked"), else: k
          end)

        {:noreply,
         socket
         |> assign(api_keys: keys)
         |> apply_pagination()
         |> put_flash(:info, "API key revoked")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to revoke API key: #{inspect(reason)}")}
    end
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, socket |> assign(page: String.to_integer(page)) |> apply_pagination()}
  end

  defp apply_pagination(socket) do
    items = socket.assigns.api_keys
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_keys: paged, total_pages: total_pages, page: page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="api-keys-page" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">API Key Management</h1>

      <%!-- Raw Key Display --%>
      <section :if={@new_raw_key} id="raw-key-display" class="alert alert-success shadow-sm">
        <div class="flex flex-col gap-2 w-full">
          <div class="flex items-center justify-between">
            <h2 class="font-semibold text-sm">New API Key Created</h2>
            <button phx-click="dismiss_raw_key" class="btn btn-xs btn-ghost">
              Dismiss
            </button>
          </div>
          <p class="text-sm">Copy this key now. It will not be shown again:</p>
          <code id="raw-key-value" class="font-mono text-sm bg-black/10 rounded px-3 py-2 break-all select-all">
            {@new_raw_key}
          </code>
        </div>
      </section>

      <%!-- API Keys Table --%>
      <section id="api-key-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="overflow-x-auto">
            <table class="table table-sm">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider">Name</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Prefix</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Created</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody id="api-key-list">
                <tr :for={key <- @paged_keys} id={"api-key-#{key.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium">{key.name}</td>
                  <td class="font-mono text-xs">{key.prefix}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      key.status == "active" && "badge-success",
                      key.status == "revoked" && "badge-error"
                    ]}>
                      {key.status}
                    </span>
                  </td>
                  <td class="text-xs text-base-content/60">{Calendar.strftime(key.created_at, "%Y-%m-%d")}</td>
                  <td>
                    <button
                      :if={key.status == "active"}
                      phx-click="revoke_api_key"
                      phx-value-id={key.id}
                      class="btn btn-xs btn-error btn-outline"
                    >
                      Revoke
                    </button>
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

      <%!-- Create API Key Form --%>
      <section id="create-api-key-form" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Create API Key</h2>
          <form phx-submit="create_api_key" class="flex items-end gap-4 mt-2">
            <div class="flex-1">
              <label for="api-key-name" class="label text-xs font-medium">Name</label>
              <input type="text" name="name" id="api-key-name" required class="input input-sm input-bordered w-full" />
            </div>
            <button type="submit" class="btn btn-sm btn-primary">Create Key</button>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
