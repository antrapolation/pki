defmodule PkiRaPortalWeb.ApiKeysLive do
  use PkiRaPortalWeb, :live_view

  require Logger

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     socket
     |> assign(
       page_title: "API Keys",
       api_keys: [],
       ra_instances: [],
       loading: true,
       selected_ra_instance_id: "",
       new_raw_key: nil,
       page: 1,
       per_page: 50
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    keys = case RaEngineClient.list_api_keys([], opts) do
      {:ok, k} -> k
      {:error, _} -> []
    end

    ra_instances =
      case RaEngineClient.list_ra_instances(opts) do
        {:ok, instances} -> instances
        {:error, _} -> []
      end

    {:noreply,
     socket
     |> assign(
       api_keys: Enum.map(keys, &normalize_key/1),
       ra_instances: ra_instances,
       loading: false
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_event("filter_ra_instance", %{"ra_instance_id" => ra_instance_id}, socket) do
    filters = if ra_instance_id == "", do: [], else: [ra_instance_id: ra_instance_id]
    keys = case RaEngineClient.list_api_keys(filters, tenant_opts(socket)) do
      {:ok, k} -> k
      {:error, _} -> []
    end

    {:noreply,
     socket
     |> assign(api_keys: Enum.map(keys, &normalize_key/1), selected_ra_instance_id: ra_instance_id, page: 1)
     |> apply_pagination()}
  end

  @impl true
  def handle_event("create_api_key", %{"name" => name}, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      user_id = get_in(socket.assigns, [:current_user, "id"]) ||
                get_in(socket.assigns, [:current_user, :id])

      case RaEngineClient.create_api_key(%{name: name, ra_user_id: user_id}, tenant_opts(socket)) do
        {:ok, key} ->
          normalized = normalize_key(key)
          keys = [Map.drop(normalized, [:raw_key]) | socket.assigns.api_keys]

          {:noreply,
           socket
           |> assign(api_keys: keys, new_raw_key: key[:raw_key] || key["raw_key"])
           |> apply_pagination()
           |> put_flash(:info, "API key created. Copy the key now - it will not be shown again.")}

        {:error, reason} ->
          Logger.error("[api_keys] Failed to create API key: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to create API key", reason))}
      end
    end
  end

  @impl true
  def handle_event("dismiss_raw_key", _params, socket) do
    {:noreply, assign(socket, new_raw_key: nil)}
  end

  @impl true
  def handle_event("revoke_api_key", %{"id" => id}, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      case RaEngineClient.revoke_api_key(id, tenant_opts(socket)) do
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
          Logger.error("[api_keys] Failed to revoke API key: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to revoke API key", reason))}
      end
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

  defp normalize_key(key) do
    name = key[:name] || key[:label] || key["name"] || key["label"] || ""
    created_at = key[:created_at] || key[:inserted_at] || key["created_at"] || key["inserted_at"]
    prefix = key[:prefix] || key["prefix"] || String.slice(name, 0, 8)
    Map.merge(key, %{name: name, created_at: format_date(created_at), prefix: prefix})
  end

  defp format_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
  defp format_date(%NaiveDateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
  defp format_date(s) when is_binary(s), do: String.slice(s, 0, 10)
  defp format_date(_), do: ""

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

      <%!-- RA Instance Filter --%>
      <div class="flex items-center gap-3">
        <label for="ra-instance-filter" class="text-xs font-medium text-base-content/60">Filter by RA Instance</label>
        <form phx-change="filter_ra_instance">
          <select name="ra_instance_id" id="ra-instance-filter" class="select select-bordered select-sm">
            <option value="">All</option>
            <option
              :for={inst <- @ra_instances}
              value={inst.id}
              selected={@selected_ra_instance_id == inst.id}
            >
              {inst.name}
            </option>
          </select>
        </form>
      </div>

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
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider w-[30%]">Name</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[22%]">Prefix</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[13%]">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[18%]">Created</th>
                  <th class="font-semibold text-xs uppercase tracking-wider w-[17%]">Actions</th>
                </tr>
              </thead>
              <tbody id="api-key-list">
                <tr :for={key <- @paged_keys} id={"api-key-#{key.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">{key.name}</td>
                  <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">{key.prefix}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      key.status == "active" && "badge-success",
                      key.status == "revoked" && "badge-error"
                    ]}>
                      {key.status}
                    </span>
                  </td>
                  <td class="text-xs text-base-content/60">{key.created_at}</td>
                  <td>
                    <button
                      :if={key.status == "active"}
                      phx-click="revoke_api_key"
                      phx-value-id={key.id}
                      title="Revoke"
                      class="btn btn-ghost btn-xs text-rose-400"
                    >
                      <.icon name="hero-no-symbol" class="size-4" />
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
