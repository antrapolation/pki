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
       ra_users: [],
       cert_profiles: [],
       loading: true,
       selected_ra_instance_id: "",
       new_raw_key: nil,
       new_webhook_secret: nil,
       show_create_form: false,
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

    ra_users =
      case RaEngineClient.list_portal_users(opts) do
        {:ok, users} -> Enum.filter(users, fn u -> (u[:status] || u["status"]) == "active" end)
        {:error, _} -> []
      end

    cert_profiles =
      case RaEngineClient.list_cert_profiles(opts) do
        {:ok, p} -> Enum.filter(p, fn p -> (p[:status] || "active") == "active" end)
        {:error, _} -> []
      end

    {:noreply,
     socket
     |> assign(
       api_keys: Enum.map(keys, &normalize_key/1),
       ra_instances: ra_instances,
       ra_users: ra_users,
       cert_profiles: cert_profiles,
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
  def handle_event("show_create_form", _params, socket) do
    {:noreply, assign(socket, show_create_form: true)}
  end

  @impl true
  def handle_event("cancel_create", _params, socket) do
    {:noreply, assign(socket, show_create_form: false)}
  end

  @impl true
  def handle_event("create_api_key", params, socket) do
    if get_role(socket) != "ra_admin" do
      {:noreply, put_flash(socket, :error, "Unauthorized")}
    else
      # Parse IP whitelist from textarea (one CIDR per line)
      ip_whitelist =
        (params["ip_whitelist"] || "")
        |> String.split("\n")
        |> Enum.map(&String.trim/1)
        |> Enum.reject(&(&1 == ""))

      # Parse allowed profile IDs from checkboxes (single checkbox submits as string, not list)
      allowed_profile_ids =
        case params["allowed_profile_ids"] do
          nil -> []
          list when is_list(list) -> list
          str when is_binary(str) -> [str]
        end

      attrs = %{
        label: params["label"],
        key_type: params["key_type"] || "client",
        ra_user_id: params["ra_user_id"],
        expiry: parse_expiry(params["expiry"]),
        rate_limit: parse_int(params["rate_limit"], 60),
        allowed_profile_ids: allowed_profile_ids,
        ip_whitelist: ip_whitelist,
        webhook_url: blank_to_nil(params["webhook_url"])
      }

      case RaEngineClient.create_api_key(attrs, tenant_opts(socket)) do
        {:ok, key} ->
          normalized = normalize_key(key)
          keys = [Map.drop(normalized, [:raw_key]) | socket.assigns.api_keys]

          {:noreply,
           socket
           |> assign(
             api_keys: keys,
             new_raw_key: key[:raw_key] || key["raw_key"],
             new_webhook_secret: key[:webhook_secret] || key["webhook_secret"],
             show_create_form: false
           )
           |> apply_pagination()
           |> put_flash(:info, "API key created. Copy credentials now — they will not be shown again.")}

        {:error, reason} ->
          Logger.error("[api_keys] Failed to create API key: #{inspect(reason)}")
          {:noreply, put_flash(socket, :error, PkiRaPortalWeb.ErrorHelpers.sanitize_error("Failed to create API key", reason))}
      end
    end
  end

  @impl true
  def handle_event("dismiss_raw_key", _params, socket) do
    {:noreply, assign(socket, new_raw_key: nil, new_webhook_secret: nil)}
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

  # ── Helpers ──────────────────────────────────────────────────────────

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp normalize_key(key) do
    id = key[:id] || key["id"]
    status = key[:status] || key["status"] || "active"
    name = key[:name] || key[:label] || key["name"] || key["label"] || ""
    created_at = key[:created_at] || key[:inserted_at] || key["created_at"] || key["inserted_at"]
    prefix = key[:prefix] || key["prefix"] || String.slice(name, 0, 8)
    key_type = key[:key_type] || key["key_type"] || "client"
    ra_user_id = key[:ra_user_id] || key["ra_user_id"]
    rate_limit = key[:rate_limit] || key["rate_limit"] || 60
    expiry = key[:expiry] || key["expiry"]
    allowed_profile_ids = key[:allowed_profile_ids] || key["allowed_profile_ids"] || []

    Map.merge(key, %{
      id: id, status: status, name: name, created_at: created_at, prefix: prefix,
      key_type: key_type, ra_user_id: ra_user_id, rate_limit: rate_limit,
      expiry: expiry, allowed_profile_ids: allowed_profile_ids
    })
  end

  defp parse_int(val, default) when is_binary(val) do
    case Integer.parse(val) do
      {int, _} -> int
      :error -> default
    end
  end
  defp parse_int(_, default), do: default

  defp parse_expiry(nil), do: nil
  defp parse_expiry(""), do: nil
  defp parse_expiry(date_str) when is_binary(date_str) do
    normalized = if String.length(date_str) == 10, do: date_str <> "T23:59:59Z", else: date_str

    case DateTime.from_iso8601(normalized) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp blank_to_nil(nil), do: nil
  defp blank_to_nil(""), do: nil
  defp blank_to_nil(val), do: val

  defp expiry_warning?(key) do
    expiry = key[:expiry] || key["expiry"]
    if expiry do
      case DateTime.from_iso8601(to_string(expiry)) do
        {:ok, dt, _} -> DateTime.diff(dt, DateTime.utc_now(), :day) < 30
        _ -> false
      end
    else
      false
    end
  end

  defp format_expiry(key) do
    expiry = key[:expiry] || key["expiry"]
    if expiry, do: String.slice(to_string(expiry), 0, 10), else: "Never"
  end

  defp profile_count(key) do
    ids = key[:allowed_profile_ids] || key["allowed_profile_ids"] || []
    if ids == [], do: "All", else: "#{length(ids)}"
  end

  defp user_display_name(user_id, users) do
    case Enum.find(users, fn u -> u.id == user_id || u[:id] == user_id end) do
      nil -> "-"
      u -> u[:display_name] || u[:username] || u["display_name"] || "-"
    end
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
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold tracking-tight">API Key Management</h1>
        <button :if={!@show_create_form} phx-click="show_create_form" class="btn btn-sm btn-primary">
          <.icon name="hero-plus" class="size-4 mr-1" /> Create Key
        </button>
      </div>

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

      <%!-- Credentials Display (one-time) --%>
      <section :if={@new_raw_key} id="raw-key-display" class="alert alert-success shadow-sm">
        <div class="flex flex-col gap-3 w-full">
          <div class="flex items-center justify-between">
            <h2 class="font-semibold text-sm">API Key Created</h2>
            <button phx-click="dismiss_raw_key" class="btn btn-xs btn-ghost">Dismiss</button>
          </div>
          <div>
            <p class="text-xs font-medium mb-1">API Key (copy now — shown once):</p>
            <code id="raw-key-value" class="font-mono text-sm bg-black/10 rounded px-3 py-2 break-all select-all block">
              {@new_raw_key}
            </code>
          </div>
          <div :if={@new_webhook_secret}>
            <p class="text-xs font-medium mb-1">Webhook Secret (for signature verification):</p>
            <code id="webhook-secret-value" class="font-mono text-sm bg-black/10 rounded px-3 py-2 break-all select-all block">
              {@new_webhook_secret}
            </code>
          </div>
        </div>
      </section>

      <%!-- API Keys Table --%>
      <section id="api-key-table" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="overflow-x-auto">
            <table class="table table-sm w-full">
              <thead>
                <tr class="border-base-300">
                  <th class="font-semibold text-xs uppercase tracking-wider">Label</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Type</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Owner</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Profiles</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Rate</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Expiry</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Status</th>
                  <th class="font-semibold text-xs uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody id="api-key-list">
                <tr :for={key <- @paged_keys} id={"api-key-#{key.id}"} class="hover:bg-base-200/50 border-base-300">
                  <td class="font-medium">{key.name}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      (key[:key_type] || "client") == "service" && "badge-info",
                      (key[:key_type] || "client") == "client" && "badge-ghost"
                    ]}>
                      {key[:key_type] || "client"}
                    </span>
                  </td>
                  <td class="text-xs">{user_display_name(key[:ra_user_id], @ra_users)}</td>
                  <td class="text-xs">{profile_count(key)}</td>
                  <td class="font-mono text-xs">{key[:rate_limit] || 60}/m</td>
                  <td class={["text-xs", expiry_warning?(key) && "text-warning font-semibold"]}>
                    {format_expiry(key)}
                  </td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      key.status == "active" && "badge-success",
                      key.status == "revoked" && "badge-error"
                    ]}>
                      {key.status}
                    </span>
                  </td>
                  <td>
                    <button
                      :if={key.status == "active"}
                      phx-click="revoke_api_key"
                      phx-value-id={key.id}
                      title="Revoke"
                      class="btn btn-ghost btn-xs text-rose-400"
                      data-confirm="Revoke this API key? This cannot be undone."
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
      <section :if={@show_create_form} id="create-api-key-form" class="card bg-base-100 shadow-sm border border-primary/30">
        <div class="card-body">
          <div class="flex items-center justify-between">
            <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">Create API Key</h2>
            <button phx-click="cancel_create" class="btn btn-ghost btn-xs">Cancel</button>
          </div>

          <form phx-submit="create_api_key" class="space-y-6 mt-4">
            <%!-- Section 1: Basic Info --%>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="api-key-label" class="label text-xs font-medium">Label <span class="text-error">*</span></label>
                <input type="text" name="label" id="api-key-label" required maxlength="100" class="input input-sm input-bordered w-full" />
              </div>
              <div>
                <label class="label text-xs font-medium">Key Type</label>
                <div class="flex gap-4 mt-1">
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name="key_type" value="client" checked class="radio radio-sm radio-primary" />
                    <div>
                      <span class="text-sm font-medium">Client</span>
                      <p class="text-xs text-base-content/50">Submit CSRs, view status</p>
                    </div>
                  </label>
                  <label class="flex items-center gap-2 cursor-pointer">
                    <input type="radio" name="key_type" value="service" class="radio radio-sm radio-primary" />
                    <div>
                      <span class="text-sm font-medium">Service</span>
                      <p class="text-xs text-base-content/50">Full API access + revoke</p>
                    </div>
                  </label>
                </div>
              </div>
              <div>
                <label for="api-key-user" class="label text-xs font-medium">Assign to User <span class="text-error">*</span></label>
                <select name="ra_user_id" id="api-key-user" required class="select select-sm select-bordered w-full">
                  <option value="">Select user</option>
                  <option :for={u <- @ra_users} value={u.id}>
                    {u[:display_name] || u[:username] || u["display_name"]}
                  </option>
                </select>
              </div>
              <div>
                <label for="api-key-expiry" class="label text-xs font-medium">Expiry Date <span class="text-error">*</span></label>
                <input type="date" name="expiry" id="api-key-expiry" required min={Date.to_iso8601(Date.add(Date.utc_today(), 1))} class="input input-sm input-bordered w-full" />
              </div>
            </div>

            <%!-- Section 2: Access Control --%>
            <div>
              <h3 class="text-xs font-semibold uppercase tracking-wide text-base-content/60 border-b border-base-300 pb-1">Access Control</h3>
              <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-3">
                <div>
                  <label class="label text-xs font-medium">Allowed Certificate Profiles</label>
                  <p class="text-xs text-base-content/50 mb-2">Leave unchecked to allow all profiles</p>
                  <div class="max-h-40 overflow-y-auto space-y-1 border border-base-300 rounded p-2">
                    <label :for={p <- @cert_profiles} class="flex items-center gap-2 cursor-pointer">
                      <input type="checkbox" name="allowed_profile_ids[]" value={p.id} class="checkbox checkbox-xs checkbox-primary" />
                      <span class="text-xs">{p.name}</span>
                    </label>
                    <p :if={@cert_profiles == []} class="text-xs text-base-content/40 italic">No profiles available</p>
                  </div>
                </div>
                <div class="space-y-3">
                  <div>
                    <label for="api-key-ip-whitelist" class="label text-xs font-medium">IP Whitelist</label>
                    <textarea name="ip_whitelist" id="api-key-ip-whitelist" rows="3" maxlength="1000"
                      placeholder="One CIDR per line, e.g.&#10;10.0.0.0/8&#10;192.168.1.0/24"
                      class="textarea textarea-bordered textarea-sm w-full font-mono text-xs"></textarea>
                    <p class="text-xs text-base-content/50 mt-0.5">Leave empty to allow all IPs</p>
                  </div>
                  <div>
                    <label for="api-key-rate-limit" class="label text-xs font-medium">Rate Limit (requests/min)</label>
                    <input type="number" name="rate_limit" id="api-key-rate-limit" value="60" min="1" max="10000" class="input input-sm input-bordered w-full" />
                  </div>
                </div>
              </div>
            </div>

            <%!-- Section 3: Webhook --%>
            <div class="collapse collapse-arrow bg-base-200/50 border border-base-300 rounded-lg">
              <input type="checkbox" />
              <div class="collapse-title text-xs font-semibold uppercase tracking-wide text-base-content/60">
                Webhook Configuration (optional)
              </div>
              <div class="collapse-content">
                <div class="pt-2">
                  <label for="api-key-webhook-url" class="label text-xs font-medium">Webhook URL</label>
                  <input type="url" name="webhook_url" id="api-key-webhook-url" maxlength="500"
                    placeholder="https://your-service.com/webhook"
                    pattern="https://.*"
                    class="input input-sm input-bordered w-full" />
                  <p class="text-xs text-base-content/50 mt-0.5">Must be HTTPS. A webhook secret will be auto-generated.</p>
                </div>
              </div>
            </div>

            <div class="flex justify-end">
              <button type="submit" class="btn btn-sm btn-primary">Create API Key</button>
            </div>
          </form>
        </div>
      </section>
    </div>
    """
  end
end
