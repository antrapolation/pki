defmodule PkiCaPortalWeb.DashboardLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @setup_steps [
    %{key: :has_users, label: "Invite Team Members", desc: "Add key managers and auditors to participate in ceremonies", icon: "hero-users", href: "/users", required: false},
    %{key: :has_hsm, label: "Configure HSM Devices", desc: "Register hardware security modules for key storage", icon: "hero-cpu-chip", href: "/hsm-devices", required: false},
    %{key: :has_keystores, label: "Create Keystores", desc: "Set up software or HSM-backed keystores for key material", icon: "hero-key", href: "/keystores", required: true},
    %{key: :has_ceremony, label: "Run Key Ceremony", desc: "Generate root or sub-CA keys with threshold secret sharing", icon: "hero-shield-check", href: "/ceremony", required: true},
    %{key: :has_active_keys, label: "Activate Issuer Keys", desc: "Activate generated keys so they can sign certificates", icon: "hero-finger-print", href: "/issuer-keys", required: true}
  ]

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Dashboard",
       engine_status: %{status: "unknown", uptime_seconds: 0, active_keys: 0},
       active_keys: [],
       recent_ceremonies: [],
       loading: true,
       load_retries: 0,
       page: 1,
       per_page: 10,
       setup_steps: @setup_steps,
       setup_status: %{},
       setup_dismissed: false
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)
    ca_id = socket.assigns.current_user[:ca_instance_id]

    {status, keys, ceremonies, keystores, users} =
      if ca_id do
        status = safe_call(fn -> CaEngineClient.get_engine_status(ca_id, opts) end,
          %{status: "unknown", uptime_seconds: 0, active_keys: 0})
        keys = safe_call(fn -> CaEngineClient.list_issuer_keys(ca_id, opts) end, [])
        ceremonies = safe_call(fn -> CaEngineClient.list_ceremonies(ca_id, opts) end, [])
        keystores = safe_call(fn -> CaEngineClient.list_keystores(ca_id, opts) end, [])
        users = safe_call(fn -> CaEngineClient.list_portal_users(opts) end, [])
        {status, keys, ceremonies, keystores, users}
      else
        {%{status: "no CA instance", uptime_seconds: 0, active_keys: 0}, [], [], [], []}
      end

    non_admin_users = Enum.filter(users, fn u -> (u[:role] || u.role) != "ca_admin" end)
    hsm_keystores = Enum.filter(keystores, fn k -> k[:type] == "hsm" end)
    active_keys = Enum.filter(keys, fn k -> k[:status] == "active" end)
    completed_ceremonies = Enum.filter(ceremonies, fn c -> c[:status] == "completed" end)

    setup_status = %{
      has_users: non_admin_users != [],
      has_hsm: hsm_keystores != [],
      has_keystores: keystores != [],
      has_ceremony: completed_ceremonies != [],
      has_active_keys: active_keys != []
    }

    retries = socket.assigns[:load_retries] || 0
    all_empty = keys == [] && ceremonies == [] && keystores == [] && status.status == "unknown"

    socket =
      if all_empty && ca_id && retries < 3 do
        Process.send_after(self(), :load_data, 2_000)
        assign(socket, load_retries: retries + 1)
      else
        assign(socket,
          engine_status: status,
          active_keys: keys,
          recent_ceremonies: ceremonies,
          setup_status: setup_status,
          loading: false,
          load_retries: 0
        )
      end

    {:noreply, socket}
  end

  defp safe_call(fun, fallback) do
    PkiCaPortalWeb.SafeEngine.safe_call(fun, fallback)
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: parse_int(page) || 1)}
  end

  def handle_event("dismiss_setup", _params, socket) do
    {:noreply, assign(socket, setup_dismissed: true)}
  end

  defp parse_int(val) when is_integer(val), do: val
  defp parse_int(val) when is_binary(val) do
    case Integer.parse(val) do
      {n, _} -> n
      :error -> nil
    end
  end
  defp parse_int(_), do: nil

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp all_setup_done?(status) do
    status[:has_keystores] && status[:has_ceremony] && status[:has_active_keys] &&
      status[:has_users] && status[:has_hsm]
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard" class="space-y-6">
      <%!-- Stat cards row --%>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div id="status-card" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-signal" class="size-5 text-success" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Engine Status</p>
                <p class="text-xl font-bold">
                  <span id="engine-status">{@engine_status.status}</span>
                </p>
              </div>
            </div>
            <p class="text-xs text-base-content/40 mt-2">Uptime: {@engine_status.uptime_seconds}s</p>
          </div>
        </div>

        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-key" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Active Keys</p>
                <p class="text-xl font-bold">
                  <span id="active-key-count">{@engine_status.active_keys}</span>
                </p>
              </div>
            </div>
          </div>
        </div>

        <div id="key-summary" class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
                <.icon name="hero-circle-stack" class="size-5 text-info" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Total Keys</p>
                <p class="text-xl font-bold">
                  <span id="key-count">{length(@active_keys)}</span>
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Setup Guide — shown to ca_admin until required steps are done --%>
      <div
        :if={@current_user[:role] == "ca_admin" && !@setup_dismissed && !all_setup_done?(@setup_status)}
        class="card bg-base-100 shadow-sm border border-primary/20"
      >
        <div class="card-body p-5">
          <div class="flex items-center justify-between mb-4">
            <div class="flex items-center gap-2">
              <.icon name="hero-rocket-launch" class="size-5 text-primary" />
              <h2 class="text-sm font-semibold text-base-content">Setup Guide</h2>
              <span class="badge badge-sm badge-primary badge-outline">
                {Enum.count(@setup_steps, fn s -> @setup_status[s.key] end)}/{length(@setup_steps)}
              </span>
            </div>
            <button phx-click="dismiss_setup" class="btn btn-ghost btn-xs text-base-content/40">
              <.icon name="hero-x-mark" class="size-4" /> Dismiss
            </button>
          </div>

          <div class="space-y-2">
            <div :for={step <- @setup_steps} class="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-base-300 transition-colors hover:border-primary/30">
              <div class={[
                "flex items-center justify-center w-8 h-8 rounded-full shrink-0",
                if(@setup_status[step.key], do: "bg-success/10", else: "bg-base-200")
              ]}>
                <.icon
                  :if={@setup_status[step.key]}
                  name="hero-check"
                  class="size-4 text-success"
                />
                <.icon
                  :if={!@setup_status[step.key]}
                  name={step.icon}
                  class="size-4 text-base-content/40"
                />
              </div>
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                  <span class={["text-sm font-medium", if(@setup_status[step.key], do: "text-base-content/40 line-through", else: "text-base-content")]}>
                    {step.label}
                  </span>
                  <span :if={step.required} class="badge badge-xs badge-warning">required</span>
                  <span :if={!step.required} class="badge badge-xs badge-ghost">optional</span>
                </div>
                <p class="text-xs text-base-content/50 truncate">{step.desc}</p>
              </div>
              <a :if={!@setup_status[step.key]} href={step.href} class="btn btn-primary btn-xs btn-outline shrink-0">
                Set up
              </a>
              <span :if={@setup_status[step.key]} class="text-xs text-success font-medium shrink-0">Done</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Recent Ceremonies --%>
      <% paginated_ceremonies = @recent_ceremonies |> Enum.drop((@page - 1) * @per_page) |> Enum.take(@per_page) %>
      <% total_ceremonies = length(@recent_ceremonies) %>
      <% total_pages = max(ceil(total_ceremonies / @per_page), 1) %>
      <% start_idx = min((@page - 1) * @per_page + 1, total_ceremonies) %>
      <% end_idx = min(@page * @per_page, total_ceremonies) %>
      <div id="recent-ceremonies" class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300">
            <h2 class="text-sm font-semibold text-base-content">Recent Ceremonies</h2>
          </div>
          <div>
            <table class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[25%]">ID</th>
                  <th class="w-[22%]">Type</th>
                  <th class="w-[22%]">Status</th>
                  <th class="w-[31%]">Algorithm</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={ceremony <- paginated_ceremonies} class="hover">
                  <td class="font-mono-data overflow-hidden text-ellipsis whitespace-nowrap">{ceremony.id}</td>
                  <td>{ceremony.ceremony_type}</td>
                  <td>
                    <span class="badge badge-sm badge-ghost">{ceremony.status}</span>
                  </td>
                  <td class="font-mono-data">{ceremony.algorithm}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={total_ceremonies > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {start_idx}–{end_idx} of {total_ceremonies}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>«</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= total_pages}>»</button>
            </div>
          </div>
        </div>
      </div>

      <%!-- Quick Actions --%>
      <% role = @current_user[:role] %>
      <div id="quick-actions">
        <h2 class="text-sm font-semibold text-base-content mb-3">Quick Actions</h2>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <a :if={role in ["ca_admin", "key_manager"]} href="/ceremony" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-shield-check" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Initiate Ceremony</span>
            </div>
          </a>
          <a :if={role == "ca_admin"} href="/users" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-users" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage Users</span>
            </div>
          </a>
          <a :if={role in ["ca_admin", "key_manager"]} href="/keystores" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-key" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">Manage Keystores</span>
            </div>
          </a>
          <a :if={role in ["ca_admin", "auditor"]} href="/audit-log" class="card bg-base-100 border border-base-300 hover:border-primary/40 transition-colors cursor-pointer">
            <div class="card-body items-center p-4 text-center">
              <.icon name="hero-document-text" class="size-6 text-primary mb-1" />
              <span class="text-sm font-medium">View Audit Log</span>
            </div>
          </a>
        </div>
      </div>
    </div>
    """
  end
end
