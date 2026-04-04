defmodule PkiRaPortalWeb.DashboardLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)
    role = get_role(socket)

    {:ok,
     socket
     |> assign(
       page_title: "Dashboard",
       role: role,
       loading: true,
       # admin assigns
       ca_reachable: nil,
       connected_keys_count: 0,
       service_configs_count: 0,
       setup_steps: %{
         ca_connections: false,
         cert_profiles: false,
         portal_users: false,
         service_configs: false,
         api_keys: false
       },
       setup_dismissed: false,
       pending_csrs_count: 0,
       stuck_csrs_count: 0,
       recent_activity: [],
       # officer assigns
       queue_count: 0,
       recent_csrs: [],
       # auditor assigns
       audit_events: [],
       audit_pending_count: 0,
       audit_approved_count: 0,
       # pagination
       page: 1,
       per_page: 10
     )
     |> apply_pagination()}
  end

  @impl true
  def handle_info(:load_data, socket) do
    opts = tenant_opts(socket)

    socket =
      case socket.assigns.role do
        "ra_admin" -> load_admin_data(socket, opts)
        "ra_officer" -> load_officer_data(socket, opts)
        "auditor" -> load_auditor_data(socket, opts)
        _ -> socket
      end

    {:noreply, assign(socket, loading: false)}
  end

  @impl true
  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {p, ""} when p > 0 -> {:noreply, socket |> assign(page: p) |> apply_pagination()}
      _ -> {:noreply, socket}
    end
  end

  def handle_event("dismiss_setup", _params, socket) do
    {:noreply, assign(socket, setup_dismissed: true)}
  end

  # ---------------------------------------------------------------------------
  # Data loaders
  # ---------------------------------------------------------------------------

  defp load_admin_data(socket, opts) do
    # CA reachability
    ca_reachable =
      case RaEngineClient.available_issuer_keys(opts) do
        {:ok, _keys} -> true
        {:error, _} -> false
      end

    # CA connections
    ca_connections =
      case RaEngineClient.list_ca_connections([], opts) do
        {:ok, conns} -> conns
        {:error, _} -> []
      end

    # Cert profiles
    profiles =
      case RaEngineClient.list_cert_profiles(opts) do
        {:ok, p} -> p
        {:error, _} -> []
      end

    # Portal users
    portal_users =
      case RaEngineClient.list_portal_users(opts) do
        {:ok, u} -> u
        {:error, _} -> []
      end

    non_admin_users = Enum.filter(portal_users, fn u ->
      role = u[:role] || u["role"]
      role != "ra_admin"
    end)

    # Service configs
    service_configs =
      case RaEngineClient.list_service_configs(opts) do
        {:ok, sc} -> sc
        {:error, _} -> []
      end

    # API keys
    api_keys =
      case RaEngineClient.list_api_keys([], opts) do
        {:ok, ak} -> ak
        {:error, _} -> []
      end

    # CSRs
    csrs =
      case RaEngineClient.list_csrs([], opts) do
        {:ok, c} -> c
        {:error, _} -> []
      end

    pending_csrs = Enum.filter(csrs, &((&1.status || &1["status"]) == "verified"))
    stuck_csrs = Enum.filter(csrs, &((&1.status || &1["status"]) == "approved"))

    # Audit events
    audit_events =
      case RaEngineClient.list_audit_events([limit: 10], opts) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    setup_steps = %{
      ca_connections: length(ca_connections) > 0,
      cert_profiles: length(profiles) > 0,
      portal_users: length(non_admin_users) > 0,
      service_configs: length(service_configs) > 0,
      api_keys: length(api_keys) > 0
    }

    socket
    |> assign(
      ca_reachable: ca_reachable,
      connected_keys_count: length(ca_connections),
      service_configs_count: length(service_configs),
      setup_steps: setup_steps,
      pending_csrs_count: length(pending_csrs),
      stuck_csrs_count: length(stuck_csrs),
      recent_activity: audit_events
    )
    |> apply_pagination()
  end

  defp load_officer_data(socket, opts) do
    csrs =
      case RaEngineClient.list_csrs([], opts) do
        {:ok, c} -> c
        {:error, _} -> []
      end

    verified_csrs = Enum.filter(csrs, &((&1.status || &1["status"]) == "verified"))
    recent = Enum.take(csrs, 10)

    socket
    |> assign(
      queue_count: length(verified_csrs),
      recent_csrs: recent
    )
    |> apply_pagination()
  end

  defp load_auditor_data(socket, opts) do
    audit_events =
      case RaEngineClient.list_audit_events([limit: 20], opts) do
        {:ok, events} -> events
        {:error, _} -> []
      end

    csrs =
      case RaEngineClient.list_csrs([], opts) do
        {:ok, c} -> c
        {:error, _} -> []
      end

    pending_count = csrs |> Enum.filter(&((&1.status || &1["status"]) == "verified")) |> length()
    approved_count = csrs |> Enum.filter(&((&1.status || &1["status"]) == "approved")) |> length()

    assign(socket,
      audit_events: audit_events,
      audit_pending_count: pending_count,
      audit_approved_count: approved_count
    )
  end

  # ---------------------------------------------------------------------------
  # Pagination (for admin recent_activity and officer recent_csrs)
  # ---------------------------------------------------------------------------

  defp apply_pagination(socket) do
    items = pageable_items(socket)
    total = length(items)
    per_page = socket.assigns.per_page
    total_pages = max(ceil(total / per_page), 1)
    page = min(socket.assigns.page, total_pages)
    start_idx = (page - 1) * per_page
    paged = items |> Enum.drop(start_idx) |> Enum.take(per_page)

    assign(socket, paged_items: paged, total_pages: total_pages, page: page)
  end

  defp pageable_items(socket) do
    case socket.assigns.role do
      "ra_admin" -> socket.assigns.recent_activity
      "ra_officer" -> socket.assigns.recent_csrs
      _ -> []
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp get_role(socket) do
    user = socket.assigns[:current_user]
    user[:role] || user["role"]
  end

  defp setup_complete_count(steps) do
    steps |> Map.values() |> Enum.count(& &1)
  end

  defp required_setup_done?(steps) do
    steps.ca_connections && steps.cert_profiles
  end

  # ---------------------------------------------------------------------------
  # Render
  # ---------------------------------------------------------------------------

  @impl true
  def render(assigns) do
    ~H"""
    <div id="dashboard" class="space-y-6">
      <h1 class="text-2xl font-bold tracking-tight">Dashboard</h1>

      <%= if @loading do %>
        <div class="flex justify-center py-12">
          <span class="loading loading-spinner loading-lg"></span>
        </div>
      <% else %>
        <%= case @role do %>
          <% "ra_admin" -> %>
            <.admin_dashboard {assigns} />
          <% "ra_officer" -> %>
            <.officer_dashboard {assigns} />
          <% "auditor" -> %>
            <.auditor_dashboard {assigns} />
          <% _ -> %>
            <p class="text-base-content/50">Dashboard not available for this role.</p>
        <% end %>
      <% end %>
    </div>
    """
  end

  # ---------------------------------------------------------------------------
  # Admin Dashboard
  # ---------------------------------------------------------------------------

  defp admin_dashboard(assigns) do
    ~H"""
    <%!-- Row 1: System Health --%>
    <section class="grid grid-cols-1 md:grid-cols-3 gap-4">
      <h2 class="md:col-span-3 text-sm font-semibold uppercase tracking-wide text-base-content/60">
        System Health
      </h2>

      <%!-- CA Engine Status --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class={[
              "flex items-center justify-center w-10 h-10 rounded-lg",
              @ca_reachable && "bg-success/10",
              !@ca_reachable && "bg-error/10"
            ]}>
              <.icon
                name={if @ca_reachable, do: "hero-signal", else: "hero-signal-slash"}
                class={["size-6", @ca_reachable && "text-success", !@ca_reachable && "text-error"]}
              />
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">CA Engine</p>
              <p class="text-lg font-bold">
                <%= if @ca_reachable, do: "Connected", else: "Unreachable" %>
              </p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Connected Issuer Keys --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
              <.icon name="hero-key" class="size-6 text-primary" />
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">CA Connections</p>
              <p class="text-2xl font-bold">{@connected_keys_count}</p>
            </div>
          </div>
        </div>
      </div>

      <%!-- Validation Services --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-info/10">
              <.icon name="hero-cog-6-tooth" class="size-6 text-info" />
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Service Configs</p>
              <p class="text-2xl font-bold">{@service_configs_count}</p>
            </div>
          </div>
        </div>
      </div>
    </section>

    <%!-- Row 2: Setup Completeness (conditional) --%>
    <section
      :if={!@setup_dismissed && !required_setup_done?(@setup_steps)}
      class="card bg-base-100 shadow-sm border border-base-300"
    >
      <div class="card-body">
        <div class="flex items-center justify-between">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
            Setup: {setup_complete_count(@setup_steps)} of 5 complete
          </h2>
          <button phx-click="dismiss_setup" class="btn btn-ghost btn-xs">Dismiss</button>
        </div>
        <div class="mt-3 space-y-2">
          <.setup_item done={@setup_steps.ca_connections} label="CA Connections" href="/ca-connection" />
          <.setup_item done={@setup_steps.cert_profiles} label="Certificate Profiles" href="/cert-profiles" />
          <.setup_item done={@setup_steps.portal_users} label="Team Members (non-admin)" href="/users" />
          <.setup_item done={@setup_steps.service_configs} label="Service Configurations" href="/service-configs" />
          <.setup_item done={@setup_steps.api_keys} label="API Keys" href="/api-keys" />
        </div>
      </div>
    </section>

    <%!-- Row 3: Attention Required --%>
    <section
      :if={@pending_csrs_count > 0 || @stuck_csrs_count > 0}
      class="grid grid-cols-1 md:grid-cols-2 gap-4"
    >
      <h2 class="md:col-span-2 text-sm font-semibold uppercase tracking-wide text-base-content/60">
        Attention Required
      </h2>

      <div :if={@pending_csrs_count > 0} class="card bg-warning/5 shadow-sm border border-warning/30">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-warning/10">
              <.icon name="hero-document-check" class="size-6 text-warning" />
            </div>
            <div class="flex-1">
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Pending Review</p>
              <p class="text-2xl font-bold">{@pending_csrs_count} CSRs</p>
            </div>
            <a href="/csrs?status=verified" class="btn btn-warning btn-sm">Review</a>
          </div>
        </div>
      </div>

      <div :if={@stuck_csrs_count > 0} class="card bg-error/5 shadow-sm border border-error/30">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-error/10">
              <.icon name="hero-exclamation-triangle" class="size-6 text-error" />
            </div>
            <div class="flex-1">
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Stuck CSRs</p>
              <p class="text-2xl font-bold">{@stuck_csrs_count} approved, not issued</p>
            </div>
            <a href="/csrs?status=approved" class="btn btn-error btn-outline btn-sm">Investigate</a>
          </div>
        </div>
      </div>
    </section>

    <%!-- Row 4: Team Activity --%>
    <section class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
          Team Activity
        </h2>
        <.activity_table events={@paged_items} />
        <.pagination_controls page={@page} total_pages={@total_pages} />
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # Officer Dashboard
  # ---------------------------------------------------------------------------

  defp officer_dashboard(assigns) do
    ~H"""
    <%!-- Row 1: My Queue --%>
    <section class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
          My Queue
        </h2>
        <div class="flex items-center gap-6 mt-2">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-14 h-14 rounded-lg bg-warning/10">
              <.icon name="hero-document-check" class="size-8 text-warning" />
            </div>
            <div>
              <p class="text-3xl font-bold">{@queue_count}</p>
              <p class="text-sm text-base-content/60">CSRs awaiting review</p>
            </div>
          </div>
          <a href="/csrs?status=verified" class="btn btn-primary">Review CSRs</a>
        </div>
      </div>
    </section>

    <%!-- Row 2: Recent CSRs --%>
    <section class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
          Recent CSRs
        </h2>
        <div class="overflow-x-auto">
          <table class="table table-sm table-fixed w-full">
            <thead>
              <tr class="border-base-300">
                <th class="font-semibold text-xs uppercase tracking-wider w-[18%]">ID</th>
                <th class="font-semibold text-xs uppercase tracking-wider w-[35%]">Subject</th>
                <th class="font-semibold text-xs uppercase tracking-wider w-[30%]">Profile</th>
                <th class="font-semibold text-xs uppercase tracking-wider w-[17%]">Status</th>
              </tr>
            </thead>
            <tbody>
              <tr :if={@paged_items == []} class="border-base-300">
                <td colspan="4" class="text-center text-base-content/50 py-6">No recent CSRs</td>
              </tr>
              <tr :for={csr <- @paged_items} class="hover:bg-base-200/50 border-base-300">
                <td class="font-mono text-xs overflow-hidden text-ellipsis whitespace-nowrap">
                  {csr.id || csr["id"]}
                </td>
                <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                  {csr.subject || csr["subject"]}
                </td>
                <td class="overflow-hidden text-ellipsis whitespace-nowrap">
                  {csr.profile_name || csr["profile_name"]}
                </td>
                <td>
                  <span class={[
                    "badge badge-sm",
                    (csr.status || csr["status"]) == "pending" && "badge-warning",
                    (csr.status || csr["status"]) == "verified" && "badge-info",
                    (csr.status || csr["status"]) == "approved" && "badge-success",
                    (csr.status || csr["status"]) == "rejected" && "badge-error"
                  ]}>
                    {csr.status || csr["status"]}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <.pagination_controls page={@page} total_pages={@total_pages} />
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # Auditor Dashboard
  # ---------------------------------------------------------------------------

  defp auditor_dashboard(assigns) do
    ~H"""
    <%!-- Row 1: Recent Activity --%>
    <section class="card bg-base-100 shadow-sm border border-base-300">
      <div class="card-body">
        <div class="flex items-center justify-between">
          <h2 class="card-title text-sm font-semibold uppercase tracking-wide text-base-content/60">
            Recent Activity
          </h2>
          <a href="/audit-log" class="btn btn-ghost btn-sm">View full audit log</a>
        </div>
        <.activity_table events={@audit_events} />
      </div>
    </section>

    <%!-- Row 2: Compliance Overview --%>
    <section class="grid grid-cols-1 md:grid-cols-2 gap-4">
      <h2 class="md:col-span-2 text-sm font-semibold uppercase tracking-wide text-base-content/60">
        Compliance
      </h2>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-warning/10">
              <.icon name="hero-clock" class="size-6 text-warning" />
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Pending CSRs</p>
              <p class="text-2xl font-bold">{@audit_pending_count}</p>
            </div>
          </div>
        </div>
      </div>

      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <div class="flex items-center gap-3">
            <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
              <.icon name="hero-check-circle" class="size-6 text-success" />
            </div>
            <div>
              <p class="text-xs font-medium text-base-content/60 uppercase tracking-wide">Approved CSRs</p>
              <p class="text-2xl font-bold">{@audit_approved_count}</p>
            </div>
          </div>
        </div>
      </div>
    </section>
    """
  end

  # ---------------------------------------------------------------------------
  # Shared components
  # ---------------------------------------------------------------------------

  defp setup_item(assigns) do
    ~H"""
    <div class="flex items-center gap-2">
      <%= if @done do %>
        <.icon name="hero-check-circle-solid" class="size-5 text-success" />
        <span class="text-sm">{@label}</span>
      <% else %>
        <.icon name="hero-x-circle" class="size-5 text-base-content/30" />
        <a href={@href} class="text-sm link link-primary">{@label}</a>
      <% end %>
    </div>
    """
  end

  defp activity_table(assigns) do
    ~H"""
    <div class="overflow-x-auto">
      <table class="table table-sm w-full">
        <thead>
          <tr class="border-base-300">
            <th class="font-semibold text-xs uppercase tracking-wider w-[25%]">Timestamp</th>
            <th class="font-semibold text-xs uppercase tracking-wider w-[20%]">Actor</th>
            <th class="font-semibold text-xs uppercase tracking-wider w-[20%]">Action</th>
            <th class="font-semibold text-xs uppercase tracking-wider w-[35%]">Details</th>
          </tr>
        </thead>
        <tbody>
          <tr :if={@events == []} class="border-base-300">
            <td colspan="4" class="text-center text-base-content/50 py-6">No recent activity</td>
          </tr>
          <tr :for={event <- @events} class="hover:bg-base-200/50 border-base-300">
            <td class="text-xs text-base-content/70">{event[:timestamp] || event["timestamp"]}</td>
            <td class="text-sm">{event[:actor] || event["actor"] || event[:actor_username] || event["actor_username"]}</td>
            <td>
              <span class="badge badge-sm badge-ghost">{event[:action] || event["action"]}</span>
            </td>
            <td class="text-sm text-base-content/70 overflow-hidden text-ellipsis whitespace-nowrap">
              {event[:details] || event["details"] || event[:resource_type] || event["resource_type"]}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  defp pagination_controls(assigns) do
    ~H"""
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
    """
  end
end
