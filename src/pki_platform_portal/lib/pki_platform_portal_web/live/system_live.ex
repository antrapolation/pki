defmodule PkiPlatformPortalWeb.SystemLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.SystemHealth

  @poll_interval 30_000

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      start_health_check()
      Process.send_after(self(), :poll, @poll_interval)
    end

    # Load DB status synchronously (fast, local query)
    db_status =
      try do
        SystemHealth.check_database()
      rescue
        _ -> %{status: :unreachable}
      end

    db_count =
      try do
        SystemHealth.database_count()
      rescue
        _ -> 0
      end

    {:ok,
     assign(socket,
       page_title: "System",
       services: Enum.map(SystemHealth.services(), &Map.merge(&1, %{status: :checking, response_time_ms: 0, checked_at: nil})),
       db_status: db_status,
       db_count: db_count,
       loading: true
     )}
  end

  @impl true
  def handle_info({ref, results}, socket) when is_reference(ref) do
    Process.demonitor(ref, [:flush])
    {:noreply, assign(socket, services: results, loading: false)}
  end

  def handle_info({:DOWN, _ref, :process, _pid, _reason}, socket) do
    {:noreply, socket}
  end

  def handle_info(:poll, socket) do
    start_health_check()
    Process.send_after(self(), :poll, @poll_interval)
    {:noreply, socket}
  end

  @impl true
  def handle_event("refresh", _params, socket) do
    start_health_check()
    {:noreply, assign(socket, loading: true)}
  end

  defp start_health_check do
    Task.async(fn -> SystemHealth.check_all() end)
  end

  defp healthy_count(services) do
    Enum.count(services, &(&1.status == :healthy))
  end

  @impl true
  def render(assigns) do
    assigns = assign(assigns, :healthy_count, healthy_count(assigns.services))
    assigns = assign(assigns, :total_count, length(assigns.services))

    ~H"""
    <div id="system-page" class="space-y-6">
      <%!-- Header row --%>
      <div class="flex items-center justify-between">
        <h1 class="text-lg font-semibold text-base-content">System Health</h1>
        <button phx-click="refresh" class="btn btn-sm btn-outline gap-2">
          <.icon name="hero-arrow-path" class="size-4" />
          Refresh
        </button>
      </div>

      <%!-- Summary cards --%>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <%!-- Services summary --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class={[
                "flex items-center justify-center w-10 h-10 rounded-lg",
                @healthy_count == @total_count && "bg-success/10",
                @healthy_count < @total_count && "bg-error/10"
              ]}>
                <.icon
                  name="hero-server-stack"
                  class={[
                    "size-5",
                    @healthy_count == @total_count && "text-success",
                    @healthy_count < @total_count && "text-error"
                  ]}
                />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Services</p>
                <p class="text-xl font-bold">{@healthy_count}/{@total_count} healthy</p>
              </div>
            </div>
          </div>
        </div>

        <%!-- PostgreSQL summary --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class={[
                "flex items-center justify-center w-10 h-10 rounded-lg",
                @db_status[:status] == :healthy && "bg-success/10",
                @db_status[:status] != :healthy && "bg-error/10"
              ]}>
                <.icon
                  name="hero-circle-stack"
                  class={[
                    "size-5",
                    @db_status[:status] == :healthy && "text-success",
                    @db_status[:status] != :healthy && "text-error"
                  ]}
                />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">PostgreSQL</p>
                <p class="text-xl font-bold">
                  {if @db_status[:status] == :healthy, do: "Connected", else: "Down"}
                </p>
              </div>
            </div>
          </div>
        </div>

        <%!-- Databases summary --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10">
                <.icon name="hero-building-library" class="size-5 text-primary" />
              </div>
              <div>
                <p class="text-xs font-medium text-base-content/50 uppercase tracking-wider">Databases</p>
                <p class="text-xl font-bold">{@db_count}</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      <%!-- Individual service cards --%>
      <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div :for={service <- @services} class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-start justify-between gap-2">
              <div class="flex items-center gap-3 min-w-0">
                <div class={[
                  "flex items-center justify-center w-9 h-9 rounded-lg shrink-0",
                  service.status == :healthy && "bg-success/10",
                  service.status != :healthy && "bg-error/10"
                ]}>
                  <.icon
                    name="hero-server"
                    class={[
                      "size-4",
                      service.status == :healthy && "text-success",
                      service.status != :healthy && "text-error"
                    ]}
                  />
                </div>
                <div class="min-w-0">
                  <p class="text-sm font-semibold text-base-content truncate">{service.name}</p>
                  <p class="text-xs text-base-content/50">port {service.port}</p>
                </div>
              </div>
              <span class={[
                "badge badge-sm shrink-0",
                service.status == :healthy && "badge-success",
                service.status == :checking && "badge-ghost",
                service.status == :unreachable && "badge-error"
              ]}>
                {case service.status do
                  :healthy -> "Healthy"
                  :checking -> "Checking..."
                  _ -> "Unreachable"
                end}
              </span>
            </div>

            <div class="mt-3 pt-3 border-t border-base-300 grid grid-cols-2 gap-2 text-xs text-base-content/60">
              <div>
                <span class="font-medium text-base-content/40 uppercase tracking-wider block mb-0.5">Response</span>
                <span>{service.response_time_ms} ms</span>
              </div>
              <div>
                <span class="font-medium text-base-content/40 uppercase tracking-wider block mb-0.5">Checked</span>
                <span>{if service[:checked_at], do: Calendar.strftime(service.checked_at, "%H:%M:%S"), else: "—"}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
