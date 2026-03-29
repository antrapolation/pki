defmodule PkiPlatformPortalWeb.TenantsLive do
  use PkiPlatformPortalWeb, :live_view

  @per_page 10

  @impl true
  def mount(_params, _session, socket) do
    tenants = list_tenants()

    {:ok,
     assign(socket,
       page_title: "Tenants",
       tenants: tenants,
       page: 1,
       per_page: @per_page
     )}
  end

  def handle_event("suspend_tenant", %{"id" => id}, socket) do
    case PkiPlatformEngine.Provisioner.suspend_tenant(id) do
      {:ok, _tenant} ->
        tenants = list_tenants()
        {:noreply, socket |> assign(tenants: tenants) |> put_flash(:info, "Tenant suspended.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to suspend: #{inspect(reason)}")}
    end
  end

  def handle_event("activate_tenant", %{"id" => id}, socket) do
    case PkiPlatformEngine.Provisioner.activate_tenant(id) do
      {:ok, _tenant} ->
        tenants = list_tenants()
        {:noreply, socket |> assign(tenants: tenants) |> put_flash(:info, "Tenant activated.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate: #{inspect(reason)}")}
    end
  end

  def handle_event("delete_tenant", %{"id" => id}, socket) do
    case PkiPlatformEngine.Provisioner.delete_tenant(id) do
      {:ok, _tenant} ->
        tenants = list_tenants()
        {:noreply, socket |> assign(tenants: tenants) |> put_flash(:info, "Tenant deleted.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to delete: #{inspect(reason)}")}
    end
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    {:noreply, assign(socket, page: String.to_integer(page))}
  end

  defp list_tenants do
    PkiPlatformEngine.Provisioner.list_tenants()
  rescue
    _ -> []
  end

  @impl true
  def render(assigns) do
    paginated = assigns.tenants |> Enum.drop((assigns.page - 1) * assigns.per_page) |> Enum.take(assigns.per_page)
    total = length(assigns.tenants)
    total_pages = max(ceil(total / assigns.per_page), 1)
    start_idx = min((assigns.page - 1) * assigns.per_page + 1, total)
    end_idx = min(assigns.page * assigns.per_page, total)

    assigns =
      assigns
      |> assign(:paginated_tenants, paginated)
      |> assign(:total, total)
      |> assign(:total_pages, total_pages)
      |> assign(:start_idx, start_idx)
      |> assign(:end_idx, end_idx)

    ~H"""
    <div id="tenants-page" class="space-y-6">
      <%!-- Header bar --%>
      <div class="flex items-center justify-between">
        <div>
          <h1 class="text-lg font-semibold text-base-content">Tenants</h1>
          <p class="text-sm text-base-content/50 mt-0.5">{@total} total</p>
        </div>
        <.link navigate="/tenants/new" class="btn btn-primary btn-sm">
          <.icon name="hero-plus" class="size-4" />
          New Tenant
        </.link>
      </div>

      <%!-- Tenant List --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="overflow-x-auto">
            <table id="tenant-list" class="table table-sm">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Name</th>
                  <th>Slug</th>
                  <th>Status</th>
                  <th>Algorithm</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :if={@paginated_tenants == []}>
                  <td colspan="6" class="text-center text-base-content/50 py-8">
                    No tenants yet.
                    <.link navigate="/tenants/new" class="text-primary hover:underline">Create your first tenant</.link>
                  </td>
                </tr>
                <tr :for={tenant <- @paginated_tenants} id={"tenant-#{tenant.id}"} class="hover">
                  <td class="font-medium">
                    <.link navigate={"/tenants/#{tenant.id}"} class="hover:text-primary transition-colors">
                      {tenant.name}
                    </.link>
                  </td>
                  <td class="font-mono text-sm">{tenant.slug}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      tenant.status == "active" && "badge-success",
                      tenant.status == "suspended" && "badge-warning",
                      tenant.status == "initialized" && "badge-ghost"
                    ]}>{tenant.status}</span>
                  </td>
                  <td class="font-mono text-sm">{tenant.signing_algorithm}</td>
                  <td class="text-base-content/60 text-sm">{Calendar.strftime(tenant.inserted_at, "%Y-%m-%d")}</td>
                  <td>
                    <div class="flex gap-1">
                      <button
                        :if={tenant.status in ["active", "initialized"]}
                        phx-click="suspend_tenant"
                        phx-value-id={tenant.id}
                        data-confirm="Are you sure you want to suspend this tenant?"
                        class="btn btn-ghost btn-xs text-warning"
                      >
                        Suspend
                      </button>
                      <button
                        :if={tenant.status == "suspended"}
                        phx-click="activate_tenant"
                        phx-value-id={tenant.id}
                        class="btn btn-ghost btn-xs text-success"
                      >
                        Activate
                      </button>
                      <button
                        :if={tenant.status == "suspended"}
                        phx-click="delete_tenant"
                        phx-value-id={tenant.id}
                        data-confirm="Are you sure? This will permanently delete the tenant and its database."
                        class="btn btn-ghost btn-xs text-error"
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <div :if={@total > 0} class="flex items-center justify-between px-5 py-3 border-t border-base-300 text-sm">
            <span class="text-base-content/60">
              Showing {@start_idx}–{@end_idx} of {@total}
            </span>
            <div class="join">
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page - 1} disabled={@page == 1}>&#171;</button>
              <button class="join-item btn btn-sm btn-active">{@page}</button>
              <button class="join-item btn btn-sm" phx-click="change_page" phx-value-page={@page + 1} disabled={@page >= @total_pages}>&#187;</button>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end
end
