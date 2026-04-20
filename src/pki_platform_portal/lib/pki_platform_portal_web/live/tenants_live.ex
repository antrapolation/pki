defmodule PkiPlatformPortalWeb.TenantsLive do
  use PkiPlatformPortalWeb, :live_view
  import PkiPlatformPortalWeb.ErrorHelpers, only: [sanitize_error: 2]

  require Logger

  @per_page 10

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: send(self(), :load_data)

    {:ok,
     assign(socket,
       page_title: "Tenants",
       tenants: [],
       runtime_ports: %{},
       loading: true,
       page: 1,
       per_page: @per_page
     )}
  end

  @impl true
  def handle_info(:load_data, socket) do
    tenants = list_tenants()
    {:noreply, assign(socket, tenants: tenants, runtime_ports: runtime_ports(), loading: false)}
  end

  def handle_event("suspend_tenant", %{"id" => id}, socket) do
    case PkiPlatformEngine.Provisioner.suspend_tenant(id) do
      {:ok, _tenant} ->
        {:noreply, socket |> reload_tenants() |> put_flash(:info, "Tenant suspended.")}

      {:error, reason} ->
        Logger.error("[tenants] Failed to suspend tenant #{id}: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to suspend", reason))}
    end
  end

  def handle_event("activate_tenant", %{"id" => id}, socket) do
    case PkiPlatformEngine.Provisioner.activate_tenant(id) do
      {:ok, _tenant} ->
        {:noreply, socket |> reload_tenants() |> put_flash(:info, "Tenant activated.")}

      {:error, reason} ->
        Logger.error("[tenants] Failed to activate tenant #{id}: #{inspect(reason)}")
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to activate", reason))}
    end
  end

  def handle_event("delete_tenant", %{"id" => id}, socket) do
    tenant = Enum.find(socket.assigns.tenants, &(to_string(&1.id) == to_string(id)))
    deletable = ["suspended", "failed", "provisioning", "initialized"]

    cond do
      is_nil(tenant) ->
        {:noreply, put_flash(socket, :error, "Tenant not found.")}

      tenant.status not in deletable ->
        {:noreply,
         put_flash(
           socket,
           :error,
           "Active tenants must be suspended before deletion."
         )}

      true ->
        case PkiPlatformEngine.Provisioner.delete_tenant(id) do
          {:ok, _tenant} ->
            {:noreply, socket |> reload_tenants() |> put_flash(:info, "Tenant deleted.")}

          {:error, reason} ->
            Logger.error("[tenants] Failed to delete tenant #{id}: #{inspect(reason)}")
            {:noreply, put_flash(socket, :error, sanitize_error("Failed to delete", reason))}
        end
    end
  end

  def handle_event("resume_provisioning", %{"id" => id}, socket) do
    case PkiPlatformEngine.TenantOnboarding.resume_provisioning(id) do
      {:ok, %{tenant: tenant, admin: %{username: username, password: password}} = result} ->
        audit_resume(socket, tenant, :ok, %{username: username})

        email_hint =
          case Map.get(result, :email) do
            {:ok, :sent} -> " A copy was emailed to #{tenant.email}."
            _ -> ""
          end

        flash_msg =
          "Tenant resumed. New ca_admin password for #{username}: #{password} " <>
            "(shown once — copy now)." <> email_hint

        {:noreply,
         socket
         |> reload_tenants()
         |> put_flash(:info, flash_msg)}

      {:error, reason} ->
        Logger.error("[tenants] Failed to resume tenant #{id}: #{inspect(reason)}")
        audit_resume(socket, id, {:error, reason}, %{})
        {:noreply, put_flash(socket, :error, sanitize_error("Failed to resume", reason))}
    end
  end

  def handle_event("change_page", %{"page" => page}, socket) do
    case Integer.parse(page) do
      {n, ""} when n >= 1 -> {:noreply, assign(socket, page: n)}
      _ -> {:noreply, socket}
    end
  end

  defp list_tenants do
    PkiPlatformEngine.Provisioner.list_tenants()
  rescue
    _ -> []
  end

  defp reload_tenants(socket) do
    assign(socket, tenants: list_tenants(), runtime_ports: runtime_ports())
  end

  defp runtime_ports do
    PkiPlatformEngine.TenantLifecycle.list_tenants()
    |> Enum.filter(&(&1.status in [:running, :starting]))
    |> Map.new(fn info -> {to_string(info.id), info.port} end)
  rescue
    _ -> %{}
  end

  defp tenant_portal_url(port, host \\ nil) when is_integer(port) do
    host = host || System.get_env("TENANT_PORTAL_HOST", "localhost")
    "http://#{host}:#{port}/"
  end

  defp audit_resume(socket, tenant_or_id, outcome, extra) do
    admin = socket.assigns.current_user
    {tenant_id, action, details} = resume_audit_shape(tenant_or_id, outcome, extra)

    _ =
      PkiPlatformEngine.PlatformAudit.log(action, %{
        actor_id: admin[:id] || admin["id"],
        actor_username: admin[:username] || admin["username"],
        portal: "platform",
        tenant_id: tenant_id,
        target_type: "tenant",
        target_id: tenant_id,
        details: details
      })

    :ok
  rescue
    e ->
      Logger.warning("[tenants] audit log failed: #{Exception.message(e)}")
      :ok
  end

  defp resume_audit_shape(%{id: id} = _tenant, :ok, extra) do
    {id, "tenant_resumed", Map.merge(%{outcome: "ok"}, extra)}
  end

  defp resume_audit_shape(id, {:error, reason}, _extra) when is_binary(id) do
    {id, "tenant_provisioning_failed", %{step: "resume", reason: inspect(reason)}}
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
          <div>
            <table id="tenant-list" class="table table-sm table-fixed w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th class="w-[20%]">Name</th>
                  <th class="w-[15%]">Slug</th>
                  <th class="w-[10%]">Status</th>
                  <th class="w-[22%]">Email</th>
                  <th class="w-[13%]">Created</th>
                  <th class="w-[20%] text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :if={@paginated_tenants == []}>
                  <td colspan="6" class="text-center text-base-content/50 py-8">
                    No tenants yet.
                    <.link navigate="/tenants/new" class="text-primary hover:underline">Create your first tenant</.link>
                  </td>
                </tr>
                <tr :for={tenant <- @paginated_tenants} id={"tenant-#{tenant.id}"} class="hover cursor-pointer">
                  <td class="font-medium overflow-hidden text-ellipsis whitespace-nowrap">
                    <.link navigate={"/tenants/#{tenant.id}"} class="hover:text-primary transition-colors">
                      {tenant.name}
                    </.link>
                  </td>
                  <td class="font-mono text-sm text-base-content/70 overflow-hidden text-ellipsis whitespace-nowrap">{tenant.slug}</td>
                  <td>
                    <span class={[
                      "badge badge-sm",
                      tenant.status == "active" && "badge-success",
                      tenant.status == "suspended" && "badge-warning",
                      tenant.status == "initialized" && "badge-info badge-outline",
                      tenant.status == "provisioning" && "badge-info",
                      tenant.status == "failed" && "badge-error"
                    ]}>{tenant.status}</span>
                  </td>
                  <td class="font-mono text-sm text-base-content/70 overflow-hidden text-ellipsis whitespace-nowrap">{tenant.email}</td>
                  <td class="text-base-content/50 text-sm"><.local_time dt={tenant.inserted_at} format="date" /></td>
                  <td class="text-right">
                    <div class="flex gap-1 justify-end">
                      <.link
                        navigate={"/tenants/#{tenant.id}"}
                        title="View Details"
                        class="btn btn-ghost btn-xs text-sky-400"
                      >
                        <.icon name="hero-eye" class="size-4" />
                      </.link>
                      <a
                        :if={tenant.status == "active" and Map.has_key?(@runtime_ports, to_string(tenant.id))}
                        href={tenant_portal_url(@runtime_ports[to_string(tenant.id)])}
                        target="_blank"
                        rel="noopener"
                        title={"Open portal (port #{@runtime_ports[to_string(tenant.id)]})"}
                        class="btn btn-ghost btn-xs text-primary"
                      >
                        <.icon name="hero-arrow-top-right-on-square" class="size-4" />
                      </a>
                      <button
                        :if={tenant.status == "initialized"}
                        phx-click="activate_tenant"
                        phx-value-id={tenant.id}
                        title="Activate"
                        class="btn btn-ghost btn-xs text-emerald-400"
                      >
                        <.icon name="hero-play" class="size-4" />
                      </button>
                      <button
                        :if={tenant.status in ["active", "initialized"]}
                        phx-click="suspend_tenant"
                        phx-value-id={tenant.id}
                        data-confirm="Are you sure you want to suspend this tenant?"
                        title="Suspend"
                        class="btn btn-ghost btn-xs text-amber-400"
                      >
                        <.icon name="hero-pause" class="size-4" />
                      </button>
                      <button
                        :if={tenant.status == "suspended"}
                        phx-click="activate_tenant"
                        phx-value-id={tenant.id}
                        title="Activate"
                        class="btn btn-ghost btn-xs text-emerald-400"
                      >
                        <.icon name="hero-play" class="size-4" />
                      </button>
                      <button
                        :if={tenant.status in ["provisioning", "failed"]}
                        phx-click="resume_provisioning"
                        phx-value-id={tenant.id}
                        data-confirm="Resume provisioning? This stops any running peer for this tenant, releases its port, and re-runs spawn → admin → active."
                        title="Resume provisioning"
                        class="btn btn-ghost btn-xs text-emerald-400"
                      >
                        <.icon name="hero-arrow-path" class="size-4" />
                      </button>
                      <button
                        :if={tenant.status in ["suspended", "failed", "provisioning", "initialized"]}
                        phx-click="delete_tenant"
                        phx-value-id={tenant.id}
                        data-confirm="Are you sure? This will permanently delete the tenant and its database."
                        title="Delete"
                        class="btn btn-ghost btn-xs text-rose-400"
                      >
                        <.icon name="hero-trash" class="size-4" />
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
