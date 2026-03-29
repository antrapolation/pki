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
       per_page: @per_page,
       form_error: nil
     )}
  end

  @impl true
  def handle_event("create_tenant", %{"name" => name, "slug" => slug} = params, socket) do
    opts =
      case Map.get(params, "signing_algorithm", "") do
        "" -> []
        algo -> [signing_algorithm: algo]
      end

    case PkiPlatformEngine.Provisioner.create_tenant(name, slug, opts) do
      {:ok, _tenant} ->
        tenants = list_tenants()

        {:noreply,
         socket
         |> assign(tenants: tenants, form_error: nil)
         |> put_flash(:info, "Tenant \"#{name}\" created successfully.")}

      {:error, %Ecto.Changeset{} = changeset} ->
        errors =
          Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
            Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
              opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
            end)
          end)

        error_msg = errors |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end) |> Enum.join("; ")
        {:noreply, assign(socket, form_error: error_msg)}

      {:error, reason} ->
        {:noreply, assign(socket, form_error: "Failed to create tenant: #{inspect(reason)}")}
    end
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
      <%!-- Create Tenant Form --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-5">
          <h2 class="text-sm font-semibold text-base-content mb-3">Create New Tenant</h2>

          <%= if @form_error do %>
            <div class="alert alert-error text-sm mb-3">
              <span class="hero-exclamation-circle text-lg" />
              <span>{@form_error}</span>
            </div>
          <% end %>

          <form id="create-tenant-form" phx-submit="create_tenant" class="flex items-end gap-3">
            <div class="flex-1">
              <label for="tenant-name" class="block text-xs font-medium text-base-content/60 mb-1">Name</label>
              <input
                type="text"
                name="name"
                id="tenant-name"
                required
                class="input input-bordered input-sm w-full"
                placeholder="Organization Name"
              />
            </div>
            <div class="flex-1">
              <label for="tenant-slug" class="block text-xs font-medium text-base-content/60 mb-1">Slug</label>
              <input
                type="text"
                name="slug"
                id="tenant-slug"
                required
                class="input input-bordered input-sm w-full"
                placeholder="org-name"
                pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
                title="Lowercase alphanumeric with hyphens"
              />
            </div>
            <div class="flex-1">
              <label for="signing-algo" class="block text-xs font-medium text-base-content/60 mb-1">Signing Algorithm</label>
              <select name="signing_algorithm" id="signing-algo" class="select select-bordered select-sm w-full">
                <optgroup label="Classical">
                  <option value="ECC-P256" selected>ECC-P256</option>
                  <option value="ECC-P384">ECC-P384</option>
                  <option value="RSA-2048">RSA-2048</option>
                  <option value="RSA-4096">RSA-4096</option>
                </optgroup>
                <optgroup label="Post-Quantum">
                  <option value="KAZ-SIGN-128">KAZ-SIGN-128</option>
                  <option value="KAZ-SIGN-192">KAZ-SIGN-192</option>
                  <option value="KAZ-SIGN-256">KAZ-SIGN-256</option>
                  <option value="ML-DSA-44">ML-DSA-44</option>
                  <option value="ML-DSA-65">ML-DSA-65</option>
                  <option value="ML-DSA-87">ML-DSA-87</option>
                </optgroup>
              </select>
            </div>
            <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Creating...">
              <.icon name="hero-plus" class="size-4" />
              Create
            </button>
          </form>
        </div>
      </div>

      <%!-- Tenant List --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body p-0">
          <div class="px-5 py-4 border-b border-base-300 flex items-center justify-between">
            <h2 class="text-sm font-semibold text-base-content">All Tenants</h2>
            <span class="text-xs text-base-content/50">{@total} total</span>
          </div>
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
                  <td colspan="6" class="text-center text-base-content/50 py-8">No tenants yet. Create one above.</td>
                </tr>
                <tr :for={tenant <- @paginated_tenants} id={"tenant-#{tenant.id}"} class="hover">
                  <td class="font-medium">{tenant.name}</td>
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
