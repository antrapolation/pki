defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  @ca_portal_host System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
  @ra_portal_host System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "New Tenant",
       form_error: nil,
       created_tenant: nil,
       ca_setup_url: nil,
       ra_setup_url: nil
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
      {:ok, tenant} ->
        ca_host = @ca_portal_host
        ra_host = @ra_portal_host

        {:noreply,
         assign(socket,
           created_tenant: tenant,
           ca_setup_url: "https://#{ca_host}/setup?tenant=#{tenant.slug}",
           ra_setup_url: "https://#{ra_host}/setup?tenant=#{tenant.slug}",
           form_error: nil
         )}

      {:error, %Ecto.Changeset{} = changeset} ->
        errors =
          Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
            Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
              opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
            end)
          end)

        error_msg =
          errors
          |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
          |> Enum.join("; ")

        {:noreply, assign(socket, form_error: error_msg)}

      {:error, reason} ->
        {:noreply, assign(socket, form_error: "Failed to create tenant: #{inspect(reason)}")}
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-new-page" class="max-w-2xl mx-auto space-y-4">
      <%!-- Back link --%>
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%= if @created_tenant do %>
        <%!-- Success card --%>
        <div class="card bg-base-100 shadow-sm border border-success/40">
          <div class="card-body p-6 space-y-5">
            <div class="flex items-center gap-3">
              <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                <.icon name="hero-check-circle" class="size-6 text-success" />
              </div>
              <div>
                <h2 class="text-base font-semibold text-base-content">Tenant Created</h2>
                <p class="text-sm text-base-content/60">
                  <span class="font-medium text-base-content">{@created_tenant.name}</span>
                  has been provisioned successfully.
                </p>
              </div>
            </div>

            <div class="divider my-0"></div>

            <div class="space-y-3">
              <p class="text-xs font-semibold uppercase tracking-wider text-base-content/50">Setup URLs</p>

              <div class="space-y-2">
                <div>
                  <p class="text-xs font-medium text-base-content/60 mb-1">CA Portal Setup</p>
                  <div class="flex items-center gap-2 bg-base-200 rounded-lg px-3 py-2">
                    <.icon name="hero-shield-check" class="size-4 text-base-content/40 shrink-0" />
                    <code
                      class="text-sm font-mono text-base-content flex-1 select-all break-all"
                      id="ca-setup-url"
                    >{@ca_setup_url}</code>
                  </div>
                </div>

                <div>
                  <p class="text-xs font-medium text-base-content/60 mb-1">RA Portal Setup</p>
                  <div class="flex items-center gap-2 bg-base-200 rounded-lg px-3 py-2">
                    <.icon name="hero-clipboard-document-check" class="size-4 text-base-content/40 shrink-0" />
                    <code
                      class="text-sm font-mono text-base-content flex-1 select-all break-all"
                      id="ra-setup-url"
                    >{@ra_setup_url}</code>
                  </div>
                </div>
              </div>
            </div>

            <div class="flex gap-3 pt-1">
              <.link navigate={"/tenants/#{@created_tenant.id}"} class="btn btn-primary btn-sm">
                <.icon name="hero-building-office" class="size-4" />
                View Tenant
              </.link>
              <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                <.icon name="hero-list-bullet" class="size-4" />
                Back to List
              </.link>
            </div>
          </div>
        </div>

      <% else %>
        <%!-- Creation form --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">New Tenant</h2>
              <p class="text-sm text-base-content/60 mt-0.5">Provision a new Certificate Authority tenant.</p>
            </div>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form id="create-tenant-form" phx-submit="create_tenant" class="space-y-4">
              <div>
                <label for="tenant-name" class="block text-xs font-medium text-base-content/60 mb-1">
                  Name <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="name"
                  id="tenant-name"
                  required
                  class="input input-bordered w-full"
                  placeholder="Acme Corporation"
                />
              </div>

              <div>
                <label for="tenant-slug" class="block text-xs font-medium text-base-content/60 mb-1">
                  Slug <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="slug"
                  id="tenant-slug"
                  required
                  class="input input-bordered w-full font-mono"
                  placeholder="acme-corp"
                  pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
                  title="Lowercase letters, numbers, and hyphens only. Must start and end with a letter or number."
                />
                <p class="text-xs text-base-content/50 mt-1">Lowercase alphanumeric with hyphens (e.g. <code class="font-mono">acme-corp</code>)</p>
              </div>

              <div>
                <label for="signing-algo" class="block text-xs font-medium text-base-content/60 mb-1">
                  Signing Algorithm
                </label>
                <select name="signing_algorithm" id="signing-algo" class="select select-bordered w-full">
                  <optgroup label="Classical">
                    <option value="ECC-P256" selected>ECC-P256 (default)</option>
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

              <div class="flex justify-end gap-3 pt-2">
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                  Cancel
                </.link>
                <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Creating...">
                  <.icon name="hero-plus" class="size-4" />
                  Create Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
