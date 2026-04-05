defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.TenantOnboarding

  require Logger

  @steps [
    {:database, "Database created"},
    {:engines, "Engines started"},
    {:instances, "CA and RA instances created"},
    {:tenant_admin, "Tenant admin account created"},
    {:credentials, "Credentials sent"}
  ]

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     assign(socket,
       page_title: "New Tenant",
       phase: :form,
       name: "",
       slug: "",
       email: "",
       form_error: nil,
       progress: Enum.map(@steps, fn {key, label} -> {key, label, :pending} end),
       tenant: nil
     )}
  end

  @impl true
  def handle_event("submit", params, socket) do
    name = String.trim(params["name"] || "")
    slug = String.trim(params["slug"] || "")
    email = String.trim(params["email"] || "")

    with :ok <- validate_name(name),
         :ok <- validate_slug(slug),
         :ok <- validate_email(email) do
      socket =
        assign(socket,
          phase: :provisioning,
          name: name,
          slug: slug,
          email: email,
          form_error: nil,
          progress: Enum.map(@steps, fn {key, label} -> {key, label, :pending} end)
        )

      send(self(), :run_provision)
      {:noreply, socket}
    else
      {:error, msg} ->
        {:noreply, assign(socket, form_error: msg)}
    end
  end

  def handle_event("retry", _params, socket) do
    failed_step = Enum.find(socket.assigns.progress, fn {_key, _label, status} ->
      match?({:error, _}, status)
    end)

    case failed_step do
      {key, _label, _} ->
        progress = Enum.map(socket.assigns.progress, fn
          {^key, label, _} -> {key, label, :pending}
          other -> other
        end)

        send(self(), step_message(key))
        {:noreply, assign(socket, progress: progress, form_error: nil)}

      nil ->
        {:noreply, socket}
    end
  end

  # --- Provisioning chain ---

  @impl true
  def handle_info(:run_provision, socket) do
    socket = update_step(socket, :database, :in_progress)

    case TenantOnboarding.create_database(socket.assigns.name, socket.assigns.slug, socket.assigns.email) do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:database, :done)
        send(self(), :run_activate)
        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        err = format_changeset_error(changeset)
        {:noreply, update_step(socket, :database, {:error, err})}

      {:error, reason} ->
        {:noreply, update_step(socket, :database, {:error, inspect(reason)})}
    end
  end

  def handle_info(:run_activate, socket) do
    socket = update_step(socket, :engines, :in_progress)

    case TenantOnboarding.activate(socket.assigns.tenant.id) do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:engines, :done)
        send(self(), :run_instances)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :engines, {:error, inspect(reason)})}
    end
  end

  def handle_info(:run_instances, socket) do
    socket = update_step(socket, :instances, :in_progress)

    case TenantOnboarding.create_instances(socket.assigns.tenant) do
      :ok ->
        socket = update_step(socket, :instances, :done)
        send(self(), :run_tenant_admin)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :instances, {:error, reason})}
    end
  end

  def handle_info(:run_tenant_admin, socket) do
    socket = update_step(socket, :tenant_admin, :in_progress)

    case TenantOnboarding.create_tenant_admin(socket.assigns.tenant) do
      {:ok, _user} ->
        socket = update_step(socket, :tenant_admin, :done)
        # Credentials are sent automatically by create_user_for_portal
        {:noreply, update_step(socket, :credentials, :done)}

      {:error, reason} ->
        {:noreply, update_step(socket, :tenant_admin, {:error, inspect(reason)})}
    end
  end

  # --- Helpers ---

  defp step_message(:database), do: :run_provision
  defp step_message(:engines), do: :run_activate
  defp step_message(:instances), do: :run_instances
  defp step_message(:tenant_admin), do: :run_tenant_admin
  defp step_message(:credentials), do: :run_tenant_admin

  defp update_step(socket, key, status) do
    progress = Enum.map(socket.assigns.progress, fn
      {^key, label, _} -> {key, label, status}
      other -> other
    end)

    assign(socket, progress: progress)
  end

  defp format_changeset_error(changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {k, v} -> "#{k}: #{Enum.join(v, ", ")}" end)
    |> Enum.join("; ")
  end

  defp validate_name(""), do: {:error, "Name is required."}
  defp validate_name(_), do: :ok

  defp validate_slug(""), do: {:error, "Slug is required."}
  defp validate_slug(slug) do
    if Regex.match?(~r/^[a-z0-9][a-z0-9-]*[a-z0-9]$/, slug),
      do: :ok,
      else: {:error, "Slug must contain only lowercase letters, numbers, and hyphens, and must start and end with a letter or number."}
  end

  defp validate_email(""), do: {:error, "Email is required."}
  defp validate_email(email) do
    if Regex.match?(~r/^[^\s@]+@[^\s@]+\.[^\s@]+$/, email),
      do: :ok,
      else: {:error, "Please enter a valid email address."}
  end

  defp all_done?(progress) do
    Enum.all?(progress, fn {_key, _label, status} -> status == :done end)
  end

  defp has_error?(progress) do
    Enum.any?(progress, fn {_key, _label, status} -> match?({:error, _}, status) end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div id="tenant-new-page" class="max-w-2xl mx-auto space-y-6">
      <%!-- Back link --%>
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%!-- Form phase --%>
      <%= if @phase == :form do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Create Tenant</h2>
              <p class="text-sm text-base-content/60 mt-0.5">Enter the details for the new Certificate Authority tenant.</p>
            </div>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form id="tenant-form" phx-submit="submit" class="space-y-4">
              <div>
                <label for="tenant-name" class="block text-xs font-medium text-base-content/60 mb-1">
                  Name <span class="text-error">*</span>
                </label>
                <input
                  type="text"
                  name="name"
                  id="tenant-name"
                  required
                  value={@name}
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
                  value={@slug}
                  class="input input-bordered w-full font-mono"
                  placeholder="acme-corp"
                  pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
                  title="Lowercase letters, numbers, and hyphens only. Must start and end with a letter or number."
                />
                <p class="text-xs text-base-content/50 mt-1">Lowercase alphanumeric with hyphens (e.g. <code class="font-mono">acme-corp</code>)</p>
              </div>

              <div>
                <label for="tenant-email" class="block text-xs font-medium text-base-content/60 mb-1">
                  Email <span class="text-error">*</span>
                </label>
                <input
                  type="email"
                  name="email"
                  id="tenant-email"
                  required
                  value={@email}
                  class="input input-bordered w-full"
                  placeholder="admin@acme-corp.com"
                />
                <p class="text-xs text-base-content/50 mt-1">Tenant admin credentials will be sent to this email.</p>
              </div>

              <div class="flex justify-end gap-3 pt-2">
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">
                  Cancel
                </.link>
                <button type="submit" class="btn btn-primary btn-sm" phx-disable-with="Creating...">
                  Create Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <%!-- Provisioning phase --%>
      <%= if @phase == :provisioning do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Creating {@name}</h2>
              <p class="text-sm text-base-content/60 mt-0.5">Setting up the tenant environment...</p>
            </div>

            <%!-- Progress checklist --%>
            <div class="space-y-3">
              <div :for={{_key, label, status} <- @progress} class="flex items-center gap-3">
                <%= case status do %>
                  <% :done -> %>
                    <div class="flex items-center justify-center w-6 h-6 rounded-full bg-success/10">
                      <.icon name="hero-check" class="size-4 text-success" />
                    </div>
                    <span class="text-sm text-base-content">{label}</span>
                  <% :in_progress -> %>
                    <span class="loading loading-spinner loading-sm text-primary"></span>
                    <span class="text-sm text-base-content">{label}</span>
                  <% {:error, _msg} -> %>
                    <div class="flex items-center justify-center w-6 h-6 rounded-full bg-error/10">
                      <.icon name="hero-x-mark" class="size-4 text-error" />
                    </div>
                    <span class="text-sm text-error">{label}</span>
                  <% :pending -> %>
                    <div class="flex items-center justify-center w-6 h-6 rounded-full bg-base-200">
                      <div class="w-2 h-2 rounded-full bg-base-content/20"></div>
                    </div>
                    <span class="text-sm text-base-content/40">{label}</span>
                <% end %>
              </div>
            </div>

            <%!-- Error details --%>
            <%= if has_error?(@progress) do %>
              <% {_key, _label, {:error, msg}} = Enum.find(@progress, fn {_, _, s} -> match?({:error, _}, s) end) %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{msg}</span>
              </div>
              <button phx-click="retry" class="btn btn-primary btn-sm">
                <.icon name="hero-arrow-path" class="size-4" />
                Retry
              </button>
            <% end %>

            <%!-- Success state --%>
            <%= if all_done?(@progress) do %>
              <div class="divider my-0"></div>
              <div class="flex items-center gap-3">
                <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                  <.icon name="hero-check-circle" class="size-6 text-success" />
                </div>
                <div>
                  <p class="text-sm font-semibold text-base-content">Tenant "{@name}" is ready.</p>
                  <p class="text-xs text-base-content/60 mt-0.5">Credentials sent to {@email}.</p>
                </div>
              </div>

              <div class="flex gap-3 pt-1">
                <.link navigate={"/tenants/#{@tenant.id}"} class="btn btn-primary btn-sm">
                  <.icon name="hero-building-office" class="size-4" />
                  View Tenant
                </.link>
                <.link navigate="/tenants/new" class="btn btn-ghost btn-sm">
                  <.icon name="hero-plus" class="size-4" />
                  Create Another
                </.link>
              </div>
            <% end %>
          </div>
        </div>
      <% end %>
    </div>
    """
  end
end
