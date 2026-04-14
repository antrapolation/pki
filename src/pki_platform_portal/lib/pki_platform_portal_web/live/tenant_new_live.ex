defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.TenantOnboarding

  require Logger

  @schema_steps [
    {:database, "Tenant schemas created"},
    {:engines, "Tenant registered"},
    {:instances, "CA and RA instances created"},
    {:tenant_admin, "Tenant admin account created"},
    {:credentials, "Credentials sent"}
  ]

  @database_steps [
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
       schema_mode: "schema",
       form_error: nil,
       progress: Enum.map(steps_for("schema"), fn {key, label} -> {key, label, :pending} end),
       tenant: nil,
       task_ref: nil
     )}
  end

  @impl true
  def handle_event("submit", params, socket) do
    name = String.trim(params["name"] || "")
    slug = String.trim(params["slug"] || "")
    email = String.trim(params["email"] || "")
    schema_mode = if params["schema_mode"] == "database", do: "database", else: "schema"

    with :ok <- validate_name(name),
         :ok <- validate_slug(slug),
         :ok <- validate_email(email) do
      socket =
        assign(socket,
          phase: :provisioning,
          name: name,
          slug: slug,
          email: email,
          schema_mode: schema_mode,
          form_error: nil,
          progress: Enum.map(steps_for(schema_mode), fn {key, label} -> {key, label, :pending} end)
        )

      send(self(), :start_database_step)
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

        send(self(), step_start_message(key))
        {:noreply, assign(socket, progress: progress, form_error: nil)}

      nil ->
        {:noreply, socket}
    end
  end

  # --- Async provisioning chain ---
  # Each step: set :in_progress → return socket (pushes spinner to client) → run Task

  # Step 1: Create database/schemas
  @impl true
  def handle_info(:start_database_step, socket) do
    socket = update_step(socket, :database, :in_progress)
    name = socket.assigns.name
    slug = socket.assigns.slug
    email = socket.assigns.email
    schema_mode = socket.assigns.schema_mode

    task = Task.async(fn ->
      TenantOnboarding.create_database(name, slug, email, schema_mode: schema_mode)
    end)

    {:noreply, assign(socket, task_ref: {:database, task.ref})}
  end

  # Step 2: Activate tenant
  def handle_info(:start_activate_step, socket) do
    socket = update_step(socket, :engines, :in_progress)
    tenant_id = socket.assigns.tenant.id

    task = Task.async(fn ->
      TenantOnboarding.activate(tenant_id)
    end)

    {:noreply, assign(socket, task_ref: {:engines, task.ref})}
  end

  # Step 3: Create instances
  def handle_info(:start_instances_step, socket) do
    socket = update_step(socket, :instances, :in_progress)
    tenant = socket.assigns.tenant

    task = Task.async(fn ->
      TenantOnboarding.create_instances(tenant)
    end)

    {:noreply, assign(socket, task_ref: {:instances, task.ref})}
  end

  # Step 4: Create tenant admin + send credentials
  def handle_info(:start_tenant_admin_step, socket) do
    socket = update_step(socket, :tenant_admin, :in_progress)
    tenant = socket.assigns.tenant

    task = Task.async(fn ->
      TenantOnboarding.create_tenant_admin(tenant)
    end)

    {:noreply, assign(socket, task_ref: {:tenant_admin, task.ref})}
  end

  # --- Task result handlers ---

  def handle_info({ref, result}, socket) when is_reference(ref) do
    # Flush the DOWN message from the Task
    Process.demonitor(ref, [:flush])

    case socket.assigns.task_ref do
      {:database, ^ref} ->
        handle_database_result(result, socket)

      {:engines, ^ref} ->
        handle_activate_result(result, socket)

      {:instances, ^ref} ->
        handle_instances_result(result, socket)

      {:tenant_admin, ^ref} ->
        handle_tenant_admin_result(result, socket)

      _ ->
        {:noreply, socket}
    end
  end

  # Handle Task crashes
  def handle_info({:DOWN, ref, :process, _pid, reason}, socket) when is_reference(ref) do
    case socket.assigns.task_ref do
      {step, ^ref} ->
        Logger.error("[tenant_new] Task crashed during #{step}: #{inspect(reason)}")
        {:noreply, update_step(socket, step, {:error, "Unexpected error. Check server logs."})}

      _ ->
        {:noreply, socket}
    end
  end

  # Catch-all for unmatched messages
  def handle_info(_msg, socket), do: {:noreply, socket}

  # --- Result handlers ---

  defp handle_database_result(result, socket) do
    case result do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:database, :done)
        send(self(), :start_activate_step)
        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        err = format_changeset_error(changeset)
        {:noreply, update_step(socket, :database, {:error, err})}

      {:error, reason} ->
        {:noreply, update_step(socket, :database, {:error, inspect(reason)})}
    end
  end

  defp handle_activate_result(result, socket) do
    case result do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:engines, :done)
        send(self(), :start_instances_step)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :engines, {:error, inspect(reason)})}
    end
  end

  defp handle_instances_result(result, socket) do
    case result do
      :ok ->
        socket = update_step(socket, :instances, :done)
        send(self(), :start_tenant_admin_step)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :instances, {:error, reason})}
    end
  end

  defp handle_tenant_admin_result(result, socket) do
    case result do
      {:ok, _user} ->
        socket =
          socket
          |> update_step(:tenant_admin, :done)
          |> update_step(:credentials, :done)

        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :tenant_admin, {:error, inspect(reason)})}
    end
  end

  # --- Helpers ---

  defp step_start_message(:database), do: :start_database_step
  defp step_start_message(:engines), do: :start_activate_step
  defp step_start_message(:instances), do: :start_instances_step
  defp step_start_message(:tenant_admin), do: :start_tenant_admin_step
  defp step_start_message(:credentials), do: :start_tenant_admin_step

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

  defp steps_for("database"), do: @database_steps
  defp steps_for(_), do: @schema_steps

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

              <%!-- Isolation mode: schema-only for now. Database mode is legacy/not fully tested. --%>
              <input type="hidden" name="schema_mode" value="schema" />

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
              <p class="text-sm text-base-content/60 mt-0.5">Setting up the tenant environment. This may take up to a minute...</p>
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
                    <span class="text-sm text-base-content font-medium">{label}</span>
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
