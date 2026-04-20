defmodule PkiPlatformPortalWeb.TenantNewLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.{Provisioner, TenantOnboarding}

  require Logger

  @steps [
    {:register, "Tenant registered"},
    {:spawn, "Tenant BEAM spawned"},
    {:admin, "Initial ca_admin created"},
    {:active, "Tenant activated"}
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
       field_errors: %{},
       progress: Enum.map(@steps, fn {key, label} -> {key, label, :pending} end),
       tenant: nil,
       beam_info: nil,
       admin_credentials: nil,
       task_ref: nil
     )}
  end

  @impl true
  def handle_event("validate", params, socket) do
    name = params["name"] || ""
    slug = params["slug"] || ""
    email = params["email"] || ""

    field_errors =
      %{}
      |> put_field_error(:name, name, &validate_name/1)
      |> put_field_error(:slug, slug, &validate_slug_with_uniqueness/1)
      |> put_field_error(:email, email, &validate_email/1)

    {:noreply,
     assign(socket,
       name: name,
       slug: slug,
       email: email,
       field_errors: field_errors,
       form_error: nil
     )}
  end

  @impl true
  def handle_event("submit", params, socket) do
    name = String.trim(params["name"] || "")
    slug = String.trim(params["slug"] || "")
    email = String.trim(params["email"] || "")

    with :ok <- validate_name(name),
         :ok <- validate_slug_with_uniqueness(slug),
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

      send(self(), :start_register_step)
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

  def handle_event("dismiss_credentials", _params, socket) do
    {:noreply, assign(socket, admin_credentials: nil)}
  end

  # --- Async provisioning chain ---
  # Each step: set :in_progress → return socket (pushes spinner to client) → run Task

  @impl true
  def handle_info(:start_register_step, socket) do
    socket = update_step(socket, :register, :in_progress)
    name = socket.assigns.name
    slug = socket.assigns.slug
    email = socket.assigns.email

    task = Task.async(fn -> TenantOnboarding.register_tenant(name, slug, email) end)
    {:noreply, assign(socket, task_ref: {:register, task.ref})}
  end

  def handle_info(:start_spawn_step, socket) do
    socket = update_step(socket, :spawn, :in_progress)
    tenant = socket.assigns.tenant

    task = Task.async(fn -> TenantOnboarding.spawn_beam(tenant) end)
    {:noreply, assign(socket, task_ref: {:spawn, task.ref})}
  end

  def handle_info(:start_admin_step, socket) do
    socket = update_step(socket, :admin, :in_progress)
    tenant = socket.assigns.tenant
    node = socket.assigns.beam_info.node

    task = Task.async(fn -> TenantOnboarding.bootstrap_first_admin(tenant, node) end)
    {:noreply, assign(socket, task_ref: {:admin, task.ref})}
  end

  def handle_info(:start_active_step, socket) do
    socket = update_step(socket, :active, :in_progress)
    tenant = socket.assigns.tenant

    task = Task.async(fn -> TenantOnboarding.activate_tenant(tenant.id) end)
    {:noreply, assign(socket, task_ref: {:active, task.ref})}
  end

  # --- Task result handlers ---

  def handle_info({ref, result}, socket) when is_reference(ref) do
    Process.demonitor(ref, [:flush])

    case socket.assigns.task_ref do
      {:register, ^ref} -> handle_register_result(result, socket)
      {:spawn, ^ref} -> handle_spawn_result(result, socket)
      {:admin, ^ref} -> handle_admin_result(result, socket)
      {:active, ^ref} -> handle_active_result(result, socket)
      _ -> {:noreply, socket}
    end
  end

  def handle_info({:DOWN, ref, :process, _pid, reason}, socket) when is_reference(ref) do
    case socket.assigns.task_ref do
      {step, ^ref} ->
        Logger.error("[tenant_new] Task crashed during #{step}: #{inspect(reason)}")
        {:noreply, update_step(socket, step, {:error, "Unexpected error. Check server logs."})}

      _ ->
        {:noreply, socket}
    end
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # --- Result handlers ---

  defp handle_register_result(result, socket) do
    case result do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:register, :done)
        send(self(), :start_spawn_step)
        {:noreply, socket}

      {:error, %Ecto.Changeset{} = changeset} ->
        {:noreply, update_step(socket, :register, {:error, format_changeset_error(changeset)})}

      {:error, reason} ->
        {:noreply, update_step(socket, :register, {:error, inspect(reason)})}
    end
  end

  defp handle_spawn_result(result, socket) do
    case result do
      {:ok, info} ->
        socket = socket |> assign(beam_info: info) |> update_step(:spawn, :done)
        send(self(), :start_admin_step)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :spawn, {:error, inspect(reason)})}
    end
  end

  defp handle_admin_result(result, socket) do
    case result do
      {:ok, user, password} ->
        socket =
          socket
          |> assign(admin_credentials: %{username: user.username, password: password})
          |> update_step(:admin, :done)

        send(self(), :start_active_step)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :admin, {:error, inspect(reason)})}
    end
  end

  defp handle_active_result(result, socket) do
    case result do
      {:ok, tenant} ->
        socket = socket |> assign(tenant: tenant) |> update_step(:active, :done)
        {:noreply, socket}

      {:error, reason} ->
        {:noreply, update_step(socket, :active, {:error, inspect(reason)})}
    end
  end

  # --- Helpers ---

  defp step_start_message(:register), do: :start_register_step
  defp step_start_message(:spawn), do: :start_spawn_step
  defp step_start_message(:admin), do: :start_admin_step
  defp step_start_message(:active), do: :start_active_step

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
  defp validate_slug(slug) when byte_size(slug) < 3,
    do: {:error, "Slug must be at least 3 characters."}
  defp validate_slug(slug) when byte_size(slug) > 63,
    do: {:error, "Slug must be at most 63 characters."}
  defp validate_slug(slug) do
    if Regex.match?(~r/^[a-z0-9][a-z0-9-]*[a-z0-9]$/, slug),
      do: :ok,
      else:
        {:error,
         "Slug must contain only lowercase letters, numbers, and hyphens, and must start and end with a letter or number."}
  end

  # Full slug validation: format first, then uniqueness. The uniqueness
  # lookup hits Postgres on every phx-change keystroke for the slug
  # field — cheap (indexed get_by/1) and catches collisions before the
  # wizard starts spinning.
  defp validate_slug_with_uniqueness(slug) do
    trimmed = String.trim(slug)

    with :ok <- validate_slug(trimmed) do
      case Provisioner.get_tenant_by_slug(trimmed) do
        nil -> :ok
        _existing -> {:error, "A tenant with that slug already exists."}
      end
    end
  rescue
    # If the platform DB is unreachable (e.g. transient outage) we
    # don't block the form — the Postgres unique constraint will
    # catch the duplicate on submit.
    _ -> validate_slug(String.trim(slug))
  end

  # Attach a field error iff the validator returned one AND the user
  # has typed something (don't yell about empty fields on first render).
  defp put_field_error(errors, field, value, validator) do
    trimmed = String.trim(value)

    cond do
      trimmed == "" ->
        Map.delete(errors, field)

      true ->
        case validator.(trimmed) do
          :ok -> Map.delete(errors, field)
          {:error, msg} -> Map.put(errors, field, msg)
        end
    end
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
      <div>
        <.link navigate="/tenants" class="inline-flex items-center gap-1 text-sm text-base-content/60 hover:text-base-content transition-colors">
          <.icon name="hero-arrow-left" class="size-4" />
          Back to Tenants
        </.link>
      </div>

      <%= if @phase == :form do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Create Tenant</h2>
              <p class="text-sm text-base-content/60 mt-0.5">
                Spawns a per-tenant BEAM node and creates the initial ca_admin user.
              </p>
            </div>

            <%= if @form_error do %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{@form_error}</span>
              </div>
            <% end %>

            <form id="tenant-form" phx-submit="submit" phx-change="validate" class="space-y-4">
              <div>
                <label for="tenant-name" class="block text-xs font-medium text-base-content/60 mb-1">
                  Name <span class="text-error">*</span>
                </label>
                <input type="text" name="name" id="tenant-name" required value={@name}
                  class={[
                    "input input-bordered w-full",
                    @field_errors[:name] && "input-error"
                  ]}
                  placeholder="Acme Corporation" />
                <p :if={@field_errors[:name]} class="text-xs text-error mt-1">
                  {@field_errors[:name]}
                </p>
              </div>

              <div>
                <label for="tenant-slug" class="block text-xs font-medium text-base-content/60 mb-1">
                  Slug <span class="text-error">*</span>
                </label>
                <input type="text" name="slug" id="tenant-slug" required value={@slug}
                  class={[
                    "input input-bordered w-full font-mono",
                    @field_errors[:slug] && "input-error"
                  ]}
                  placeholder="acme-corp"
                  pattern="[a-z0-9][a-z0-9-]*[a-z0-9]"
                  title="Lowercase letters, numbers, and hyphens only." />
                <p :if={@field_errors[:slug]} class="text-xs text-error mt-1">
                  {@field_errors[:slug]}
                </p>
                <p :if={!@field_errors[:slug]} class="text-xs text-base-content/50 mt-1">
                  Becomes the tenant subdomain. Lowercase alphanumeric with hyphens.
                </p>
              </div>

              <div>
                <label for="tenant-email" class="block text-xs font-medium text-base-content/60 mb-1">
                  Email <span class="text-error">*</span>
                </label>
                <input type="email" name="email" id="tenant-email" required value={@email}
                  class={[
                    "input input-bordered w-full",
                    @field_errors[:email] && "input-error"
                  ]}
                  placeholder="admin@acme-corp.com" />
                <p :if={@field_errors[:email]} class="text-xs text-error mt-1">
                  {@field_errors[:email]}
                </p>
                <p :if={!@field_errors[:email]} class="text-xs text-base-content/50 mt-1">
                  Initial ca_admin email.
                </p>
              </div>

              <div class="flex justify-end gap-3 pt-2">
                <.link navigate="/tenants" class="btn btn-ghost btn-sm">Cancel</.link>
                <button
                  type="submit"
                  class="btn btn-primary btn-sm"
                  disabled={@field_errors != %{}}
                  phx-disable-with="Creating..."
                >
                  Create Tenant
                </button>
              </div>
            </form>
          </div>
        </div>
      <% end %>

      <%= if @phase == :provisioning do %>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-6 space-y-5">
            <div>
              <h2 class="text-base font-semibold text-base-content">Creating {@name}</h2>
              <p class="text-sm text-base-content/60 mt-0.5">
                Spawning the tenant BEAM and booting its app stack. This can take 30-60 seconds.
              </p>
            </div>

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

            <%= if has_error?(@progress) do %>
              <% {_key, _label, {:error, msg}} = Enum.find(@progress, fn {_, _, s} -> match?({:error, _}, s) end) %>
              <div class="alert alert-error text-sm">
                <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                <span>{msg}</span>
              </div>
              <button phx-click="retry" class="btn btn-primary btn-sm">
                <.icon name="hero-arrow-path" class="size-4" /> Retry
              </button>
            <% end %>

            <%= if @admin_credentials && all_done?(@progress) do %>
              <div class="alert alert-warning shadow-sm">
                <.icon name="hero-key" class="size-5" />
                <div class="flex-1">
                  <p class="font-semibold text-sm">
                    Initial ca_admin password for
                    <code class="font-mono">{@admin_credentials.username}</code>
                  </p>
                  <p class="font-mono text-sm mt-1">{@admin_credentials.password}</p>
                  <p class="text-xs text-base-content/60 mt-1">
                    Copy this now — it will not be shown again. Send it to {@email} securely.
                  </p>
                </div>
                <button phx-click="dismiss_credentials" class="btn btn-ghost btn-xs">Dismiss</button>
              </div>
            <% end %>

            <%= if all_done?(@progress) do %>
              <div class="divider my-0"></div>
              <div class="flex items-center gap-3">
                <div class="flex items-center justify-center w-10 h-10 rounded-lg bg-success/10">
                  <.icon name="hero-check-circle" class="size-6 text-success" />
                </div>
                <div>
                  <p class="text-sm font-semibold text-base-content">
                    Tenant "{@name}" is ready on port <code class="font-mono">{@beam_info && @beam_info.port}</code>.
                  </p>
                  <p class="text-xs text-base-content/60 mt-0.5">
                    Node: <code class="font-mono">{@beam_info && @beam_info.node}</code>
                  </p>
                </div>
              </div>

              <div class="flex gap-3 pt-1">
                <.link navigate={"/tenants/#{@tenant.id}"} class="btn btn-primary btn-sm">
                  <.icon name="hero-building-office" class="size-4" /> View Tenant
                </.link>
                <.link navigate="/tenants/new" class="btn btn-ghost btn-sm">
                  <.icon name="hero-plus" class="size-4" /> Create Another
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
