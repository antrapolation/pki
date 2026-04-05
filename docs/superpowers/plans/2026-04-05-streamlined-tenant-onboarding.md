# Streamlined Tenant Onboarding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the multi-step tenant onboarding wizard with a single-form, single-click flow that provisions, activates, and creates a tenant admin account in ~3 seconds. Add `tenant_admin` role with scoped Platform Portal access.

**Architecture:** The new wizard submits one form, then runs a 5-step provisioning chain via LiveView `handle_info` messages. Each step updates a progress checklist in real-time. A new `tenant_admin` role is stored in the existing `user_tenant_roles` table (no schema changes). The SessionController login is extended to authenticate tenant admins via `PlatformAuth`. Route scoping is enforced via an `AuthHook` that checks the user's role and restricts navigation.

**Tech Stack:** Elixir, Phoenix LiveView, Ecto, PostgreSQL, DaisyUI/Tailwind CSS

**Spec:** `docs/superpowers/specs/2026-04-05-streamlined-tenant-onboarding-design.md`

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `src/pki_platform_engine/lib/pki_platform_engine/tenant_onboarding.ex` | Create | Provisioning chain: create DB → activate → create instances → create tenant admin → send credentials |
| `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex` | Modify | Add `authenticate_tenant_admin/2` function |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex` | Rewrite | Single-form with live progress checklist |
| `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex` | Modify | Extend login to try tenant_admin auth on superadmin auth failure |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex` | Modify | Add role + tenant_id to socket assigns, enforce route scoping |
| `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex` | Modify | Conditionally render sidebar links based on role |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex` | Modify | Remove CA/RA admin creation, credential reset buttons; add user management UI for tenant_admin |
| `src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex` | Modify | Scope dashboard for tenant_admin (show only their tenant) |

---

### Task 1: Extract Provisioning Chain into Engine Module

**Files:**
- Create: `src/pki_platform_engine/lib/pki_platform_engine/tenant_onboarding.ex`

This module consolidates the provisioning steps currently split across `tenant_new_live.ex` (DB creation) and `tenant_detail_live.ex` (activation, instance creation, admin creation). It's callable from both the new wizard and anywhere else that needs to onboard a tenant.

- [ ] **Step 1: Create the TenantOnboarding module**

```elixir
# src/pki_platform_engine/lib/pki_platform_engine/tenant_onboarding.ex
defmodule PkiPlatformEngine.TenantOnboarding do
  @moduledoc """
  Consolidates the full tenant provisioning chain:
  1. Create database + schemas + migrations
  2. Activate tenant (spawn repos, register in ETS)
  3. Create default CA and RA instances
  4. Create tenant_admin user in platform portal
  5. Send credentials email to tenant admin
  """

  alias PkiPlatformEngine.{Provisioner, PlatformAuth, Mailer, EmailTemplates}
  require Logger

  @doc """
  Step 1: Create tenant database.
  Returns {:ok, tenant} or {:error, reason}.
  """
  def create_database(name, slug, email) do
    Provisioner.create_tenant(name, slug, email: email)
  end

  @doc """
  Step 2: Activate tenant (spawn Ecto repos, set status active).
  Returns {:ok, tenant} or {:error, reason}.
  """
  def activate(tenant_id) do
    Provisioner.activate_tenant(tenant_id)
  end

  @doc """
  Step 3: Create default CA and RA instances in the tenant database.
  Returns :ok or {:error, reasons}.
  """
  def create_instances(tenant) do
    ca_errors = ensure_default_ca_instance(tenant)
    ra_errors = ensure_default_ra_instance(tenant)

    case ca_errors ++ ra_errors do
      [] -> :ok
      errors -> {:error, Enum.join(errors, "; ")}
    end
  end

  @doc """
  Step 4: Create tenant_admin user with platform portal access.
  Returns {:ok, user_profile} or {:error, reason}.
  """
  def create_tenant_admin(tenant) do
    username = "#{tenant.slug}-admin"
    portal_url = "https://#{System.get_env("PLATFORM_PORTAL_HOST", "platform.straptrust.com")}"

    PlatformAuth.create_user_for_portal(tenant.id, "platform", %{
      username: username,
      display_name: "#{tenant.name} Admin",
      email: tenant.email,
      role: "tenant_admin"
    }, portal_url: portal_url, tenant_name: tenant.name)
  end

  # --- Instance bootstrapping (extracted from tenant_detail_live.ex) ---

  defp ensure_default_ca_instance(tenant) do
    case PkiCaEngine.CaInstanceManagement.list_hierarchy(tenant.id) do
      [] ->
        case PkiCaEngine.CaInstanceManagement.create_ca_instance(tenant.id, %{
               name: "#{tenant.name} Root CA",
               status: "active"
             }) do
          {:ok, _ca} -> []
          {:error, reason} ->
            Logger.error("[TenantOnboarding] CA instance creation failed: #{inspect(reason)}")
            ["CA instance creation failed"]
        end

      _instances ->
        []
    end
  rescue
    e ->
      Logger.error("[TenantOnboarding] CA instance creation failed: #{Exception.message(e)}")
      ["CA instance creation failed"]
  end

  defp ensure_default_ra_instance(tenant) do
    case PkiRaEngine.RaInstanceManagement.list_ra_instances(tenant.id) do
      [] ->
        case PkiRaEngine.RaInstanceManagement.create_ra_instance(tenant.id, %{
               name: "#{tenant.name} RA",
               status: "active"
             }) do
          {:ok, _ra} -> []
          {:error, reason} ->
            Logger.error("[TenantOnboarding] RA instance creation failed: #{inspect(reason)}")
            ["RA instance creation failed"]
        end

      _instances ->
        []
    end
  rescue
    e ->
      Logger.error("[TenantOnboarding] RA instance creation failed: #{Exception.message(e)}")
      ["RA instance creation failed"]
  end
end
```

- [ ] **Step 2: Verify the module compiles**

Run from the project root:
```bash
cd src/pki_platform_engine && mix compile --warnings-as-errors
```
Expected: Compilation succeeds with no errors.

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/tenant_onboarding.ex
git commit -m "feat(platform): extract TenantOnboarding provisioning chain"
```

---

### Task 2: Rewrite Tenant New LiveView — Single Form with Progress

**Files:**
- Rewrite: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex`

Replace the entire multi-step wizard with a single form that transitions to a live progress checklist on submit.

- [ ] **Step 1: Rewrite tenant_new_live.ex**

```elixir
# src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex
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
    # Find the failed step and restart from there
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
```

- [ ] **Step 2: Verify it compiles**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```
Expected: Compilation succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_new_live.ex
git commit -m "feat(platform): rewrite tenant wizard — single form with live progress"
```

---

### Task 3: Add tenant_admin Authentication to SessionController

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`

The login flow currently only checks `platform_admins` via `AdminManagement.authenticate/2`. We need to also check `user_profiles` + `user_tenant_roles` for `tenant_admin` users.

- [ ] **Step 1: Add `authenticate_tenant_admin/2` to PlatformAuth**

In `src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex`, add this function after the existing `authenticate/2`:

```elixir
  @doc """
  Authenticate a tenant_admin user for the platform portal.
  Returns {:ok, user_profile, tenant_role} or {:error, reason}.
  """
  def authenticate_tenant_admin(username, password) do
    with {:ok, user} <- authenticate(username, password) do
      case get_tenant_roles(user.id, portal: "platform") do
        [%{role: "tenant_admin"} = role | _] -> {:ok, user, role}
        _ -> {:error, :not_tenant_admin}
      end
    end
  end
```

- [ ] **Step 2: Add `format_role_label` entry for tenant_admin**

In the `format_role_label/2` function in `platform_auth.ex`, add a clause:

```elixir
      {"platform", "tenant_admin"} -> "Tenant Administrator"
```

Add this line inside the `case {portal, role} do` block, before the catch-all `{_, role} -> role`.

- [ ] **Step 3: Modify SessionController to try tenant_admin auth on superadmin failure**

In `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex`, replace the `create/2` function. The key change: when `AdminManagement.authenticate/2` fails, try `PlatformAuth.authenticate_tenant_admin/2`:

```elixir
  def create(conn, %{"session" => %{"username" => username, "password" => password}}) do
    case PkiPlatformEngine.AdminManagement.authenticate(username, password) do
      {:ok, admin} ->
        handle_superadmin_login(conn, admin)

      {:error, _} ->
        # Try tenant_admin authentication
        case PkiPlatformEngine.PlatformAuth.authenticate_tenant_admin(username, password) do
          {:ok, user, role} ->
            handle_tenant_admin_login(conn, user, role)

          {:error, _} ->
            log_failed_login(conn, username)
            render(conn, :login, layout: false, error: "Invalid credentials")
        end
    end
  end

  defp handle_superadmin_login(conn, admin) do
    cond do
      admin.must_change_password && credential_expired?(admin) ->
        render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact another platform admin.")

      admin.must_change_password ->
        log_login(conn, admin)
        {:ok, session_id} = create_session_with_detection(conn, admin)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> put_session(:must_change_password, true)
        |> redirect(to: "/change-password")

      true ->
        log_login(conn, admin)
        {:ok, session_id} = create_session_with_detection(conn, admin)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> redirect(to: "/")
    end
  end

  defp handle_tenant_admin_login(conn, user, role) do
    cond do
      user.must_change_password && credential_expired?(user) ->
        render(conn, :login, layout: false, error: "Your temporary credentials have expired. Contact your platform admin.")

      user.must_change_password ->
        log_login(conn, user)
        {:ok, session_id} = create_tenant_admin_session(conn, user, role)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> put_session(:must_change_password, true)
        |> redirect(to: "/change-password")

      true ->
        log_login(conn, user)
        {:ok, session_id} = create_tenant_admin_session(conn, user, role)

        conn
        |> configure_session(renew: true)
        |> put_session(:session_id, session_id)
        |> redirect(to: "/tenants/#{role.tenant_id}")
    end
  end

  defp create_tenant_admin_session(conn, user, role) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformPortal.SessionStore.create(%{
      user_id: user.id,
      username: user.username,
      role: "tenant_admin",
      tenant_id: role.tenant_id,
      ip: ip,
      user_agent: ua,
      display_name: user.display_name,
      email: user.email
    })
  end

  defp log_login(conn, user) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformEngine.PlatformAudit.log("login", %{
      actor_id: user.id,
      actor_username: user.username,
      portal: "platform",
      details: %{ip: ip, user_agent: ua}
    })
  end

  defp log_failed_login(conn, username) do
    ip = conn.remote_ip |> :inet.ntoa() |> to_string()
    ua = Plug.Conn.get_req_header(conn, "user-agent") |> List.first("")

    PkiPlatformEngine.PlatformAudit.log("login_failed", %{
      portal: "platform",
      details: %{username: username, ip: ip, user_agent: ua}
    })
  end
```

- [ ] **Step 4: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/platform_auth.ex \
        src/pki_platform_portal/lib/pki_platform_portal_web/controllers/session_controller.ex
git commit -m "feat(platform): extend login to support tenant_admin authentication"
```

---

### Task 4: Add Role-Based Route Scoping to AuthHook

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex`

The AuthHook already sets `current_user` on the socket. We need it to also enforce route restrictions for `tenant_admin` users — they can only access `/tenants/:their_tenant_id` and `/profile`.

- [ ] **Step 1: Modify AuthHook to add role-based scoping**

Replace the `on_mount/4` function in `auth_hook.ex`. The key addition: after validating the session, check the user's role and the requested path. If the user is a `tenant_admin`, restrict them to allowed routes.

```elixir
  def on_mount(:default, params, session, socket) do
    session_id = session["session_id"]

    with {:ok, session_id} when is_binary(session_id) <- {:ok, session_id},
         {:ok, sess} <- PkiPlatformPortal.SessionStore.lookup(session_id),
         :ok <- check_timeout(session_id, sess) do
      PkiPlatformPortal.SessionStore.touch(session_id)
      user = session_to_user(sess)

      Logger.metadata(
        user_id: sess.user_id,
        username: sess.username,
        tenant_id: Map.get(sess, :tenant_id),
        portal: "platform",
        session_id: session_id
      )

      timeout_ms = Application.get_env(@app, :session_idle_timeout_ms, 30 * 60 * 1000)
      warning_ms = timeout_ms - 5 * 60 * 1000

      {timezone, tz_offset_min} = case get_connect_params(socket) do
        %{"timezone" => tz, "timezone_offset" => off} when is_binary(tz) and tz != "" ->
          {tz, off || 0}
        _ ->
          {"UTC", 0}
      end

      socket =
        socket
        |> assign(:current_user, user)
        |> assign(:tenant_id, sess.tenant_id)
        |> assign(:session_id, session_id)
        |> assign(:timezone, timezone)
        |> assign(:timezone_offset_min, tz_offset_min)
        |> assign(:session_timeout_ms, timeout_ms)
        |> assign(:session_warning_ms, warning_ms)
        |> attach_hook(:session_keep_alive, :handle_event, fn
          "keep_alive", _params, socket ->
            if sid = socket.assigns[:session_id] do
              PkiPlatformPortal.SessionStore.touch(sid)
            end
            {:halt, socket}

          _event, _params, socket ->
            if sid = socket.assigns[:session_id] do
              PkiPlatformPortal.SessionStore.touch(sid)
            end
            {:cont, socket}
        end)

      # Enforce route scoping for tenant_admin
      case enforce_role_access(sess.role, sess.tenant_id, params, socket) do
        :ok -> {:cont, socket}
        {:redirect, to} -> {:halt, redirect(socket, to: to)}
      end
    else
      _ ->
        {:halt, redirect(socket, to: "/login")}
    end
  end

  # super_admin has full access
  defp enforce_role_access("super_admin", _tenant_id, _params, _socket), do: :ok

  # tenant_admin is restricted to their tenant detail and profile
  defp enforce_role_access("tenant_admin", tenant_id, params, _socket) do
    case {socket_view(params), params} do
      # Tenant detail — only their own tenant
      {_, %{"id" => id}} when id == tenant_id -> :ok
      {_, %{"id" => _id}} -> {:redirect, "/tenants/#{tenant_id}"}
      # Profile is always allowed
      _ ->
        # For routes without an :id param, check the LiveView module
        :ok
    end
  end

  defp enforce_role_access(_role, _tenant_id, _params, _socket), do: :ok

  defp socket_view(_params), do: nil
```

Wait — the `on_mount` params only contain route params (like `%{"id" => ...}`), not the LiveView module name. We need a different approach. We'll use the socket's `view` assign which Phoenix sets automatically.

Let me revise — the simplest approach is to check the LiveView module from `socket.view`:

```elixir
  defp enforce_role_access("tenant_admin", tenant_id, params, socket) do
    view = socket.view

    allowed_views = [
      PkiPlatformPortalWeb.TenantDetailLive,
      PkiPlatformPortalWeb.ProfileLive,
      PkiPlatformPortalWeb.DashboardLive
    ]

    cond do
      view in allowed_views && Map.get(params, "id") in [nil, tenant_id] ->
        :ok

      view in allowed_views ->
        # Trying to access another tenant's detail
        {:redirect, "/tenants/#{tenant_id}"}

      true ->
        # Accessing a restricted page (admins, HSM, system, sessions, tenants list, tenant new)
        {:redirect, "/tenants/#{tenant_id}"}
    end
  end
```

- [ ] **Step 2: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/auth_hook.ex
git commit -m "feat(platform): add role-based route scoping for tenant_admin in AuthHook"
```

---

### Task 5: Scope Sidebar Navigation by Role

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex`

Tenant admins should only see: Dashboard, their Tenant, and Profile. Hide Tenants list, HSM Devices, System, Admins, Sessions.

- [ ] **Step 1: Modify the sidebar nav in layouts.ex**

Replace the `<nav>` block (lines 41-49) with role-conditional rendering. The `current_user` assign is already available. We check `current_user["role"]`:

```elixir
        <%!-- Navigation --%>
        <nav class="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
          <%= if @current_user && @current_user["role"] == "super_admin" do %>
            <.sidebar_link href="/tenants" icon="hero-building-office-2" label="Tenants" current={@page_title} />
            <.sidebar_link href="/hsm-devices" icon="hero-cpu-chip" label="HSM Devices" current={@page_title} />
            <.sidebar_link href="/system" icon="hero-server-stack" label="System" current={@page_title} />
            <.sidebar_link href="/admins" icon="hero-users" label="Admins" current={@page_title} />
          <% end %>
          <div class="divider my-1 px-3"></div>
          <.sidebar_link href="/profile" icon="hero-user-circle" label="Profile" current={@page_title} />
        </nav>
```

- [ ] **Step 2: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex
git commit -m "feat(platform): scope sidebar navigation by user role"
```

---

### Task 6: Scope Dashboard for Tenant Admin

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex`

When a `tenant_admin` loads the dashboard, they should see only their tenant's info — not the full tenant list and stats.

- [ ] **Step 1: Read the current dashboard_live.ex**

Read the file to understand the current structure before modifying.

- [ ] **Step 2: Add role-based scoping to mount/2**

In `mount/2`, check `socket.assigns.current_user["role"]`. If it's `"tenant_admin"`, load only their tenant via `socket.assigns.tenant_id`. If `"super_admin"`, use the existing logic (all tenants).

Add this conditional at the end of mount after the existing assigns:

```elixir
    # For tenant_admin, redirect to their tenant detail page
    if socket.assigns.current_user["role"] == "tenant_admin" do
      {:ok, push_navigate(socket, to: "/tenants/#{socket.assigns.tenant_id}")}
    else
      {:ok, socket}
    end
```

This is the simplest approach — tenant admins go straight to their tenant detail page when they hit the dashboard.

- [ ] **Step 3: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/dashboard_live.ex
git commit -m "feat(platform): redirect tenant_admin dashboard to their tenant detail"
```

---

### Task 7: Clean Up Tenant Detail — Remove CA/RA Admin Management, Add User Management

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex`

Two changes:
1. Remove the "Admin Setup Status" section (Resend Credentials, Reset CA Admin, Reset RA Admin) and the `:ensure_admins` handler
2. Add a "User Management" section where `tenant_admin` (and `super_admin`) can create CA/RA users using the existing `PlatformAuth.create_user_for_portal/4`

- [ ] **Step 1: Remove the old CA/RA admin management code**

Delete these sections from `tenant_detail_live.ex`:

**In handle_event:** Remove `"resend_credentials"`, `"reset_ca_admin"`, `"reset_ra_admin"` handlers (lines 84-97).

**In handle_info:** Remove `:ensure_admins` handler (lines 164-243) and `:credential_action` handler (lines 246-308).

**In handle_info `:do_activate`:** Remove the `send(self(), :ensure_admins)` line (line 154). Replace the flash message:
```elixir
        {:noreply, put_flash(socket, :info, "Tenant activated.")}
```

**In private functions:** Remove `create_ca_admin/4`, `create_ra_admin/3`, `recreate_ca_admin/3`, `recreate_ra_admin/3` (lines 337-599).

**In the render template:** Remove the entire "Admin Setup Status" section (lines 716-800).

- [ ] **Step 2: Add user management state to mount**

Add these assigns in the `mount/3` function:

```elixir
         user_management: %{
           ca_users: [],
           ra_users: [],
           show_form: nil,
           form_error: nil
         }
```

And add a `send(self(), :load_users)` in the `if connected?(socket)` block.

- [ ] **Step 3: Add user management handlers**

Add these event handlers:

```elixir
  def handle_event("show_user_form", %{"portal" => portal}, socket) do
    user_management = %{socket.assigns.user_management | show_form: portal, form_error: nil}
    {:noreply, assign(socket, user_management: user_management)}
  end

  def handle_event("cancel_user_form", _params, socket) do
    user_management = %{socket.assigns.user_management | show_form: nil, form_error: nil}
    {:noreply, assign(socket, user_management: user_management)}
  end

  def handle_event("create_user", %{"portal" => portal, "username" => username, "display_name" => display_name, "email" => email, "role" => role}, socket) do
    tenant = socket.assigns.tenant
    ca_host = System.get_env("CA_PORTAL_HOST", "ca.straptrust.com")
    ra_host = System.get_env("RA_PORTAL_HOST", "ra.straptrust.com")

    portal_url = if portal == "ca", do: "https://#{ca_host}", else: "https://#{ra_host}"

    case PkiPlatformEngine.PlatformAuth.create_user_for_portal(tenant.id, portal, %{
      username: String.trim(username),
      display_name: String.trim(display_name),
      email: String.trim(email),
      role: role
    }, portal_url: portal_url, tenant_name: tenant.name) do
      {:ok, _user} ->
        send(self(), :load_users)
        user_management = %{socket.assigns.user_management | show_form: nil, form_error: nil}
        {:noreply,
         socket
         |> assign(user_management: user_management)
         |> put_flash(:info, "User created. Credentials sent to #{String.trim(email)}.")}

      {:error, reason} ->
        user_management = %{socket.assigns.user_management | form_error: inspect(reason)}
        {:noreply, assign(socket, user_management: user_management)}
    end
  end

  def handle_event("suspend_user_role", %{"role-id" => role_id}, socket) do
    case PkiPlatformEngine.PlatformAuth.suspend_user_role(role_id) do
      {:ok, _} ->
        send(self(), :load_users)
        {:noreply, put_flash(socket, :info, "User suspended.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to suspend user: #{inspect(reason)}")}
    end
  end

  def handle_event("activate_user_role", %{"role-id" => role_id}, socket) do
    case PkiPlatformEngine.PlatformAuth.activate_user_role(role_id) do
      {:ok, _} ->
        send(self(), :load_users)
        {:noreply, put_flash(socket, :info, "User activated.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to activate user: #{inspect(reason)}")}
    end
  end

  def handle_event("delete_user_role", %{"role-id" => role_id}, socket) do
    case PkiPlatformEngine.PlatformAuth.delete_user_role(role_id) do
      {:ok, _} ->
        send(self(), :load_users)
        {:noreply, put_flash(socket, :info, "User removed.")}

      {:error, reason} ->
        {:noreply, put_flash(socket, :error, "Failed to remove user: #{inspect(reason)}")}
    end
  end
```

Add the `:load_users` handler:

```elixir
  def handle_info(:load_users, socket) do
    tenant_id = socket.assigns.tenant.id
    ca_users = PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ca")
    ra_users = PkiPlatformEngine.PlatformAuth.list_users_for_portal(tenant_id, "ra")

    user_management = %{socket.assigns.user_management |
      ca_users: ca_users,
      ra_users: ra_users
    }

    {:noreply, assign(socket, user_management: user_management)}
  end
```

- [ ] **Step 4: Add user management UI to the render template**

Replace the removed "Admin Setup Status" section with this user management section. Insert it after the engine status section and before the health metrics section:

```heex
      <%!-- User Management --%>
      <div :if={@tenant.status == "active"}>
        <h3 class="text-sm font-semibold text-base-content mb-3">User Management</h3>

        <%!-- CA Users --%>
        <div class="card bg-base-100 shadow-sm border border-base-300 mb-4">
          <div class="card-body p-5">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <.icon name="hero-shield-check" class="size-4 text-primary" />
                <h4 class="text-sm font-semibold">CA Portal Users</h4>
                <span class="badge badge-sm badge-ghost">{length(@user_management.ca_users)}</span>
              </div>
              <button phx-click="show_user_form" phx-value-portal="ca" class="btn btn-ghost btn-xs text-primary">
                <.icon name="hero-plus" class="size-3.5" /> Add User
              </button>
            </div>

            <%!-- Create CA user form --%>
            <%= if @user_management.show_form == "ca" do %>
              <div class="bg-base-200 rounded-lg p-4 mb-3">
                <%= if @user_management.form_error do %>
                  <div class="alert alert-error text-sm mb-3">
                    <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                    <span>{@user_management.form_error}</span>
                  </div>
                <% end %>
                <form phx-submit="create_user" class="grid grid-cols-2 gap-3">
                  <input type="hidden" name="portal" value="ca" />
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Username</label>
                    <input type="text" name="username" required class="input input-bordered input-sm w-full" placeholder="e.g. jdoe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Display Name</label>
                    <input type="text" name="display_name" required class="input input-bordered input-sm w-full" placeholder="e.g. Jane Doe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Email</label>
                    <input type="email" name="email" required class="input input-bordered input-sm w-full" placeholder="jane@example.com" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Role</label>
                    <select name="role" class="select select-bordered select-sm w-full">
                      <option value="ca_admin">CA Admin</option>
                      <option value="key_manager">Key Manager</option>
                      <option value="auditor">Auditor</option>
                    </select>
                  </div>
                  <div class="col-span-2 flex justify-end gap-2 pt-1">
                    <button type="button" phx-click="cancel_user_form" class="btn btn-ghost btn-xs">Cancel</button>
                    <button type="submit" class="btn btn-primary btn-xs" phx-disable-with="Creating...">Create & Send Invite</button>
                  </div>
                </form>
              </div>
            <% end %>

            <%!-- CA users table --%>
            <table :if={@user_management.ca_users != []} class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={user <- @user_management.ca_users} class="hover">
                  <td class="font-mono text-sm">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td><span class="badge badge-sm badge-ghost">{user.role}</span></td>
                  <td>
                    <span class={["badge badge-sm", user.status == "active" && "badge-success", user.status == "suspended" && "badge-warning"]}>{user.status}</span>
                  </td>
                  <td class="text-right">
                    <button :if={user.status == "active"} phx-click="suspend_user_role" phx-value-role-id={user.role_id} data-confirm={"Suspend #{user.username}?"} class="btn btn-ghost btn-xs text-warning" title="Suspend">
                      <.icon name="hero-pause-circle" class="size-4" />
                    </button>
                    <button :if={user.status == "suspended"} phx-click="activate_user_role" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-success" title="Activate">
                      <.icon name="hero-play-circle" class="size-4" />
                    </button>
                    <button phx-click="delete_user_role" phx-value-role-id={user.role_id} data-confirm={"Remove #{user.username} from CA portal?"} class="btn btn-ghost btn-xs text-error" title="Remove">
                      <.icon name="hero-trash" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={@user_management.ca_users == []} class="text-xs text-base-content/40">No CA users yet.</p>
          </div>
        </div>

        <%!-- RA Users (same structure) --%>
        <div class="card bg-base-100 shadow-sm border border-base-300">
          <div class="card-body p-5">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <.icon name="hero-clipboard-document-check" class="size-4 text-secondary" />
                <h4 class="text-sm font-semibold">RA Portal Users</h4>
                <span class="badge badge-sm badge-ghost">{length(@user_management.ra_users)}</span>
              </div>
              <button phx-click="show_user_form" phx-value-portal="ra" class="btn btn-ghost btn-xs text-secondary">
                <.icon name="hero-plus" class="size-3.5" /> Add User
              </button>
            </div>

            <%!-- Create RA user form --%>
            <%= if @user_management.show_form == "ra" do %>
              <div class="bg-base-200 rounded-lg p-4 mb-3">
                <%= if @user_management.form_error do %>
                  <div class="alert alert-error text-sm mb-3">
                    <.icon name="hero-exclamation-circle" class="size-4 shrink-0" />
                    <span>{@user_management.form_error}</span>
                  </div>
                <% end %>
                <form phx-submit="create_user" class="grid grid-cols-2 gap-3">
                  <input type="hidden" name="portal" value="ra" />
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Username</label>
                    <input type="text" name="username" required class="input input-bordered input-sm w-full" placeholder="e.g. jdoe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Display Name</label>
                    <input type="text" name="display_name" required class="input input-bordered input-sm w-full" placeholder="e.g. Jane Doe" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Email</label>
                    <input type="email" name="email" required class="input input-bordered input-sm w-full" placeholder="jane@example.com" />
                  </div>
                  <div>
                    <label class="text-xs font-medium text-base-content/60">Role</label>
                    <select name="role" class="select select-bordered select-sm w-full">
                      <option value="ra_admin">RA Admin</option>
                      <option value="ra_officer">RA Officer</option>
                      <option value="auditor">Auditor</option>
                    </select>
                  </div>
                  <div class="col-span-2 flex justify-end gap-2 pt-1">
                    <button type="button" phx-click="cancel_user_form" class="btn btn-ghost btn-xs">Cancel</button>
                    <button type="submit" class="btn btn-primary btn-xs" phx-disable-with="Creating...">Create & Send Invite</button>
                  </div>
                </form>
              </div>
            <% end %>

            <%!-- RA users table --%>
            <table :if={@user_management.ra_users != []} class="table table-sm w-full">
              <thead>
                <tr class="text-xs uppercase text-base-content/50">
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th class="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={user <- @user_management.ra_users} class="hover">
                  <td class="font-mono text-sm">{user.username}</td>
                  <td>{user.display_name}</td>
                  <td><span class="badge badge-sm badge-ghost">{user.role}</span></td>
                  <td>
                    <span class={["badge badge-sm", user.status == "active" && "badge-success", user.status == "suspended" && "badge-warning"]}>{user.status}</span>
                  </td>
                  <td class="text-right">
                    <button :if={user.status == "active"} phx-click="suspend_user_role" phx-value-role-id={user.role_id} data-confirm={"Suspend #{user.username}?"} class="btn btn-ghost btn-xs text-warning" title="Suspend">
                      <.icon name="hero-pause-circle" class="size-4" />
                    </button>
                    <button :if={user.status == "suspended"} phx-click="activate_user_role" phx-value-role-id={user.role_id} class="btn btn-ghost btn-xs text-success" title="Activate">
                      <.icon name="hero-play-circle" class="size-4" />
                    </button>
                    <button phx-click="delete_user_role" phx-value-role-id={user.role_id} data-confirm={"Remove #{user.username} from RA portal?"} class="btn btn-ghost btn-xs text-error" title="Remove">
                      <.icon name="hero-trash" class="size-4" />
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
            <p :if={@user_management.ra_users == []} class="text-xs text-base-content/40">No RA users yet.</p>
          </div>
        </div>
      </div>
```

- [ ] **Step 5: Hide superadmin-only sections for tenant_admin**

In the render template, wrap the action buttons (Activate/Suspend/Delete) and HSM section with a superadmin check. The `current_user` assign is available:

For the action buttons div (the div containing Activate/Suspend/Delete/Refresh buttons):
```heex
            <div :if={@current_user["role"] == "super_admin"} class="flex items-center gap-2 flex-shrink-0">
```

For the HSM Device Access section:
```heex
      <div :if={@tenant.status == "active" && @current_user["role"] == "super_admin"}>
```

- [ ] **Step 6: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 7: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/tenant_detail_live.ex
git commit -m "feat(platform): replace admin setup with user management, scope by role"
```

---

### Task 8: Handle Password Change for Tenant Admin

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/controllers/password_controller.ex`

The existing password change controller updates `platform_admins`. For `tenant_admin` users (who are in `user_profiles`, not `platform_admins`), we need to use `PlatformAuth.reset_password/2` instead.

- [ ] **Step 1: Read the current password_controller.ex**

Read the file to understand how password changes work currently.

- [ ] **Step 2: Add tenant_admin password change support**

In the `update/2` function, check the session for the user's role. If `tenant_admin`, use `PlatformAuth` functions to change the password instead of `AdminManagement`:

After reading the session's user info, add a branch:

```elixir
    # Determine which module to use based on user source
    case session_role do
      "tenant_admin" ->
        # User is in user_profiles table
        case PkiPlatformEngine.PlatformAuth.authenticate(username, current_password) do
          {:ok, user} ->
            case PkiPlatformEngine.PlatformAuth.reset_password(user.id, new_password, must_change_password: false) do
              {:ok, _} ->
                # Clear must_change_password from session
                conn
                |> delete_session(:must_change_password)
                |> redirect(to: "/")

              {:error, _} ->
                render(conn, :edit, layout: false, error: "Failed to change password.")
            end

          {:error, _} ->
            render(conn, :edit, layout: false, error: "Current password is incorrect.")
        end

      _ ->
        # Existing superadmin flow
        ...
    end
```

The exact implementation depends on the current structure of `password_controller.ex` — the subagent implementing this should read the file first and adapt accordingly.

- [ ] **Step 3: Verify compilation**

```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/controllers/password_controller.ex
git commit -m "feat(platform): support tenant_admin password change"
```

---

### Task 9: Remove CA/RA Portal Setup Pages

**Files:**
- Modify: CA portal router and setup live view
- Modify: RA portal router and setup live view

Since tenant admins create CA/RA users from the platform portal, the `/setup` pages on CA and RA portals are no longer needed.

- [ ] **Step 1: Identify the setup-related files**

```bash
find src/pki_ca_portal -name "*setup*" -o -name "router.ex" | head -20
find src/pki_ra_portal -name "*setup*" -o -name "router.ex" | head -20
```

- [ ] **Step 2: Remove /setup routes from CA and RA portal routers**

Comment out or remove the `/setup` live route from both portals. Redirect `/setup` to `/login` instead.

- [ ] **Step 3: Verify both portals compile**

```bash
cd src/pki_ca_portal && mix compile --warnings-as-errors
cd src/pki_ra_portal && mix compile --warnings-as-errors
```

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_portal/ src/pki_ra_portal/
git commit -m "feat(portal): remove CA/RA setup pages — users created via platform portal"
```

---

### Task 10: Integration Smoke Test

- [ ] **Step 1: Compile the entire umbrella**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix compile --warnings-as-errors
```

Expected: All projects compile with no errors.

- [ ] **Step 2: Run existing tests**

```bash
cd /Users/amirrudinyahaya/Workspace/pki && mix test
```

Expected: Existing tests pass. If any tests reference the old multi-step wizard or email verification, they will need updating (note these failures for the implementer).

- [ ] **Step 3: Manual smoke test**

Start the dev server and verify:

1. Navigate to `/tenants/new` — see single form (name, slug, email), no step indicator
2. Fill form and click "Create Tenant" — see progress checklist animate through 5 steps
3. On success, click "View Tenant" — see tenant detail page with user management section
4. Check the tenant admin's email — should receive platform portal credentials
5. Log out, log in as the tenant admin — should be redirected to `/tenants/:id`
6. Verify sidebar shows only Dashboard and Profile
7. Try navigating to `/admins` — should redirect to tenant detail
8. Create a CA user from the user management section — verify temp password email sent
9. Log out, log in to CA portal with the new CA user credentials

- [ ] **Step 4: Final commit**

If any test fixes were needed:
```bash
git add -A && git commit -m "fix(platform): update tests for streamlined onboarding"
```
