# User Profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-service `/profile` page to all three portals (Admin, CA, RA) where users can view/edit their profile and change their password.

**Architecture:** Each portal gets a `ProfileLive` LiveView with two card sections (profile info + change password). Backend functions are added to each engine's existing context module. The CA/RA portals use their engine client behaviour pattern; the admin portal calls `AdminManagement` directly.

**Tech Stack:** Phoenix LiveView, Ecto, Argon2, daisyUI/Tailwind CSS

---

## File Map

### Admin Portal
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex` — add `update_admin_profile/2`, `change_admin_password/3`
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/profile_live.ex` — ProfileLive LiveView
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex` — add `/profile` route
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex` — add sidebar link + is_active? clause

### CA Portal
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex` — add `update_user_profile/3`, `verify_and_change_password/4`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex` — add callbacks + delegators for `update_user_profile`, `verify_and_change_password`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex` — implement new callbacks
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex` — ProfileLive LiveView
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex` — add `/profile` route, redirect `/change-password`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts.ex` — add sidebar link + is_active? clause

### RA Portal
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex` — add `update_user_profile/3`, `verify_and_change_password/4`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex` — add callbacks + delegators for `update_user_profile`, `verify_and_change_password`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex` — implement new callbacks
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex` — ProfileLive LiveView
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex` — add `/profile` route, redirect `/change-password`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex` — add sidebar link + is_active? clause

---

## Task 1: Admin Portal — Backend (AdminManagement)

**Files:**
- Modify: `src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex:59-68`

- [ ] **Step 1: Add `update_admin_profile/2` to AdminManagement**

Add after the existing `get_admin/1` function (line 61):

```elixir
def update_admin_profile(%PlatformAdmin{} = admin, attrs) do
  allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])

  admin
  |> PlatformAdmin.changeset(Map.merge(%{username: admin.username}, allowed))
  |> PlatformRepo.update()
end
```

Note: We merge `username: admin.username` because `PlatformAdmin.changeset/2` has `validate_required([:username, :display_name])` — we must keep the existing username in the cast to pass validation.

- [ ] **Step 2: Add `change_admin_password/3` to AdminManagement**

Add after `update_admin_profile/2`:

```elixir
def change_admin_password(%PlatformAdmin{} = admin, current_password, new_password) do
  if Argon2.verify_pass(current_password, admin.password_hash) do
    admin
    |> PlatformAdmin.password_changeset(%{password: new_password})
    |> PlatformRepo.update()
  else
    {:error, :invalid_current_password}
  end
end
```

- [ ] **Step 3: Verify compilation**

Run: `cd src/pki_platform_engine && mix compile --warnings-as-errors`
Expected: Compilation succeeds with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/pki_platform_engine/lib/pki_platform_engine/admin_management.ex
git commit -m "feat(admin): add update_admin_profile and change_admin_password to AdminManagement"
```

---

## Task 2: Admin Portal — ProfileLive LiveView

**Files:**
- Create: `src/pki_platform_portal/lib/pki_platform_portal_web/live/profile_live.ex`

- [ ] **Step 1: Create ProfileLive**

```elixir
defmodule PkiPlatformPortalWeb.ProfileLive do
  use PkiPlatformPortalWeb, :live_view

  alias PkiPlatformEngine.AdminManagement

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user
    admin = AdminManagement.get_admin(user["id"])

    {:ok,
     assign(socket,
       page_title: "Profile",
       admin: admin,
       profile_form: %{"display_name" => admin.display_name || "", "email" => admin.email || ""},
       password_form: %{"current_password" => "", "new_password" => "", "password_confirmation" => ""},
       profile_error: nil,
       password_error: nil
     )}
  end

  @impl true
  def handle_event("update_profile", %{"display_name" => display_name, "email" => email}, socket) do
    admin = socket.assigns.admin

    case AdminManagement.update_admin_profile(admin, %{display_name: display_name, email: email}) do
      {:ok, updated} ->
        {:noreply,
         socket
         |> assign(:admin, updated)
         |> assign(:profile_form, %{"display_name" => updated.display_name || "", "email" => updated.email || ""})
         |> assign(:profile_error, nil)
         |> assign(:current_user, Map.merge(socket.assigns.current_user, %{"display_name" => updated.display_name, "email" => updated.email}))
         |> put_flash(:info, "Profile updated successfully.")}

      {:error, changeset} ->
        error = format_changeset_error(changeset)
        {:noreply, assign(socket, :profile_error, error)}
    end
  end

  @impl true
  def handle_event("change_password", params, socket) do
    %{"current_password" => current, "new_password" => new_pw, "password_confirmation" => confirm} = params
    admin = socket.assigns.admin

    cond do
      String.length(new_pw) < 8 ->
        {:noreply, assign(socket, :password_error, "New password must be at least 8 characters.")}

      new_pw != confirm ->
        {:noreply, assign(socket, :password_error, "New password and confirmation do not match.")}

      true ->
        case AdminManagement.change_admin_password(admin, current, new_pw) do
          {:ok, updated} ->
            {:noreply,
             socket
             |> assign(:admin, updated)
             |> assign(:password_form, %{"current_password" => "", "new_password" => "", "password_confirmation" => ""})
             |> assign(:password_error, nil)
             |> put_flash(:info, "Password changed successfully.")}

          {:error, :invalid_current_password} ->
            {:noreply, assign(socket, :password_error, "Current password is incorrect.")}

          {:error, changeset} ->
            error = format_changeset_error(changeset)
            {:noreply, assign(socket, :password_error, error)}
        end
    end
  end

  defp format_changeset_error(%Ecto.Changeset{} = changeset) do
    Ecto.Changeset.traverse_errors(changeset, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map_join(", ", fn {field, errors} -> "#{field}: #{Enum.join(errors, ", ")}" end)
  end

  defp format_changeset_error(_), do: "An unexpected error occurred."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-2xl mx-auto space-y-6">
      <%!-- Profile Information Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-user-circle" class="size-4 inline -mt-0.5" /> Profile Information
          </h2>

          <%!-- Read-only fields --%>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <p class="text-sm text-base-content font-mono">{@admin.username}</p>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <span class="badge badge-sm badge-primary">{@admin.role}</span>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Status</label>
              <span class={["badge badge-sm", if(@admin.status == "active", do: "badge-success", else: "badge-warning")]}>
                {@admin.status}
              </span>
            </div>
          </div>

          <%= if @profile_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@profile_error}</span>
            </div>
          <% end %>

          <%!-- Editable fields --%>
          <form phx-submit="update_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input
                type="text"
                name="display_name"
                id="display_name"
                value={@profile_form["display_name"]}
                class="input input-bordered input-sm w-full"
                maxlength="100"
              />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input
                type="email"
                name="email"
                id="email"
                value={@profile_form["email"]}
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="md:col-span-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-check" class="size-4" /> Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Change Password Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-lock-closed" class="size-4 inline -mt-0.5" /> Change Password
          </h2>

          <%= if @password_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@password_error}</span>
            </div>
          <% end %>

          <form phx-submit="change_password" class="space-y-4">
            <div>
              <label for="current_password" class="block text-xs font-medium text-base-content/60 mb-1">Current Password</label>
              <input
                type="password"
                name="current_password"
                id="current_password"
                required
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="new_password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
                <input
                  type="password"
                  name="new_password"
                  id="new_password"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
              <div>
                <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  name="password_confirmation"
                  id="password_confirmation"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-lock-closed" class="size-4" /> Change Password
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Verify compilation**

Run: `cd src/pki_platform_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/live/profile_live.ex
git commit -m "feat(admin): add ProfileLive LiveView for admin portal"
```

---

## Task 3: Admin Portal — Router + Sidebar

**Files:**
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/router.ex:52-59`
- Modify: `src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex:41-45,118-122`

- [ ] **Step 1: Add `/profile` route to router**

In `router.ex`, add `live "/profile", ProfileLive` inside the `:authenticated` live_session (after line 58, before the closing `end`):

```elixir
    live_session :authenticated, on_mount: PkiPlatformPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/tenants", TenantsLive
      live "/tenants/new", TenantNewLive
      live "/tenants/:id", TenantDetailLive
      live "/system", SystemLive
      live "/admins", AdminsLive
      live "/profile", ProfileLive
    end
```

- [ ] **Step 2: Add Profile sidebar link in layouts.ex**

In `layouts.ex`, add a divider and profile link after the Admins link (after line 45):

```elixir
        <nav class="flex-1 px-2 py-3 space-y-0.5 overflow-y-auto">
          <.sidebar_link href="/" icon="hero-home" label="Dashboard" current={@page_title} />
          <.sidebar_link href="/tenants" icon="hero-building-office-2" label="Tenants" current={@page_title} />
          <.sidebar_link href="/system" icon="hero-server-stack" label="System" current={@page_title} />
          <.sidebar_link href="/admins" icon="hero-users" label="Admins" current={@page_title} />
          <div class="divider my-1 px-3"></div>
          <.sidebar_link href="/profile" icon="hero-user-circle" label="Profile" current={@page_title} />
        </nav>
```

- [ ] **Step 3: Add `is_active?` clause for Profile**

In `layouts.ex`, add a clause after line 122 (`defp is_active?("Admins", "Admins"), do: true`):

```elixir
  defp is_active?("Profile", "Profile"), do: true
```

- [ ] **Step 4: Verify compilation**

Run: `cd src/pki_platform_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/pki_platform_portal/lib/pki_platform_portal_web/router.ex src/pki_platform_portal/lib/pki_platform_portal_web/components/layouts.ex
git commit -m "feat(admin): add /profile route and sidebar navigation"
```

---

## Task 4: CA Portal — Backend (CaEngine UserManagement)

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/user_management.ex:182-215`

- [ ] **Step 1: Add `update_user_profile/3` to CaEngine.UserManagement**

Add after `update_user/3` (after line 204):

```elixir
@doc "Updates a user's display_name and/or email (self-service profile edit)."
@spec update_user_profile(String.t(), String.t(), map()) :: {:ok, CaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
def update_user_profile(tenant_id, user_id, attrs) do
  repo = TenantRepo.ca_repo(tenant_id)
  case repo.get(CaUser, user_id) do
    nil ->
      {:error, :not_found}

    user ->
      allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])
      user |> CaUser.update_changeset(allowed) |> repo.update()
  end
end
```

- [ ] **Step 2: Add `verify_and_change_password/4` to CaEngine.UserManagement**

Add after `update_user_profile/3`:

```elixir
@doc "Verifies the current password and updates to a new one."
@spec verify_and_change_password(String.t(), String.t(), String.t(), String.t()) ::
        {:ok, CaUser.t()} | {:error, :not_found | :invalid_current_password | Ecto.Changeset.t()}
def verify_and_change_password(tenant_id, user_id, current_password, new_password) do
  repo = TenantRepo.ca_repo(tenant_id)
  case repo.get(CaUser, user_id) do
    nil ->
      {:error, :not_found}

    user ->
      if Argon2.verify_pass(current_password, user.password_hash) do
        user
        |> CaUser.password_changeset(%{password: new_password, must_change_password: false})
        |> repo.update()
      else
        {:error, :invalid_current_password}
      end
  end
end
```

- [ ] **Step 3: Verify compilation**

Run: `cd src/pki_ca_engine && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/user_management.ex
git commit -m "feat(ca-engine): add update_user_profile and verify_and_change_password"
```

---

## Task 5: CA Portal — Engine Client (Behaviour + Mock)

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex:30-36,55-61`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex:210-267`

- [ ] **Step 1: Add callbacks to CaEngineClient behaviour**

In `ca_engine_client.ex`, add after the `@callback reset_password` line (line 36):

```elixir
@callback update_user_profile(String.t(), map(), opts()) :: {:ok, map()} | {:error, term()}
@callback verify_and_change_password(String.t(), String.t(), String.t(), opts()) :: {:ok, map()} | {:error, term()}
```

- [ ] **Step 2: Add delegator functions to CaEngineClient**

In `ca_engine_client.ex`, add after the `reset_password` delegator (line 61):

```elixir
def update_user_profile(user_id, attrs, opts \\ []), do: impl().update_user_profile(user_id, attrs, opts)
def verify_and_change_password(user_id, current_password, new_password, opts \\ []), do: impl().verify_and_change_password(user_id, current_password, new_password, opts)
```

- [ ] **Step 3: Implement in Mock**

In `mock.ex`, add before the `reset_password` implementation (before line 267):

```elixir
@impl true
def update_user_profile(user_id, attrs, _opts \\ []) do
  update_state(:users, fn users ->
    Enum.map(users, fn
      %{id: ^user_id} = user ->
        user
        |> Map.merge(Map.take(attrs, [:display_name, :email, "display_name", "email"]))

      user ->
        user
    end)
  end)

  {:ok, %{id: user_id, display_name: attrs[:display_name] || attrs["display_name"], email: attrs[:email] || attrs["email"]}}
end

@impl true
def verify_and_change_password(_user_id, _current_password, _new_password, _opts \\ []) do
  {:ok, %{}}
end
```

- [ ] **Step 4: Verify compilation**

Run: `cd src/pki_ca_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client.ex src/pki_ca_portal/lib/pki_ca_portal/ca_engine_client/mock.ex
git commit -m "feat(ca-portal): add update_user_profile and verify_and_change_password to engine client"
```

---

## Task 6: CA Portal — ProfileLive LiveView

**Files:**
- Create: `src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex`

- [ ] **Step 1: Create ProfileLive**

```elixir
defmodule PkiCaPortalWeb.ProfileLive do
  use PkiCaPortalWeb, :live_view

  alias PkiCaPortal.CaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {:ok,
     assign(socket,
       page_title: "Profile",
       profile_form: %{"display_name" => user[:display_name] || user["display_name"] || "", "email" => user[:email] || user["email"] || ""},
       password_form: %{"current_password" => "", "new_password" => "", "password_confirmation" => ""},
       profile_error: nil,
       password_error: nil
     )}
  end

  @impl true
  def handle_event("update_profile", %{"display_name" => display_name, "email" => email}, socket) do
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    case CaEngineClient.update_user_profile(user_id, %{display_name: display_name, email: email}, opts) do
      {:ok, _updated} ->
        updated_user = user
          |> Map.put(:display_name, display_name)
          |> Map.put("display_name", display_name)
          |> Map.put(:email, email)
          |> Map.put("email", email)

        {:noreply,
         socket
         |> assign(:current_user, updated_user)
         |> assign(:profile_form, %{"display_name" => display_name, "email" => email})
         |> assign(:profile_error, nil)
         |> put_flash(:info, "Profile updated successfully.")}

      {:error, reason} ->
        {:noreply, assign(socket, :profile_error, format_error(reason))}
    end
  end

  @impl true
  def handle_event("change_password", params, socket) do
    %{"current_password" => current, "new_password" => new_pw, "password_confirmation" => confirm} = params
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    cond do
      String.length(new_pw) < 8 ->
        {:noreply, assign(socket, :password_error, "New password must be at least 8 characters.")}

      new_pw != confirm ->
        {:noreply, assign(socket, :password_error, "New password and confirmation do not match.")}

      true ->
        case CaEngineClient.verify_and_change_password(user_id, current, new_pw, opts) do
          {:ok, _} ->
            {:noreply,
             socket
             |> assign(:password_form, %{"current_password" => "", "new_password" => "", "password_confirmation" => ""})
             |> assign(:password_error, nil)
             |> put_flash(:info, "Password changed successfully.")}

          {:error, :invalid_current_password} ->
            {:noreply, assign(socket, :password_error, "Current password is incorrect.")}

          {:error, reason} ->
            {:noreply, assign(socket, :password_error, format_error(reason))}
        end
    end
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp format_error(:invalid_current_password), do: "Current password is incorrect."
  defp format_error(:not_found), do: "User not found."
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(_), do: "An unexpected error occurred."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-2xl mx-auto space-y-6">
      <%!-- Profile Information Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-user-circle" class="size-4 inline -mt-0.5" /> Profile Information
          </h2>

          <%!-- Read-only fields --%>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <p class="text-sm text-base-content font-mono">{@current_user[:username] || @current_user["username"]}</p>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <span class="badge badge-sm badge-primary">{@current_user[:role] || @current_user["role"]}</span>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Status</label>
              <span class="badge badge-sm badge-success">active</span>
            </div>
          </div>

          <%= if @profile_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@profile_error}</span>
            </div>
          <% end %>

          <%!-- Editable fields --%>
          <form phx-submit="update_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input
                type="text"
                name="display_name"
                id="display_name"
                value={@profile_form["display_name"]}
                class="input input-bordered input-sm w-full"
                maxlength="100"
              />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input
                type="email"
                name="email"
                id="email"
                value={@profile_form["email"]}
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="md:col-span-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-check" class="size-4" /> Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Change Password Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-lock-closed" class="size-4 inline -mt-0.5" /> Change Password
          </h2>

          <%= if @password_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@password_error}</span>
            </div>
          <% end %>

          <form phx-submit="change_password" class="space-y-4">
            <div>
              <label for="current_password" class="block text-xs font-medium text-base-content/60 mb-1">Current Password</label>
              <input
                type="password"
                name="current_password"
                id="current_password"
                required
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="new_password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
                <input
                  type="password"
                  name="new_password"
                  id="new_password"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
              <div>
                <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  name="password_confirmation"
                  id="password_confirmation"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-lock-closed" class="size-4" /> Change Password
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Verify compilation**

Run: `cd src/pki_ca_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/live/profile_live.ex
git commit -m "feat(ca-portal): add ProfileLive LiveView"
```

---

## Task 7: CA Portal — Router + Sidebar

**Files:**
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/router.ex:30-31,41-49`
- Modify: `src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts.ex:46-53,126-133`

- [ ] **Step 1: Redirect `/change-password` to `/profile` in router**

In `router.ex`, replace the existing `/change-password` routes (lines 30-31) with redirects:

```elixir
    get "/change-password", PasswordController, :redirect_to_profile
    put "/change-password", PasswordController, :update
```

Add to `PasswordController`:

Actually, simpler approach — just change the `edit` action to always redirect to `/profile`:

In `src/pki_ca_portal/lib/pki_ca_portal_web/controllers/password_controller.ex`, replace the `edit` function:

```elixir
def edit(conn, _params) do
  redirect(conn, to: "/profile")
end
```

- [ ] **Step 2: Add `/profile` route**

In `router.ex`, add `live "/profile", ProfileLive` to the authenticated live_session (after line 48):

```elixir
    live_session :authenticated, on_mount: PkiCaPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/users", UsersLive
      live "/keystores", KeystoresLive
      live "/ceremony", CeremonyLive
      live "/ca-instances", CaInstancesLive
      live "/audit-log", AuditLogLive
      live "/quick-setup", QuickSetupLive
      live "/profile", ProfileLive
    end
```

- [ ] **Step 3: Add Profile sidebar link in layouts.ex**

In `layouts.ex`, add a profile link after the Quick Setup divider section (after line 53):

```elixir
          <.sidebar_link href="/quick-setup" icon="hero-beaker" label="Quick Setup" current={@page_title} />
          <.sidebar_link href="/profile" icon="hero-user-circle" label="Profile" current={@page_title} />
```

- [ ] **Step 4: Add `is_active?` clause for Profile**

In `layouts.ex`, add after line 132 (`defp is_active?("Quick Setup", "Quick Setup"), do: true`):

```elixir
  defp is_active?("Profile", "Profile"), do: true
```

- [ ] **Step 5: Verify compilation**

Run: `cd src/pki_ca_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/pki_ca_portal/lib/pki_ca_portal_web/router.ex src/pki_ca_portal/lib/pki_ca_portal_web/components/layouts.ex src/pki_ca_portal/lib/pki_ca_portal_web/controllers/password_controller.ex
git commit -m "feat(ca-portal): add /profile route, sidebar link, redirect /change-password"
```

---

## Task 8: RA Portal — Backend (RaEngine UserManagement)

**Files:**
- Modify: `src/pki_ra_engine/lib/pki_ra_engine/user_management.ex:159-181`

- [ ] **Step 1: Add `update_user_profile/3` to RaEngine.UserManagement**

Add after `update_user/3` (after line 171):

```elixir
@doc "Updates a user's display_name and/or email (self-service profile edit)."
@spec update_user_profile(String.t(), String.t(), map()) :: {:ok, RaUser.t()} | {:error, :not_found | Ecto.Changeset.t()}
def update_user_profile(tenant_id, user_id, attrs) do
  repo = TenantRepo.ra_repo(tenant_id)
  case repo.get(RaUser, user_id) do
    nil ->
      {:error, :not_found}

    user ->
      allowed = Map.take(attrs, [:display_name, :email, "display_name", "email"])
      user |> RaUser.changeset(allowed) |> repo.update()
  end
end
```

- [ ] **Step 2: Add `verify_and_change_password/4` to RaEngine.UserManagement**

Add after `update_user_profile/3`:

```elixir
@doc "Verifies the current password and updates to a new one."
@spec verify_and_change_password(String.t(), String.t(), String.t(), String.t()) ::
        {:ok, RaUser.t()} | {:error, :not_found | :invalid_current_password | Ecto.Changeset.t()}
def verify_and_change_password(tenant_id, user_id, current_password, new_password) do
  repo = TenantRepo.ra_repo(tenant_id)
  case repo.get(RaUser, user_id) do
    nil ->
      {:error, :not_found}

    user ->
      if Argon2.verify_pass(current_password, user.password_hash) do
        user
        |> RaUser.password_changeset(%{password: new_password, must_change_password: false})
        |> repo.update()
      else
        {:error, :invalid_current_password}
      end
  end
end
```

- [ ] **Step 3: Verify compilation**

Run: `cd src/pki_ra_engine && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 4: Commit**

```bash
git add src/pki_ra_engine/lib/pki_ra_engine/user_management.ex
git commit -m "feat(ra-engine): add update_user_profile and verify_and_change_password"
```

---

## Task 9: RA Portal — Engine Client (Behaviour + Mock)

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex:40-41,70-71`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex:499-506`

- [ ] **Step 1: Add callbacks to RaEngineClient behaviour**

In `ra_engine_client.ex`, add after the `@callback reset_password` line (line 40):

```elixir
@callback update_user_profile(String.t(), map(), keyword()) :: {:ok, map()} | {:error, term()}
@callback verify_and_change_password(String.t(), String.t(), String.t(), keyword()) :: {:ok, map()} | {:error, term()}
```

- [ ] **Step 2: Add delegator functions to RaEngineClient**

In `ra_engine_client.ex`, add after the `reset_password` delegator (line 71):

```elixir
def update_user_profile(user_id, attrs, opts \\ []), do: impl().update_user_profile(user_id, attrs, opts)
def verify_and_change_password(user_id, current_password, new_password, opts \\ []), do: impl().verify_and_change_password(user_id, current_password, new_password, opts)
```

- [ ] **Step 3: Implement in Mock**

In `mock.ex`, add before the `reset_password` implementation (before line 505):

```elixir
@impl true
def update_user_profile(user_id, attrs, _opts \\ []) do
  update_state(:users, fn users ->
    Enum.map(users, fn
      %{id: ^user_id} = user ->
        user
        |> Map.merge(Map.take(attrs, [:display_name, :email, "display_name", "email"]))

      user ->
        user
    end)
  end)

  {:ok, %{id: user_id, display_name: attrs[:display_name] || attrs["display_name"], email: attrs[:email] || attrs["email"]}}
end

@impl true
def verify_and_change_password(_user_id, _current_password, _new_password, _opts \\ []) do
  {:ok, %{}}
end
```

- [ ] **Step 4: Verify compilation**

Run: `cd src/pki_ra_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 5: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client.ex src/pki_ra_portal/lib/pki_ra_portal/ra_engine_client/mock.ex
git commit -m "feat(ra-portal): add update_user_profile and verify_and_change_password to engine client"
```

---

## Task 10: RA Portal — ProfileLive LiveView

**Files:**
- Create: `src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex`

- [ ] **Step 1: Create ProfileLive**

```elixir
defmodule PkiRaPortalWeb.ProfileLive do
  use PkiRaPortalWeb, :live_view

  alias PkiRaPortal.RaEngineClient

  @impl true
  def mount(_params, _session, socket) do
    user = socket.assigns.current_user

    {:ok,
     assign(socket,
       page_title: "Profile",
       profile_form: %{"display_name" => user[:display_name] || user["display_name"] || "", "email" => user[:email] || user["email"] || ""},
       password_form: %{"current_password" => "", "new_password" => "", "password_confirmation" => ""},
       profile_error: nil,
       password_error: nil
     )}
  end

  @impl true
  def handle_event("update_profile", %{"display_name" => display_name, "email" => email}, socket) do
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    case RaEngineClient.update_user_profile(user_id, %{display_name: display_name, email: email}, opts) do
      {:ok, _updated} ->
        updated_user = user
          |> Map.put(:display_name, display_name)
          |> Map.put("display_name", display_name)
          |> Map.put(:email, email)
          |> Map.put("email", email)

        {:noreply,
         socket
         |> assign(:current_user, updated_user)
         |> assign(:profile_form, %{"display_name" => display_name, "email" => email})
         |> assign(:profile_error, nil)
         |> put_flash(:info, "Profile updated successfully.")}

      {:error, reason} ->
        {:noreply, assign(socket, :profile_error, format_error(reason))}
    end
  end

  @impl true
  def handle_event("change_password", params, socket) do
    %{"current_password" => current, "new_password" => new_pw, "password_confirmation" => confirm} = params
    user = socket.assigns.current_user
    user_id = user[:id] || user["id"]
    opts = tenant_opts(socket)

    cond do
      String.length(new_pw) < 8 ->
        {:noreply, assign(socket, :password_error, "New password must be at least 8 characters.")}

      new_pw != confirm ->
        {:noreply, assign(socket, :password_error, "New password and confirmation do not match.")}

      true ->
        case RaEngineClient.verify_and_change_password(user_id, current, new_pw, opts) do
          {:ok, _} ->
            {:noreply,
             socket
             |> assign(:password_form, %{"current_password" => "", "new_password" => "", "password_confirmation" => ""})
             |> assign(:password_error, nil)
             |> put_flash(:info, "Password changed successfully.")}

          {:error, :invalid_current_password} ->
            {:noreply, assign(socket, :password_error, "Current password is incorrect.")}

          {:error, reason} ->
            {:noreply, assign(socket, :password_error, format_error(reason))}
        end
    end
  end

  defp tenant_opts(socket) do
    case socket.assigns[:tenant_id] do
      nil -> []
      tid -> [tenant_id: tid]
    end
  end

  defp format_error(:invalid_current_password), do: "Current password is incorrect."
  defp format_error(:not_found), do: "User not found."
  defp format_error(reason) when is_binary(reason), do: reason
  defp format_error(_), do: "An unexpected error occurred."

  @impl true
  def render(assigns) do
    ~H"""
    <div class="max-w-2xl mx-auto space-y-6">
      <%!-- Profile Information Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-user-circle" class="size-4 inline -mt-0.5" /> Profile Information
          </h2>

          <%!-- Read-only fields --%>
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Username</label>
              <p class="text-sm text-base-content font-mono">{@current_user[:username] || @current_user["username"]}</p>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Role</label>
              <span class="badge badge-sm badge-primary">{@current_user[:role] || @current_user["role"]}</span>
            </div>
            <div>
              <label class="block text-xs font-medium text-base-content/60 mb-1">Status</label>
              <span class="badge badge-sm badge-success">active</span>
            </div>
          </div>

          <%= if @profile_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@profile_error}</span>
            </div>
          <% end %>

          <%!-- Editable fields --%>
          <form phx-submit="update_profile" class="grid grid-cols-1 md:grid-cols-2 gap-4 items-end">
            <div>
              <label for="display_name" class="block text-xs font-medium text-base-content/60 mb-1">Display Name</label>
              <input
                type="text"
                name="display_name"
                id="display_name"
                value={@profile_form["display_name"]}
                class="input input-bordered input-sm w-full"
                maxlength="100"
              />
            </div>
            <div>
              <label for="email" class="block text-xs font-medium text-base-content/60 mb-1">Email</label>
              <input
                type="email"
                name="email"
                id="email"
                value={@profile_form["email"]}
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="md:col-span-2">
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-check" class="size-4" /> Save Changes
              </button>
            </div>
          </form>
        </div>
      </div>

      <%!-- Change Password Card --%>
      <div class="card bg-base-100 shadow-sm border border-base-300">
        <div class="card-body">
          <h2 class="text-sm font-semibold text-base-content mb-4">
            <.icon name="hero-lock-closed" class="size-4 inline -mt-0.5" /> Change Password
          </h2>

          <%= if @password_error do %>
            <div class="alert alert-error text-sm mb-4">
              <.icon name="hero-exclamation-circle" class="size-4" />
              <span>{@password_error}</span>
            </div>
          <% end %>

          <form phx-submit="change_password" class="space-y-4">
            <div>
              <label for="current_password" class="block text-xs font-medium text-base-content/60 mb-1">Current Password</label>
              <input
                type="password"
                name="current_password"
                id="current_password"
                required
                class="input input-bordered input-sm w-full"
              />
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label for="new_password" class="block text-xs font-medium text-base-content/60 mb-1">New Password</label>
                <input
                  type="password"
                  name="new_password"
                  id="new_password"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
              <div>
                <label for="password_confirmation" class="block text-xs font-medium text-base-content/60 mb-1">Confirm New Password</label>
                <input
                  type="password"
                  name="password_confirmation"
                  id="password_confirmation"
                  required
                  minlength="8"
                  class="input input-bordered input-sm w-full"
                />
              </div>
            </div>
            <div>
              <button type="submit" class="btn btn-primary btn-sm">
                <.icon name="hero-lock-closed" class="size-4" /> Change Password
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
    """
  end
end
```

- [ ] **Step 2: Verify compilation**

Run: `cd src/pki_ra_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/live/profile_live.ex
git commit -m "feat(ra-portal): add ProfileLive LiveView"
```

---

## Task 11: RA Portal — Router + Sidebar

**Files:**
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/router.ex:30-31,41-49`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/password_controller.ex:4-9`
- Modify: `src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex:42-48`

- [ ] **Step 1: Redirect `/change-password` to `/profile`**

In `src/pki_ra_portal/lib/pki_ra_portal_web/controllers/password_controller.ex`, replace the `edit` function:

```elixir
def edit(conn, _params) do
  redirect(conn, to: "/profile")
end
```

- [ ] **Step 2: Add `/profile` route to router**

In `router.ex`, add `live "/profile", ProfileLive` to the authenticated live_session (after line 48):

```elixir
    live_session :authenticated, on_mount: PkiRaPortalWeb.Live.AuthHook do
      live "/", DashboardLive
      live "/ra-instances", RaInstancesLive
      live "/users", UsersLive
      live "/csrs", CsrsLive
      live "/cert-profiles", CertProfilesLive
      live "/service-configs", ServiceConfigsLive
      live "/api-keys", ApiKeysLive
      live "/profile", ProfileLive
    end
```

- [ ] **Step 3: Add Profile sidebar link**

In `layouts.ex`, add a divider and profile link after the API Keys link (after line 48):

```elixir
          <.sidebar_link href="/api-keys" icon="hero-key" label="API Keys" current={@page_title} />
          <div class="divider my-1 px-3"></div>
          <.sidebar_link href="/profile" icon="hero-user-circle" label="Profile" current={@page_title} />
```

- [ ] **Step 4: Add `is_active?` clause for Profile**

In `layouts.ex`, find the existing `is_active?` clauses and add:

```elixir
  defp is_active?("Profile", "Profile"), do: true
```

- [ ] **Step 5: Verify compilation**

Run: `cd src/pki_ra_portal && mix compile --warnings-as-errors`
Expected: Compilation succeeds.

- [ ] **Step 6: Commit**

```bash
git add src/pki_ra_portal/lib/pki_ra_portal_web/router.ex src/pki_ra_portal/lib/pki_ra_portal_web/components/layouts.ex src/pki_ra_portal/lib/pki_ra_portal_web/controllers/password_controller.ex
git commit -m "feat(ra-portal): add /profile route, sidebar link, redirect /change-password"
```

---

## Task 12: Smoke Test All Portals

- [ ] **Step 1: Compile all portals**

Run each in sequence:
```bash
cd src/pki_platform_portal && mix compile --warnings-as-errors
cd src/pki_ca_portal && mix compile --warnings-as-errors
cd src/pki_ra_portal && mix compile --warnings-as-errors
```

Expected: All compile without warnings or errors.

- [ ] **Step 2: Verify routes are registered**

```bash
cd src/pki_platform_portal && mix phx.routes | grep profile
cd src/pki_ca_portal && mix phx.routes | grep profile
cd src/pki_ra_portal && mix phx.routes | grep profile
```

Expected: Each shows a `/profile` LiveView route.
