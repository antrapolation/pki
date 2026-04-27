# pki_tenant_web Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all verified gaps found by the code audit: add missing RBAC guards to three LiveViews, wire two stub wizard handlers to real pages, and add the missing `/activation` nav link.

**Architecture:** All fixes are in `pki_tenant_web` — no changes to engine apps. RBAC pattern to follow: `get_role(socket)` helper or inline `socket.assigns.current_user[:role]` check, same as `api_keys_live.ex`. Tests run `mix test` inside `src/pki_tenant_web` — the test helper stops engine apps so tests are compile/route-level only.

**Tech Stack:** Elixir, Phoenix LiveView, HEEx templates. No Ecto, no DB calls.

---

## Files to modify

| File | Change |
|------|--------|
| `src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex` | Add role guard to `start_activation` handler |
| `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex` | Add role guard to `initiate_ceremony` handler |
| `src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.ex` | Add role guard to `mount/3` (redirects non-ca_admin immediately) |
| `src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ca_app.html.heex` | Add `/activation` nav link under KEY MANAGEMENT |
| `src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex` | Wire `invite_user` → navigate to `/users`; `configure_service` → navigate to `/service-configs` |
| `src/pki_tenant_web/test/routes_test.exs` | Add test: CA router has `/activation` route (already exists, just asserting nav completeness) |

---

## Task 1: RBAC guard on `start_activation` in activation_live.ex

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex:150`

The `start_activation` handler calls `ActivationCeremony.start/1` with no role check. An auditor-role user navigating directly to `/activation` can open an activation session. Only `key_manager` and `ca_admin` should be able to start activation.

- [ ] **Step 1: Locate the handler**

Run:
```bash
grep -n "def handle_event(\"start_activation\"" src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex
```
Expected: line ~150.

- [ ] **Step 2: Add role guard**

In `src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex`, wrap the existing `start_activation` body with a role check. The existing function starts at line 150:

```elixir
  def handle_event("start_activation", %{"key_id" => key_id}, socket) do
    role = to_string(socket.assigns.current_user[:role] || socket.assigns.current_user["role"])

    if role not in ["key_manager", "ca_admin"] do
      {:noreply, put_flash(socket, :error, "Only Key Managers and CA Admins can activate keys.")}
    else
      case Enum.find(socket.assigns.issuer_keys, fn k -> k.id == key_id end) do
        nil ->
          {:noreply, put_flash(socket, :error, "Key not found.")}

        key ->
          case ActivationCeremony.start(key_id) do
            # ... rest of existing code unchanged ...
```

The `else` branch wraps everything from `case Enum.find(...)` down to the closing `end` of the original function. The rest of the function body is untouched.

- [ ] **Step 3: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 4: Run existing tests**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -5
```
Expected: same pass count as before (no regressions).

- [ ] **Step 5: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/ca/live/activation_live.ex
git commit -m "fix: RBAC guard on start_activation — require key_manager or ca_admin"
```

---

## Task 2: RBAC guard on `initiate_ceremony` in ceremony_live.ex

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex:461`

The CA sidebar shows the Key Ceremony link only to `ca_admin`, but the handler has no server-side check. Any authenticated CA user navigating directly to `/ceremonies` can trigger `initiate_ceremony`. The guard should set `wizard_error` (which is what all other validation failures in this handler do) rather than a flash, so it shows inline in the wizard form.

- [ ] **Step 1: Locate the handler**

```bash
grep -n "def handle_event(\"initiate_ceremony\"" src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex
```
Expected: line ~461.

- [ ] **Step 2: Add role guard**

At the top of the `initiate_ceremony` handler, before the existing `cond do`, add a role check. The new function starts:

```elixir
  def handle_event("initiate_ceremony", params, socket) do
    role = to_string(socket.assigns.current_user[:role] || socket.assigns.current_user["role"])

    if role != "ca_admin" do
      {:noreply, assign(socket, wizard_error: "Only CA Admins can initiate key ceremonies.")}
    else
      ca_id = params["ca_instance_id"]
      # ... rest of existing code (the cond do block) unchanged ...
    end
  end
```

The `else` branch contains the entire existing body starting from `ca_id = params["ca_instance_id"]` through the end of the function.

- [ ] **Step 3: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 4: Run existing tests**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -5
```
Expected: same pass count.

- [ ] **Step 5: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/ca/live/ceremony_live.ex
git commit -m "fix: RBAC guard on initiate_ceremony — require ca_admin"
```

---

## Task 3: RBAC guard on HSM wizard via mount redirect

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.ex:25`

The HSM wizard has 4 mutation handlers (`next_gateway`, `next_token`, `next_keys`, `create_keystore`) — none check the caller's role. Rather than adding the same guard to all 4, add one check in `mount/3` that redirects non-`ca_admin` users immediately back to the dashboard. This is idiomatic for LiveView — mount is where access control decisions belong.

- [ ] **Step 1: Read the mount function**

The `mount/3` callback starts at line 25 of `hsm_wizard_live.ex`. It ends after the `resume_from_id` block (around line 80). Read it to confirm the current structure before editing.

```bash
grep -n "def mount" src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.ex
```

- [ ] **Step 2: Add role guard at the top of mount**

Insert a role check at the very beginning of `mount/3`, before the existing assigns setup:

```elixir
  @impl true
  def mount(params, _session, socket) do
    role = to_string(socket.assigns[:current_user][:role] || socket.assigns[:current_user]["role"])

    if role != "ca_admin" do
      {:ok,
       socket
       |> put_flash(:error, "Only CA Admins can configure HSM devices.")
       |> push_navigate(to: "/")}
    else
      setup_id = params["setup_id"]
      ca_instance_id = socket.assigns[:current_user][:ca_instance_id] || PkiTenant.ca_instance_id()
      tenant_id = socket.assigns[:tenant_id] || PkiTenant.tenant_id()
      # ... rest of existing mount body unchanged ...
    end
  end
```

The `else` branch contains the entire existing body starting from `setup_id = params["setup_id"]`.

- [ ] **Step 3: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 4: Run existing tests**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -5
```
Expected: same pass count.

- [ ] **Step 5: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/ca/live/hsm_wizard_live.ex
git commit -m "fix: RBAC guard on HSM wizard — redirect non-ca_admin at mount"
```

---

## Task 4: Add `/activation` nav link to CA sidebar

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ca_app.html.heex:23-28`
- Modify: `src/pki_tenant_web/test/routes_test.exs`

The CA sidebar KEY MANAGEMENT section shows: Key Ceremony, My Shares, Issuer Keys, Certificates. The Activation page (`/activation`) is missing — key managers have no way to navigate to it from the sidebar. It should appear between "My Shares" and "Issuer Keys" (logical flow: ceremony → activation → issuer keys).

The `is_active?` function in `layouts.ex` already handles `"Activation"` via the default catch-all fallback, so no change to `layouts.ex` is needed — only the template.

- [ ] **Step 1: Locate the KEY MANAGEMENT section in ca_app.html.heex**

The section starts at:
```heex
<.sidebar_section :if={role in ["ca_admin", "key_manager"]} label="KEY MANAGEMENT">
```
It currently has 4 links. Add the Activation link as the third entry (after My Shares, before Issuer Keys):

```heex
      <.sidebar_section :if={role in ["ca_admin", "key_manager"]} label="KEY MANAGEMENT">
        <.sidebar_link :if={role == "ca_admin"} href="/ceremonies" icon="hero-shield-check" label="Key Ceremony" current={@page_title} />
        <.sidebar_link href="/ceremonies/custodian" icon="hero-key" label="My Shares" current={@page_title} />
        <.sidebar_link href="/activation" icon="hero-lock-open" label="Activation" current={@page_title} />
        <.sidebar_link href="/issuer-keys" icon="hero-finger-print" label="Issuer Keys" current={@page_title} />
        <.sidebar_link href="/certificates" icon="hero-document-text" label="Certificates" current={@page_title} />
      </.sidebar_section>
```

- [ ] **Step 2: Add `is_active?` clause to layouts.ex**

The `is_active?/2` function in `src/pki_tenant_web/lib/pki_tenant_web/components/layouts.ex` needs an entry for "Activation" so the link highlights correctly when on the activation page. The activation page sets `page_title: "Key Activation"`. Add:

```elixir
  defp is_active?("Activation", page) when page in ["Activation", "Activation Ceremony"], do: true
```

Add this line after the existing `is_active?("Issuer Keys", ...)` clause (around line 89).

> **Why "Activation Ceremony":** `activation_live.ex` sets `page_title: "Activation Ceremony"` in `mount/3`. The `is_active?` function receives `label` (the sidebar text "Activation") and `current` (the page's `page_title`), so both must be covered.

- [ ] **Step 3: Add a route test**

In `src/pki_tenant_web/test/routes_test.exs`, inside the `describe "CaRouter"` block, add:

```elixir
    test "has /activation route backed by Ca.ActivationLive" do
      assert "/activation" in live_paths(@ca_routes)

      route = Enum.find(@ca_routes, fn r -> r.path == "/activation" end)
      assert route.metadata.phoenix_live_view |> elem(0) == PkiTenantWeb.Ca.ActivationLive
    end
```

- [ ] **Step 4: Run tests**

```bash
cd src/pki_tenant_web && mix test test/routes_test.exs 2>&1 | tail -10
```
Expected: new test passes (route already exists, just asserting it).

- [ ] **Step 5: Compile check**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ca_app.html.heex \
        src/pki_tenant_web/lib/pki_tenant_web/components/layouts.ex \
        src/pki_tenant_web/test/routes_test.exs
git commit -m "fix: add /activation nav link to CA sidebar under KEY MANAGEMENT"
```

---

## Task 5: Fix setup_wizard Step 3 — `invite_user` stub

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex:303`

The `invite_user` handler currently returns a flash "not yet available in tenant mode." User management IS fully implemented at `/users`. The wizard should navigate the user there. Since the setup wizard is a multi-step flow, a `push_navigate` after the wizard step is the right action — users leave the wizard and land on the Users page.

- [ ] **Step 1: Locate the stub**

```bash
grep -n "invite_user\|not yet available" src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex
```
Expected: line ~303.

- [ ] **Step 2: Replace the stub**

Replace the current handler:

```elixir
  def handle_event("invite_user", _params, socket) do
    {:noreply, put_flash(socket, :info, "User invitation is not yet available in tenant mode.")}
  end
```

With:

```elixir
  def handle_event("invite_user", _params, socket) do
    {:noreply, push_navigate(socket, to: "/users")}
  end
```

- [ ] **Step 3: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 4: Run tests**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex
git commit -m "fix: setup wizard invite_user step navigates to /users instead of stub flash"
```

---

## Task 6: Fix setup_wizard Step 4 — `configure_service` stub

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex:311`

Same pattern as Task 5. `configure_service` in the setup wizard returns "not yet available." The Service Configs page at `/service-configs` is fully implemented. Navigate there.

- [ ] **Step 1: Locate the stub**

```bash
grep -n "configure_service\|not yet available" src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex
```
Expected: line ~311.

- [ ] **Step 2: Replace the stub**

Replace:

```elixir
  def handle_event("configure_service", _params, socket) do
    {:noreply, put_flash(socket, :info, "Service configuration is not yet available in tenant mode.")}
  end
```

With:

```elixir
  def handle_event("configure_service", _params, socket) do
    {:noreply, push_navigate(socket, to: "/service-configs")}
  end
```

- [ ] **Step 3: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 4: Run tests**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -5
```

- [ ] **Step 5: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/ra/live/setup_wizard_live.ex
git commit -m "fix: setup wizard configure_service step navigates to /service-configs"
```

---

## Task 7: P3 polish — RA sidebar /setup-wizard + CA layout role helper

**Files:**
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ra_app.html.heex:31-35`
- Modify: `src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ca_app.html.heex:16`

Two small polish items bundled:

**7a — RA sidebar `/setup-wizard` link:** The setup wizard is only reachable via the welcome splash. RA admins who have already completed setup may want to re-run it (e.g., to add a new API key or update a cert profile). Add a "Setup Wizard" link under CONFIGURATION for `ra_admin`.

**7b — CA layout role inconsistency:** `ca_app.html.heex` uses `<% role = @current_user.role %>` (struct dot access) while `ra_app.html.heex` uses `<% role = user_role(@current_user) %>`. The `user_role/1` helper handles both atom and string keys safely (`user[:role] || user["role"]`). Update CA layout to use the same helper.

- [ ] **Step 1: Add /setup-wizard link to RA sidebar**

In `ra_app.html.heex`, find the CONFIGURATION section:

```heex
      <.sidebar_section :if={role == "ra_admin"} label="CONFIGURATION">
        <.sidebar_link href="/cert-profiles" icon="hero-clipboard-document-list" label="Certificate Profiles" current={@page_title} />
        <.sidebar_link href="/ca-connection" icon="hero-link" label="CA Connection" current={@page_title} />
        <.sidebar_link href="/service-configs" icon="hero-globe-alt" label="Validation Endpoints" current={@page_title} />
      </.sidebar_section>
```

Add the Setup Wizard link at the end of the section:

```heex
      <.sidebar_section :if={role == "ra_admin"} label="CONFIGURATION">
        <.sidebar_link href="/cert-profiles" icon="hero-clipboard-document-list" label="Certificate Profiles" current={@page_title} />
        <.sidebar_link href="/ca-connection" icon="hero-link" label="CA Connection" current={@page_title} />
        <.sidebar_link href="/service-configs" icon="hero-globe-alt" label="Validation Endpoints" current={@page_title} />
        <.sidebar_link href="/setup-wizard" icon="hero-sparkles" label="Setup Wizard" current={@page_title} />
      </.sidebar_section>
```

- [ ] **Step 2: Add is_active? clause for Setup Wizard**

In `layouts.ex`, add after the existing RA page matching clauses:

```elixir
  defp is_active?("Setup Wizard", page) when page in ["Setup Wizard", "RA Setup Wizard"], do: true
```

- [ ] **Step 3: Fix CA layout role access**

In `ca_app.html.heex`, change line 16 from:

```heex
  <% role = @current_user.role %>
```

To:

```heex
  <% role = user_role(@current_user) %>
```

This matches how `ra_app.html.heex` handles it. The `user_role/1` helper is already imported via `use PkiTenantWeb, :html` in `Layouts`.

- [ ] **Step 4: Verify it compiles**

```bash
cd src/pki_tenant_web && mix compile 2>&1 | grep -E "error|warning" | head -20
```
Expected: no errors.

- [ ] **Step 5: Run full test suite**

```bash
cd src/pki_tenant_web && mix test 2>&1 | tail -10
```
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ra_app.html.heex \
        src/pki_tenant_web/lib/pki_tenant_web/components/layouts/ca_app.html.heex \
        src/pki_tenant_web/lib/pki_tenant_web/components/layouts.ex
git commit -m "fix: add /setup-wizard to RA sidebar; unify CA layout role helper"
```

---

## Critical Path Verification

After all 7 tasks are complete, verify the 7 critical flows at runtime (requires a live local tenant with PG up and engines running):

| # | Flow | Steps to verify |
|---|------|----------------|
| 1 | Root key ceremony | Login as ca_admin → Ceremony → initiate (works); login as auditor → direct URL `/ceremonies` → initiate (should get "Only CA Admins" error) |
| 2 | Key activation | Login as key_manager → `/activation` (visible in sidebar) → start activation (works); login as auditor → `/activation` → "start" button (should get flash error) |
| 3 | HSM wizard access | Login as key_manager → navigate to `/hsm-wizard` → should redirect to `/` with flash "Only CA Admins" |
| 4 | CSR → signed cert | RA portal: submit CSR → approve → verify cert appears in Certificates list |
| 5 | Cert revocation | CA portal: Certificates → revoke cert with reason → cert status changes |
| 6 | Audit log | Perform any action → Audit Log page shows the event with correct actor |
| 7 | User lifecycle | Users page → create user → log in as new user → admin suspends → reactivates |

Also verify setup wizard: log in as ra_admin → `/setup-wizard` → Step 3 (Invite Team) button navigates to `/users` → Step 4 (Service Config) button navigates to `/service-configs`.
