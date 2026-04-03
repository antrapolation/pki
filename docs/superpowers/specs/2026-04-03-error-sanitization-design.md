# Error Message Sanitization Design

**Date:** 2026-04-03
**Status:** Approved
**Goal:** Replace all 56 instances where internal error details (inspect(reason), Exception.message(e)) leak to users with sanitized, user-friendly messages while logging technical details server-side.

---

## 1. Pattern

Every error path follows the same transformation:

**Before:**
```elixir
{:error, reason} ->
  put_flash(socket, :error, "Failed to create user: #{inspect(reason)}")
```

**After:**
```elixir
{:error, reason} ->
  Logger.error("[users] Failed to create user: #{inspect(reason)}")
  put_flash(socket, :error, sanitize_error("Failed to create user", reason))
```

The `inspect(reason)` is moved to a `Logger.error` call (server-side only). The user sees a sanitized message via `sanitize_error/2`.

---

## 2. Sanitization Helper

One `ErrorHelpers` module per portal providing `sanitize_error/2`:

```elixir
defmodule PkiCaPortalWeb.ErrorHelpers do
  def sanitize_error(context, :not_found), do: "#{context}: record not found."
  def sanitize_error(context, :duplicate), do: "#{context}: already exists."
  def sanitize_error(context, :duplicate_key_alias), do: "#{context}: a key with that alias already exists."
  def sanitize_error(context, :invalid_credentials), do: "Invalid username or password."
  def sanitize_error(context, :unauthorized), do: "You don't have permission for this action."
  def sanitize_error(context, :rate_limited), do: "Too many attempts. Please wait."
  def sanitize_error(context, :invalid_threshold), do: "#{context}: invalid threshold configuration."
  def sanitize_error(context, :share_not_found), do: "#{context}: share not found."
  def sanitize_error(context, %Ecto.Changeset{} = cs), do: "#{context}: #{format_changeset(cs)}"
  def sanitize_error(context, reason) when is_atom(reason), do: "#{context}: #{Phoenix.Naming.humanize(reason)}."
  def sanitize_error(context, reason) when is_binary(reason), do: "#{context}: #{reason}"
  def sanitize_error(context, _reason), do: "#{context}. Please try again or contact your administrator."

  defp format_changeset(%Ecto.Changeset{} = cs) do
    Ecto.Changeset.traverse_errors(cs, fn {msg, opts} ->
      Regex.replace(~r"%{(\w+)}", msg, fn _, key ->
        opts |> Keyword.get(String.to_existing_atom(key), key) |> to_string()
      end)
    end)
    |> Enum.map(fn {field, msgs} -> "#{field} #{Enum.join(msgs, ", ")}" end)
    |> Enum.join("; ")
  end
end
```

**Known atoms** get specific, actionable messages.
**Ecto changesets** get field-level validation messages (user-actionable).
**Binary strings** pass through (already human-readable from the engine layer).
**Atom errors** get humanized (`:not_found` -> "Not found").
**Everything else** (tuples, structs, exceptions) gets the generic fallback.

---

## 3. Locations to Fix

### CA Portal (17 locations)

| File | Lines | Pattern |
|------|-------|---------|
| `live/users_live.ex` | 59, 72, 85, 97, 109, 122 | `put_flash` with `inspect(reason)` |
| `live/keystores_live.ex` | 90 | `put_flash` with `inspect(reason)` |
| `live/issuer_keys_live.ex` | 102, 122 | `put_flash` with `inspect(reason)` |
| `live/hsm_devices_live.ex` | 38 | `put_flash` with `inspect(reason)` |
| `live/ca_instances_live.ex` | 65, 97 | `put_flash` with `inspect(reason)` |
| `ca_engine_client/direct.ex` | 444, 669, 751, 1125, 1130, 1148 | `Exception.message(e)` in error tuples |

### RA Portal (17 locations)

| File | Lines | Pattern |
|------|-------|---------|
| `controllers/password_controller.ex` | 31 | `render` with `inspect(reason)` |
| `controllers/setup_controller.ex` | 85 | `format_changeset_error` uses `inspect` |
| `live/csrs_live.ex` | 91, 109 | `put_flash` with `inspect(reason)` |
| `live/api_keys_live.ex` | 78, 103 | `put_flash` with `inspect(reason)` |
| `live/cert_profiles_live.ex` | 80, 123, 140 | `put_flash` with `inspect(reason)` |
| `live/users_live.ex` | 57, 69, 81, 92, 103, 115 | `put_flash` with `inspect(reason)` |
| `live/service_configs_live.ex` | 45 | `put_flash` with `inspect(reason)` |
| `live/ra_instances_live.ex` | 49 | `put_flash` with `inspect(reason)` |

### Platform Portal (22 locations)

| File | Lines | Pattern |
|------|-------|---------|
| `live/tenant_detail_live.ex` | 53, 77, 108, 120, 153, 362, 400, 460, 484, 506, 566 | Mixed `inspect` and `Exception.message` |
| `live/hsm_devices_live.ex` | 47, 56, 68, 71, 86 | `put_flash` with `inspect(reason)` |
| `live/tenants_live.ex` | 33, 44, 55 | `put_flash` with `inspect(reason)` |
| `live/admins_live.ex` | 86, 106, 129 | `put_flash` with `inspect(reason)` |

---

## 4. Client Module Sanitization

The `ca_engine_client/direct.ex` and `http.ex` files return `{:error, Exception.message(e)}` from rescue blocks. These error messages flow up to LiveViews where they become the `reason` in `{:error, reason}`.

Since `sanitize_error/2` passes through binary strings, these are partially safe. But `Exception.message(e)` can contain stack-trace-like info for some exception types.

**Fix:** In client rescue blocks, replace `Exception.message(e)` with a generic category string and log the full exception:

```elixir
# Before
rescue
  e -> {:error, Exception.message(e)}

# After  
rescue
  e ->
    Logger.error("[ca_engine_client] Operation failed: #{Exception.message(e)}")
    {:error, "operation failed"}
```

---

## 5. What's NOT In Scope

- **Changing ErrorHTML/ErrorJSON** — already safe, show generic messages
- **Phoenix endpoint error config** — already correct
- **Logger calls** — these are server-side only, fine to keep `inspect`
- **dev.exs `debug_errors: true`** — this is dev-only, acceptable
- **Changing error return types from engine modules** — only sanitize at the presentation layer
