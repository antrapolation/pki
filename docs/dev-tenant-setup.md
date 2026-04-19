# Per-Tenant BEAM: Local Development Setup

## Prerequisites

- Elixir 1.18+, Erlang/OTP 25+
- PostgreSQL running (for platform node only)
- `pki_platform` database exists

## Quick Start (Single Tenant, Dev Mode)

### 1. Boot the tenant node directly (no platform needed for dev)

```bash
cd <project-root>

# Set tenant env vars
export TENANT_ID="dev-tenant-001"
export TENANT_SLUG="dev"
export TENANT_PORT="4010"
export MNESIA_DIR="/tmp/pki-dev-mnesia"
export MIX_ENV=dev

# Create Mnesia directory
mkdir -p $MNESIA_DIR

# Start the tenant node
cd src/pki_tenant_web
iex -S mix phx.server
```

### 2. Access the portals

Add to `/etc/hosts`:
```
127.0.0.1 dev.ca.localhost
127.0.0.1 dev.ra.localhost
```

Or use `lvh.me` (resolves to 127.0.0.1):
- CA portal: http://dev.ca.lvh.me:4010
- RA portal: http://dev.ra.lvh.me:4010
- Fallback (no subdomain): http://localhost:4010 → CA portal

### 3. Create a portal user (via IEx)

In the running IEx session:

```elixir
# Create an admin user
alias PkiMnesia.{Repo, Structs.PortalUser}

user = PortalUser.new(%{
  username: "admin",
  password_hash: Argon2.hash_pwd_salt("admin123"),
  display_name: "Dev Admin",
  email: "admin@dev.local",
  role: :ca_admin,
  status: "active"
})
{:ok, _} = Repo.insert(user)
```

### 4. Login

Go to http://dev.ca.lvh.me:4010/login
- Username: `admin`
- Password: `admin123`

### 5. Run through the core flows

**CA Portal (dev.ca.lvh.me:4010):**
1. Dashboard should show empty state
2. Navigate to Ceremonies → initiate a new ceremony
3. Navigate to Issuer Keys → see keys from ceremony
4. Navigate to Certificates → empty until CSR is signed

**RA Portal (dev.ra.lvh.me:4010):**
1. Login with same credentials (role must include RA access)
2. Dashboard → Setup Wizard if first time
3. CSRs → Submit CSR button
4. Cert Profiles → create a profile

## Full Stack (Platform + Tenant)

### 1. Boot platform node

```bash
cd <project-root>
DATABASE_URL="ecto://postgres:postgres@localhost/pki_platform" \
SECRET_KEY_BASE="dev-only-key-base-64-chars-long-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" \
iex --sname pki_platform -S mix run --no-halt
```

### 2. Create tenant via platform

```elixir
# In platform IEx:
PkiPlatformEngine.TenantLifecycle.create_tenant(%{
  id: "dev-tenant-001",
  slug: "dev",
  name: "Dev Tenant"
})
```

This spawns a tenant BEAM node via `:peer`, allocates a port, and configures Caddy.

### 3. Check tenant health

```elixir
PkiPlatformEngine.TenantLifecycle.list_tenants()
# Should show dev-tenant-001 as :running
```

## Troubleshooting

- **"Mnesia failed to start"**: Delete `$MNESIA_DIR` and restart
- **Port conflict**: Change `TENANT_PORT` to an unused port
- **No styling**: Run `mix esbuild pki_tenant_web && mix tailwind pki_tenant_web` first
- **"Unknown service" on page load**: Check hostname matches `*.ca.*` or `*.ra.*` pattern
