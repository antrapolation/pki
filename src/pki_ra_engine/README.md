# RA Engine

Registration Authority Engine for the PQC Certificate Authority System. Processes Certificate Signing Requests (CSRs), manages domain control validation (DCV), and coordinates with the CA Engine for certificate issuance.

## Ports

| Port | Purpose |
|------|---------|
| 4003 | HTTP API (internal) |

## Environment Variables

### Required (production)

| Variable | Description |
|----------|-------------|
| `RA_ENGINE_DATABASE_URL` | PostgreSQL connection URL |
| `CA_ENGINE_URL` | CA Engine API base URL (e.g., `http://localhost:4001`) |
| `INTERNAL_API_SECRET` | Shared secret for portal-to-engine authentication |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4003` | HTTP listen port |
| `POOL_SIZE` | `10` | Database connection pool size |
| `PLATFORM_DATABASE_URL` | — | Platform DB URL (for audit logging) |

## TLS / HTTPS

The RA Engine listens on **plain HTTP only**. It is designed to run behind a TLS-terminating reverse proxy (Caddy, nginx, or a cloud load balancer).

**Do not expose port 4003 directly to the internet.**

See `docs/deployment-guide.md` section 5 for the recommended Caddy configuration with automatic Let's Encrypt certificates.

### Architecture

```
Internet --> [Caddy :443 TLS] --> [RA Engine :4003 HTTP] (localhost only)
```

The firewall should only allow ports 80 and 443. All internal service ports (4001-4006) should be bound to `localhost` or blocked by the firewall.

## Running

### Development

```bash
mix deps.get
mix ecto.setup
mix run --no-halt
```

### Production (release)

```bash
MIX_ENV=prod mix release
_build/prod/rel/pki_ra_engine/bin/pki_ra_engine start
```

### Container

```bash
podman build -f Containerfile -t pki-ra-engine ../..
podman run -p 4003:4003 --env-file .env pki-ra-engine
```

## API Authentication

All `/api/v1/*` endpoints require a `Bearer` token in the `Authorization` header:

- **Internal secret**: Portal-to-engine calls use the shared `INTERNAL_API_SECRET`
- **API key**: External clients use API keys (base64-encoded, created via the portal)

Multi-tenant requests must include the `X-Tenant-Id` header.

## Testing

```bash
mix test          # 292 tests
mix test --seed 0 # deterministic ordering
```
