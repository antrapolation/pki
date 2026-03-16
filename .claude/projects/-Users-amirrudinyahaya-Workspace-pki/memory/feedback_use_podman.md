---
name: Use Podman for services
description: User uses Podman (not Docker) for running databases and other services like Postgres
type: feedback
---

Use Podman instead of Docker for running services (Postgres, etc.) in development and testing.

**Why:** User's preferred container runtime is Podman, not Docker.

**How to apply:**
- Use `podman` commands instead of `docker` commands
- Use `podman run` for spinning up Postgres containers for dev/test
- Update any docker-compose references to use `podman-compose` or `podman` directly
