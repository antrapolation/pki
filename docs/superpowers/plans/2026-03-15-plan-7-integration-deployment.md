# Plan 7: Integration & Deployment — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a Podman Compose deployment for all PKI services + SSDID registry, wire up SSDID auth SDKs into each service, and verify end-to-end integration.

**Architecture:** All services run as containers via `podman-compose`. SSDID registry provides DID resolution. Each PKI service bootstraps an SSDID identity on startup. Inter-service auth uses SSDID mutual authentication over HTTP (within compose network).

**Tech Stack:** Podman, podman-compose, Elixir releases, SSDID server/client SDKs, PostgreSQL

**Spec Reference:** Sections 2.3, 2.4, 8, 10, 12

---

## Chunk 1: Compose Infrastructure

### Task 1: Create compose.yml

All services orchestrated via Podman Compose.

**Services:**
- `postgres` — PostgreSQL 16 with multiple databases
- `ssdid-registry` — SSDID DID registry (port 4000)
- `pki-ca-engine` — Core CA Engine (port 4001)
- `pki-ra-engine` — RA Engine with REST API (port 4003)
- `pki-ca-portal` — CA Admin Portal (port 4002)
- `pki-ra-portal` — RA Admin Portal (port 4004)
- `pki-validation` — OCSP/CRL (port 4005)

### Task 2: Create Containerfiles for each service

Elixir multi-stage build: compile release in build stage, run in minimal runtime image.

### Task 3: Create database init script

Script to create all required databases in the shared Postgres container.

---

## Chunk 2: SSDID SDK Integration

### Task 4: Add ssdid_server_sdk + ssdid_client_sdk to each service

Wire up the SSDID SDKs as path dependencies. Each service bootstraps its DID identity on startup.

### Task 5: Create SSDID bootstrap module for PKI services

Shared pattern for initializing SSDID identity and registering with the registry.

---

## Summary

Produces a working `podman-compose up` that starts the entire PKI CA system.
