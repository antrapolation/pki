# System Bootstrap — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement the tenant bootstrap flow that creates system keypairs (:root, :sub_root, host signing/cipher keys) and the Keypair ACL when the first CA Admin sets up a new tenant.

**Spec:** Section 7

---

### Task 1: SystemKeypairs module

Creates 4 system keypairs during bootstrap:
- `:root` — system root signing key
- `:sub_root` — operational root signing key
- `:strap_ca_remote_service_host_signing_key` — service signing
- `:strap_ca_remote_service_host_cipher_key` — service encryption

All registered with Key Vault, passwords encrypted with CA Admin's KEM public key.

### Task 2: Bootstrap orchestrator

`PkiCaEngine.Bootstrap.setup_tenant/3` — called from /setup page:
1. Create CA Admin user with credentials
2. Initialize Keypair ACL
3. Create system keypairs
4. Update tenant status to "active"

### Task 3: Update CA Engine setup controller/API

Wire the bootstrap into the existing `/setup` and `/api/v1/auth/register` flows.

### Task 4: Integration test — full tenant bootstrap

---

## Plan Summary

| Task | Tests |
|------|-------|
| 1 | ~8 |
| 2 | ~6 |
| 3 | ~4 |
| 4 | ~3 |
| **Total** | **~20** |
