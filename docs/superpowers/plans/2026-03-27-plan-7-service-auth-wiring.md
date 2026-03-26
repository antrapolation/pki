# Service Auth Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the Bootstrap module into the CA Engine's setup API, update the CA Portal setup flow, and ensure the full bootstrap works end-to-end.

**Spec:** Sections 7, 8

---

### Task 1: Wire Bootstrap into CA Engine setup API

Update `auth_controller.ex` register endpoint to call `Bootstrap.setup_tenant/4` instead of just creating a user. This makes the `/api/v1/auth/register` endpoint perform the full tenant initialization.

### Task 2: Update CA Portal setup flow

Update the CA Portal's setup controller to call the engine's register endpoint which now bootstraps the full tenant (admin + ACL + system keypairs).

### Task 3: Final integration verification

Run all tests across all services. Verify everything compiles and passes. Push.

---

## Plan Summary

| Task | Tests |
|------|-------|
| 1 | Existing CA Engine tests pass |
| 2 | Existing CA Portal tests pass |
| 3 | Full cross-service verification |
