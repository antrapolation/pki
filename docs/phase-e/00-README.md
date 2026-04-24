# Phase E — HSM-First Key Ceremony

This folder contains the design, specification, and implementation plan for **Phase E** of the PKI system: a switch from software-keystore-by-default to **HSM-first key management** with lease-based activation, three key generation modes, and auditor-quorum ceremonies.

## Read in this order

| # | Document | Purpose | Audience |
|---|---|---|---|
| 01 | [Architecture Decision Record — HSM-First Key Management](./01-adr-hsm-first-key-management.md) | The **why**: rationale, alternatives considered, consequences | Future maintainers, auditors (Baker Tilly et al.) |
| 02 | [Spec Amendment — Key Ceremony v1.1](./02-spec-amendment-key-ceremony-v1.1.md) | The **what**: changes to Product Spec v1.0 (new fields, new flows, updated security guarantees) | Customers, auditors, sales |
| 03 | [Implementation Plan with Tasks](./03-implementation-plan-with-tasks.md) | The **how**: 22 executable tasks (E1.1 → E5.2) with file paths, dependencies, exceptions | Engineers (executor models like Claude Sonnet) |

## Status

- **Design**: Complete (2026-04-24)
- **Implementation**: Not started
- **Hardware budget**: $0 (Phase E1-E5 development uses SoftHSM2)
- **Total estimate**: ~16-18 days of focused engineering

## Phase scope (in / out)

| In Phase E | Out of Phase E |
|---|---|
| HSM-first architecture using existing Phase D Dispatcher | Real smart-card m-of-n (needs hardware → Phase E5+) |
| SoftHSM2-backed dev/test path | HSM cloning ceremony for DR backup HSM |
| Lease-based activation (k-of-n authorize → 4h/100ops session) | WebTrust audit submission |
| Three key generation modes (threshold, password, single-custodian) | Cert renewal flow (Phase F) |
| Single-custodian guardrails (root must be threshold) | Configure keypair access UI (existing schema, separate work) |
| Auditor as ceremony quorum participant | Mnesia transaction retry/back-off (low impact, defer) |
| Cryptographic transcript signing (hash chain + auditor signature) | |
| Signed-share envelopes (NFR compliance) | |

## Hardware roadmap (procurement, not Phase E code work)

| Stage | Hardware | Cost | Unblocks |
|---|---|---|---|
| Phase E1-E5 development | None (SoftHSM2 already installed) | $0 | All Elixir code, 80% of value |
| PKCS#11 hardware validation | 1 × Nitrokey HSM 2 | ~$50 | "Does our PKCS#11 path work on real silicon?" |
| Real m-of-n smart-card testing | 1 × used Thales Luna PCIe + 5 PED keys | ~$1.5k | Phase E6 prep |
| First pilot customer | 2 × Thales Luna USB HSM 7 + 14 PED keys | ~$15k | WebTrust pilot, real customer ceremony |
