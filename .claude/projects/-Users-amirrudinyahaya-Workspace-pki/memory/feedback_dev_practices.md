---
name: Development practices preferences
description: User wants TDD, SOLID, DRY, KISS, and Elixir protocols over behaviours in all implementation plans and code
type: feedback
---

Always follow TDD (Red-Green-Refactor), SOLID principles, DRY, and KISS in all implementation plans and code.

**Why:** User explicitly requested these as mandatory development methodology for the PKI project.

**How to apply:**
- Every implementation task must follow TDD: write failing test first, implement minimal code to pass, refactor
- Prefer Elixir protocols over behaviours for polymorphism (protocols dispatch on data type, better for the provider pattern used in this project)
- Keep interfaces small and focused (Interface Segregation)
- Single responsibility per module
- Don't repeat logic across modules — extract shared code
- Simplest solution that works — no premature abstraction
