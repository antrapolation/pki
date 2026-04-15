defmodule PkiSystem.MixProject do
  use Mix.Project

  @version "0.2.0"

  def project do
    [
      app: :pki_system,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      releases: releases(),
      aliases: aliases(),
      # No Erlang source in root — all .erl code lives in path deps under src/
      erlc_paths: [],
      # Root lib/ only has PkiSystem.Release for deployment migrations
      elixirc_paths: ["lib"]
    ]
  end

  def application do
    [extra_applications: [:logger, :runtime_tools]]
  end

  defp deps do
    [
      # ── Engines ──
      {:pki_platform_engine, path: "src/pki_platform_engine"},
      {:pki_ca_engine, path: "src/pki_ca_engine"},
      {:pki_ra_engine, path: "src/pki_ra_engine"},
      {:pki_validation, path: "src/pki_validation"},
      {:pki_audit_trail, path: "src/pki_audit_trail"},

      # ── Portals ──
      {:pki_ca_portal, path: "src/pki_ca_portal"},
      {:pki_ra_portal, path: "src/pki_ra_portal"},
      {:pki_platform_portal, path: "src/pki_platform_portal"},

      # ── Shared (override to resolve version conflicts) ──
      {:gettext, "~> 0.26", override: true},
      {:jason, "~> 1.2", override: true},
      {:logger_json, "~> 6.0", override: true}
    ]
  end

  defp releases do
    [
      # Release 1: All engine backends (no web portals)
      # Runs: CA Engine API (4001), RA Engine API (4003), Validation (4005)
      # Manages: DB migrations, background jobs, tenant provisioning
      pki_engines: [
        validate_compile_env: false,
        applications: [
          pki_platform_engine: :permanent,
          pki_ca_engine: :permanent,
          pki_ra_engine: :permanent,
          pki_validation: :permanent,
          pki_audit_trail: :permanent
        ]
      ],

      # Release 2: All web portals + engines in direct mode
      # Runs: CA Portal (4002), RA Portal (4004), Platform Portal (4006)
      # Engine HTTP APIs NOT started (gated by start_http config)
      # Portals call engine modules in-process (ENGINE_CLIENT_MODE=direct)
      pki_portals: [
        validate_compile_env: false,
        applications: [
          pki_platform_engine: :permanent,
          pki_ca_engine: :transient,
          pki_ra_engine: :transient,
          pki_validation: :transient,
          pki_audit_trail: :transient,
          pki_ca_portal: :permanent,
          pki_ra_portal: :permanent,
          pki_platform_portal: :permanent
        ]
      ],

      # Release 3: Audit trail service (lightweight)
      pki_audit: [
        validate_compile_env: false,
        applications: [
          pki_platform_engine: :permanent,
          pki_audit_trail: :permanent
        ]
      ]
    ]
  end

  defp aliases do
    [
      "ecto.setup": [
        "ecto.create",
        "ecto.migrate"
      ],
      "ecto.reset": [
        "ecto.drop",
        "ecto.setup"
      ],
      # Build and digest assets for all 3 portals (called by deploy/build.sh)
      "assets.deploy": [
        "tailwind pki_ca_portal --minify",
        "esbuild pki_ca_portal --minify",
        "tailwind pki_ra_portal --minify",
        "esbuild pki_ra_portal --minify",
        "tailwind pki_platform_portal --minify",
        "esbuild pki_platform_portal --minify",
        "phx.digest src/pki_ca_portal/priv/static -o src/pki_ca_portal/priv/static",
        "phx.digest src/pki_ra_portal/priv/static -o src/pki_ra_portal/priv/static",
        "phx.digest src/pki_platform_portal/priv/static -o src/pki_platform_portal/priv/static"
      ]
    ]
  end
end
