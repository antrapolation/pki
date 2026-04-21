ExUnit.start(
  exclude: [
    # softhsm2-util not guaranteed to be installed (local dev / CI).
    # Run with `mix test --include softhsm` on a box that has it.
    :softhsm,
    # Tests that hardcode Postgres port 5434 from the legacy
    # multi-instance dev setup. Native PG on 5432 is the new baseline.
    :legacy_db_mode
  ]
)

Ecto.Adapters.SQL.Sandbox.mode(PkiPlatformEngine.PlatformRepo, :manual)
