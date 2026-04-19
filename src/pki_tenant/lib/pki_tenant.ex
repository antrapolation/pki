defmodule PkiTenant do
  @moduledoc """
  Top-level accessors for tenant-scoped runtime constants.

  The per-tenant BEAM architecture assigns one tenant per node. Things
  like `tenant_id` are set once at boot from `TENANT_ID` environment
  variable (see `PkiTenant.Application`). This module surfaces them
  without every caller re-reading `System.get_env/1`.
  """

  @doc """
  Returns the tenant_id this BEAM node is running as. Falls back to
  `"dev"` in development / test when `TENANT_ID` is unset, matching the
  same default used by `PkiTenant.Application`.
  """
  @spec tenant_id() :: String.t()
  def tenant_id do
    System.get_env("TENANT_ID") || "dev"
  end
end
