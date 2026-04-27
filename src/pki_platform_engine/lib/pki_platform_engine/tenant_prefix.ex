defmodule PkiPlatformEngine.TenantPrefix do
  @moduledoc """
  Generates PostgreSQL schema prefixes for schema-per-tenant isolation.

  Each tenant gets four schemas: `t_{uuid_hex}_ca`, `t_{uuid_hex}_ra`,
  `t_{uuid_hex}_audit`, and `t_{uuid_hex}_validation`. The uuid_hex is
  the full 32 hex chars of the tenant UUID (hyphens stripped). The longest
  prefix is `t_<32hex>_validation` = 45 chars, well within PostgreSQL's
  63-char limit.
  """

  @prefix_pattern ~r/\At_[0-9a-f]{32}_(ca|ra|audit|validation)\z/

  @doc "CA schema prefix for a tenant."
  def ca_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_ca"

  @doc "RA schema prefix for a tenant."
  def ra_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_ra"

  @doc "Audit schema prefix for a tenant."
  def audit_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_audit"

  @doc "Validation schema prefix for a tenant."
  def validation_prefix(tenant_id), do: "t_#{uuid_hex(tenant_id)}_validation"

  @doc "Returns all four prefixes as a map."
  def all_prefixes(tenant_id) do
    %{
      ca_prefix: ca_prefix(tenant_id),
      ra_prefix: ra_prefix(tenant_id),
      audit_prefix: audit_prefix(tenant_id),
      validation_prefix: validation_prefix(tenant_id)
    }
  end

  @doc """
  Validates that a prefix string matches the expected pattern.
  Use this at every point where a prefix enters raw SQL.
  Raises ArgumentError if the prefix is invalid.
  """
  def validate_prefix!(prefix) when is_binary(prefix) do
    unless prefix =~ @prefix_pattern do
      raise ArgumentError,
        "Invalid schema prefix: #{inspect(prefix)}. " <>
        "Expected format: t_<32hex>_(ca|ra|audit|validation)"
    end
    prefix
  end

  @doc "Returns the compiled regex pattern for prefix validation."
  def prefix_pattern, do: @prefix_pattern

  defp uuid_hex(id) when is_binary(id) do
    stripped = String.replace(id, "-", "")

    unless stripped =~ ~r/\A[0-9a-f]{32}\z/ do
      raise ArgumentError,
        "Invalid UUID for schema prefix generation: #{inspect(id)}. " <>
        "Expected a 32-hex-char UUID (with or without hyphens)."
    end

    stripped
  end
end
