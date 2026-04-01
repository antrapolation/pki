defmodule PkiCaEngine.HsmDeviceManagement do
  @moduledoc """
  Thin wrapper over PkiPlatformEngine.HsmManagement for tenant-scoped access.

  HSM devices are platform-level resources. This module provides
  the tenant-filtered view used by the CA portal. All lookups are
  tenant-scoped to enforce isolation.
  """

  alias PkiPlatformEngine.HsmManagement

  @doc "Lists HSM devices accessible to a tenant."
  def list_devices_for_tenant(nil), do: []
  def list_devices_for_tenant(tenant_id) do
    HsmManagement.list_devices_for_tenant(tenant_id)
  end

  @doc "Gets a device by ID, scoped to tenant access."
  def get_device_for_tenant(nil, _id), do: {:error, :tenant_id_required}
  def get_device_for_tenant(tenant_id, id) do
    HsmManagement.get_device_for_tenant(tenant_id, id)
  end

  @doc "Probes a device, verifying tenant access first (atomic)."
  def probe_device_for_tenant(nil, _id), do: {:error, :tenant_id_required}
  def probe_device_for_tenant(tenant_id, id) do
    HsmManagement.probe_device_for_tenant(tenant_id, id)
  end
end
