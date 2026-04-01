defmodule PkiCaEngine.HsmDeviceManagement do
  @moduledoc """
  Thin wrapper over PkiPlatformEngine.HsmManagement for tenant-scoped access.

  HSM devices are platform-level resources. This module provides
  the tenant-filtered view used by the CA portal.
  """

  alias PkiPlatformEngine.HsmManagement

  @doc "Lists HSM devices accessible to a tenant."
  def list_devices_for_tenant(tenant_id) do
    HsmManagement.list_devices_for_tenant(tenant_id)
  end

  @doc "Gets a device by ID (platform-level lookup)."
  def get_device(id) do
    HsmManagement.get_device(id)
  end
end
