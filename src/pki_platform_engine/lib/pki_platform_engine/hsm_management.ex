defmodule PkiPlatformEngine.HsmManagement do
  @moduledoc """
  Platform-level HSM device management.

  HSM devices are infrastructure resources managed by the platform admin.
  Tenants are granted access to specific devices via tenant_hsm_access.
  """

  import Ecto.Query
  require Logger

  alias PkiPlatformEngine.{PlatformRepo, HsmDevice, TenantHsmAccess}

  # ---------------------------------------------------------------------------
  # Device CRUD (platform admin)
  # ---------------------------------------------------------------------------

  @doc "Registers a new HSM device. Probes PKCS#11 library to verify connectivity."
  def register_device(attrs) do
    lib_path = attrs[:pkcs11_lib_path] || attrs["pkcs11_lib_path"]

    case probe_pkcs11(lib_path) do
      {:ok, manufacturer} ->
        attrs = Map.put(attrs, :manufacturer, manufacturer)

        %HsmDevice{}
        |> HsmDevice.changeset(attrs)
        |> PlatformRepo.insert()

      {:error, reason} ->
        {:error, {:pkcs11_unreachable, reason}}
    end
  end

  @doc "Lists all HSM devices (platform admin view)."
  def list_devices do
    PlatformRepo.all(HsmDevice)
  end

  @doc "Gets a device by ID."
  def get_device(id) do
    case PlatformRepo.get(HsmDevice, id) do
      nil -> {:error, :not_found}
      device -> {:ok, device}
    end
  end

  @doc "Re-probes a device to test connectivity."
  def probe_device(id) do
    case PlatformRepo.get(HsmDevice, id) do
      nil -> {:error, :not_found}
      device ->
        case probe_pkcs11(device.pkcs11_lib_path) do
          {:ok, manufacturer} ->
            device
            |> HsmDevice.changeset(%{manufacturer: manufacturer, status: "active"})
            |> PlatformRepo.update()

          {:error, reason} ->
            {:error, {:pkcs11_unreachable, reason}}
        end
    end
  end

  @doc "Deactivates a device."
  def deactivate_device(id) do
    case PlatformRepo.get(HsmDevice, id) do
      nil -> {:error, :not_found}
      device ->
        device
        |> HsmDevice.changeset(%{status: "inactive"})
        |> PlatformRepo.update()
    end
  end

  # ---------------------------------------------------------------------------
  # Tenant access (platform admin assigns devices to tenants)
  # ---------------------------------------------------------------------------

  @doc "Grants a tenant access to an HSM device."
  def grant_tenant_access(tenant_id, hsm_device_id) do
    %TenantHsmAccess{}
    |> TenantHsmAccess.changeset(%{tenant_id: tenant_id, hsm_device_id: hsm_device_id})
    |> PlatformRepo.insert()
  end

  @doc "Revokes a tenant's access to an HSM device."
  def revoke_tenant_access(tenant_id, hsm_device_id) do
    case PlatformRepo.one(
      from a in TenantHsmAccess,
        where: a.tenant_id == ^tenant_id and a.hsm_device_id == ^hsm_device_id
    ) do
      nil -> {:error, :not_found}
      access -> PlatformRepo.delete(access)
    end
  end

  @doc "Lists HSM devices accessible to a specific tenant (active only)."
  def list_devices_for_tenant(tenant_id) do
    from(d in HsmDevice,
      join: a in TenantHsmAccess, on: a.hsm_device_id == d.id,
      where: a.tenant_id == ^tenant_id and d.status == "active",
      select: d
    )
    |> PlatformRepo.all()
  end

  @doc "Gets a device by ID only if the tenant has access to it."
  def get_device_for_tenant(tenant_id, hsm_device_id) do
    query = from(d in HsmDevice,
      join: a in TenantHsmAccess,
        on: a.hsm_device_id == d.id and a.tenant_id == ^tenant_id,
      where: d.id == ^hsm_device_id and d.status == "active"
    )
    case PlatformRepo.one(query) do
      nil -> {:error, :not_found}
      device -> {:ok, device}
    end
  end

  @doc "Probes a device atomically — verifies tenant access and probes in one operation."
  def probe_device_for_tenant(tenant_id, hsm_device_id) do
    with {:ok, device} <- get_device_for_tenant(tenant_id, hsm_device_id) do
      case probe_pkcs11(device.pkcs11_lib_path) do
        {:ok, manufacturer} ->
          device
          |> HsmDevice.changeset(%{manufacturer: manufacturer, status: "active"})
          |> PlatformRepo.update()

        {:error, reason} ->
          {:error, {:pkcs11_unreachable, reason}}
      end
    end
  end

  @doc "Lists all tenant access records for a device."
  def list_device_tenants(hsm_device_id) do
    from(a in TenantHsmAccess,
      where: a.hsm_device_id == ^hsm_device_id,
      select: a.tenant_id
    )
    |> PlatformRepo.all()
  end

  # ---------------------------------------------------------------------------
  # PKCS#11 probing
  # ---------------------------------------------------------------------------

  defp probe_pkcs11(lib_path) when is_binary(lib_path) and lib_path != "" do
    if Path.type(lib_path) != :absolute do
      {:error, :lib_path_must_be_absolute}
    else
      nif = StrapSofthsmPrivKeyStoreProvider.Native.SofthsmNif

      case nif.get_info(lib_path) do
        {:ok, manufacturer} -> {:ok, String.trim(manufacturer)}
        {:error, reason} -> {:error, reason}
      end
    end
  rescue
    e -> {:error, Exception.message(e)}
  end
  defp probe_pkcs11(_), do: {:error, :invalid_lib_path}
end
