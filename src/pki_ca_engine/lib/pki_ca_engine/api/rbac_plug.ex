defmodule PkiCaEngine.Api.RbacPlug do
  @moduledoc """
  Role-based access control for CA Engine API routes.

  Reads the user role from the `x-user-role` header (set by the portal's
  engine client) and enforces permission checks per route.

  For internal auth without a role header, full access is granted
  (backward compatibility for portal bootstrap/admin calls).
  """

  import Plug.Conn
  require Logger

  @role_permissions %{
    "ca_admin" => [
      :manage_users,
      :manage_keystores,
      :manage_ca_instances,
      :view_keystores,
      :view_issuer_keys,
      :view_status,
      :view_ceremonies,
      :view_certificates,
      :view_keypairs,
      :view_audit_log,
      :view_ca_instances
    ],
    "key_manager" => [
      :manage_ceremonies,
      :manage_keypairs,
      :sign_certificates,
      :finalize_ceremony,
      :view_keystores,
      :view_issuer_keys,
      :view_status,
      :view_ceremonies,
      :view_certificates,
      :view_keypairs,
      :view_audit_log,
      :view_ca_instances
    ],
    "auditor" => [
      :finalize_ceremony,
      :view_keystores,
      :view_issuer_keys,
      :view_status,
      :view_ceremonies,
      :view_certificates,
      :view_keypairs,
      :view_audit_log,
      :view_ca_instances
    ]
  }

  @doc """
  Enforces RBAC on an already-matched connection.

  Called inline in the router:

      conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(&UserController.index/1)

  Connections that are already halted (e.g. by AuthPlug) pass through unchanged.
  """
  def call(%Plug.Conn{halted: true} = conn, _permission), do: conn

  def call(conn, required_permission) do
    role = List.first(get_req_header(conn, "x-user-role"))

    cond do
      # No role header — backward compat for internal/bootstrap calls
      is_nil(role) or role == "" ->
        conn

      # Known role with required permission
      has_permission?(role, required_permission) ->
        assign(conn, :user_role, role)

      # Known role without the required permission
      Map.has_key?(@role_permissions, role) ->
        Logger.warning("rbac_plug: role=#{role} denied permission=#{required_permission}")

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(
          403,
          Jason.encode!(%{
            error: "forbidden",
            message: "Role '#{role}' does not have '#{required_permission}' permission"
          })
        )
        |> halt()

      # Unknown role
      true ->
        Logger.warning("rbac_plug: unknown role=#{role}")

        conn
        |> put_resp_content_type("application/json")
        |> send_resp(403, Jason.encode!(%{error: "forbidden", message: "Unknown role"}))
        |> halt()
    end
  end

  defp has_permission?(role, permission) do
    permissions = Map.get(@role_permissions, role, [])
    permission in permissions
  end
end
