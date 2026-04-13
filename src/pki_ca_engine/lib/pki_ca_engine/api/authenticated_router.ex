defmodule PkiCaEngine.Api.AuthenticatedRouter do
  @moduledoc """
  Authenticated router -- all routes require a valid internal API secret via AuthPlug,
  and are further gated by role-based access control via RbacPlug.
  """

  use Plug.Router

  alias PkiCaEngine.Api.{
    UserController,
    KeystoreController,
    IssuerKeyController,
    StatusController,
    CeremonyController,
    CertificateController,
    AuditLogController,
    KeyVaultController,
    CaInstanceController,
    RbacPlug
  }

  plug PkiCaEngine.Api.AuthPlug
  plug :match
  plug :dispatch

  # ── Helpers ──────────────────────────────────────────────────────

  # Dispatch only when the connection has not been halted (e.g. by RbacPlug).
  defp dispatch_unless_halted(%Plug.Conn{halted: true} = conn, _fun), do: conn
  defp dispatch_unless_halted(conn, fun), do: fun.(conn)

  # ── Users (ca_admin only) ───────────────────────────────────────

  get "/users" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(&UserController.index/1)
  end

  post "/users" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(&UserController.create/1)
  end

  get "/users/:id" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(fn c -> UserController.show(c, id) end)
  end

  put "/users/:id/password" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(fn c -> UserController.update_password(c, id) end)
  end

  delete "/users/:id" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(fn c -> UserController.delete(c, id) end)
  end

  get "/users/by-username/:username" do
    conn |> RbacPlug.call(:manage_users) |> dispatch_unless_halted(fn c -> UserController.by_username(c, username) end)
  end

  # ── Keystores ───────────────────────────────────────────────────

  get "/keystores" do
    conn |> RbacPlug.call(:view_keystores) |> dispatch_unless_halted(&KeystoreController.index/1)
  end

  post "/keystores" do
    conn |> RbacPlug.call(:manage_keystores) |> dispatch_unless_halted(&KeystoreController.create/1)
  end

  # ── Issuer Keys ─────────────────────────────────────────────────

  get "/issuer-keys" do
    conn |> RbacPlug.call(:view_issuer_keys) |> dispatch_unless_halted(&IssuerKeyController.index/1)
  end

  # ── Engine Status ───────────────────────────────────────────────

  get "/status" do
    conn |> RbacPlug.call(:view_status) |> dispatch_unless_halted(&StatusController.show/1)
  end

  # ── Ceremonies ──────────────────────────────────────────────────

  get "/ceremonies" do
    conn |> RbacPlug.call(:view_ceremonies) |> dispatch_unless_halted(&CeremonyController.index/1)
  end

  post "/ceremonies" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(&CeremonyController.create/1)
  end

  # Ceremony lifecycle (multi-phase via KeyCeremonyManager)
  post "/ceremonies/start" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(&CeremonyController.start_ceremony/1)
  end

  post "/ceremonies/:id/generate-keypair" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(fn c -> CeremonyController.generate_keypair(c, id) end)
  end

  post "/ceremonies/:id/self-sign" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(fn c -> CeremonyController.self_sign(c, id) end)
  end

  post "/ceremonies/:id/csr" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(fn c -> CeremonyController.gen_csr(c, id) end)
  end

  post "/ceremonies/:id/assign-custodians" do
    conn |> RbacPlug.call(:manage_ceremonies) |> dispatch_unless_halted(fn c -> CeremonyController.assign_custodians(c, id) end)
  end

  post "/ceremonies/:id/finalize" do
    conn |> RbacPlug.call(:finalize_ceremony) |> dispatch_unless_halted(fn c -> CeremonyController.finalize(c, id) end)
  end

  get "/ceremonies/:id/status" do
    conn |> RbacPlug.call(:view_ceremonies) |> dispatch_unless_halted(fn c -> CeremonyController.status(c, id) end)
  end

  # ── Certificates ────────────────────────────────────────────────

  get "/certificates" do
    conn |> RbacPlug.call(:view_certificates) |> dispatch_unless_halted(&CertificateController.index/1)
  end

  get "/certificates/:serial" do
    conn |> RbacPlug.call(:view_certificates) |> dispatch_unless_halted(fn c -> CertificateController.show(c, serial) end)
  end

  post "/certificates/sign" do
    conn |> RbacPlug.call(:sign_certificates) |> dispatch_unless_halted(&CertificateController.sign/1)
  end

  post "/certificates/revoke" do
    conn |> RbacPlug.call(:sign_certificates) |> dispatch_unless_halted(&CertificateController.revoke/1)
  end

  # ── Key Vault (keypairs) ────────────────────────────────────────

  post "/keypairs/register" do
    conn |> RbacPlug.call(:manage_keypairs) |> dispatch_unless_halted(&KeyVaultController.register/1)
  end

  post "/keypairs/:id/grant" do
    conn |> RbacPlug.call(:manage_keypairs) |> dispatch_unless_halted(fn c -> KeyVaultController.grant_access(c, id) end)
  end

  post "/keypairs/:id/activate" do
    conn |> RbacPlug.call(:manage_keypairs) |> dispatch_unless_halted(fn c -> KeyVaultController.activate(c, id) end)
  end

  post "/keypairs/:id/revoke-grant" do
    conn |> RbacPlug.call(:manage_keypairs) |> dispatch_unless_halted(fn c -> KeyVaultController.revoke_grant(c, id) end)
  end

  get "/keypairs" do
    conn |> RbacPlug.call(:view_keypairs) |> dispatch_unless_halted(&KeyVaultController.list/1)
  end

  get "/keypairs/:id" do
    conn |> RbacPlug.call(:view_keypairs) |> dispatch_unless_halted(fn c -> KeyVaultController.show(c, id) end)
  end

  # ── Audit Log ───────────────────────────────────────────────────

  get "/audit-log" do
    conn |> RbacPlug.call(:view_audit_log) |> dispatch_unless_halted(&AuditLogController.index/1)
  end

  # ── CA Instances ────────────────────────────────────────────────

  get "/ca-instances" do
    conn |> RbacPlug.call(:view_ca_instances) |> dispatch_unless_halted(&CaInstanceController.index/1)
  end

  post "/ca-instances" do
    conn |> RbacPlug.call(:manage_ca_instances) |> dispatch_unless_halted(&CaInstanceController.create/1)
  end

  get "/ca-instances/:id" do
    conn |> RbacPlug.call(:view_ca_instances) |> dispatch_unless_halted(fn c -> CaInstanceController.show(c, id) end)
  end

  patch "/ca-instances/:id" do
    conn |> RbacPlug.call(:manage_ca_instances) |> dispatch_unless_halted(fn c -> CaInstanceController.update(c, id) end)
  end

  get "/ca-instances/:id/children" do
    conn |> RbacPlug.call(:view_ca_instances) |> dispatch_unless_halted(fn c -> CaInstanceController.children(c, id) end)
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
