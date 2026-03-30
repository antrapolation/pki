defmodule PkiCaEngine.Api.AuthenticatedRouter do
  @moduledoc """
  Authenticated router -- all routes require a valid internal API secret via AuthPlug.
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
    KeyVaultController
  }

  plug PkiCaEngine.Api.AuthPlug
  plug :match
  plug :dispatch

  # Users
  get "/users" do
    UserController.index(conn)
  end

  post "/users" do
    UserController.create(conn)
  end

  get "/users/:id" do
    UserController.show(conn, id)
  end

  put "/users/:id/password" do
    UserController.update_password(conn, id)
  end

  delete "/users/:id" do
    UserController.delete(conn, id)
  end

  get "/users/by-username/:username" do
    UserController.by_username(conn, username)
  end

  # Keystores
  get "/keystores" do
    KeystoreController.index(conn)
  end

  post "/keystores" do
    KeystoreController.create(conn)
  end

  # Issuer Keys
  get "/issuer-keys" do
    IssuerKeyController.index(conn)
  end

  # Engine Status
  get "/status" do
    StatusController.show(conn)
  end

  # Ceremonies
  get "/ceremonies" do
    CeremonyController.index(conn)
  end

  post "/ceremonies" do
    CeremonyController.create(conn)
  end

  # Ceremony lifecycle (multi-phase via KeyCeremonyManager)
  post "/ceremonies/start" do
    CeremonyController.start_ceremony(conn)
  end

  post "/ceremonies/:id/generate-keypair" do
    CeremonyController.generate_keypair(conn, id)
  end

  post "/ceremonies/:id/self-sign" do
    CeremonyController.self_sign(conn, id)
  end

  post "/ceremonies/:id/csr" do
    CeremonyController.gen_csr(conn, id)
  end

  post "/ceremonies/:id/assign-custodians" do
    CeremonyController.assign_custodians(conn, id)
  end

  post "/ceremonies/:id/finalize" do
    CeremonyController.finalize(conn, id)
  end

  get "/ceremonies/:id/status" do
    CeremonyController.status(conn, id)
  end

  # Certificates
  get "/certificates" do
    CertificateController.index(conn)
  end

  get "/certificates/:serial" do
    CertificateController.show(conn, serial)
  end

  post "/certificates/sign" do
    CertificateController.sign(conn)
  end

  post "/certificates/revoke" do
    CertificateController.revoke(conn)
  end

  # Key Vault
  post "/keypairs/register" do
    KeyVaultController.register(conn)
  end

  post "/keypairs/:id/grant" do
    KeyVaultController.grant_access(conn, id)
  end

  post "/keypairs/:id/activate" do
    KeyVaultController.activate(conn, id)
  end

  post "/keypairs/:id/revoke-grant" do
    KeyVaultController.revoke_grant(conn, id)
  end

  get "/keypairs" do
    KeyVaultController.list(conn)
  end

  get "/keypairs/:id" do
    KeyVaultController.show(conn, id)
  end

  # Audit Log
  get "/audit-log" do
    AuditLogController.index(conn)
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
