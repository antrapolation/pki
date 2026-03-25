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
    AuditLogController
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

  delete "/users/:id" do
    UserController.delete(conn, id)
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

  # Audit Log
  get "/audit-log" do
    AuditLogController.index(conn)
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
