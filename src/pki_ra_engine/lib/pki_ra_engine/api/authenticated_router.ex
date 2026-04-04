defmodule PkiRaEngine.Api.AuthenticatedRouter do
  @moduledoc """
  Authenticated router — all routes require a valid API key or internal secret
  via AuthPlug.
  """

  use Plug.Router

  alias PkiRaEngine.Api.{
    CsrController,
    CertController,
    UserController,
    CertProfileController,
    ServiceConfigController,
    ApiKeyController,
    RaInstanceController,
    DcvController
  }

  plug PkiRaEngine.Api.AuthPlug
  plug :match
  plug :dispatch

  # --- CSR routes ---

  post "/csr" do
    CsrController.submit(conn)
  end

  get "/csr" do
    CsrController.list(conn)
  end

  get "/csr/:id" do
    CsrController.show(conn, id)
  end

  post "/csr/:id/approve" do
    CsrController.approve(conn, id)
  end

  post "/csr/:id/reject" do
    CsrController.reject(conn, id)
  end

  # --- DCV routes ---

  post "/csr/:id/dcv" do
    DcvController.create(conn, id)
  end

  post "/csr/:id/dcv/verify" do
    DcvController.verify(conn, id)
  end

  get "/csr/:id/dcv" do
    DcvController.show(conn, id)
  end

  # --- Certificate routes ---

  get "/certificates" do
    CertController.index(conn)
  end

  get "/certificates/:serial" do
    CertController.show(conn, serial)
  end

  post "/certificates/:serial/revoke" do
    CertController.revoke(conn, serial)
  end

  # --- User management routes ---

  get "/users" do
    UserController.index(conn)
  end

  post "/users" do
    UserController.create(conn)
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

  # --- Cert profile routes ---

  get "/cert-profiles" do
    CertProfileController.index(conn)
  end

  post "/cert-profiles" do
    CertProfileController.create(conn)
  end

  put "/cert-profiles/:id" do
    CertProfileController.update(conn, id)
  end

  delete "/cert-profiles/:id" do
    CertProfileController.delete(conn, id)
  end

  # --- Service config routes ---

  get "/service-configs" do
    ServiceConfigController.index(conn)
  end

  post "/service-configs" do
    ServiceConfigController.upsert(conn)
  end

  # --- API key routes ---

  get "/api-keys" do
    ApiKeyController.index(conn)
  end

  post "/api-keys" do
    ApiKeyController.create(conn)
  end

  post "/api-keys/:id/revoke" do
    ApiKeyController.revoke(conn, id)
  end

  # --- RA instance routes ---

  get "/ra-instances" do
    RaInstanceController.index(conn)
  end

  post "/ra-instances" do
    RaInstanceController.create(conn)
  end

  get "/ra-instances/:id" do
    RaInstanceController.show(conn, id)
  end

  patch "/ra-instances/:id" do
    RaInstanceController.update(conn, id)
  end

  # Available issuer keys (proxy to CA engine)
  get "/available-issuer-keys" do
    RaInstanceController.available_issuer_keys(conn)
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
