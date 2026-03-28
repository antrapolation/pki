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
    ApiKeyController
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

  # --- Certificate routes ---

  get "/certificates" do
    CertController.index(conn)
  end

  get "/certificates/:serial" do
    CertController.show(conn, serial)
  end

  # --- User management routes ---

  get "/users" do
    UserController.index(conn)
  end

  post "/users" do
    UserController.create(conn)
  end

  delete "/users/:id" do
    UserController.delete(conn, id)
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

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
