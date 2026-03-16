defmodule PkiRaEngine.Api.AuthenticatedRouter do
  @moduledoc """
  Authenticated router — all routes require a valid API key via AuthPlug.
  """

  use Plug.Router

  plug PkiRaEngine.Api.AuthPlug
  plug :match
  plug :dispatch

  post "/csr" do
    PkiRaEngine.Api.CsrController.submit(conn)
  end

  get "/csr" do
    PkiRaEngine.Api.CsrController.list(conn)
  end

  get "/csr/:id" do
    PkiRaEngine.Api.CsrController.show(conn, id)
  end

  post "/csr/:id/approve" do
    PkiRaEngine.Api.CsrController.approve(conn, id)
  end

  post "/csr/:id/reject" do
    PkiRaEngine.Api.CsrController.reject(conn, id)
  end

  get "/certificates" do
    PkiRaEngine.Api.CertController.index(conn)
  end

  match _ do
    send_resp(conn, 404, Jason.encode!(%{error: "not_found"}))
  end
end
