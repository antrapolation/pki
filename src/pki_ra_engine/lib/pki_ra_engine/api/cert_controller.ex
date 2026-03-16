defmodule PkiRaEngine.Api.CertController do
  @moduledoc """
  Placeholder controller for certificate-related REST endpoints.
  """

  import Plug.Conn

  def index(conn) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(%{data: [], message: "Certificate endpoints coming soon"}))
  end
end
