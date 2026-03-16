defmodule PkiCaPortalWeb.PageController do
  use PkiCaPortalWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
