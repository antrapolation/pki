defmodule PkiRaPortalWeb.PageController do
  use PkiRaPortalWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
