defmodule PkiTenantWeb.ConnCase do
  @moduledoc """
  Test case for controller/endpoint tests that require a connection.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint PkiTenantWeb.Endpoint

      import Plug.Conn
      import Phoenix.ConnTest
      import PkiTenantWeb.ConnCase
    end
  end

  setup _tags do
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
