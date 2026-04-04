defmodule PkiRaEngine.Api.AuthPlugTest do
  use PkiRaEngine.DataCase, async: true

  alias PkiRaEngine.Api.AuthPlug
  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.UserManagement

  @opts AuthPlug.init([])

  defp create_user! do
    {:ok, user} =
      UserManagement.create_user(nil, %{
        display_name: "Auth Plug User",
        role: "ra_officer"
      })

    user
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "auth plug test"})

    raw_key
  end

  defp call_plug(conn) do
    conn
    |> Plug.Conn.put_req_header("content-type", "application/json")
    |> AuthPlug.call(@opts)
  end

  describe "call/2" do
    test "passes through and assigns current_api_key with valid Bearer token" do
      user = create_user!()
      raw_key = create_api_key!(user)

      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
        |> call_plug()

      refute conn.halted
      assert conn.assigns[:current_api_key] != nil
      assert conn.assigns[:current_api_key].ra_user_id == user.id
    end

    test "returns 401 when no Authorization header is present" do
      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end

    test "returns 401 with invalid API key" do
      fake_key = Base.encode64(:crypto.strong_rand_bytes(32))

      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{fake_key}")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end

    test "returns 401 with revoked API key" do
      user = create_user!()

      {:ok, %{raw_key: raw_key, api_key: api_key}} =
        ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "revoke test"})

      {:ok, _revoked} = ApiKeyManagement.revoke_key(nil, api_key.id)

      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end

    test "returns 401 with empty Bearer token" do
      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer ")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end

    test "returns 401 with non-Bearer authorization scheme" do
      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Basic dXNlcjpwYXNz")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end

    test "returns 401 with expired API key" do
      user = create_user!()
      past = DateTime.add(DateTime.utc_now(), -3600, :second)

      {:ok, %{raw_key: raw_key}} =
        ApiKeyManagement.create_api_key(nil, %{
          ra_user_id: user.id,
          label: "expired key",
          expiry: past
        })

      conn =
        Plug.Test.conn(:get, "/api/v1/csr")
        |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
        |> call_plug()

      assert conn.halted
      assert conn.status == 401
      assert Jason.decode!(conn.resp_body) == %{"error" => "unauthorized"}
    end
  end
end
