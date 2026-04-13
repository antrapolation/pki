defmodule PkiCaEngine.Api.AuthPlug do
  @moduledoc """
  Plug that verifies an internal API secret from the Authorization header.

  Expects: `Authorization: Bearer <INTERNAL_API_SECRET>`

  The secret is configured via `config :pki_ca_engine, :internal_api_secret`.
  """

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    expected_secret = Application.get_env(:pki_ca_engine, :internal_api_secret)

    with ["Bearer " <> token] <- get_req_header(conn, "authorization"),
         true <- is_binary(expected_secret) and expected_secret != "",
         true <- Plug.Crypto.secure_compare(token, expected_secret) do
      tenant_id = List.first(Plug.Conn.get_req_header(conn, "x-tenant-id"))

      case validate_tenant(tenant_id) do
        :ok ->
          conn |> assign(:tenant_id, tenant_id)

        {:error, :unknown_tenant} ->
          conn
          |> put_resp_content_type("application/json")
          |> send_resp(422, Jason.encode!(%{error: "unknown_tenant"}))
          |> halt()
      end
    else
      _ ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Jason.encode!(%{error: "unauthorized"}))
        |> halt()
    end
  end

  defp validate_tenant(nil), do: :ok
  defp validate_tenant(""), do: :ok
  defp validate_tenant(tenant_id) do
    case PkiCaEngine.TenantRepo.ca_repo_safe(tenant_id) do
      {:ok, _repo} -> :ok
      {:error, :tenant_not_found} -> {:error, :unknown_tenant}
    end
  end
end
