defmodule PkiRaEngine.Api.AuthenticatedRouter do
  @moduledoc """
  Authenticated router — all routes require a valid API key or internal secret
  via AuthPlug. Routes are additionally guarded by RbacPlug for API key callers.
  """

  use Plug.Router

  alias PkiRaEngine.Api.{
    CaConnectionController,
    CsrController,
    CertController,
    UserController,
    CertProfileController,
    ServiceConfigController,
    ApiKeyController,
    RaInstanceController,
    DcvController,
    RbacPlug,
    ApiKeyScopePlug
  }

  plug PkiRaEngine.Api.AuthPlug
  plug :match
  plug :dispatch

  # --- CSR routes ---

  post "/csr" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:submit_csr)
    |> dispatch_unless_halted(&CsrController.submit/1)
  end

  get "/csr" do
    conn
    |> RbacPlug.call(:view_csrs)
    |> ApiKeyScopePlug.call(:view_csr)
    |> dispatch_unless_halted(&CsrController.list/1)
  end

  get "/csr/:id" do
    conn
    |> RbacPlug.call(:view_csrs)
    |> ApiKeyScopePlug.call(:view_csr)
    |> dispatch_unless_halted(&CsrController.show(&1, id))
  end

  post "/csr/:id/approve" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:officer_review)
    |> dispatch_unless_halted(&CsrController.approve(&1, id))
  end

  post "/csr/:id/reject" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:officer_review)
    |> dispatch_unless_halted(&CsrController.reject(&1, id))
  end

  # --- DCV routes ---

  post "/csr/:id/dcv" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:manage_dcv)
    |> dispatch_unless_halted(&DcvController.create(&1, id))
  end

  post "/csr/:id/dcv/verify" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:manage_dcv)
    |> dispatch_unless_halted(&DcvController.verify(&1, id))
  end

  get "/csr/:id/dcv" do
    conn
    |> RbacPlug.call(:view_csrs)
    |> ApiKeyScopePlug.call(:view_csr)
    |> dispatch_unless_halted(&DcvController.show(&1, id))
  end

  # --- Certificate routes ---

  get "/certificates" do
    conn
    |> RbacPlug.call(:view_csrs)
    |> ApiKeyScopePlug.call(:view_certificates)
    |> dispatch_unless_halted(&CertController.index/1)
  end

  get "/certificates/:serial" do
    conn
    |> RbacPlug.call(:view_csrs)
    |> ApiKeyScopePlug.call(:view_certificates)
    |> dispatch_unless_halted(&CertController.show(&1, serial))
  end

  post "/certificates/:serial/revoke" do
    conn
    |> RbacPlug.call(:process_csrs)
    |> ApiKeyScopePlug.call(:revoke_certificate)
    |> dispatch_unless_halted(&CertController.revoke(&1, serial))
  end

  # --- User management routes ---

  get "/users" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&UserController.index/1)
  end

  post "/users" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&UserController.create/1)
  end

  put "/users/:id/password" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&UserController.update_password(&1, id))
  end

  delete "/users/:id" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&UserController.delete(&1, id))
  end

  get "/users/by-username/:username" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&UserController.by_username(&1, username))
  end

  # --- Cert profile routes ---

  get "/cert-profiles" do
    conn |> RbacPlug.call(:manage_cert_profiles) |> dispatch_unless_halted(&CertProfileController.index/1)
  end

  post "/cert-profiles" do
    conn |> RbacPlug.call(:manage_cert_profiles) |> dispatch_unless_halted(&CertProfileController.create/1)
  end

  put "/cert-profiles/:id" do
    conn |> RbacPlug.call(:manage_cert_profiles) |> dispatch_unless_halted(&CertProfileController.update(&1, id))
  end

  delete "/cert-profiles/:id" do
    conn |> RbacPlug.call(:manage_cert_profiles) |> dispatch_unless_halted(&CertProfileController.delete(&1, id))
  end

  # --- Service config routes ---

  get "/service-configs" do
    conn |> RbacPlug.call(:manage_service_configs) |> dispatch_unless_halted(&ServiceConfigController.index/1)
  end

  post "/service-configs" do
    conn |> RbacPlug.call(:manage_service_configs) |> dispatch_unless_halted(&ServiceConfigController.upsert/1)
  end

  # --- API key routes ---

  get "/api-keys" do
    conn |> RbacPlug.call(:manage_api_keys) |> dispatch_unless_halted(&ApiKeyController.index/1)
  end

  post "/api-keys" do
    conn |> RbacPlug.call(:manage_api_keys) |> dispatch_unless_halted(&ApiKeyController.create/1)
  end

  put "/api-keys/:id" do
    conn |> RbacPlug.call(:manage_api_keys) |> dispatch_unless_halted(&ApiKeyController.update(&1, id))
  end

  post "/api-keys/:id/revoke" do
    conn |> RbacPlug.call(:manage_api_keys) |> dispatch_unless_halted(&ApiKeyController.revoke(&1, id))
  end

  # --- RA instance routes ---

  get "/ra-instances" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&RaInstanceController.index/1)
  end

  post "/ra-instances" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&RaInstanceController.create/1)
  end

  get "/ra-instances/:id" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&RaInstanceController.show(&1, id))
  end

  patch "/ra-instances/:id" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&RaInstanceController.update(&1, id))
  end

  # Available issuer keys (proxy to CA engine)
  get "/available-issuer-keys" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&RaInstanceController.available_issuer_keys/1)
  end

  # --- CA connection routes ---

  get "/ca-connections" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.index/1)
  end

  post "/ca-connections" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.create/1)
  end

  get "/ca-connections/keys" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.connected_keys/1)
  end

  delete "/ca-connections/:id" do
    conn |> RbacPlug.call(:manage_ra_admins) |> dispatch_unless_halted(&CaConnectionController.delete(&1, id))
  end

  match _ do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(404, Jason.encode!(%{error: "not_found"}))
  end

  # Helper: only call the controller if RBAC didn't halt the conn
  defp dispatch_unless_halted(%Plug.Conn{halted: true} = conn, _fun), do: conn
  defp dispatch_unless_halted(conn, fun), do: fun.(conn)
end
