defmodule PkiRaEngine.IntegrationTest do
  @moduledoc """
  Layer 3 integration tests: RA → CA cross-service flow.

  Tests the full CSR lifecycle from submission through CA signing,
  using a CaEngineStub to simulate the CA engine's sign_certificate response.

  Covers:
  1. Submit CSR → pending
  2. Validate CSR → verified
  3. Approve CSR → approved
  4. Forward to CA stub → issued (with cert serial)
  5. Full flow via REST API
  """

  use PkiRaEngine.DataCase, async: false

  alias PkiRaEngine.Api.Router
  alias PkiRaEngine.ApiKeyManagement
  alias PkiRaEngine.CertProfileConfig
  alias PkiRaEngine.CsrValidation
  alias PkiRaEngine.UserManagement

  @valid_csr_pem "-----BEGIN CERTIFICATE REQUEST-----\nMIIBintegration\n-----END CERTIFICATE REQUEST-----"
  @opts Router.init([])

  setup do
    # Configure the CA engine stub for this test
    Application.put_env(:pki_ra_engine, :ca_engine_module, PkiRaEngine.Test.CaEngineStub)

    on_exit(fn ->
      Application.delete_env(:pki_ra_engine, :ca_engine_module)
    end)

    :ok
  end

  # ── Helpers ──────────────────────────────────────────────────────────

  defp create_officer! do
    {:ok, user} =
      UserManagement.create_user(nil, %{
        display_name: "RA Officer",
        role: "ra_officer"
      })

    user
  end

  defp create_profile! do
    {:ok, profile} =
      CertProfileConfig.create_profile(nil, %{
        name: "integration_profile_#{System.unique_integer([:positive])}"
      })

    profile
  end

  defp create_api_key!(user) do
    {:ok, %{raw_key: raw_key}} =
      ApiKeyManagement.create_api_key(nil, %{ra_user_id: user.id, label: "integration_test"})

    raw_key
  end

  defp auth_conn(method, path, body, raw_key) do
    conn =
      if body do
        Plug.Test.conn(method, path, Jason.encode!(body))
      else
        Plug.Test.conn(method, path)
      end

    conn
    |> Plug.Conn.put_req_header("authorization", "Bearer #{raw_key}")
    |> Plug.Conn.put_req_header("content-type", "application/json")
  end

  defp json_response(conn) do
    Jason.decode!(conn.resp_body)
  end

  # ── Direct module integration tests ────────────────────────────────

  describe "full CSR lifecycle via modules" do
    test "submit → validate → approve → forward_to_ca → issued" do
      officer = create_officer!()
      profile = create_profile!()

      # Step 1: Submit CSR
      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      assert csr.status == "pending"
      assert csr.csr_pem == @valid_csr_pem
      assert csr.cert_profile_id == profile.id

      # Step 2: Validate CSR
      {:ok, validated} = CsrValidation.validate_csr(nil,csr.id)
      assert validated.status == "verified"

      # Step 3: Approve CSR (auto-forwards to CA in background task)
      {:ok, approved} = CsrValidation.approve_csr(nil, validated.id, officer.id)
      assert approved.status == "approved"
      assert approved.reviewed_by == officer.id
      assert approved.reviewed_at != nil

      # Step 4: Wait for auto-forward background task to complete
      Process.sleep(200)

      # Step 5: Verify final state — should be issued by auto-forward
      {:ok, final} = CsrValidation.get_csr(nil, csr.id)
      assert final.status == "issued"
      assert final.issued_cert_serial != nil
      assert is_binary(final.issued_cert_serial)
      assert String.length(final.issued_cert_serial) > 0
    end

    test "forward_to_ca rejects non-approved CSR" do
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      assert {:error, {:invalid_transition, "pending", "issued"}} =
               CsrValidation.forward_to_ca(nil,csr.id)
    end

    test "forward_to_ca rejects verified-but-not-approved CSR" do
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      {:ok, verified} = CsrValidation.validate_csr(nil,csr.id)

      assert {:error, {:invalid_transition, "verified", "issued"}} =
               CsrValidation.forward_to_ca(nil,verified.id)
    end

    test "forward_to_ca cannot be called twice" do
      officer = create_officer!()
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      {:ok, validated} = CsrValidation.validate_csr(nil,csr.id)
      {:ok, approved} = CsrValidation.approve_csr(nil,validated.id, officer.id)
      {:ok, _issued} = CsrValidation.forward_to_ca(nil,approved.id)

      assert {:error, {:invalid_transition, "issued", "issued"}} =
               CsrValidation.forward_to_ca(nil,csr.id)
    end

    test "forward_to_ca with failing CA module returns error" do
      # Temporarily configure a module that returns errors
      Application.put_env(:pki_ra_engine, :ca_engine_module, __MODULE__.FailingCaStub)

      officer = create_officer!()
      profile = create_profile!()

      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      {:ok, validated} = CsrValidation.validate_csr(nil,csr.id)
      {:ok, approved} = CsrValidation.approve_csr(nil,validated.id, officer.id)

      assert {:error, :ca_signing_failed} = CsrValidation.forward_to_ca(nil,approved.id)

      # CSR should remain approved (not issued)
      {:ok, still_approved} = CsrValidation.get_csr(nil,csr.id)
      assert still_approved.status == "approved"

      # Restore stub
      Application.put_env(:pki_ra_engine, :ca_engine_module, PkiRaEngine.Test.CaEngineStub)
    end

    test "multiple CSRs can go through full lifecycle independently" do
      officer = create_officer!()
      profile = create_profile!()

      # Submit two CSRs
      {:ok, csr1} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      {:ok, csr2} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)

      # Process CSR1 through full lifecycle
      {:ok, v1} = CsrValidation.validate_csr(nil,csr1.id)
      {:ok, a1} = CsrValidation.approve_csr(nil,v1.id, officer.id)
      {:ok, issued1} = CsrValidation.forward_to_ca(nil,a1.id)

      # Process CSR2 through full lifecycle
      {:ok, v2} = CsrValidation.validate_csr(nil,csr2.id)
      {:ok, a2} = CsrValidation.approve_csr(nil,v2.id, officer.id)
      {:ok, issued2} = CsrValidation.forward_to_ca(nil,a2.id)

      # Both should be issued with different serials
      assert issued1.status == "issued"
      assert issued2.status == "issued"
      assert issued1.issued_cert_serial != issued2.issued_cert_serial
    end
  end

  # ── REST API integration tests ─────────────────────────────────────

  describe "full CSR lifecycle via REST API" do
    test "submit → auto-validate → approve → check status via API" do
      officer = create_officer!()
      raw_key = create_api_key!(officer)
      profile = create_profile!()

      # Step 1: Submit CSR via REST (auto-validates)
      submit_body = %{
        "csr_pem" => @valid_csr_pem,
        "cert_profile_id" => profile.id
      }

      submit_conn =
        auth_conn(:post, "/api/v1/csr", submit_body, raw_key)
        |> Router.call(@opts)

      assert submit_conn.status == 201
      submit_resp = json_response(submit_conn)
      csr_id = submit_resp["id"]
      assert csr_id != nil
      # Auto-validated after submit
      assert submit_resp["status"] in ["pending", "verified"]

      # Step 2: Approve via REST
      approve_body = %{"reviewer_user_id" => officer.id}

      approve_conn =
        auth_conn(:post, "/api/v1/csr/#{csr_id}/approve", approve_body, raw_key)
        |> Router.call(@opts)

      assert approve_conn.status == 200
      approve_resp = json_response(approve_conn)
      assert approve_resp["status"] == "approved"

      # Step 3: Forward to CA (via module — no REST endpoint for this yet)
      {:ok, issued} = CsrValidation.forward_to_ca(nil,csr_id)
      assert issued.status == "issued"
      assert issued.issued_cert_serial != nil

      # Step 4: Verify final status via REST GET
      get_conn =
        auth_conn(:get, "/api/v1/csr/#{csr_id}", nil, raw_key)
        |> Router.call(@opts)

      assert get_conn.status == 200
      get_resp = json_response(get_conn)
      assert get_resp["status"] == "issued"
      assert get_resp["issued_cert_serial"] == issued.issued_cert_serial
    end

    test "submit CSR with invalid profile returns error" do
      officer = create_officer!()
      raw_key = create_api_key!(officer)

      submit_body = %{
        "csr_pem" => @valid_csr_pem,
        "cert_profile_id" => Uniq.UUID.uuid7()
      }

      conn =
        auth_conn(:post, "/api/v1/csr", submit_body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end

    test "approve a pending (non-verified) CSR returns error" do
      officer = create_officer!()
      raw_key = create_api_key!(officer)
      profile = create_profile!()

      # Submit without auto-validate (use module directly to control state)
      {:ok, csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)

      approve_body = %{"reviewer_user_id" => officer.id}

      conn =
        auth_conn(:post, "/api/v1/csr/#{csr.id}/approve", approve_body, raw_key)
        |> Router.call(@opts)

      assert conn.status == 422
    end

    test "list CSRs filtered by status shows only matching" do
      officer = create_officer!()
      raw_key = create_api_key!(officer)
      profile = create_profile!()

      # Create one CSR and leave it pending
      {:ok, _pending_csr} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)

      # Create another CSR and validate it
      {:ok, csr2} = CsrValidation.submit_csr(nil,@valid_csr_pem, profile.id)
      {:ok, _verified} = CsrValidation.validate_csr(nil,csr2.id)

      # List only verified CSRs
      conn =
        auth_conn(:get, "/api/v1/csr?status=verified", nil, raw_key)
        |> Router.call(@opts)

      assert conn.status == 200
      resp = json_response(conn)
      assert length(resp) >= 1
      assert Enum.all?(resp, &(&1["status"] == "verified"))
    end
  end

  # ── Failing CA stub for error path testing ─────────────────────────

  defmodule FailingCaStub do
    def sign_certificate(_tenant_id, _issuer_key_id, _csr_pem, _cert_profile) do
      {:error, :ca_signing_failed}
    end
  end
end
