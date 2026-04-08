defmodule PkiValidation.Api.RouterTest do
  # async: false because several new endpoints exercise the application-
  # supervised PkiValidation.SigningKeyStore, which is a single global
  # process. Shared-sandbox mode lets that process see rows inserted by
  # the current test.
  use PkiValidation.DataCase, async: false

  alias PkiValidation.Api.Router
  alias PkiValidation.Schema.{CertificateStatus, SigningKeyConfig}
  alias PkiValidation.{SigningKeyStore, CertId}

  @opts Router.init([])
  @sha1_alg_der <<0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00>>

  describe "GET /health" do
    test "returns 200 and healthy=true for a clean store (including empty)" do
      # Ensure the app-level SigningKeyStore is in a clean state regardless
      # of what previous tests in this file left behind. Other tests in
      # this module intentionally push the store into a degraded state to
      # exercise the 503 path, and because the sandbox + named singleton
      # combination can leave the store holding stale refs after a test
      # transaction rolls back, a fresh reload here is the simplest
      # guarantee that this test starts from a known good state.
      PkiValidation.SigningKeyStore.reload()

      # This test intentionally exercises the "clean store" case regardless
      # of whether any SigningKeyConfig rows happen to exist in the sandbox.
      # By design, an empty store is considered healthy: `state.failed == []`
      # trivially holds, so /health returns 200. A separate test in the next
      # describe block covers the "healthy with a loaded key" case with
      # signing_keys_loaded >= 1.
      conn = conn(:get, "/health") |> Router.call(@opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "ok"
      # signing_keys_loaded is always present on a 200 response — it may be 0
      # (empty store) or >= 1 (loaded keys), but never missing.
      assert is_integer(body["signing_keys_loaded"])
    end
  end

  describe "GET /health (with SigningKeyStore status)" do
    test "returns 200 with signing_keys_loaded when store is healthy" do
      issuer_key_id = Uniq.UUID.uuid7()

      {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
      p256_oid = {1, 2, 840, 10045, 3, 1, 7}

      ec_priv_record =
        {:ECPrivateKey, 1, priv_scalar, {:namedCurve, p256_oid}, pub_point, :asn1_NOVALUE}

      %{cert: cert_der} =
        :public_key.pkix_test_root_cert(~c"Test Health Signer", [{:key, ec_priv_record}])

      cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
      encrypted = SigningKeyStore.encrypt_for_test(priv_scalar, "")

      {:ok, _} =
        %SigningKeyConfig{}
        |> SigningKeyConfig.changeset(%{
          issuer_key_id: issuer_key_id,
          algorithm: "ecc_p256",
          certificate_pem: cert_pem,
          encrypted_private_key: encrypted,
          not_before: DateTime.utc_now(),
          not_after: DateTime.add(DateTime.utc_now(), 30, :day),
          status: "active"
        })
        |> Repo.insert()

      :ok = SigningKeyStore.reload()

      on_exit(fn ->
        try do
          SigningKeyStore.reload()
        catch
          :exit, _ -> :ok
        end
      end)

      conn = conn(:get, "/health") |> Router.call(@opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "ok"
      assert is_integer(body["signing_keys_loaded"])
      assert body["signing_keys_loaded"] >= 1
    end

    test "returns 503 degraded when a signing key fails to decrypt" do
      issuer_key_id = Uniq.UUID.uuid7()

      {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
      p256_oid = {1, 2, 840, 10045, 3, 1, 7}

      ec_priv_record =
        {:ECPrivateKey, 1, priv_scalar, {:namedCurve, p256_oid}, pub_point, :asn1_NOVALUE}

      %{cert: cert_der} =
        :public_key.pkix_test_root_cert(~c"Test Degraded Signer", [{:key, ec_priv_record}])

      cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])

      # Encrypt with a NON-empty password — the application store defaults to
      # empty password, so decryption will fail and the store becomes
      # unhealthy.
      encrypted = SigningKeyStore.encrypt_for_test(priv_scalar, "wrong-password")

      {:ok, _} =
        %SigningKeyConfig{}
        |> SigningKeyConfig.changeset(%{
          issuer_key_id: issuer_key_id,
          algorithm: "ecc_p256",
          certificate_pem: cert_pem,
          encrypted_private_key: encrypted,
          not_before: DateTime.utc_now(),
          not_after: DateTime.add(DateTime.utc_now(), 30, :day),
          status: "active"
        })
        |> Repo.insert()

      :ok = SigningKeyStore.reload()

      on_exit(fn ->
        try do
          SigningKeyStore.reload()
        catch
          :exit, _ -> :ok
        end
      end)

      conn = conn(:get, "/health") |> Router.call(@opts)

      assert conn.status == 503
      body = Jason.decode!(conn.resp_body)
      assert body["status"] == "degraded"
      assert is_integer(body["signing_keys_loaded"])
      assert is_integer(body["signing_keys_failed"])
      assert body["signing_keys_failed"] >= 1
      assert Map.has_key?(body, "last_error")
      assert is_binary(body["last_error"])
    end
  end

  describe "POST /ocsp" do
    test "returns good for active certificate" do
      insert_cert("ROUTER001", "active")

      conn =
        conn(:post, "/ocsp", %{"serial_number" => "ROUTER001"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "good"} = Jason.decode!(conn.resp_body)
    end

    test "returns revoked for revoked certificate" do
      insert_cert("ROUTER002", "revoked")

      conn =
        conn(:post, "/ocsp", %{"serial_number" => "ROUTER002"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "revoked"} = Jason.decode!(conn.resp_body)
    end

    test "returns unknown for nonexistent certificate" do
      conn =
        conn(:post, "/ocsp", %{"serial_number" => "NONEXISTENT"})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "unknown"} = Jason.decode!(conn.resp_body)
    end

    test "returns 400 for missing serial_number" do
      conn =
        conn(:post, "/ocsp", %{})
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 400
      assert %{"error" => _} = Jason.decode!(conn.resp_body)
    end
  end

  describe "GET /crl" do
    test "returns CRL structure" do
      conn = conn(:get, "/crl") |> Router.call(@opts)

      assert conn.status == 200
      body = Jason.decode!(conn.resp_body)
      assert body["type"] == "X509CRL"
      assert is_list(body["revoked_certificates"])
    end
  end

  describe "malformed OCSP request body" do
    test "POST /ocsp with non-JSON body raises ParseError" do
      assert_raise Plug.Parsers.ParseError, fn ->
        conn(:post, "/ocsp", "not json{{{")
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)
      end
    end

    test "POST /ocsp with missing serial_number returns 400" do
      conn =
        conn(:post, "/ocsp", Jason.encode!(%{wrong_field: "abc"}))
        |> put_req_header("content-type", "application/json")
        |> Router.call(@opts)

      assert conn.status == 400
    end
  end

  describe "unknown routes" do
    test "returns 404" do
      conn = conn(:get, "/unknown") |> Router.call(@opts)

      assert conn.status == 404
      assert %{"error" => "not_found"} = Jason.decode!(conn.resp_body)
    end
  end

  describe "POST /ocsp/der" do
    setup :setup_der_signing_key

    test "returns DER OCSP response with correct content-type for active cert", ctx do
      insert_active_cert(ctx.issuer_key_id, "12345")
      request_der = build_ocsp_request_der(ctx.issuer_key_hash, 12345)

      conn =
        :post
        |> conn("/ocsp/der", request_der)
        |> put_req_header("content-type", "application/ocsp-request")
        |> Router.call(@opts)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/ocsp-response"]
      assert ["public, max-age=300, no-transform"] = get_resp_header(conn, "cache-control")
      assert [<<"\"", _::binary>>] = get_resp_header(conn, "etag")
      assert is_binary(conn.resp_body)

      {:ok, {:OCSPResponse, status, _bytes}} = :OCSP.decode(:OCSPResponse, conn.resp_body)
      assert status == :successful
    end

    test "returns malformedRequest for garbage body", _ctx do
      conn =
        :post
        |> conn("/ocsp/der", <<0, 0, 0, 0>>)
        |> put_req_header("content-type", "application/ocsp-request")
        |> Router.call(@opts)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/ocsp-response"]
      {:ok, {:OCSPResponse, status, body}} = :OCSP.decode(:OCSPResponse, conn.resp_body)
      assert status == :malformedRequest
      assert body == :asn1_NOVALUE
    end
  end

  describe "GET /ocsp/der/:base64" do
    setup :setup_der_signing_key

    test "decodes url-safe base64 and returns DER OCSP response", ctx do
      insert_active_cert(ctx.issuer_key_id, "54321")
      request_der = build_ocsp_request_der(ctx.issuer_key_hash, 54321)
      b64 = Base.url_encode64(request_der, padding: false)

      conn = :get |> conn("/ocsp/der/" <> b64) |> Router.call(@opts)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/ocsp-response"]
      {:ok, {:OCSPResponse, status, _}} = :OCSP.decode(:OCSPResponse, conn.resp_body)
      assert status == :successful
    end

    test "returns malformedRequest for invalid base64", _ctx do
      # "!!!!" is not valid base64 in either variant
      conn = :get |> conn("/ocsp/der/!!!!") |> Router.call(@opts)

      assert conn.status == 200
      {:ok, {:OCSPResponse, status, _}} = :OCSP.decode(:OCSPResponse, conn.resp_body)
      assert status == :malformedRequest
    end
  end

  describe "GET /crl/der/:issuer_key_id" do
    setup :setup_der_signing_key

    test "returns DER CRL with application/pkix-crl content-type", ctx do
      insert_revoked_cert_row(ctx.issuer_key_id, "9001", "key_compromise")

      conn = :get |> conn("/crl/der/" <> ctx.issuer_key_id) |> Router.call(@opts)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/pkix-crl"]
      assert ["public, max-age=3600, no-transform"] = get_resp_header(conn, "cache-control")
      assert [etag] = get_resp_header(conn, "etag")
      assert String.starts_with?(etag, "\"")

      # Body must parse as a valid CertificateList.
      cert_list = :public_key.der_decode(:CertificateList, conn.resp_body)
      assert {:CertificateList, _tbs, _alg, _sig} = cert_list
    end

    test "returns 404 for an unknown issuer", _ctx do
      unknown = Uniq.UUID.uuid7()
      conn = :get |> conn("/crl/der/" <> unknown) |> Router.call(@opts)
      assert conn.status == 404
    end
  end

  describe "GET /crl/der (default issuer)" do
    setup :setup_der_signing_key

    test "returns DER CRL for the first active issuer", ctx do
      insert_revoked_cert_row(ctx.issuer_key_id, "9002", "superseded")

      conn = :get |> conn("/crl/der") |> Router.call(@opts)

      assert conn.status == 200
      assert get_resp_header(conn, "content-type") == ["application/pkix-crl"]

      assert {:CertificateList, _tbs, _alg, _sig} =
               :public_key.der_decode(:CertificateList, conn.resp_body)
    end
  end

  describe "POST /notify/signing-key-rotation" do
    test "returns 200 with a valid bearer token" do
      conn =
        :post
        |> conn("/notify/signing-key-rotation", "")
        |> put_req_header("authorization", "Bearer test-secret")
        |> Router.call(@opts)

      assert conn.status == 200
      assert %{"status" => "ok"} = Jason.decode!(conn.resp_body)
    end

    test "returns 401 without authorization header" do
      conn =
        :post
        |> conn("/notify/signing-key-rotation", "")
        |> Router.call(@opts)

      assert conn.status == 401
      assert %{"error" => "unauthorized"} = Jason.decode!(conn.resp_body)
    end

    test "returns 401 with wrong bearer token" do
      conn =
        :post
        |> conn("/notify/signing-key-rotation", "")
        |> put_req_header("authorization", "Bearer wrong-token")
        |> Router.call(@opts)

      assert conn.status == 401
    end
  end

  # ---- Shared setup + helpers for DER endpoint tests ----

  defp setup_der_signing_key(_ctx) do
    issuer_key_id = Uniq.UUID.uuid7()

    # Generate a matching ECC P-256 keypair. The private_key bytes stored
    # in SigningKeyConfig don't need to correspond to the cert for status
    # tests to pass (we only verify structure, not signature verification),
    # but we use matching keys to mirror real-world shape.
    {pub_point, priv_scalar} = :crypto.generate_key(:ecdh, :secp256r1)
    p256_oid = {1, 2, 840, 10045, 3, 1, 7}

    ec_priv_record =
      {:ECPrivateKey, 1, priv_scalar, {:namedCurve, p256_oid}, pub_point, :asn1_NOVALUE}

    %{cert: cert_der} =
      :public_key.pkix_test_root_cert(~c"Test Router Signer", [{:key, ec_priv_record}])

    cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])

    # Encrypt with the empty password to match the application-level
    # SigningKeyStore's default password. If we used a different password
    # here the application store would silently drop the key.
    encrypted = SigningKeyStore.encrypt_for_test(priv_scalar, "")

    {:ok, _} =
      %SigningKeyConfig{}
      |> SigningKeyConfig.changeset(%{
        issuer_key_id: issuer_key_id,
        algorithm: "ecc_p256",
        certificate_pem: cert_pem,
        encrypted_private_key: encrypted,
        not_before: DateTime.utc_now(),
        not_after: DateTime.add(DateTime.utc_now(), 30, :day),
        status: "active"
      })
      |> Repo.insert()

    # Poke the application-supervised store so the new key is visible to
    # the router (which uses the default-named SigningKeyStore).
    :ok = SigningKeyStore.reload()

    issuer_key_hash = CertId.issuer_key_hash(cert_der)

    on_exit(fn ->
      # After the sandbox tears down the inserted rows, tell the global
      # store to rebuild its cache so it doesn't hold a stale reference
      # into a now-absent DB row for subsequent tests.
      try do
        SigningKeyStore.reload()
      catch
        :exit, _ -> :ok
      end
    end)

    {:ok, issuer_key_id: issuer_key_id, issuer_key_hash: issuer_key_hash}
  end

  defp insert_active_cert(issuer_key_id, serial_str) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial_str,
      issuer_key_id: issuer_key_id,
      subject_dn: "CN=#{serial_str}",
      status: "active",
      not_before: DateTime.utc_now(),
      not_after: DateTime.add(DateTime.utc_now(), 1, :day)
    })
    |> Repo.insert!()
  end

  defp insert_revoked_cert_row(issuer_key_id, serial_str, reason) do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial_str,
      issuer_key_id: issuer_key_id,
      subject_dn: "CN=#{serial_str}",
      status: "revoked",
      not_before: DateTime.utc_now(),
      not_after: DateTime.add(DateTime.utc_now(), 1, :day),
      revoked_at: DateTime.utc_now(),
      revocation_reason: reason
    })
    |> Repo.insert!()
  end

  defp build_ocsp_request_der(issuer_key_hash, serial) do
    cert_id = {
      :CertID,
      @sha1_alg_der,
      :crypto.strong_rand_bytes(20),
      issuer_key_hash,
      serial
    }

    request = {:Request, cert_id, :asn1_NOVALUE}
    tbs = {:TBSRequest, :v1, :asn1_NOVALUE, [request], :asn1_NOVALUE}
    ocsp_req = {:OCSPRequest, tbs, :asn1_NOVALUE}
    {:ok, der} = :OCSP.encode(:OCSPRequest, ocsp_req)
    IO.iodata_to_binary(der)
  end

  defp get_resp_header(conn, key), do: Plug.Conn.get_resp_header(conn, key)

  defp conn(method, path, params \\ nil) do
    Plug.Test.conn(method, path, params)
  end

  defp put_req_header(conn, key, value) do
    Plug.Conn.put_req_header(conn, key, value)
  end

  defp insert_cert(serial, "active") do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: "019577a0-0000-7000-8000-000000000001",
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "active",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z]
    })
    |> Repo.insert!()
  end

  defp insert_cert(serial, "revoked") do
    %CertificateStatus{}
    |> CertificateStatus.changeset(%{
      serial_number: serial,
      issuer_key_id: "019577a0-0000-7000-8000-000000000001",
      subject_dn: "CN=#{serial}.example.com,O=Test,C=MY",
      status: "revoked",
      not_before: ~U[2026-01-01 00:00:00.000000Z],
      not_after: ~U[2027-12-31 23:59:59.000000Z],
      revoked_at: ~U[2026-06-01 00:00:00.000000Z],
      revocation_reason: "key_compromise"
    })
    |> Repo.insert!()
  end
end
