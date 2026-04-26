defmodule PkiRaEngine.E2ESigningToOcspTest do
  @moduledoc """
  End-to-end test: CSR submission → RA validation → RA approval → CA signing → OCSP check.

  Uses a real ECC-P256 keypair and a dev-activated software keystore.
  PostgreSQL is NOT required — all state lives in Mnesia.

  Run as: mix test test/pki_ra_engine/e2e_signing_to_ocsp_test.exs
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, CaInstance}
  alias PkiRaEngine.{CsrValidation, CertProfileConfig}
  alias PkiCaEngine.{CertificateSigning, KeyActivation}
  alias PkiValidation.OcspResponder

  @secp256r1_oid {1, 2, 840, 10045, 3, 1, 7}

  setup do
    dir = TestHelper.setup_mnesia()
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    # Real ECC-P256 keypair for the issuer CA.
    {pub, priv} = :crypto.generate_key(:ecdh, :secp256r1)
    ec_priv = {:ECPrivateKey, 1, priv, {:namedCurve, @secp256r1_oid}, pub, :asn1_NOVALUE}
    priv_der = :public_key.der_encode(:ECPrivateKey, ec_priv)

    # Self-signed cert so CertificateSigning can embed the issuer cert.
    %{cert: cert_der} =
      :public_key.pkix_test_root_cert(~c"E2E Test CA", [{:key, ec_priv}])

    cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])

    # Create a CaInstance. check_leaf_ca requires the instance to have no
    # child CAs (is_leaf? = true when no children rows exist).
    ca_instance = CaInstance.new(%{name: "E2E Test CA Instance", is_offline: false})
    {:ok, ca_instance} = Repo.insert(ca_instance)

    # Insert IssuerKey.
    issuer_key =
      IssuerKey.new(%{
        ca_instance_id: ca_instance.id,
        key_alias: "e2e-test-issuer",
        algorithm: "ECC-P256",
        status: "active",
        keystore_type: :software,
        is_root: false,
        certificate_der: cert_der,
        certificate_pem: cert_pem
      })

    {:ok, issuer_key} = Repo.insert(issuer_key)

    # Activate the key in the default KeyActivation. Dispatcher.sign goes through
    # the default registration name so this is required for OCSP signing to work.
    {:ok, :dev_activated} = KeyActivation.dev_activate(KeyActivation, issuer_key.id, priv_der)

    # Cert profile pointing to the issuer key.
    {:ok, profile} =
      CertProfileConfig.create_profile(%{
        name: "E2E Test Profile",
        issuer_key_id: issuer_key.id,
        validity_days: 90
      })

    on_exit(fn ->
      KeyActivation.deactivate(KeyActivation, issuer_key.id)
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      TestHelper.teardown_mnesia(dir)
    end)

    %{issuer_key: issuer_key, profile: profile}
  end

  test "full pipeline: CSR → RA validate → RA approve → CA sign → OCSP good", %{
    issuer_key: issuer_key,
    profile: profile
  } do
    # Generate leaf keypair and PEM-encoded CSR.
    {leaf_pub, leaf_priv} = :crypto.generate_key(:ecdh, :secp256r1)

    leaf_ec_priv =
      {:ECPrivateKey, 1, leaf_priv, {:namedCurve, @secp256r1_oid}, leaf_pub, :asn1_NOVALUE}

    {:ok, csr_pem} =
      PkiCrypto.Csr.generate("ECC-P256", leaf_ec_priv, "/CN=leaf.e2e.test")

    # Step 1 — RA: submit CSR
    {:ok, csr} = CsrValidation.submit_csr(csr_pem, profile.id)
    assert csr.status == "pending"

    # Step 2 — RA: structural validation (pending → verified)
    {:ok, verified_csr} = CsrValidation.validate_csr(csr.id)
    assert verified_csr.status == "verified"

    # Step 3 — RA: officer approval (verified → approved)
    {:ok, approved_csr} = CsrValidation.approve_csr(csr.id, "test-officer")
    assert approved_csr.status == "approved"

    # Step 4 — CA: sign the certificate.
    # CertificateSigning.sign_certificate is called directly instead of
    # forward_to_ca, which fires an async Task and doesn't return the result.
    cert_profile_map = %{
      id: profile.id,
      issuer_key_id: issuer_key.id,
      validity_days: 90
    }

    {:ok, issued_cert} =
      CertificateSigning.sign_certificate(issuer_key.id, csr_pem, cert_profile_map)

    assert is_binary(issued_cert.cert_der)
    assert is_binary(issued_cert.serial_number)
    assert issued_cert.issuer_key_id == issuer_key.id

    # The DER must decode as a valid Certificate ASN.1 structure.
    {:Certificate, tbs, _sig_alg, _sig} =
      :public_key.der_decode(:Certificate, issued_cert.cert_der)

    assert elem(tbs, 0) == :TBSCertificate

    # Step 5 — OCSP: unsigned status lookup (no key activation needed).
    {:ok, status} = OcspResponder.check_status(issued_cert.serial_number)
    assert status.status == "good"

    # Step 6 — OCSP: signed response via Dispatcher → SoftwareAdapter → KeyActivation.
    {:ok, signed} =
      OcspResponder.signed_response(issued_cert.serial_number, issuer_key.id)

    assert signed.status != :try_later
    assert signed.status.status == "good"
    assert is_binary(signed.signature)
    assert signed.algorithm == "ECC-P256"
  end

  test "OCSP returns try_later when issuer key is not activated", %{issuer_key: issuer_key} do
    # Deactivate first so we know the key is not in the cache.
    KeyActivation.deactivate(KeyActivation, issuer_key.id)

    {:ok, result} = OcspResponder.signed_response("any-serial", issuer_key.id)
    assert result.status == :try_later
  end

  test "revoked certificate appears as revoked in OCSP", %{
    issuer_key: issuer_key,
    profile: profile
  } do
    {leaf_pub, leaf_priv} = :crypto.generate_key(:ecdh, :secp256r1)

    leaf_ec_priv =
      {:ECPrivateKey, 1, leaf_priv, {:namedCurve, @secp256r1_oid}, leaf_pub, :asn1_NOVALUE}

    {:ok, csr_pem} =
      PkiCrypto.Csr.generate("ECC-P256", leaf_ec_priv, "/CN=revoked.e2e.test")

    cert_profile_map = %{id: profile.id, issuer_key_id: issuer_key.id, validity_days: 90}
    {:ok, issued_cert} = CertificateSigning.sign_certificate(issuer_key.id, csr_pem, cert_profile_map)

    # Revoke it.
    {:ok, _} = CertificateSigning.revoke_certificate(issued_cert.serial_number, "key_compromise")

    {:ok, status} = OcspResponder.check_status(issued_cert.serial_number)
    assert status.status == "revoked"
  end
end
