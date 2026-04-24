defmodule PkiCaEngine.ActivateWithExternalCertTest do
  @moduledoc """
  Tests for CeremonyOrchestrator.activate_with_external_cert/3.

  Covers the "Sub CA rooted to external root" flow: a key ceremony generates an
  ECC keypair and leaves the IssuerKey in "pending" status with a CSR. The
  external root CA signs and returns the cert. These tests verify that:

  - A matching, unexpired cert with a compatible algorithm activates the key.
  - A cert whose public key does not match → :public_key_mismatch.
  - An expired cert → :cert_expired.
  - A cert whose public key algorithm family mismatches → :algo_mismatch.
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{Repo, TestHelper}
  alias PkiMnesia.Structs.IssuerKey
  alias PkiCaEngine.CeremonyOrchestrator

  # ---------------------------------------------------------------------------
  # Test setup
  # ---------------------------------------------------------------------------

  setup do
    dir = TestHelper.setup_mnesia()

    on_exit(fn ->
      TestHelper.teardown_mnesia(dir)
    end)

    # Generate an ECC P-256 keypair for use in tests.
    {pub_point, priv_bin} = :crypto.generate_key(:ecdh, :secp256r1)
    # Match how ECC-P256 adapter stores the key (raw EC point = pub_point binary)
    fingerprint = :crypto.hash(:sha256, pub_point) |> Base.encode16(case: :lower)

    # Build a native Erlang EC key for X509 certificate operations.
    curve_oid = {1, 2, 840, 10045, 3, 1, 7}
    ec_private_key = {:ECPrivateKey, 1, priv_bin, {:namedCurve, curve_oid}, pub_point, :asn1_NOVALUE}
    ec_public_key = {pub_point, {:namedCurve, curve_oid}}

    # Insert a "pending" IssuerKey into Mnesia.
    key = IssuerKey.new(%{
      ca_instance_id: "ca-test-extcert",
      key_alias: "ext-cert-test",
      algorithm: "ECC-P256",
      status: "pending",
      is_root: false,
      fingerprint: fingerprint
    })
    {:ok, _} = Repo.insert(key)

    %{
      key: key,
      ec_private_key: ec_private_key,
      ec_public_key: ec_public_key,
      pub_point: pub_point,
      priv_bin: priv_bin
    }
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  # Build a self-signed cert for the given key with a given validity window.
  # Returns a PEM string.
  defp build_cert_pem(ec_private_key, validity_days) do
    native_pub_key = extract_pub_for_x509(ec_private_key)
    subject_dn = "/CN=Test Sub-CA"

    cert =
      X509.Certificate.self_signed(
        ec_private_key,
        subject_dn,
        template: :root_ca,
        hash: :sha256,
        serial: {:random, 8},
        validity: validity_days
      )

    # Override validity to expired if validity_days is negative
    _ = native_pub_key
    X509.Certificate.to_pem(cert)
  end

  # Build an explicitly expired cert (notAfter in the past).
  defp build_expired_cert_pem(ec_private_key) do
    _subject_dn = "/CN=Expired Sub-CA"
    # Use :public_key directly to build a cert with a past validity.
    not_before = ~c"000101000000Z"
    not_after = ~c"010101000000Z"

    validity = {:Validity, {:utcTime, not_before}, {:utcTime, not_after}}

    native_priv = ec_private_key

    # Build a TBSCertificate with expired validity
    {pub_point_bytes, params} = extract_ec_pub_fields(ec_private_key)

    spki = {:OTPSubjectPublicKeyInfo,
              {:PublicKeyAlgorithm, {1, 2, 840, 10045, 2, 1}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}},
              {pub_point_bytes, params}}

    issuer = {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, "Expired Sub-CA"}]]}
    subject = issuer

    tbs = {:OTPTBSCertificate,
            :v3,
            1,
            {:SignatureAlgorithm, {1, 2, 840, 10045, 4, 3, 2}, :asn1_NOVALUE},
            issuer,
            validity,
            subject,
            spki,
            :asn1_NOVALUE,
            :asn1_NOVALUE,
            []}

    tbs_der = :public_key.pkix_encode(:OTPTBSCertificate, tbs, :otp)
    sig = :public_key.sign(tbs_der, :sha256, native_priv)

    cert_record = {:OTPCertificate,
                    tbs,
                    {:SignatureAlgorithm, {1, 2, 840, 10045, 4, 3, 2}, :asn1_NOVALUE},
                    sig}

    cert_der = :public_key.pkix_encode(:OTPCertificate, cert_record, :otp)
    cert_pem = :public_key.pem_encode([{:Certificate, cert_der, :not_encrypted}])
    cert_pem
  rescue
    _ ->
      # Fallback: use X509 with a very-past validity if the above OTP path fails
      X509.Certificate.to_pem(
        X509.Certificate.self_signed(
          ec_private_key,
          "/CN=Expired",
          template: :root_ca,
          hash: :sha256,
          validity: X509.Certificate.Validity.new(
            ~U[2000-01-01 00:00:00Z],
            ~U[2001-01-01 00:00:00Z]
          )
        )
      )
  end

  defp extract_pub_for_x509({:ECPrivateKey, _, priv_bin, {:namedCurve, curve_oid}, pub_point, _}) do
    {:ECPrivateKey, 1, priv_bin, {:namedCurve, curve_oid}, pub_point, :asn1_NOVALUE}
  end
  defp extract_pub_for_x509(key), do: key

  defp extract_ec_pub_fields({:ECPrivateKey, _, _, {:namedCurve, _oid}, pub_point, _}) do
    {pub_point, :asn1_NOVALUE}
  end

  # ---------------------------------------------------------------------------
  # Test cases
  # ---------------------------------------------------------------------------

  describe "activate_with_external_cert/3" do
    test "matching cert activates key — status flips to active", %{
      key: key,
      ec_private_key: ec_priv
    } do
      cert_pem = build_cert_pem(ec_priv, 3650)

      assert {:ok, updated_key} = CeremonyOrchestrator.activate_with_external_cert(key.id, cert_pem)
      assert updated_key.status == "active"
      assert updated_key.certificate_pem != nil
      assert updated_key.certificate_der != nil
    end

    test "matching DER cert also activates key", %{
      key: key,
      ec_private_key: ec_priv
    } do
      cert_pem = build_cert_pem(ec_priv, 3650)
      # Parse and re-export as DER
      {:ok, cert} = X509.Certificate.from_pem(cert_pem)
      cert_der = X509.Certificate.to_der(cert)

      assert {:ok, updated_key} = CeremonyOrchestrator.activate_with_external_cert(key.id, cert_der)
      assert updated_key.status == "active"
    end

    test "returns :not_found for unknown key ID" do
      assert {:error, :not_found} =
               CeremonyOrchestrator.activate_with_external_cert("no-such-id", "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
    end

    test "returns :key_not_pending when key is already active", %{
      key: key,
      ec_private_key: ec_priv
    } do
      # First activation
      cert_pem = build_cert_pem(ec_priv, 3650)
      {:ok, _} = CeremonyOrchestrator.activate_with_external_cert(key.id, cert_pem)

      # Second attempt — key is now "active"
      assert {:error, :key_not_pending} =
               CeremonyOrchestrator.activate_with_external_cert(key.id, cert_pem)
    end

    test "wrong public key returns :public_key_mismatch", %{key: key} do
      # Generate a *different* EC keypair and sign with it
      {_other_pub, other_priv_bin} = :crypto.generate_key(:ecdh, :secp256r1)
      curve_oid = {1, 2, 840, 10045, 3, 1, 7}

      other_ec_priv =
        {:ECPrivateKey, 1, other_priv_bin,
         {:namedCurve, curve_oid},
         elem(:crypto.generate_key(:ecdh, :secp256r1), 0),
         :asn1_NOVALUE}

      wrong_cert_pem = build_cert_pem(other_ec_priv, 3650)

      assert {:error, :public_key_mismatch} =
               CeremonyOrchestrator.activate_with_external_cert(key.id, wrong_cert_pem)
    end

    test "expired cert returns :cert_expired", %{key: key, ec_private_key: ec_priv} do
      expired_pem = build_expired_cert_pem(ec_priv)

      assert {:error, :cert_expired} =
               CeremonyOrchestrator.activate_with_external_cert(key.id, expired_pem)
    end

    test "mismatched algorithm returns :algo_mismatch", %{key: key} do
      # Build a cert with an RSA key — key.algorithm is "ECC-P256" → mismatch
      rsa_private_key = :public_key.generate_key({:rsa, 2048, 65537})

      rsa_cert_pem =
        X509.Certificate.to_pem(
          X509.Certificate.self_signed(
            rsa_private_key,
            "/CN=RSA Sub-CA",
            template: :root_ca,
            hash: :sha256,
            validity: 3650
          )
        )

      assert {:error, :algo_mismatch} =
               CeremonyOrchestrator.activate_with_external_cert(key.id, rsa_cert_pem)
    end

    test "malformed input returns :malformed_cert", %{key: key} do
      assert {:error, :malformed_cert} =
               CeremonyOrchestrator.activate_with_external_cert(key.id, "not-a-cert")
    end
  end
end
