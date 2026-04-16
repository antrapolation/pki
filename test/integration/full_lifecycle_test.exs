defmodule PkiIntegration.FullLifecycleTest do
  @moduledoc """
  End-to-end: Mnesia boot -> ceremony -> CSR -> sign -> OCSP -> CRL.
  Runs in a single BEAM (no :peer) to test the complete tenant data path.

  This test exercises the full certificate issuance pipeline on Mnesia:
    1. Create CA instance
    2. Create issuer key + generate ECC keypair
    3. Self-sign a root certificate
    4. Dev-activate the key (bypasses ceremony for speed)
    5. Create a certificate profile
    6. Generate and submit a CSR
    7. Sign the certificate via CertificateSigning
    8. OCSP check: should be "good"
    9. Revoke the certificate
   10. OCSP check: should be "revoked"
  """
  use ExUnit.Case, async: false

  alias PkiMnesia.{TestHelper, Repo}
  alias PkiMnesia.Structs.{IssuerKey, ThresholdShare}
  alias PkiCaEngine.{CertificateSigning, KeyActivation, CaInstanceManagement}
  alias PkiCaEngine.KeyCeremony.ShareEncryption
  alias PkiRaEngine.{CsrValidation, CertProfileConfig}
  alias PkiValidation.OcspResponder

  setup do
    dir = TestHelper.setup_mnesia()
    Application.put_env(:pki_ca_engine, :allow_dev_activate, true)

    {:ok, ka_pid} = KeyActivation.start_link(name: :integration_ka, timeout_ms: 60_000)

    on_exit(fn ->
      if Process.alive?(ka_pid), do: GenServer.stop(ka_pid)
      Application.put_env(:pki_ca_engine, :allow_dev_activate, false)
      TestHelper.teardown_mnesia(dir)
    end)

    %{ka: :integration_ka}
  end

  test "full lifecycle: create CA -> dev-activate key -> create profile -> submit CSR -> sign -> OCSP check", %{ka: ka} do
    # ── 1. Create CA instance ────────────────────────────────────────────
    {:ok, ca} = CaInstanceManagement.create_ca_instance(%{name: "Integration Root CA", is_root: true})
    assert ca.name == "Integration Root CA"
    assert ca.is_root == true

    # ── 2. Create issuer key ─────────────────────────────────────────────
    key = IssuerKey.new(%{
      ca_instance_id: ca.id,
      algorithm: "ECC-P256",
      status: "active",
      is_root: true,
      ceremony_mode: :full
    })

    # Generate a real ECC key pair for signing
    ec_key = X509.PrivateKey.new_ec(:secp256r1)
    private_key_der = X509.PrivateKey.to_der(ec_key)

    # Self-sign a root cert
    root_cert = X509.Certificate.self_signed(
      ec_key,
      "/CN=Integration Root CA",
      template: :root_ca,
      hash: :sha256,
      serial: {:random, 8},
      validity: 365 * 10
    )
    cert_der = X509.Certificate.to_der(root_cert)
    cert_pem = X509.Certificate.to_pem(root_cert)

    key = %{key | certificate_der: cert_der, certificate_pem: cert_pem}
    {:ok, _} = Repo.insert(key)

    # ── 3. Dev-activate the key ──────────────────────────────────────────
    {:ok, :dev_activated} = KeyActivation.dev_activate(ka, key.id, private_key_der)
    assert KeyActivation.is_active?(ka, key.id) == true

    # ── 4. Create cert profile ───────────────────────────────────────────
    {:ok, profile} = CertProfileConfig.create_profile(%{
      name: "Test TLS",
      issuer_key_id: key.id,
      validity_days: 365,
      approval_mode: "manual"
    })
    assert profile.name == "Test TLS"

    # ── 5. Generate a CSR ────────────────────────────────────────────────
    subject_key = X509.PrivateKey.new_ec(:secp256r1)
    csr = X509.CSR.new(subject_key, "/CN=test.example.com", hash: :sha256)
    csr_pem = X509.CSR.to_pem(csr)

    # ── 6. Submit CSR ────────────────────────────────────────────────────
    {:ok, csr_record} = CsrValidation.submit_csr(csr_pem, profile.id)
    assert csr_record.status == "pending"

    # ── 7. Sign certificate directly (bypassing RA approval for integration test) ──
    {:ok, cert} = CertificateSigning.sign_certificate(
      key.id,
      csr_pem,
      %{
        id: profile.id,
        issuer_key_id: key.id,
        subject_dn: "/CN=test.example.com",
        validity_days: 365
      },
      activation_server: ka
    )
    assert cert.serial_number != nil
    assert cert.cert_der != nil
    assert cert.status == "active"

    # ── 8. OCSP check: should be good ───────────────────────────────────
    {:ok, ocsp} = OcspResponder.check_status(cert.serial_number)
    assert ocsp.status == "good"

    # ── 9. Revoke ────────────────────────────────────────────────────────
    {:ok, revoked} = CertificateSigning.revoke_certificate(cert.serial_number, "keyCompromise")
    assert revoked.status == "revoked"
    assert revoked.revocation_reason == "keyCompromise"

    # ── 10. OCSP check: should be revoked ────────────────────────────────
    {:ok, ocsp_after} = OcspResponder.check_status(cert.serial_number)
    assert ocsp_after.status == "revoked"
  end

  test "ceremony flow: split key -> encrypt shares -> submit shares -> activate -> sign", %{ka: ka} do
    # ── 1. Create CA + issuer key ────────────────────────────────────────
    {:ok, ca} = CaInstanceManagement.create_ca_instance(%{name: "Ceremony CA", is_root: true})

    ec_key = X509.PrivateKey.new_ec(:secp256r1)
    private_key_der = X509.PrivateKey.to_der(ec_key)

    root_cert = X509.Certificate.self_signed(
      ec_key,
      "/CN=Ceremony CA",
      template: :root_ca,
      hash: :sha256,
      serial: {:random, 8},
      validity: 365 * 10
    )
    cert_der = X509.Certificate.to_der(root_cert)
    cert_pem = X509.Certificate.to_pem(root_cert)

    key = IssuerKey.new(%{
      ca_instance_id: ca.id,
      algorithm: "ECC-P256",
      status: "active",
      is_root: true,
      ceremony_mode: :full,
      threshold_config: %{k: 2, n: 3},
      certificate_der: cert_der,
      certificate_pem: cert_pem
    })
    {:ok, _} = Repo.insert(key)

    # ── 2. Split the private key into shares ─────────────────────────────
    {:ok, shares} = PkiCrypto.Shamir.split(private_key_der, 2, 3)
    assert length(shares) == 3

    # ── 3. Encrypt each share with a custodian password and store ────────
    custodians = [
      %{name: "alice", password: "alice-strong-pass-123"},
      %{name: "bob", password: "bob-strong-pass-456"},
      %{name: "charlie", password: "charlie-strong-pass-789"}
    ]

    shares
    |> Enum.with_index(1)
    |> Enum.zip(custodians)
    |> Enum.each(fn {{share, idx}, custodian} ->
      {:ok, encrypted} = ShareEncryption.encrypt_share(share, custodian.password)

      threshold_share = ThresholdShare.new(%{
        issuer_key_id: key.id,
        custodian_name: custodian.name,
        share_index: idx,
        encrypted_share: encrypted,
        password_hash: :crypto.hash(:sha256, custodian.password),
        min_shares: 2,
        total_shares: 3,
        status: "active"
      })

      {:ok, _} = Repo.insert(threshold_share)
    end)

    # ── 4. Submit threshold shares to activate the key ───────────────────
    # Submit first share (alice) - should be accepted but not yet activated
    {:ok, :share_accepted} = KeyActivation.submit_share(ka, key.id, "alice", "alice-strong-pass-123")
    assert KeyActivation.is_active?(ka, key.id) == false

    # Submit second share (bob) - should trigger activation (k=2 threshold met)
    {:ok, :key_activated} = KeyActivation.submit_share(ka, key.id, "bob", "bob-strong-pass-456")
    assert KeyActivation.is_active?(ka, key.id) == true

    # ── 5. Verify the reconstructed key works for signing ────────────────
    {:ok, profile} = CertProfileConfig.create_profile(%{
      name: "Ceremony TLS",
      issuer_key_id: key.id,
      validity_days: 365,
      approval_mode: "manual"
    })

    subject_key = X509.PrivateKey.new_ec(:secp256r1)
    csr = X509.CSR.new(subject_key, "/CN=ceremony-test.example.com", hash: :sha256)
    csr_pem = X509.CSR.to_pem(csr)

    {:ok, cert} = CertificateSigning.sign_certificate(
      key.id,
      csr_pem,
      %{
        id: profile.id,
        issuer_key_id: key.id,
        subject_dn: "/CN=ceremony-test.example.com",
        validity_days: 365
      },
      activation_server: ka
    )

    assert cert.serial_number != nil
    assert cert.cert_der != nil
    assert cert.status == "active"

    # ── 6. OCSP check on ceremony-signed cert ───────────────────────────
    {:ok, ocsp} = OcspResponder.check_status(cert.serial_number)
    assert ocsp.status == "good"

    # ── 7. Deactivate the key ────────────────────────────────────────────
    :ok = KeyActivation.deactivate(ka, key.id)
    assert KeyActivation.is_active?(ka, key.id) == false

    # Signing should fail now
    subject_key2 = X509.PrivateKey.new_ec(:secp256r1)
    csr2 = X509.CSR.new(subject_key2, "/CN=should-fail.example.com", hash: :sha256)
    csr2_pem = X509.CSR.to_pem(csr2)

    assert {:error, :key_not_active} = CertificateSigning.sign_certificate(
      key.id,
      csr2_pem,
      %{
        id: profile.id,
        issuer_key_id: key.id,
        subject_dn: "/CN=should-fail.example.com",
        validity_days: 365
      },
      activation_server: ka
    )
  end
end
