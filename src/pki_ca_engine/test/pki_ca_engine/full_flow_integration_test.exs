defmodule PkiCaEngine.FullFlowIntegrationTest do
  @moduledoc """
  Full-flow integration tests verifying that the certificate signing pipeline
  produces certificates with all fields needed by the validation service.

  These tests verify the CA engine → Validation service contract:
  - Signed certificates contain serial_number, issuer_key_id, subject_dn,
    not_before, not_after, cert_der, cert_pem (all required by notification)
  - Revoked certificates have revoked_at and revocation_reason set
  - ValidationNotifier.notify_issuance/1 payload matches issued cert fields
  - ValidationNotifier.notify_revocation/2 payload matches revocation data

  NOTE: These tests don't require a running validation HTTP server.
  The ValidationNotifier tests (validation_notifier_test.exs) and the
  notification endpoint tests (in pki_validation) cover the HTTP layer.
  """
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.{CertificateSigning, KeyActivation}
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}

  setup do
    # Ensure ValidationNotifier doesn't attempt real HTTP calls
    original_url = Application.get_env(:pki_ca_engine, :validation_url)
    Application.put_env(:pki_ca_engine, :validation_url, nil)
    on_exit(fn -> Application.put_env(:pki_ca_engine, :validation_url, original_url) end)

    # Set up CA with ceremony + activated key
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "fullflow-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    {:ok, keystore} =
      Repo.insert(Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"}))

    {:ok, initiator} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "key_manager"})
      )

    custodians =
      for _i <- 1..3 do
        {:ok, user} =
          Repo.insert(
            CaUser.changeset(%CaUser{}, %{ca_instance_id: ca.id, role: "key_manager"})
          )
        user
      end

    {:ok, {ceremony, issuer_key}} =
      SyncCeremony.initiate(ca.id, %{
        algorithm: "RSA-4096",
        keystore_id: keystore.id,
        threshold_k: 2,
        threshold_n: 3,
        initiated_by: initiator.id
      })

    {:ok, keypair} = SyncCeremony.generate_keypair("RSA-4096")

    custodian_passwords =
      Enum.map(custodians, fn user -> {user.id, "password-#{user.id}"} end)

    {:ok, 3} =
      SyncCeremony.distribute_shares(ceremony, keypair.private_key, custodian_passwords)

    {cert_der, cert_pem} =
      PkiCaEngine.IntegrationHelpers.generate_self_signed_root_cert(keypair.private_key)
    {:ok, _completed} = SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)

    activation_name = :"fullflow_activation_#{System.unique_integer([:positive])}"

    start_supervised!(
      {KeyActivation, name: activation_name, timeout_ms: 60_000},
      restart: :temporary
    )

    [c1, c2 | _] = custodians
    {:ok, :share_accepted} = KeyActivation.submit_share(activation_name, nil, issuer_key.id, c1.id, "password-#{c1.id}")
    {:ok, :key_activated} = KeyActivation.submit_share(activation_name, nil, issuer_key.id, c2.id, "password-#{c2.id}")

    issuer_key = Repo.get!(PkiCaEngine.Schema.IssuerKey, issuer_key.id)
    {csr_pem, _subject} = PkiCaEngine.IntegrationHelpers.generate_test_csr()

    %{
      ca: ca,
      issuer_key: issuer_key,
      activation_server: activation_name,
      csr_pem: csr_pem
    }
  end

  describe "issued certificate has all fields needed by validation service" do
    test "certificate contains complete data for notify_issuance payload", ctx do
      cert_profile = %{validity_days: 365, subject_dn: "CN=fullflow.example.com,O=Test"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          nil,
          ctx.issuer_key.id,
          ctx.csr_pem,
          cert_profile,
          activation_server: ctx.activation_server
        )

      # These are the exact fields ValidationNotifier.notify_issuance/1 sends
      assert is_binary(cert.serial_number) and cert.serial_number != ""
      assert cert.issuer_key_id == ctx.issuer_key.id
      assert cert.subject_dn == "CN=fullflow.example.com,O=Test"
      assert %DateTime{} = cert.not_before
      assert %DateTime{} = cert.not_after
      assert DateTime.compare(cert.not_after, cert.not_before) == :gt

      # Cert DER/PEM must be present for the validation service's DER OCSP responder
      assert is_binary(cert.cert_der) and byte_size(cert.cert_der) > 0
      assert is_binary(cert.cert_pem) and String.contains?(cert.cert_pem, "CERTIFICATE")

      # Status must be "active" for OCSP to return "good"
      assert cert.status == "active"
    end

    test "multiple certificates get unique serials (required for OCSP lookup)", ctx do
      profile = %{validity_days: 365, subject_dn: "CN=serial-test.example.com,O=Test"}
      opts = [activation_server: ctx.activation_server]

      {:ok, cert1} = CertificateSigning.sign_certificate(nil, ctx.issuer_key.id, ctx.csr_pem, profile, opts)

      # Generate a different CSR to avoid duplicate fingerprint
      {csr2, _} = PkiCaEngine.IntegrationHelpers.generate_test_csr("/CN=serial-test-2.example.com/O=Test")
      {:ok, cert2} = CertificateSigning.sign_certificate(nil, ctx.issuer_key.id, csr2, profile, opts)

      assert cert1.serial_number != cert2.serial_number
    end
  end

  describe "revoked certificate has all fields needed by validation service" do
    test "revocation sets fields required for notify_revocation and CRL", ctx do
      cert_profile = %{validity_days: 365, subject_dn: "CN=revoke-flow.example.com,O=Test"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          nil,
          ctx.issuer_key.id,
          ctx.csr_pem,
          cert_profile,
          activation_server: ctx.activation_server
        )

      {:ok, revoked} =
        CertificateSigning.revoke_certificate(nil, cert.serial_number, "key_compromise")

      # These fields map to the validation service's CertificateStatus schema
      assert revoked.status == "revoked"
      assert revoked.revocation_reason == "key_compromise"
      assert %DateTime{} = revoked.revoked_at

      # Serial must be preserved for OCSP/CRL lookup
      assert revoked.serial_number == cert.serial_number
    end
  end

  describe "notification fire-and-forget semantics" do
    test "signing succeeds even when validation URL is not configured", ctx do
      # validation_url is already set to nil in setup
      cert_profile = %{validity_days: 365, subject_dn: "CN=no-notify.example.com,O=Test"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          nil,
          ctx.issuer_key.id,
          ctx.csr_pem,
          cert_profile,
          activation_server: ctx.activation_server
        )

      assert cert.status == "active"
    end

    test "signing succeeds when validation service is unreachable", ctx do
      Application.put_env(:pki_ca_engine, :validation_url, "http://127.0.0.1:1")

      cert_profile = %{validity_days: 365, subject_dn: "CN=unreachable.example.com,O=Test"}

      # The signing result must succeed regardless of notification outcome.
      # The Task.start fire-and-forget is non-deterministic; we verify only
      # the return value, not whether the async Task logs anything.
      assert {:ok, cert} =
               CertificateSigning.sign_certificate(
                 nil,
                 ctx.issuer_key.id,
                 ctx.csr_pem,
                 cert_profile,
                 activation_server: ctx.activation_server
               )

      assert cert.status == "active"
    end
  end

  describe "key lifecycle affects signing" do
    test "signing fails after key is retired via IssuerKeyManagement", ctx do
      # Retire the key
      {:ok, _retired} = PkiCaEngine.IssuerKeyManagement.update_status(nil, ctx.issuer_key, "retired")

      cert_profile = %{validity_days: 365, subject_dn: "CN=retired.example.com,O=Test"}

      assert {:error, :key_not_active} =
               CertificateSigning.sign_certificate(
                 nil,
                 ctx.issuer_key.id,
                 ctx.csr_pem,
                 cert_profile,
                 activation_server: ctx.activation_server
               )
    end

    test "signing fails after key is archived", ctx do
      {:ok, _archived} = PkiCaEngine.IssuerKeyManagement.update_status(nil, ctx.issuer_key, "archived")

      cert_profile = %{validity_days: 365, subject_dn: "CN=archived.example.com,O=Test"}

      assert {:error, :key_not_active} =
               CertificateSigning.sign_certificate(
                 nil,
                 ctx.issuer_key.id,
                 ctx.csr_pem,
                 cert_profile,
                 activation_server: ctx.activation_server
               )
    end
  end
end
