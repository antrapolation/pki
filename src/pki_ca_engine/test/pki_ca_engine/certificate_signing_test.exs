defmodule PkiCaEngine.CertificateSigningTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.CertificateSigning
  alias PkiCaEngine.KeyActivation
  alias PkiCaEngine.KeyCeremony.SyncCeremony
  alias PkiCaEngine.Schema.{CaInstance, CaUser, Keystore}

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "signing-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    {:ok, keystore} =
      Repo.insert(
        Keystore.changeset(%Keystore{}, %{ca_instance_id: ca.id, type: "software"})
      )

    {:ok, initiator} =
      Repo.insert(
        CaUser.changeset(%CaUser{}, %{
          ca_instance_id: ca.id,
          role: "key_manager"
        })
      )

    custodians =
      for i <- 1..3 do
        {:ok, user} =
          Repo.insert(
            CaUser.changeset(%CaUser{}, %{
              ca_instance_id: ca.id,
              role: "key_manager"
            })
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

    # Complete ceremony as root with a real self-signed certificate
    {cert_der, cert_pem} =
      PkiCaEngine.IntegrationHelpers.generate_self_signed_root_cert(keypair.private_key)
    {:ok, _completed} = SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)

    # Start a KeyActivation server and activate the key
    activation_name = :"test_signing_activation_#{System.unique_integer([:positive])}"

    start_supervised!(
      {KeyActivation,
       name: activation_name, timeout_ms: 60_000},
      restart: :temporary
    )

    [c1, c2 | _] = custodians
    {:ok, :share_accepted} = KeyActivation.submit_share(activation_name, issuer_key.id, c1.id, "password-#{c1.id}")
    {:ok, :key_activated} = KeyActivation.submit_share(activation_name, issuer_key.id, c2.id, "password-#{c2.id}")

    # Reload issuer_key after ceremony completion (now has cert)
    issuer_key = Repo.get!(PkiCaEngine.Schema.IssuerKey, issuer_key.id)

    # Generate a real CSR for tests
    {csr_pem, _subject} = PkiCaEngine.IntegrationHelpers.generate_test_csr()

    %{
      ca: ca,
      issuer_key: issuer_key,
      activation_server: activation_name,
      csr_pem: csr_pem
    }
  end

  describe "sign_certificate/4" do
    test "signs a certificate when key is active", ctx do
      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365, subject_dn: "CN=test.example.com,O=Test"}

      assert {:ok, cert} =
               CertificateSigning.sign_certificate(
                 ctx.issuer_key.id,
                 csr_data,
                 cert_profile,
                 activation_server: ctx.activation_server
               )

      assert cert.serial_number != nil
      assert cert.issuer_key_id == ctx.issuer_key.id
      assert cert.subject_dn == "CN=test.example.com,O=Test"
      assert cert.status == "active"
      assert cert.not_before != nil
      assert cert.not_after != nil
      assert cert.cert_der != nil
      assert cert.cert_pem != nil
    end

    test "returns error when key is not active", ctx do
      # Deactivate the key first
      :ok = KeyActivation.deactivate(ctx.activation_server, ctx.issuer_key.id)

      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365, subject_dn: "CN=test.example.com,O=Test"}

      assert {:error, :key_not_active} =
               CertificateSigning.sign_certificate(
                 ctx.issuer_key.id,
                 csr_data,
                 cert_profile,
                 activation_server: ctx.activation_server
               )
    end

    test "generates unique serial numbers for each certificate", ctx do
      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365, subject_dn: "CN=test.example.com,O=Test"}

      {:ok, cert1} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data, cert_profile,
          activation_server: ctx.activation_server
        )

      {:ok, cert2} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data, cert_profile,
          activation_server: ctx.activation_server
        )

      assert cert1.serial_number != cert2.serial_number
    end

    test "uses default subject_dn from CSR when not in profile", ctx do
      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data, cert_profile,
          activation_server: ctx.activation_server
        )

      assert cert.subject_dn != nil
    end
  end

  describe "revoke_certificate/2" do
    test "revokes an active certificate", ctx do
      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365, subject_dn: "CN=revoke.example.com,O=Test"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data, cert_profile,
          activation_server: ctx.activation_server
        )

      assert {:ok, revoked} = CertificateSigning.revoke_certificate(cert.serial_number, "keyCompromise")
      assert revoked.status == "revoked"
      assert revoked.revocation_reason == "keyCompromise"
      assert revoked.revoked_at != nil
    end

    test "returns error for non-existent certificate" do
      assert {:error, :not_found} = CertificateSigning.revoke_certificate("nonexistent-serial", "keyCompromise")
    end
  end

  describe "get_certificate/1" do
    test "retrieves certificate by serial number", ctx do
      csr_data = ctx.csr_pem
      cert_profile = %{validity_days: 365, subject_dn: "CN=get.example.com,O=Test"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data, cert_profile,
          activation_server: ctx.activation_server
        )

      assert {:ok, found} = CertificateSigning.get_certificate(cert.serial_number)
      assert found.id == cert.id
      assert found.serial_number == cert.serial_number
    end

    test "returns error for non-existent serial" do
      assert {:error, :not_found} = CertificateSigning.get_certificate("does-not-exist")
    end
  end

  describe "list_certificates/2" do
    test "lists certificates by issuer_key_id", ctx do
      csr_data = ctx.csr_pem

      {:ok, _cert1} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data,
          %{validity_days: 365, subject_dn: "CN=list1.example.com,O=Test"},
          activation_server: ctx.activation_server
        )

      {:ok, _cert2} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data,
          %{validity_days: 365, subject_dn: "CN=list2.example.com,O=Test"},
          activation_server: ctx.activation_server
        )

      certs = CertificateSigning.list_certificates(ctx.issuer_key.id)
      assert length(certs) == 2
    end

    test "filters certificates by status", ctx do
      csr_data = ctx.csr_pem

      # This cert has DN "active" but will be revoked below
      {:ok, cert_to_revoke} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data,
          %{validity_days: 365, subject_dn: "CN=active.example.com,O=Test"},
          activation_server: ctx.activation_server
        )

      # This cert has DN "revoked" but actually stays active (never revoked)
      {:ok, _cert_stays_active} =
        CertificateSigning.sign_certificate(
          ctx.issuer_key.id, csr_data,
          %{validity_days: 365, subject_dn: "CN=revoked.example.com,O=Test"},
          activation_server: ctx.activation_server
        )

      # Revoke the first cert (DN=active), leaving the second (DN=revoked) active
      CertificateSigning.revoke_certificate(cert_to_revoke.serial_number, "keyCompromise")

      active_certs = CertificateSigning.list_certificates(ctx.issuer_key.id, status: "active")
      assert length(active_certs) == 1
      assert hd(active_certs).subject_dn == "CN=revoked.example.com,O=Test"

      revoked_certs = CertificateSigning.list_certificates(ctx.issuer_key.id, status: "revoked")
      assert length(revoked_certs) == 1
      assert hd(revoked_certs).subject_dn == "CN=active.example.com,O=Test"
    end

    test "returns empty list for unknown issuer_key_id" do
      assert [] == CertificateSigning.list_certificates(Uniq.UUID.uuid7())
    end
  end
end
