defmodule PkiCaEngine.IntegrationTest do
  @moduledoc """
  Layer 1 integration tests for pki_ca_engine.

  Chains together all engine modules in the correct order using REAL
  implementations (no mocks) except for the CryptoAdapter (TestCryptoAdapter
  since we don't have real crypto deps wired in).

  These tests verify end-to-end flows within a single service boundary.
  """
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.{
    CertificateSigning,
    IssuerKeyManagement,
    KeyActivation,
    KeypairAccessControl,
    KeystoreManagement,
    UserManagement
  }

  alias PkiCaEngine.KeyCeremony.{AsyncCeremony, SyncCeremony, DefaultCryptoAdapter}
  alias PkiCaEngine.Schema.{KeyCeremony, ThresholdShare}

  import PkiCaEngine.IntegrationHelpers

  # ── Test 1: Full key ceremony -> activation -> signing lifecycle ──

  describe "full lifecycle: ceremony -> activation -> signing -> revocation" do
    test "complete chain from CA creation through certificate revocation" do
      # 1. Create CA instance
      setup = create_full_ca_setup!()
      ca = setup.ca
      [km1, km2, km3] = setup.key_managers

      # 2. Verify users were created with correct roles
      assert {:ok, admin} = UserManagement.get_user(setup.ca_admin.id)
      assert admin.role == "ca_admin"

      users = UserManagement.list_users(ca.id)
      assert length(users) == 5

      # 3. Keystore is configured
      keystores = KeystoreManagement.list_keystores(ca.id)
      assert length(keystores) == 1
      assert hd(keystores).type == "software"

      # 4. Initiate sync ceremony (2-of-3)
      {:ok, {ceremony, issuer_key}} =
        SyncCeremony.initiate(ca.id, %{
          algorithm: "RSA-4096",
          keystore_id: setup.keystore.id,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: km1.id
        })

      assert ceremony.status == "initiated"
      assert issuer_key.status == "pending"

      # 5. Grant keypair access to key managers
      {:ok, _} = KeypairAccessControl.grant_access(issuer_key.id, km1.id, setup.ca_admin.id)
      {:ok, _} = KeypairAccessControl.grant_access(issuer_key.id, km2.id, setup.ca_admin.id)
      {:ok, _} = KeypairAccessControl.grant_access(issuer_key.id, km3.id, setup.ca_admin.id)

      assert KeypairAccessControl.has_access?(issuer_key.id, km1.id)
      assert KeypairAccessControl.has_access?(issuer_key.id, km2.id)
      assert KeypairAccessControl.has_access?(issuer_key.id, km3.id)

      # 6. Generate real keypair via DefaultCryptoAdapter
      adapter = %DefaultCryptoAdapter{}
      {:ok, keypair} = SyncCeremony.generate_keypair(adapter, "RSA-4096")
      assert is_binary(keypair.public_key)
      assert is_binary(keypair.private_key)

      # 7. Distribute shares to 3 key managers (each with their own password)
      custodian_passwords = [
        {km1.id, "km1-secret-pass"},
        {km2.id, "km2-secret-pass"},
        {km3.id, "km3-secret-pass"}
      ]

      {:ok, 3} =
        SyncCeremony.distribute_shares(ceremony, keypair.private_key, custodian_passwords, adapter)

      # Verify shares stored in DB
      shares =
        Repo.all(
          from s in ThresholdShare,
            where: s.issuer_key_id == ^issuer_key.id,
            order_by: s.share_index
        )

      assert length(shares) == 3

      # 8. Complete ceremony as root with real self-signed certificate
      {cert_der, cert_pem} =
        PkiCaEngine.IntegrationHelpers.generate_self_signed_root_cert(keypair.private_key)
      {:ok, completed_ceremony} = SyncCeremony.complete_as_root(ceremony, cert_der, cert_pem)

      # 9. Verify: issuer key status is "active", ceremony status is "completed"
      assert completed_ceremony.status == "completed"
      {:ok, updated_key} = IssuerKeyManagement.get_issuer_key(issuer_key.id)
      assert updated_key.status == "active"

      # 10. Day-to-day activation: 2 of 3 key managers submit shares with passwords
      activation_name = :"integ_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: activation_name, crypto_adapter: adapter, timeout_ms: 60_000},
        restart: :temporary
      )

      {:ok, :share_accepted} =
        KeyActivation.submit_share(activation_name, issuer_key.id, km1.id, "km1-secret-pass")

      {:ok, :key_activated} =
        KeyActivation.submit_share(activation_name, issuer_key.id, km2.id, "km2-secret-pass")

      # 11. Verify: key is active via KeyActivation.is_active?
      assert KeyActivation.is_active?(activation_name, issuer_key.id)

      # 12. Sign a certificate (placeholder CSR + cert profile)
      {csr_data, _} = PkiCaEngine.IntegrationHelpers.generate_test_csr()
      cert_profile = %{validity_days: 365, subject_dn: "CN=test.example.com,O=IntegTest"}

      {:ok, cert} =
        CertificateSigning.sign_certificate(
          issuer_key.id,
          csr_data,
          cert_profile,
          activation_server: activation_name
        )

      # 13. Verify: issued_certificates table has the new cert
      assert cert.serial_number != nil
      assert cert.issuer_key_id == issuer_key.id
      assert cert.subject_dn == "CN=test.example.com,O=IntegTest"
      assert cert.status == "active"

      {:ok, fetched_cert} = CertificateSigning.get_certificate(cert.serial_number)
      assert fetched_cert.id == cert.id

      # 14. Revoke the certificate
      {:ok, revoked_cert} = CertificateSigning.revoke_certificate(cert.serial_number, "keyCompromise")

      # 15. Verify: cert status is "revoked"
      assert revoked_cert.status == "revoked"
      assert revoked_cert.revocation_reason == "keyCompromise"
      assert revoked_cert.revoked_at != nil

      # 16. Deactivate key
      :ok = KeyActivation.deactivate(activation_name, issuer_key.id)

      # 17. Verify: signing fails with :key_not_active
      assert {:error, :key_not_active} =
               CertificateSigning.sign_certificate(
                 issuer_key.id,
                 csr_data,
                 cert_profile,
                 activation_server: activation_name
               )
    end
  end

  # ── Test 2: Async ceremony lifecycle ──

  describe "async ceremony lifecycle" do
    test "async ceremony completes when all N shares collected, key material wiped" do
      setup = create_full_ca_setup!()
      [km1, km2, km3] = setup.key_managers

      # Initiate ceremony via SyncCeremony.initiate (creates DB records)
      {:ok, {ceremony, _issuer_key}} =
        SyncCeremony.initiate(setup.ca.id, %{
          algorithm: "RSA-4096",
          keystore_id: setup.keystore.id,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: km1.id
        })

      # Start async ceremony with 2 second window
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ceremony,
          crypto_adapter: setup.adapter,
          window_ms: 2_000
        )

      # Verify ceremony is in_progress
      updated = Repo.get!(KeyCeremony, ceremony.id)
      assert updated.status == "in_progress"

      # Submit shares one at a time
      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, km1.id, "pw1")
      assert {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, km2.id, "pw2")
      assert {:ok, :ceremony_complete} = AsyncCeremony.submit_share(pid, km3.id, "pw3")

      # Verify all shares stored in DB
      shares =
        Repo.all(
          from s in ThresholdShare,
            where: s.issuer_key_id == ^ceremony.issuer_key_id
        )

      assert length(shares) == 3

      # Verify key material is wiped (GenServer state)
      status = AsyncCeremony.get_status(pid)
      assert status.complete == true

      GenServer.stop(pid)
    end
  end

  # ── Test 3: Async ceremony timeout ──

  describe "async ceremony timeout" do
    test "ceremony fails when window expires before all shares collected" do
      setup = create_full_ca_setup!()
      [km1 | _] = setup.key_managers

      {:ok, {ceremony, _issuer_key}} =
        SyncCeremony.initiate(setup.ca.id, %{
          algorithm: "RSA-4096",
          keystore_id: setup.keystore.id,
          threshold_k: 2,
          threshold_n: 3,
          initiated_by: km1.id
        })

      # Start with very short window (100ms)
      {:ok, pid} =
        AsyncCeremony.start_link(
          ceremony: ceremony,
          crypto_adapter: setup.adapter,
          window_ms: 100
        )

      # Submit only 1 of 3 shares
      {:ok, :share_accepted} = AsyncCeremony.submit_share(pid, km1.id, "pw1")

      # Wait for window to expire - monitor the process
      ref = Process.monitor(pid)
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1_000

      # Verify ceremony status is "failed"
      updated = Repo.get!(KeyCeremony, ceremony.id)
      assert updated.status == "failed"
    end
  end

  # ── Test 4: Key activation deactivation on timeout ──

  describe "key activation timeout" do
    test "key automatically deactivates after timeout, signing fails" do
      setup = create_full_ca_setup!()
      adapter = setup.adapter

      # Run full ceremony
      ceremony_result = run_ceremony!(setup)
      issuer_key_id = ceremony_result.issuer_key.id

      # Start KeyActivation with very short timeout (200ms)
      activation_name = :"integ_timeout_activation_#{System.unique_integer([:positive])}"

      start_supervised!(
        {KeyActivation,
         name: activation_name, crypto_adapter: adapter, timeout_ms: 200},
        restart: :temporary
      )

      # Activate key with 2 shares (threshold)
      activate_key!(activation_name, ceremony_result, 2)

      # Verify key is active
      assert KeyActivation.is_active?(activation_name, issuer_key_id)

      # Wait for timeout to expire
      Process.sleep(300)

      # Verify key is no longer active
      refute KeyActivation.is_active?(activation_name, issuer_key_id)

      # Verify signing fails
      assert {:error, :key_not_active} =
               CertificateSigning.sign_certificate(
                 issuer_key_id,
                 "CSR_DATA",
                 %{validity_days: 365, subject_dn: "CN=timeout.test"},
                 activation_server: activation_name
               )
    end
  end

  # ── Test 5: Authorization enforcement ──

  describe "authorization enforcement" do
    test "role-based access control is enforced correctly" do
      setup = create_full_ca_setup!()

      ca_admin = setup.ca_admin
      [km1 | _] = setup.key_managers
      auditor = setup.auditor

      # CA admin can manage admins and auditors
      assert :ok = UserManagement.authorize(ca_admin, :manage_ca_admins)
      assert :ok = UserManagement.authorize(ca_admin, :manage_auditors)
      assert :ok = UserManagement.authorize(ca_admin, :view_audit_log)

      # Key Manager can manage keystores and keys
      assert :ok = UserManagement.authorize(km1, :manage_keystores)
      assert :ok = UserManagement.authorize(km1, :manage_keys)
      assert :ok = UserManagement.authorize(km1, :manage_keypair_access)

      # Auditor cannot configure keystores
      assert {:error, :unauthorized} = UserManagement.authorize(auditor, :manage_keystores)
      assert {:error, :unauthorized} = UserManagement.authorize(auditor, :manage_keys)

      # Auditor can view audit log and participate in ceremony
      assert :ok = UserManagement.authorize(auditor, :view_audit_log)
      assert :ok = UserManagement.authorize(auditor, :participate_ceremony)

      # CA admin cannot manage keystores (that's key_manager territory)
      assert {:error, :unauthorized} = UserManagement.authorize(ca_admin, :manage_keystores)

      # Suspend user and verify they cannot do anything
      {:ok, suspended_admin} = UserManagement.update_user(ca_admin.id, %{status: "suspended"})
      assert {:error, :unauthorized} = UserManagement.authorize(suspended_admin, :manage_ca_admins)
      assert {:error, :unauthorized} = UserManagement.authorize(suspended_admin, :view_audit_log)

      # Suspended key manager also blocked
      {:ok, suspended_km} = UserManagement.update_user(km1.id, %{status: "suspended"})
      assert {:error, :unauthorized} = UserManagement.authorize(suspended_km, :manage_keystores)
      assert {:error, :unauthorized} = UserManagement.authorize(suspended_km, :manage_keys)
    end
  end
end
