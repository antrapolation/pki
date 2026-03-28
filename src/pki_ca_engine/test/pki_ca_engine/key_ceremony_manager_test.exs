defmodule PkiCaEngine.KeyCeremonyManagerTest do
  use PkiCaEngine.DataCase, async: false

  alias PkiCaEngine.KeyCeremonyManager
  alias PkiCaEngine.KeypairACL
  alias PkiCaEngine.CredentialManager
  alias PkiCaEngine.Schema.{CaInstance, CaUser}

  @password "ceremony-test-pw-123"

  setup do
    {:ok, ca} =
      Repo.insert(
        CaInstance.changeset(%CaInstance{}, %{
          name: "ceremony-mgr-ca-#{System.unique_integer([:positive])}",
          created_by: "admin"
        })
      )

    # Create an admin user with credentials so we can initialize the ACL
    {:ok, admin_user} =
      CredentialManager.create_user_with_credentials(
        ca.id,
        %{username: "acl-admin-#{System.unique_integer([:positive])}", display_name: "ACL Admin", role: "ca_admin"},
        @password
      )

    admin_kem_cred = CredentialManager.get_kem_credential(admin_user.id)

    # Initialize the ACL (required for credential_own protection mode)
    {:ok, _acl_result} = KeypairACL.initialize(ca.id, admin_kem_cred.public_key)

    # Create key_manager users
    {:ok, km1} = create_user(ca.id, "key_manager", "keyadmin1")
    {:ok, km2} = create_user(ca.id, "key_manager", "keyadmin2")

    # Create auditor user
    {:ok, auditor} = create_user(ca.id, "auditor", "auditor1")

    # Create ca_admin user (not key_manager)
    {:ok, ca_admin} = create_user(ca.id, "ca_admin", "caadmin1")

    sessions = [
      %{user_id: km1.id, role: "key_manager", username: "keyadmin1"},
      %{user_id: km2.id, role: "key_manager", username: "keyadmin2"}
    ]

    auditor_session = %{user_id: auditor.id, role: "auditor", username: "auditor1"}
    ca_admin_session = %{user_id: ca_admin.id, role: "ca_admin", username: "caadmin1"}

    %{
      ca: ca,
      km1: km1,
      km2: km2,
      auditor: auditor,
      ca_admin: ca_admin,
      sessions: sessions,
      auditor_session: auditor_session,
      ca_admin_session: ca_admin_session
    }
  end

  describe "start_ceremony/2" do
    test "starts with valid key_manager sessions", ctx do
      assert {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      assert Process.alive?(pid)
      GenServer.stop(pid)
    end

    test "rejects sessions with non-key_manager role", ctx do
      bad_sessions = [ctx.ca_admin_session]

      assert {:error, :unauthorized} =
               KeyCeremonyManager.start_ceremony(ctx.ca.id, bad_sessions)
    end

    test "rejects mixed sessions where any is not key_manager", ctx do
      mixed = ctx.sessions ++ [ctx.ca_admin_session]

      assert {:error, :unauthorized} =
               KeyCeremonyManager.start_ceremony(ctx.ca.id, mixed)
    end

    test "rejects empty sessions list", ctx do
      assert {:error, :unauthorized} =
               KeyCeremonyManager.start_ceremony(ctx.ca.id, [])
    end
  end

  describe "generate_keypair/4" do
    test "generates keypair in :setup phase and transitions to :key_generated", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      assert {:ok, keypair_data} =
               KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      assert is_binary(keypair_data.public_key)
      assert is_binary(keypair_data.encrypted_private_key)

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :key_generated

      GenServer.stop(pid)
    end

    test "generates split_auth_token keypair", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      assert {:ok, keypair_data} =
               KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :split_auth_token,
                 threshold_k: 2,
                 threshold_n: 3
               )

      assert is_binary(keypair_data.public_key)
      assert is_binary(keypair_data.encrypted_private_key)

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :key_generated

      GenServer.stop(pid)
    end

    test "fails in wrong phase", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      # Generate first keypair
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      # Try again in :key_generated phase
      assert {:error, :wrong_phase} =
               KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      GenServer.stop(pid)
    end
  end

  describe "gen_self_sign_cert/3" do
    test "generates self-signed cert in :key_generated and transitions to :cert_bound", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      subject_info = "/CN=Root CA/O=Test Org"
      cert_profile = %{validity_days: 3650}

      assert {:ok, cert_pem} = KeyCeremonyManager.gen_self_sign_cert(pid, subject_info, cert_profile)
      assert is_binary(cert_pem)
      assert cert_pem =~ "BEGIN CERTIFICATE"

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :cert_bound

      GenServer.stop(pid)
    end

    test "fails in wrong phase (:setup)", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      assert {:error, :wrong_phase} =
               KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Test", %{})

      GenServer.stop(pid)
    end

    test "fails in wrong phase (:cert_bound)", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)
      {:ok, _} = KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root", %{validity_days: 365})

      assert {:error, :wrong_phase} =
               KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Again", %{})

      GenServer.stop(pid)
    end
  end

  describe "gen_csr/2" do
    test "generates CSR in :key_generated and transitions to :cert_bound", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      subject_info = "/CN=Sub CA/O=Test Org"

      assert {:ok, csr_pem} = KeyCeremonyManager.gen_csr(pid, subject_info)
      assert is_binary(csr_pem)
      assert csr_pem =~ "BEGIN CERTIFICATE REQUEST"

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :cert_bound

      GenServer.stop(pid)
    end

    test "fails in wrong phase", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      assert {:error, :wrong_phase} =
               KeyCeremonyManager.gen_csr(pid, "/CN=Sub")

      GenServer.stop(pid)
    end
  end

  describe "assign_custodians/3" do
    test "splits shares and returns encrypted shares for each custodian", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      {:ok, _} =
        KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :split_auth_token,
          threshold_k: 2,
          threshold_n: 3
        )

      {:ok, _} = KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root", %{validity_days: 365})

      custodians = [
        %{user_id: ctx.km1.id, password: "custodian-pw-1"},
        %{user_id: ctx.km2.id, password: "custodian-pw-2"},
        %{user_id: ctx.auditor.id, password: "custodian-pw-3"}
      ]

      assert {:ok, encrypted_shares} =
               KeyCeremonyManager.assign_custodians(pid, custodians, 2)

      assert length(encrypted_shares) == 3
      assert Enum.all?(encrypted_shares, &is_binary/1)

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :custodians_assigned

      GenServer.stop(pid)
    end

    test "fails in wrong phase", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      custodians = [%{user_id: ctx.km1.id, password: "pw"}]

      assert {:error, :wrong_phase} =
               KeyCeremonyManager.assign_custodians(pid, custodians, 1)

      GenServer.stop(pid)
    end
  end

  describe "finalize/2" do
    test "auditor finalizes ceremony and GenServer stops", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      {:ok, _} =
        KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :split_auth_token,
          threshold_k: 2,
          threshold_n: 3
        )

      {:ok, _} = KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root", %{validity_days: 365})

      custodians = [
        %{user_id: ctx.km1.id, password: "pw1"},
        %{user_id: ctx.km2.id, password: "pw2"},
        %{user_id: ctx.auditor.id, password: "pw3"}
      ]

      {:ok, _} = KeyCeremonyManager.assign_custodians(pid, custodians, 2)

      ref = Process.monitor(pid)

      assert {:ok, audit_trail} = KeyCeremonyManager.finalize(pid, ctx.auditor_session)
      assert is_list(audit_trail)
      assert length(audit_trail) >= 4

      # Verify audit trail contains expected actions
      actions = Enum.map(audit_trail, & &1.action)
      assert "ceremony_started" in actions
      assert "keypair_generated" in actions
      assert "self_sign_cert_generated" in actions
      assert "custodians_assigned" in actions
      assert "ceremony_finalized" in actions

      # GenServer should stop after finalize
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    end

    test "non-auditor cannot finalize", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)
      {:ok, _} = KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root", %{validity_days: 365})

      non_auditor = %{user_id: ctx.km1.id, role: "key_manager", username: "keyadmin1"}

      assert {:error, :unauthorized} = KeyCeremonyManager.finalize(pid, non_auditor)

      GenServer.stop(pid)
    end

    test "fails in wrong phase (:setup)", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      assert {:error, :wrong_phase} = KeyCeremonyManager.finalize(pid, ctx.auditor_session)

      GenServer.stop(pid)
    end

    test "credential_own can finalize from :cert_bound (no custodians needed)", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)
      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)
      {:ok, _} = KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root", %{validity_days: 365})

      ref = Process.monitor(pid)

      assert {:ok, audit_trail} = KeyCeremonyManager.finalize(pid, ctx.auditor_session)
      assert is_list(audit_trail)

      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    end
  end

  describe "get_status/1" do
    test "returns current phase and keypair info", ctx do
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :setup
      assert status.ca_instance_id == ctx.ca.id
      assert status.keypair_id == nil
      assert status.protection_mode == nil

      {:ok, _} = KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      status = KeyCeremonyManager.get_status(pid)
      assert status.phase == :key_generated
      assert status.keypair_id != nil
      assert status.protection_mode == :credential_own

      GenServer.stop(pid)
    end
  end

  describe "full root issuer flow" do
    test "start -> generate -> self_sign -> assign custodians -> finalize", ctx do
      # 1. Start ceremony
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      # 2. Generate keypair with split_auth_token
      {:ok, keypair_data} =
        KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :split_auth_token,
          threshold_k: 2,
          threshold_n: 3
        )

      assert is_binary(keypair_data.public_key)

      # 3. Self-sign certificate
      {:ok, cert_pem} =
        KeyCeremonyManager.gen_self_sign_cert(pid, "/CN=Root CA/O=Antrapolation", %{
          validity_days: 7300
        })

      assert cert_pem =~ "BEGIN CERTIFICATE"

      # 4. Assign custodians
      custodians = [
        %{user_id: ctx.km1.id, password: "custodian-alpha"},
        %{user_id: ctx.km2.id, password: "custodian-beta"},
        %{user_id: ctx.auditor.id, password: "custodian-gamma"}
      ]

      {:ok, shares} = KeyCeremonyManager.assign_custodians(pid, custodians, 2)
      assert length(shares) == 3

      # 5. Finalize
      ref = Process.monitor(pid)
      {:ok, audit_trail} = KeyCeremonyManager.finalize(pid, ctx.auditor_session)

      assert length(audit_trail) == 5
      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    end
  end

  describe "sub-CA flow" do
    test "start -> generate -> gen_csr -> finalize (credential_own, no custodians)", ctx do
      # 1. Start ceremony
      {:ok, pid} = KeyCeremonyManager.start_ceremony(ctx.ca.id, ctx.sessions)

      # 2. Generate keypair with credential_own
      {:ok, _keypair_data} =
        KeyCeremonyManager.generate_keypair(pid, "ECC-P256", :credential_own)

      # 3. Generate CSR
      {:ok, csr_pem} = KeyCeremonyManager.gen_csr(pid, "/CN=Sub CA/O=Antrapolation")
      assert csr_pem =~ "BEGIN CERTIFICATE REQUEST"

      # 4. Finalize (credential_own allows finalize from :cert_bound)
      ref = Process.monitor(pid)
      {:ok, audit_trail} = KeyCeremonyManager.finalize(pid, ctx.auditor_session)

      actions = Enum.map(audit_trail, & &1.action)
      assert "ceremony_started" in actions
      assert "keypair_generated" in actions
      assert "csr_generated" in actions
      assert "ceremony_finalized" in actions

      assert_receive {:DOWN, ^ref, :process, ^pid, :normal}, 1000
    end
  end

  # --- Helpers ---

  defp create_user(ca_instance_id, role, username) do
    %CaUser{}
    |> CaUser.registration_changeset(%{
      ca_instance_id: ca_instance_id,
      username: "#{username}-#{System.unique_integer([:positive])}",
      password: @password,
      display_name: String.capitalize(username),
      role: role
    })
    |> Repo.insert()
  end
end
